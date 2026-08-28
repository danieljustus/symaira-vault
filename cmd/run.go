package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/secrets"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	runEnvFlags          []string
	runEnvFiles          []string
	runPassthrough       []string
	runWorkingDir        string
	runTimeout           time.Duration
	runBroker            bool
	runBrokerStrict      bool
	runBrokerPassthrough []string
)

func newRunCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected as environment variables",
		Long: `Executes a command with vault secrets injected as environment variables. Use --env NAME=path.field to map secrets.

With --broker the child's outbound traffic is routed through an in-process egress credential broker, so brokered secrets never enter the child environment. The broker mode is configured with --broker-strict (reject hosts without a matching template) and --broker-passthrough (tunnel certificate-pinning hosts without TLS interception).`,
		Example: `  # Inject AWS_SECRET_ACCESS_KEY from vault entry "work/aws.secret"
  symvault run --env AWS_SECRET_ACCESS_KEY=work/aws.secret -- aws s3 ls

  # Multiple secrets from env file
  symvault run --env-file .env.symvault -- npm run dev

  # Pass through parent NODE_ENV and PORT to the child process
  NODE_ENV=production PORT=8080 symvault run --passthrough NODE_ENV,PORT -- npm start

  # Route the child through the egress broker: strict mode, with one
  # certificate-pinning host tunneled without TLS interception
  symvault run --broker --broker-strict --broker-passthrough corp.internal -- ./deploy.sh

  # Multiple secrets, custom working dir
  symvault run \
    --env DB_PASS=prod/db.password \
    --env API_TOKEN=stripe.token \
    --workdir /tmp/job -- ./deploy.sh`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
				// Parse --env flags: each is "ENV_NAME=path.field"
				envMap := make(map[string]string)
				for _, envFlag := range runEnvFlags {
					parts := strings.SplitN(envFlag, "=", 2)
					if len(parts) != 2 {
						return fmt.Errorf("invalid --env format: %q (expected NAME=path.field)", envFlag)
					}
					envName := parts[0]
					secretRef := parts[1]

					value, resolveErr := secrets.ResolveSecretRef(v, secretRef)
					if resolveErr != nil {
						return resolveErr
					}
					envMap[envName] = value
				}

				// Parse --env-file flags: each file contains "ENV_NAME=path.field" lines
				for _, envFilePath := range runEnvFiles {
					parsed, parseErr := parseEnvFile(envFilePath)
					if parseErr != nil {
						return parseErr
					}
					for envName, secretRef := range parsed {
						if _, exists := envMap[envName]; exists {
							return fmt.Errorf("duplicate env var %q: defined in both --env and --env-file (or in multiple --env-file)", envName)
						}
						value, resolveErr := secrets.ResolveSecretRef(v, secretRef)
						if resolveErr != nil {
							return resolveErr
						}
						envMap[envName] = value
					}
				}

				// args contains the command and its arguments (everything after --)
				// In --broker mode an in-process egress broker proxies the
				// child's outbound traffic; credentials are attached
				// server-side and never enter the child environment.
				var brokerCleanup func()
				if runBroker {
					brokerEnv, cleanup, brokerErr := brokerEnvForRun(v, runBrokerStrict, runBrokerPassthrough)
					if brokerErr != nil {
						return brokerErr
					}
					brokerCleanup = cleanup
					for k, val := range brokerEnv {
						envMap[k] = val
					}
				}

				result, err := secrets.RunCommand(secrets.RunOptions{
					Command:     args,
					Env:         envMap,
					Passthrough: runPassthrough,
					WorkingDir:  runWorkingDir,
					Timeout:     runTimeout,
				})
				if brokerCleanup != nil {
					brokerCleanup()
				}
				if err != nil {
					return err
				}

				// Print stdout/stderr
				if result.Stdout != "" {
					_, _ = fmt.Print(result.Stdout)
				}
				if result.Stderr != "" {
					_, _ = fmt.Fprint(os.Stderr, result.Stderr)
				}

				if result.ExitCode != 0 {
					return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("command exited with code %d", result.ExitCode), nil)
				}

				return nil
			})
		},
	}
	c.Flags().StringArrayVarP(&runEnvFlags, "env", "e", nil, "Environment variable mapping (NAME=path.field)")
	c.Flags().StringArrayVarP(&runEnvFiles, "env-file", "f", nil, "File with env variable mappings (NAME=path.field), one per line")
	c.Flags().StringArrayVar(&runPassthrough, "passthrough", nil, "Parent env var names to pass through to the child process (comma-separated)")
	c.Flags().StringVarP(&runWorkingDir, "working-dir", "C", "", "Working directory for the command")
	c.Flags().DurationVarP(&runTimeout, "timeout", "t", 0, "Timeout for the command (e.g., 30s)")
	c.Flags().BoolVar(&runBroker, "broker", false, "Route the child's outbound traffic through the egress credential broker (credentials never enter the child environment); configure with --broker-strict and --broker-passthrough")
	c.Flags().BoolVar(&runBrokerStrict, "broker-strict", false, "With --broker: reject requests to hosts without a matching template with 403")
	c.Flags().StringSliceVar(&runBrokerPassthrough, "broker-passthrough", nil, "With --broker: hosts tunneled without TLS interception (comma-separated, domain suffixes match)")
	c.GroupID = cli.GroupIDVault
	return c
}

// parseEnvFile reads an env file and returns a map of env var names to secret references.
// Lines starting with # are comments. Blank lines are ignored.
// Each non-comment line must be in the format NAME=path.field.
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- env file path is user-provided CLI argument
	if err != nil {
		return nil, fmt.Errorf("open env file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format in %s:%d: %q (expected NAME=path.field)", path, lineNum, line)
		}
		name := strings.TrimSpace(parts[0])
		ref := strings.TrimSpace(parts[1])
		if name == "" || ref == "" {
			return nil, fmt.Errorf("empty name or ref in %s:%d: %q", path, lineNum, line)
		}
		result[name] = ref
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file %q: %w", path, err)
	}
	return result, nil
}
