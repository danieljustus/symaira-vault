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
	runEnvFlags   []string
	runEnvFiles   []string
	runWorkingDir string
	runTimeout    time.Duration
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command with secrets injected as environment variables",
	Long:  "Executes a command with vault secrets injected as environment variables. Use --env NAME=path.field to map secrets.",
	Example: `  # Inject AWS_SECRET_ACCESS_KEY from vault entry "work/aws.secret"
  symvault run --env AWS_SECRET_ACCESS_KEY=work/aws.secret -- aws s3 ls

  # Multiple secrets from env file
  symvault run --env-file .env.symvault -- npm run dev

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
			result, err := secrets.RunCommand(secrets.RunOptions{
				Command:    args,
				Env:        envMap,
				WorkingDir: runWorkingDir,
				Timeout:    runTimeout,
			})
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

// parseEnvFile reads an env file and returns a map of env var names to secret references.
// Lines starting with # are comments. Blank lines are ignored.
// Each non-comment line must be in the format NAME=path.field.
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
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

func init() {
	runCmd.Flags().StringArrayVarP(&runEnvFlags, "env", "e", nil, "Environment variable mapping (NAME=path.field)")
	runCmd.Flags().StringArrayVarP(&runEnvFiles, "env-file", "f", nil, "File with env variable mappings (NAME=path.field), one per line")
	runCmd.Flags().StringVarP(&runWorkingDir, "working-dir", "C", "", "Working directory for the command")
	runCmd.Flags().DurationVarP(&runTimeout, "timeout", "t", 0, "Timeout for the command (e.g., 30s)")
	rootCmd.AddCommand(runCmd)
}
