package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/secrets"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var (
	runEnvFlags   []string
	runWorkingDir string
	runTimeout    time.Duration
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command with secrets injected as environment variables",
	Long:  "Executes a command with vault secrets injected as environment variables. Use --env NAME=path.field to map secrets.",
	Example: `  # Inject AWS_SECRET_ACCESS_KEY from vault entry "work/aws.secret"
  openpass run --env AWS_SECRET_ACCESS_KEY=work/aws.secret -- aws s3 ls

  # Multiple secrets, custom working dir
  openpass run \
    --env DB_PASS=prod/db.password \
    --env API_TOKEN=stripe.token \
    --workdir /tmp/job -- ./deploy.sh`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVault(func(svc vaultsvc.Service) error {
			// Parse --env flags: each is "ENV_NAME=path.field"
			envMap := make(map[string]string)
			for _, envFlag := range runEnvFlags {
				parts := strings.SplitN(envFlag, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid --env format: %q (expected NAME=path.field)", envFlag)
				}
				envName := parts[0]
				secretRef := parts[1]

				value, resolveErr := secrets.ResolveSecretRef(svc, secretRef)
				if resolveErr != nil {
					return resolveErr
				}
				envMap[envName] = value
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

func init() {
	runCmd.Flags().StringArrayVarP(&runEnvFlags, "env", "e", nil, "Environment variable mapping (NAME=path.field)")
	runCmd.Flags().StringVarP(&runWorkingDir, "working-dir", "C", "", "Working directory for the command")
	runCmd.Flags().DurationVarP(&runTimeout, "timeout", "t", 0, "Timeout for the command (e.g., 30s)")
	rootCmd.AddCommand(runCmd)
}
