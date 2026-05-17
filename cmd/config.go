package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
)

var configValidateJSON bool

const exitConfigError errorspkg.ExitCode = 6

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage OpenPass configuration",
	Long:  `Manage OpenPass configuration including validation and profiles.`,
	Example: `  # Validate the default config file
  openpass config validate

  # Validate a specific file
  openpass config validate ~/custom-config.yaml

  # JSON output
  openpass config validate --output json`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate the configuration file",
	Long: `Validate the OpenPass configuration file for schema errors.

If no path is given, validates the default config at ~/.openpass/config.yaml.`,
	Args: cobra.MaximumNArgs(1),
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var path string
		if len(args) > 0 {
			path = args[0]
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot determine home directory", err)
			}
			path = filepath.Join(home, ".openpass", "config.yaml")
		}

		cfg, err := configpkg.Load(path)
		jsonOut := wantJSONOutput(configValidateJSON)
		if err != nil {
			if jsonOut {
				PrintJSON(map[string]interface{}{
					"valid": false,
					"error": err.Error(),
				})
				return errorspkg.NewCLIError(exitConfigError, "config load failed", err)
			}
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("cannot load config from %s: %v", path, err), err)
		}

		if err := cfg.Validate(); err != nil {
			if jsonOut {
				PrintJSON(map[string]interface{}{
					"valid":  false,
					"errors": strings.Split(err.Error(), "\n"),
				})
				return errorspkg.NewCLIError(exitConfigError, "config validation failed", err)
			}
			printlnQuietAware(fmt.Sprintf("Configuration is invalid (%s):", path))
			for _, line := range strings.Split(err.Error(), "\n") {
				if line != "" {
					printlnQuietAware("  ✗ " + line)
				}
			}
			return errorspkg.NewCLIError(exitConfigError, "config validation failed", err)
		}

		if jsonOut {
			PrintJSON(map[string]interface{}{
				"valid": true,
				"path":  path,
			})
			return nil
		}

		printlnQuietAware(fmt.Sprintf("Configuration is valid (%s)", path))
		return nil
	},
}

func init() {
	configValidateCmd.Flags().BoolVar(&configValidateJSON, "json", false, "output validation result as JSON (deprecated: use --output=json)")
	configCmd.AddCommand(configValidateCmd)
	rootCmd.AddCommand(configCmd)
}
