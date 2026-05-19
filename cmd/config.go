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

var (
	configValidateJSON bool
	configFile         string
)

const exitConfigError errorspkg.ExitCode = 6

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage OpenPass configuration",
	Long:  `Manage OpenPass configuration including validation, profiles, and key-value editing.`,
	Example: `  # Validate the default config file
  openpass config validate

  # Validate a specific file
  openpass config validate ~/custom-config.yaml

  # Get a config value
  openpass config get vaultDir

  # Set a config value
  openpass config set agents.claude-code.canWrite true

  # List all config
  openpass config list

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

func resolveConfigPath(_ []string) string {
	if configFile != "" {
		return configFile
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".openpass", "config.yaml")
}

func configKeyCompletionFunc(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	known := configpkg.KnownConfigKeys()
	matches := make([]string, 0, len(known))
	for _, k := range known {
		if strings.Contains(k, "*") {
			continue
		}
		if toComplete == "" || strings.HasPrefix(k, toComplete) {
			matches = append(matches, k)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

var configGetCmd = &cobra.Command{
	Use:   "get <dotted.path>",
	Short: "Get a configuration value",
	Long: `Get the value of a configuration key using dotted path notation.

Examples:
  openpass config get vaultDir
  openpass config get agents.claude-code.canWrite
  openpass config get mcp.port`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: configKeyCompletionFunc,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		path := resolveConfigPath(args)
		if path == "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot determine config file path", nil)
		}
		key := args[0]

		root, err := configpkg.LoadConfigNode(path)
		if err != nil {
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("cannot load config: %v", err), err)
		}

		node, err := configpkg.GetConfigValue(root, key)
		if err != nil {
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("key %q not found", key), err)
		}

		val := configpkg.NodeToString(node)
		if outputFormat == "json" {
			return PrintResult(map[string]string{key: val})
		}
		printlnQuietAware(val)
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <dotted.path> <value>",
	Short: "Set a configuration value",
	Long: `Set the value of a configuration key using dotted path notation.
The value is automatically parsed as YAML to infer types: true/false for booleans,
numbers for integers, and quoted strings for text.

Examples:
  openpass config set vaultDir ~/my-vault
  openpass config set agents.claude-code.canWrite true
  openpass config set mcp.port 9090
  openpass config set clipboard.auto_clear_duration 60`,
	Args:              cobra.ExactArgs(2),
	ValidArgsFunction: configKeyCompletionFunc,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		path := resolveConfigPath(args)
		if path == "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot determine config file path", nil)
		}
		key := args[0]
		value := args[1]

		root, err := configpkg.LoadConfigNode(path)
		if err != nil {
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("cannot load config: %v", err), err)
		}

		if err := configpkg.SetConfigValue(root, key, value); err != nil {
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("cannot set %q: %v", key, err), err)
		}

		if err := configpkg.SaveConfigNode(path, root); err != nil {
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("cannot write config: %v", err), err)
		}

		if _, loadErr := configpkg.Load(path); loadErr != nil {
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("config is invalid after update: %v", loadErr), loadErr)
		}

		printlnQuietAware(fmt.Sprintf("Set %s = %s", key, value))
		return nil
	},
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all configuration values",
	Long: `Display the entire OpenPass configuration in YAML format.

This shows the raw config file contents as-is.`,
	Args: cobra.NoArgs,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		path := resolveConfigPath(args)
		if path == "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot determine config file path", nil)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return errorspkg.NewCLIError(exitConfigError, fmt.Sprintf("cannot load config: %v", err), err)
		}
		printQuietAware("%s", string(raw))
		return nil
	},
}

func init() {
	configValidateCmd.Flags().BoolVar(&configValidateJSON, "json", false, "output validation result as JSON (deprecated: use --output=json)")

	configGetCmd.Flags().StringVar(&configFile, "file", "", "path to config file (default: ~/.openpass/config.yaml)")
	configSetCmd.Flags().StringVar(&configFile, "file", "", "path to config file (default: ~/.openpass/config.yaml)")
	configListCmd.Flags().StringVar(&configFile, "file", "", "path to config file (default: ~/.openpass/config.yaml)")

	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configListCmd)
	rootCmd.AddCommand(configCmd)
}
