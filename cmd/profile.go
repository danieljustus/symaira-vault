package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
)

var profileVaultPath string

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage vault profiles",
	Long:  `Manage named vault profiles for switching between multiple vaults.`,
	Example: `  symvault profile list
  symvault profile add work --vault ~/.symvault-work
  symvault profile use work`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all profiles",
	Args:  cobra.NoArgs,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot determine home directory", err)
		}

		cfg, err := configpkg.Load(filepath.Join(home, ".symvault", "config.yaml"))
		if err != nil {
			cfg = configpkg.Default()
		}

		if len(cfg.Profiles) == 0 {
			printlnQuietAware("No profiles configured.")
			printlnQuietAware("Use 'symvault profile add <name> --vault <path>' to create a profile.")
			return nil
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "NAME\tVAULT PATH\tDEFAULT")
		for name, p := range cfg.Profiles {
			isDefault := ""
			if name == cfg.DefaultProfile {
				isDefault = "*"
			}
			vaultPath := p.VaultPath
			if vaultPath == "" {
				vaultPath = "(not set)"
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", name, vaultPath, isDefault)
		}
		_ = w.Flush()

		return nil
	},
}

var profileAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new profile",
	Long: `Add a new vault profile with a name and vault path.

Example:
  symvault profile add work --vault ~/.symvault-work`,
	Args: cobra.ExactArgs(1),
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if name == "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "profile name cannot be empty", nil)
		}

		if profileVaultPath == "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "--vault is required", nil)
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot determine home directory", err)
		}

		configPath := filepath.Join(home, ".symvault", "config.yaml")
		cfg, err := configpkg.Load(configPath)
		if err != nil {
			cfg = configpkg.Default()
		}

		if cfg.Profiles == nil {
			cfg.Profiles = make(map[string]*configpkg.Profile)
		}

		if _, exists := cfg.Profiles[name]; exists {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("profile %q already exists", name), nil)
		}

		cfg.Profiles[name] = &configpkg.Profile{VaultPath: profileVaultPath}

		if err := cfg.Save(); err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot save config", err)
		}

		printlnQuietAware(fmt.Sprintf("Profile %q added with vault %s", name, profileVaultPath))
		return nil
	},
}

var profileUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the default profile",
	Long: `Set the default profile to use when no --vault or OPENPASS_VAULT is specified.

Example:
  symvault profile use work`,
	Args: cobra.ExactArgs(1),
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])

		home, err := os.UserHomeDir()
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot determine home directory", err)
		}

		configPath := filepath.Join(home, ".symvault", "config.yaml")
		cfg, err := configpkg.Load(configPath)
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot load config", err)
		}

		if _, exists := cfg.Profiles[name]; !exists {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("profile %q not found", name), nil)
		}

		cfg.DefaultProfile = name

		if err := cfg.Save(); err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot save config", err)
		}

		printlnQuietAware(fmt.Sprintf("Default profile set to %q", name))
		return nil
	},
}

func init() {
	profileAddCmd.Flags().StringVar(&profileVaultPath, "vault", "", "path to the vault directory (required)")
	_ = profileAddCmd.MarkFlagRequired("vault")

	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileAddCmd)
	profileCmd.AddCommand(profileUseCmd)
	rootCmd.AddCommand(profileCmd)
}
