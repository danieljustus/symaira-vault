package admin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/config"
	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/git"
	"github.com/danieljustus/OpenPass/internal/session"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var initAuthMethod string

var initCmd = &cobra.Command{
	Use:   "init [vault-dir]",
	Short: "Initialize a new password vault",
	Long:  "Creates a new vault directory with identity and configuration.",
	Example: `  # Initialize default vault
  openpass init

  # Initialize with specific auth method
  openpass init --auth touchid

  # Initialize custom vault directory
  openpass init ~/my-vault`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			vaultDir string
			err      error
		)
		if len(args) > 0 {
			vaultDir, err = cli.ExpandVaultDir(args[0])
		} else {
			vaultDir, err = cli.VaultPath()
		}
		if err != nil {
			return err
		}

		if _, statErr := os.Stat(filepath.Join(vaultDir, "config.yaml")); statErr == nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("vault already initialized at %s", vaultDir), nil)
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("cannot check vault directory: %w", statErr)
		}

		if mkdirErr := os.MkdirAll(vaultDir, 0o700); mkdirErr != nil {
			return fmt.Errorf("cannot create vault directory: %w", mkdirErr)
		}

		passphrase, err := cli.ReadHiddenInput("Enter passphrase for vault identity (minimum 12 characters): ", nil)
		if err != nil {
			return fmt.Errorf("cannot read passphrase: %w", err)
		}
		defer cryptopkg.Wipe(passphrase)
		if len(passphrase) < 12 {
			return fmt.Errorf("passphrase must be at least 12 characters")
		}
		authMethod, err := resolveInitAuthMethod(initAuthMethod)
		if err != nil {
			return err
		}

		cfg := config.Default()
		cfg.VaultDir = vaultDir
		if authErr := cfg.SetAuthMethod(authMethod); authErr != nil {
			return authErr
		}
		cfg.DefaultAgent = "cli"
		cfg.Agents = map[string]config.AgentProfile{
			"cli": {
				Name:            "cli",
				AllowedPaths:    []string{"*"},
				CanWrite:        config.BoolPtr(true),
				RequireApproval: config.BoolPtr(false),
			},
		}

		// Initialize Git config with defaults (auto-push enabled)
		cfg.Git = &config.GitConfig{
			AutoPush:       true,
			CommitTemplate: "Update from OpenPass",
		}

		identity, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg)
		if err != nil {
			return fmt.Errorf("cannot initialize vault: %w", err)
		}

		if err := git.Init(vaultDir); err != nil {
			return fmt.Errorf("cannot initialize git: %w", err)
		}

		if err := git.CreateGitignore(vaultDir); err != nil {
			return fmt.Errorf("cannot create .gitignore: %w", err)
		}
		if authMethod == config.AuthMethodTouchID {
			if err := session.SaveBiometricPassphrase(context.Background(), vaultDir, passphrase); err != nil {
				return fmt.Errorf("cannot configure Touch ID unlock: %w", err)
			}
			cli.PrintQuietAware("Touch ID unlock enabled\n")
		}

		cli.PrintQuietAware("Vault initialized at %s\n", vaultDir)
		cli.PrintQuietAware("Public key: %s\n", identity.Recipient().String())
		printPostInitHints()
		return nil
	},
}

func printPostInitHints() {
	if cli.QuietMode {
		return
	}
	cli.PrintlnQuietAware("")
	cli.PrintlnQuietAware("Next steps:")
	cli.PrintlnQuietAware("  1. Add your first entry:    openpass add my-first-entry")
	cli.PrintlnQuietAware("  2. Create a backup:         openpass backup")
	cli.PrintlnQuietAware("  3. Verify the setup:        openpass doctor")
	cli.PrintlnQuietAware("  4. (Optional) full wizard:  openpass setup   # adds sync, recipients, agents")
	cli.PrintlnQuietAware("")
	cli.PrintlnQuietAware("Tip: 'openpass --help' lists all commands. Use 'openpass <cmd> --help' for details.")
}

func init() {
	cli.RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initAuthMethod, "auth", "ask", "unlock method for this vault (ask, passphrase, touchid)")
}

func resolveInitAuthMethod(method string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", "ask":
		if session.BiometricAvailable() && cli.StdinIsTerminal() {
			answer, err := cli.ReadVisibleInput("Use Touch ID for future unlocks? [y/N]: ")
			if err != nil {
				return "", err
			}
			if strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes") {
				return config.AuthMethodTouchID, nil
			}
		}
		return config.AuthMethodPassphrase, nil
	default:
		normalized, err := config.NormalizeAuthMethod(method)
		if err != nil {
			return "", err
		}
		if normalized == config.AuthMethodTouchID && !session.BiometricAvailable() {
			return "", fmt.Errorf("touch ID is not available in this OpenPass build or on this Mac")
		}
		return normalized, nil
	}
}
