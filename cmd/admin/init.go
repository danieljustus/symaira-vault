package admin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/git"
	"github.com/danieljustus/symaira-vault/internal/session"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var initAuthMethod string

var initCmd = &cobra.Command{
	Use:   "init [vault-dir]",
	Short: "Initialize a new password vault",
	Long:  "Creates a new vault directory with identity and configuration.",
	Example: `  # Initialize default vault
  symvault init

  # Initialize with specific auth method
  symvault init --auth touchid

  # Initialize custom vault directory
  symvault init ~/my-vault`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !term.IsTerminal(int(os.Stdin.Fd())) && !cli.HasCachedEnvPassphrase() {
			return fmt.Errorf("init requires a TTY or SYMVAULT_PASSPHRASE/OPENPASS_PASSPHRASE env var; use `symvault setup` for interactive initialization")
		}

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

		var passphrase []byte
		if cached := cli.ConsumeCachedEnvPassphrase(); len(cached) > 0 {
			passphrase = cached
		} else {
			passphrase, err = cli.ReadHiddenInput("Enter passphrase for vault identity (minimum 12 characters): ", nil)
			if err != nil {
				return fmt.Errorf("cannot read passphrase: %w", err)
			}
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
		// A non-nil Vault section is required for InitWithPassphrase to take
		// the argon2id path (see internal/vault/vault.go); without it, new
		// vaults would silently fall back to legacy scrypt.
		cfg.Vault = &config.VaultConfig{
			SearchIndex:     true,
			AutoHealZeroKey: true,
		}
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
			CommitTemplate: "Update from Symaira Vault",
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
		printPostInitHints(vaultDir)
		return nil
	},
}

func printPostInitHints(vaultDir string) {
	if cli.QuietMode {
		return
	}
	cli.PrintlnQuietAware("")
	cli.PrintlnQuietAware("Next steps:")
	cli.PrintlnQuietAware("  1. Add your first entry:    symvault add my-first-entry")
	cli.PrintlnQuietAware("  2. Create a backup:         symvault backup")
	cli.PrintlnQuietAware("  3. Verify the setup:        symvault doctor")
	cli.PrintlnQuietAware("  4. (Optional) full wizard:  symvault setup   # adds sync, recipients, agents")
	cli.PrintlnQuietAware("")
	cli.PrintlnQuietAware("Tip: See config.yaml.example for agent profiles, clipboard timeout, and other")
	cli.PrintlnQuietAware("     settings — copy it to one of these locations as a starting point:")
	cli.PrintlnQuietAware("     - Vault config:  " + filepath.Join(vaultDir, "config.yaml"))
	cli.PrintlnQuietAware("     - Global config: ~/.symvault/config.yaml")
	cli.PrintlnQuietAware("     https://github.com/danieljustus/symaira-vault/blob/main/config.yaml.example")
	cli.PrintlnQuietAware("")
	cli.PrintlnQuietAware("Tip: 'symvault --help' lists all commands. Use 'symvault <cmd> --help' for details.")
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
			return "", fmt.Errorf("touch ID is not available in this Symaira Vault build or on this Mac")
		}
		return normalized, nil
	}
}
