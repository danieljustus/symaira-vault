package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
			vaultDir, err = expandVaultDir(args[0])
		} else {
			vaultDir, err = vaultPath()
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

		passphrase, err := readHiddenInput("Enter passphrase for vault identity: ", nil)
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
				CanWrite:        true,
				RequireApproval: false,
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
			printQuietAware("Touch ID unlock enabled\n")
		}

		printQuietAware("Vault initialized at %s\n", vaultDir)
		printQuietAware("Public key: %s\n", identity.Recipient().String())
		printPostInitHints()
		return nil
	},
}

func printPostInitHints() {
	if quietMode {
		return
	}
	printlnQuietAware("")
	printlnQuietAware("Next steps:")
	printlnQuietAware("  1. Add your first entry:    openpass add my-first-entry")
	printlnQuietAware("  2. Create a backup:         openpass backup")
	printlnQuietAware("  3. Verify the setup:        openpass doctor")
	printlnQuietAware("  4. (Optional) full wizard:  openpass setup   # adds sync, recipients, agents")
	printlnQuietAware("")
	printlnQuietAware("Tip: 'openpass --help' lists all commands. Use 'openpass <cmd> --help' for details.")
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initAuthMethod, "auth", "ask", "unlock method for this vault (ask, passphrase, touchid)")
}

func resolveInitAuthMethod(method string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", "ask":
		if session.BiometricAvailable() && stdinIsTerminal() {
			answer, err := readVisibleInput("Use Touch ID for future unlocks? [y/N]: ")
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

func stdinIsTerminal() bool {
	fdRaw := os.Stdin.Fd()
	if fdRaw > uintptr(^uint(0)>>1) {
		return false
	}
	return isTerminalFunc(int(fdRaw))
}

func readVisibleInput(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := readLineFromStdin()
	if err != nil && len(line) == 0 {
		return "", fmt.Errorf("read response: %w", err)
	}
	return strings.TrimSpace(string(line)), nil
}

func expandVaultDir(vaultDir string) (string, error) {
	if vaultDir == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(vaultDir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, vaultDir[2:]), nil
	}
	return filepath.Clean(vaultDir), nil
}
