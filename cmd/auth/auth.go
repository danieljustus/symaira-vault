// Package auth provides authentication and session management commands.
package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/session"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var AuthStatusJSON bool

var AuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage vault unlock authentication",
	Example: `  # Check current auth status (passphrase vs Touch ID)
  symaira auth status

  # Enable Touch ID (macOS)
  symaira auth set touchid

  # Switch back to passphrase-only
  symaira auth set passphrase`,
}

var AuthStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault unlock authentication status",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = cmd, args
		vaultDir, cfg, err := loadAuthConfig()
		if err != nil {
			return err
		}
		method := cfg.EffectiveAuthMethod()
		cache := session.GetCacheStatus()
		payload := map[string]any{
			"vault":            vaultDir,
			"method":           method,
			"touchIDAvailable": session.BiometricAvailable(),
			"cache":            cache,
		}
		if cli.WantJSONOutput(AuthStatusJSON) {
			printer, err := cli.NewPrinter("json")
			if err != nil {
				return err
			}
			return printer.Print(payload)
		}
		cli.PrintlnQuietAware("Vault: " + vaultDir)
		cli.PrintlnQuietAware("Auth method: " + method)
		cli.PrintlnQuietAware(fmt.Sprintf("Touch ID available: %t", payload["touchIDAvailable"]))
		cli.PrintlnQuietAware(fmt.Sprintf("Session cache: %s (persistent: %t)", cache.Backend, cache.Persistent))
		return nil
	},
}

var AuthSetCmd = &cobra.Command{
	Use:   "set passphrase|touchid",
	Short: "Set the vault unlock authentication method",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			_ = cmd.Help()
			return fmt.Errorf("set requires exactly 1 argument: passphrase or touchid")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = cmd, args
		method, err := configpkg.NormalizeAuthMethod(args[0])
		if err != nil {
			return err
		}
		vaultDir, cfg, err := loadAuthConfig()
		if err != nil {
			return err
		}

		switch method {
		case configpkg.AuthMethodPassphrase:
			if err := cfg.SetAuthMethod(configpkg.AuthMethodPassphrase); err != nil {
				return err
			}
			if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			if err := session.ClearBiometricPassphrase(vaultDir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not remove Touch ID unlock item: %v\n", err)
			}
			cli.PrintlnQuietAware("Auth method set to passphrase")
			return nil
		case configpkg.AuthMethodTouchID:
			if !session.BiometricAvailable() {
				return fmt.Errorf("touch ID is not available in this Symaira Vault build or on this Mac")
			}
			passphrase, err := passphraseForBiometricSetup(vaultDir)
			if err != nil {
				return err
			}
			defer cryptopkg.Wipe(passphrase)
			if err := session.SaveBiometricPassphrase(context.Background(), vaultDir, passphrase); err != nil {
				return fmt.Errorf("save Touch ID unlock item: %w", err)
			}
			if err := cfg.SetAuthMethod(configpkg.AuthMethodTouchID); err != nil {
				return err
			}
			if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			cli.PrintlnQuietAware("Auth method set to touchid")
			return nil
		default:
			return fmt.Errorf("unsupported auth method %q", method)
		}
	},
}

func init() {
	AuthStatusCmd.Flags().BoolVar(&AuthStatusJSON, "json", false, "output auth status as JSON (deprecated: use --output=json)")
	AuthCmd.AddCommand(AuthStatusCmd)
	AuthCmd.AddCommand(AuthSetCmd)
	cli.RootCmd.AddCommand(AuthCmd)
}

func loadAuthConfig() (string, *configpkg.Config, error) {
	vaultDir, err := cli.VaultPath()
	if err != nil {
		return "", nil, err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return "", nil, fmt.Errorf("vault not initialized. Run 'symaira init' first")
	}
	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		return "", nil, fmt.Errorf("load config: %w", err)
	}
	return vaultDir, cfg, nil
}

func passphraseForBiometricSetup(vaultDir string) ([]byte, error) {
	if passphrase, err := cli.SessionLoadPassphrase(vaultDir); err == nil && len(passphrase) > 0 {
		return passphrase, nil
	}

	if envPass := os.Getenv("OPENPASS_PASSPHRASE"); envPass != "" {
		passphrase := []byte(envPass)
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		if _, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase); err != nil {
			return nil, fmt.Errorf("open vault: %w", err)
		}
		return passphrase, nil
	}

	passphrase, err := cli.ReadHiddenInput("Passphrase: ", nil)
	if err != nil {
		return nil, err
	}
	if _, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase); err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	return passphrase, nil
}
