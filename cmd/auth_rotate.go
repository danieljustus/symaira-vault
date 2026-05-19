package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/audit"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/session"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var rotateReencrypt bool
var rotateYes bool

var rotatePassphraseCmd = &cobra.Command{
	Use:   "rotate-passphrase",
	Short: "Change the vault master passphrase",
	Long: `Change the vault's master passphrase without re-initializing the vault.
The X25519 key pair stays the same — only the passphrase protecting it is changed.
Optionally re-encrypts all entries with the new passphrase.`,
	Example: `  # Change the passphrase only
  openpass rotate-passphrase

  # Change passphrase AND re-encrypt all entries (slow but clean)
  openpass rotate-passphrase --reencrypt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = cmd, args
		vaultDir, cfg, err := loadAuthConfig()
		if err != nil {
			return err
		}

		oldPassphrase, err := readHiddenInput("Current passphrase: ", nil)
		if err != nil {
			return fmt.Errorf("cannot read current passphrase: %w", err)
		}
		defer cryptopkg.Wipe(oldPassphrase)

		v, err := vaultpkg.OpenWithPassphrase(vaultDir, oldPassphrase)
		if err != nil {
			return fmt.Errorf("current passphrase is incorrect: %w", err)
		}

		newPassphrase, err := readHiddenInput("New passphrase (minimum 12 characters): ", nil)
		if err != nil {
			return fmt.Errorf("cannot read new passphrase: %w", err)
		}
		defer cryptopkg.Wipe(newPassphrase)

		if len(newPassphrase) < 12 {
			return fmt.Errorf("passphrase must be at least 12 characters")
		}

		confirmation, err := readHiddenInput("Confirm new passphrase: ", nil)
		if err != nil {
			return fmt.Errorf("cannot read confirmation: %w", err)
		}
		defer cryptopkg.Wipe(confirmation)

		if string(newPassphrase) != string(confirmation) {
			return fmt.Errorf("passphrases do not match")
		}

		if string(oldPassphrase) == string(newPassphrase) {
			return fmt.Errorf("new passphrase must be different from the current passphrase")
		}

		if !rotateYes {
			fmt.Fprintf(os.Stderr, "Change vault passphrase? (y/N): ")
			answer, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
			if readErr != nil && answer == "" {
				return fmt.Errorf("read confirmation: %w", readErr)
			}
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stderr, "Canceled")
				return nil
			}
		}

		newPassphraseForEnc := make([]byte, len(newPassphrase))
		copy(newPassphraseForEnc, newPassphrase)
		defer cryptopkg.Wipe(newPassphraseForEnc)

		if err := cryptopkg.SaveIdentity(v.Identity, filepath.Join(vaultDir, "identity.age"), newPassphraseForEnc, 0); err != nil {
			return fmt.Errorf("save identity with new passphrase: %w", err)
		}

		if rotateReencrypt {
			recipients, recErr := v.GetAllRecipientsForEncryption()
			if recErr != nil {
				return fmt.Errorf("get recipients for re-encryption: %w", recErr)
			}
			if recErr := vaultpkg.ReencryptAll(vaultDir, v.Identity, recipients); recErr != nil {
				return fmt.Errorf("re-encrypt entries: %w", recErr)
			}
		}

		ttl := configuredSessionTTL(v, 0)
		if cacheErr := sessionSavePassphrase(vaultDir, newPassphrase, ttl); cacheErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not update session cache: %v\n", cacheErr)
		}
		_ = sessionSaveIdentity(vaultDir, v.Identity.String(), ttl)

		if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID {
			if bioErr := session.SaveBiometricPassphrase(context.Background(), vaultDir, newPassphrase); bioErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not update Touch ID unlock: %v\n", bioErr)
			}
		}

		cfg.Vault.LastRotated = time.Now().UTC()
		if saveErr := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); saveErr != nil {
			return fmt.Errorf("save config: %w", saveErr)
		}

		if commitErr := v.AutoCommit("Rotate vault passphrase"); commitErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: git auto-commit failed: %v\n", commitErr)
		}

		auditLog, auditErr := audit.New("openpass", vaultDir)
		if auditErr == nil {
			if err := auditLog.LogEntry(audit.LogEntry{Action: "rotate-passphrase", OK: true, Timestamp: time.Now().UTC().Format(time.RFC3339)}); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: audit log write failed: %v\n", err)
			}
			_ = auditLog.Close()
		}

		printlnQuietAware("Passphrase rotated successfully.")
		return nil
	},
}

func init() {
	rotatePassphraseCmd.Flags().BoolVar(&rotateReencrypt, "reencrypt", true, "Re-encrypt all entries")
	rotatePassphraseCmd.Flags().BoolVarP(&rotateYes, "yes", "y", false, "Skip confirmation prompt")
	authCmd.AddCommand(rotatePassphraseCmd)
}
