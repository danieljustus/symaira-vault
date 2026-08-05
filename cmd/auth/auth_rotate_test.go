package auth

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/session"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	testCurrentPassphrase = "test-passphrase"
	testNewPassphrase     = "new-strong-passphrase-2026"
)

// runRotate executes the given rotate-passphrase command with stdin lines
// (old, new, confirm[, confirm-prompt answer]) and returns stdout.
//
// NOTE: the command must be constructed BEFORE the caller sets the
// package-level rotateYes/rotateReencrypt vars — pflag's flag registration
// resets the bound variable to the flag default.
func runRotate(t *testing.T, cmd *cobra.Command, input string) (string, error) {
	t.Helper()
	restoreStdin := pipeStdin(t, input)
	defer restoreStdin()

	var err error
	out := captureStdout(t, func() {
		err = cmd.RunE(cmd, nil)
	})
	return out, err
}

func TestRotatePassphrase_HappyPath(t *testing.T) {
	vaultDir, _ := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newRotatePassphraseCmd()
	rotateYes = true
	rotateReencrypt = false
	t.Cleanup(func() {
		rotateYes = false
		rotateReencrypt = true
	})

	out, err := runRotate(t, cmd, testCurrentPassphrase+"\n"+testNewPassphrase+"\n"+testNewPassphrase+"\n")
	if err != nil {
		t.Fatalf("rotate error = %v", err)
	}
	if !strings.Contains(out, "Passphrase rotated successfully.") {
		t.Errorf("output = %q, want success message", out)
	}

	// The vault must now open with the new passphrase.
	if _, err := vaultpkg.OpenWithPassphrase(vaultDir, []byte(testNewPassphrase)); err != nil {
		t.Errorf("open vault with new passphrase: %v", err)
	}
	if _, err := vaultpkg.OpenWithPassphrase(vaultDir, []byte(testCurrentPassphrase)); err == nil {
		t.Error("vault still opens with the old passphrase after rotation")
	}

	// The session cache must hold the new passphrase.
	got, err := session.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("load cached session: %v", err)
	}
	if string(got) != testNewPassphrase {
		t.Errorf("cached passphrase = %q, want %q", got, testNewPassphrase)
	}

	// The config must record the rotation timestamp.
	cfg, err := configpkg.Load(vaultDir + "/config.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Vault == nil || cfg.Vault.LastRotated.IsZero() {
		t.Error("config LastRotated was not updated after rotation")
	}
}

func TestRotatePassphrase_WrongCurrentPassphrase(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newRotatePassphraseCmd()
	rotateYes = true
	t.Cleanup(func() { rotateYes = false })

	_, err := runRotate(t, cmd, "wrong-passphrase\n"+testNewPassphrase+"\n"+testNewPassphrase+"\n")
	if err == nil {
		t.Fatal("expected error for wrong current passphrase, got nil")
	}
	if !strings.Contains(err.Error(), "current passphrase is incorrect") {
		t.Errorf("error = %v, want incorrect-passphrase message", err)
	}
}

func TestRotatePassphrase_NewPassphraseTooShort(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newRotatePassphraseCmd()
	rotateYes = true
	t.Cleanup(func() { rotateYes = false })

	_, err := runRotate(t, cmd, testCurrentPassphrase+"\nshort\nshort\n")
	if err == nil {
		t.Fatal("expected error for short passphrase, got nil")
	}
	if !strings.Contains(err.Error(), "at least 12 characters") {
		t.Errorf("error = %v, want minimum-length message", err)
	}
}

func TestRotatePassphrase_ConfirmationMismatch(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newRotatePassphraseCmd()
	rotateYes = true
	t.Cleanup(func() { rotateYes = false })

	_, err := runRotate(t, cmd, testCurrentPassphrase+"\n"+testNewPassphrase+"\nother-strong-passphrase-99\n")
	if err == nil {
		t.Fatal("expected error for mismatched confirmation, got nil")
	}
	if !strings.Contains(err.Error(), "passphrases do not match") {
		t.Errorf("error = %v, want mismatch message", err)
	}
}

func TestRotatePassphrase_SamePassphraseRejected(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newRotatePassphraseCmd()
	rotateYes = true
	t.Cleanup(func() { rotateYes = false })

	_, err := runRotate(t, cmd, testCurrentPassphrase+"\n"+testCurrentPassphrase+"\n"+testCurrentPassphrase+"\n")
	if err == nil {
		t.Fatal("expected error for unchanged passphrase, got nil")
	}
	if !strings.Contains(err.Error(), "must be different") {
		t.Errorf("error = %v, want different-passphrase message", err)
	}
}

func TestRotatePassphrase_CancelConfirmation(t *testing.T) {
	vaultDir, _ := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newRotatePassphraseCmd()
	// rotateYes stays false (flag default): the confirmation prompt runs.

	var err error
	restoreStdin := pipeStdin(t, testCurrentPassphrase+"\n"+testNewPassphrase+"\n"+testNewPassphrase+"\nn\n")
	defer restoreStdin()
	stderr := captureStderr(t, func() {
		err = cmd.RunE(cmd, nil)
	})
	if err != nil {
		t.Fatalf("rotate cancel error = %v", err)
	}
	if !strings.Contains(stderr, "Canceled") {
		t.Errorf("stderr = %q, want canceled message", stderr)
	}

	// Nothing must have changed: the vault still opens with the old passphrase.
	if _, err := vaultpkg.OpenWithPassphrase(vaultDir, []byte(testCurrentPassphrase)); err != nil {
		t.Errorf("open vault with old passphrase after cancel: %v", err)
	}
	if _, err := vaultpkg.OpenWithPassphrase(vaultDir, []byte(testNewPassphrase)); err == nil {
		t.Error("vault opens with the new passphrase despite cancellation")
	}
}

func TestRotatePassphrase_ReadCurrentPassphraseFails(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newRotatePassphraseCmd()
	rotateYes = true
	t.Cleanup(func() { rotateYes = false })

	// Empty stdin: the first hidden-input read hits EOF.
	_, err := runRotate(t, cmd, "")
	if err == nil {
		t.Fatal("expected error for empty stdin, got nil")
	}
	if !strings.Contains(err.Error(), "cannot read current passphrase") {
		t.Errorf("error = %v, want read-failure message", err)
	}
}

func TestRotatePassphrase_UpdatesTouchIDStore(t *testing.T) {
	vaultDir, _ := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	store := installTestBiometricStore(t, true)

	cmd := newRotatePassphraseCmd()
	rotateYes = true
	rotateReencrypt = false
	t.Cleanup(func() {
		rotateYes = false
		rotateReencrypt = true
	})

	// Switch the config to touchid so the rotate path refreshes biometrics.
	cfg, err := configpkg.Load(vaultDir + "/config.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := cfg.SetAuthMethod(configpkg.AuthMethodTouchID); err != nil {
		t.Fatalf("SetAuthMethod: %v", err)
	}
	if err := cfg.SaveTo(vaultDir + "/config.yaml"); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	if _, err := runRotate(t, cmd, testCurrentPassphrase+"\n"+testNewPassphrase+"\n"+testNewPassphrase+"\n"); err != nil {
		t.Fatalf("rotate error = %v", err)
	}
	if string(store.saved) != testNewPassphrase {
		t.Errorf("biometric store saved %q, want %q", store.saved, testNewPassphrase)
	}
}
