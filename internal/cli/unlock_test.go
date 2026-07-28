package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/session"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestUnlockVaultWithTTL_InteractiveSkipsBiometric(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := configpkg.Default()
	if err := cfg.SetAuthMethod(configpkg.AuthMethodTouchID); err != nil {
		t.Fatalf("SetAuthMethod() error = %v", err)
	}
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}

	oldLoadPassphrase := SessionLoadPassphrase
	oldLoadBiometric := SessionLoadBiometric
	t.Cleanup(func() {
		SessionLoadPassphrase = oldLoadPassphrase
		SessionLoadBiometric = oldLoadBiometric
	})

	SessionLoadPassphrase = func(string) ([]byte, error) { return nil, errors.New("miss") }

	biometricCalled := false
	SessionLoadBiometric = func(context.Context, string) ([]byte, error) {
		biometricCalled = true
		return append([]byte(nil), passphrase...), nil
	}

	// Non-interactive unlock: biometric must NOT be called.
	_, _, err := UnlockVaultWithTTL(vaultDir, false, 0, false)
	if err == nil {
		t.Fatal("expected locked error for non-interactive unlock without session or env passphrase")
	}
	if biometricCalled {
		t.Fatal("SessionLoadBiometric must not be called in non-interactive mode")
	}
}

func TestUnlockVaultWithTTLRefreshesTouchIDItemAfterBiometricUnlock(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := configpkg.Default()
	if err := cfg.SetAuthMethod(configpkg.AuthMethodTouchID); err != nil {
		t.Fatalf("SetAuthMethod() error = %v", err)
	}
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}

	oldLoadPassphrase := SessionLoadPassphrase
	oldSavePassphrase := SessionSavePassphrase
	oldLoadBiometric := SessionLoadBiometric
	oldSaveBiometric := SessionSaveBiometric
	oldLoadIdentity := SessionLoadIdentity
	oldSaveIdentity := SessionSaveIdentity
	t.Cleanup(func() {
		SessionLoadPassphrase = oldLoadPassphrase
		SessionSavePassphrase = oldSavePassphrase
		SessionLoadBiometric = oldLoadBiometric
		SessionSaveBiometric = oldSaveBiometric
		SessionLoadIdentity = oldLoadIdentity
		SessionSaveIdentity = oldSaveIdentity
	})

	SessionLoadIdentity = func(string) (string, error) { return "", errors.New("miss") }
	SessionLoadPassphrase = func(string) ([]byte, error) { return nil, errors.New("miss") }
	SessionSavePassphrase = func(string, []byte, time.Duration) error { return nil }
	SessionSaveIdentity = func(string, string, time.Duration) error { return nil }
	SessionLoadBiometric = func(context.Context, string) ([]byte, error) {
		return append([]byte(nil), passphrase...), nil
	}
	var savedVaultDir string
	var savedPassphrase []byte
	SessionSaveBiometric = func(_ context.Context, dir string, p []byte) error {
		savedVaultDir = dir
		savedPassphrase = append([]byte(nil), p...)
		return nil
	}

	v, _, err := UnlockVaultWithTTL(vaultDir, true, 0, false)
	if err != nil {
		t.Fatalf("UnlockVaultWithTTL() error = %v", err)
	}
	if v == nil {
		t.Fatal("UnlockVaultWithTTL() returned nil vault")
	}
	if savedVaultDir != vaultDir {
		t.Fatalf("biometric vault dir = %q, want %q", savedVaultDir, vaultDir)
	}
	if string(savedPassphrase) != string(passphrase) {
		t.Fatalf("biometric passphrase = %q, want %q", savedPassphrase, passphrase)
	}
}

func TestUnlockVaultWithTTLDoesNotSaveTouchIDItemForUncachedEnvPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := configpkg.Default()
	if err := cfg.SetAuthMethod(configpkg.AuthMethodTouchID); err != nil {
		t.Fatalf("SetAuthMethod() error = %v", err)
	}
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}

	oldLoadPassphrase := SessionLoadPassphrase
	oldSavePassphrase := SessionSavePassphrase
	oldLoadBiometric := SessionLoadBiometric
	oldSaveBiometric := SessionSaveBiometric
	oldLoadIdentity := SessionLoadIdentity
	oldSaveIdentity := SessionSaveIdentity
	t.Cleanup(func() {
		SessionLoadPassphrase = oldLoadPassphrase
		SessionSavePassphrase = oldSavePassphrase
		SessionLoadBiometric = oldLoadBiometric
		SessionSaveBiometric = oldSaveBiometric
		SessionLoadIdentity = oldLoadIdentity
		SessionSaveIdentity = oldSaveIdentity
	})

	SessionLoadIdentity = func(string) (string, error) { return "", errors.New("miss") }
	SessionLoadPassphrase = func(string) ([]byte, error) { return nil, errors.New("miss") }
	SessionLoadBiometric = func(context.Context, string) ([]byte, error) {
		return nil, session.ErrBiometricNotConfigured
	}
	SessionSavePassphrase = func(string, []byte, time.Duration) error { return nil }
	SessionSaveIdentity = func(string, string, time.Duration) error { return nil }
	SessionSaveBiometric = func(context.Context, string, []byte) error {
		t.Fatal("SessionSaveBiometric should not be called for uncached env passphrase")
		return nil
	}
	// Prime the early-cached env passphrase (normally sniffed in main()
	// before any child process can inherit it).
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	cachedEnvPassphrase = append([]byte(nil), passphrase...)

	v, _, err := UnlockVaultWithTTL(vaultDir, false, 0, false)
	if err != nil {
		t.Fatalf("UnlockVaultWithTTL() error = %v", err)
	}
	if v == nil {
		t.Fatal("UnlockVaultWithTTL() returned nil vault")
	}
}

// TestUnlockVaultWithTTL_EnvPassphraseSetButGateDisabled reproduces issue #714:
// SYMVAULT_PASSPHRASE alone (without the explicit opt-in gate) is silently
// ignored in non-interactive mode. The error must now say why.
func TestUnlockVaultWithTTL_EnvPassphraseSetButGateDisabled(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := configpkg.Default()
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}

	oldLoadPassphrase := SessionLoadPassphrase
	oldLoadIdentity := SessionLoadIdentity
	t.Cleanup(func() {
		SessionLoadPassphrase = oldLoadPassphrase
		SessionLoadIdentity = oldLoadIdentity
		ClearCachedEnvPassphrase()
	})
	SessionLoadIdentity = func(string) (string, error) { return "", errors.New("miss") }
	SessionLoadPassphrase = func(string) ([]byte, error) { return nil, errors.New("miss") }

	// Isolate from ambient environments where the gate may be enabled.
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "")
	t.Setenv("OPENPASS_ALLOW_ENV_PASSPHRASE", "")

	// Env passphrase is available but the opt-in gate is NOT enabled.
	SetCachedEnvPassphrase(append([]byte(nil), passphrase...))

	_, _, err := UnlockVaultWithTTL(vaultDir, false, 0, false)
	if err == nil {
		t.Fatal("expected locked error when the env passphrase gate is disabled")
	}
	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected *CLIError, got %T: %v", err, err)
	}
	if cliErr.Code != errorspkg.ExitLocked {
		t.Errorf("expected ExitLocked, got %v", cliErr.Code)
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected error to state that the env passphrase is disabled, got: %v", err)
	}
	if !strings.Contains(cliErr.Hint, "SYMVAULT_ALLOW_ENV_PASSPHRASE") ||
		!strings.Contains(cliErr.Hint, "security.allow_env_passphrase") {
		t.Errorf("expected hint to name SYMVAULT_ALLOW_ENV_PASSPHRASE and security.allow_env_passphrase, got: %q", cliErr.Hint)
	}
	// The security gate must be preserved: the cached passphrase is not consumed.
	if !HasCachedEnvPassphrase() {
		t.Error("cached env passphrase must not be consumed when the gate is disabled")
	}
}

func TestEnvPassphraseIgnored(t *testing.T) {
	ClearCachedEnvPassphrase()
	t.Cleanup(ClearCachedEnvPassphrase)
	// Isolate from ambient developer/CI environments where the gate may be enabled.
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "")
	t.Setenv("OPENPASS_ALLOW_ENV_PASSPHRASE", "")

	// Nothing set: not "ignored", simply absent.
	if envPassphraseIgnored(configpkg.Default()) {
		t.Error("expected false when no env passphrase is set")
	}

	// Set but not allowed: ignored.
	t.Setenv("SYMVAULT_PASSPHRASE", "x")
	if !envPassphraseIgnored(configpkg.Default()) {
		t.Error("expected true when SYMVAULT_PASSPHRASE is set without the opt-in gate")
	}

	// Set and allowed via env: honored, not ignored.
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	if envPassphraseIgnored(configpkg.Default()) {
		t.Error("expected false when SYMVAULT_ALLOW_ENV_PASSPHRASE=1 allows the env passphrase")
	}

	// Set and allowed via config: honored, not ignored.
	allowedCfg := configpkg.Default()
	allowedCfg.Security = &configpkg.SecurityConfig{AllowEnvPassphrase: true}
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "")
	if envPassphraseIgnored(allowedCfg) {
		t.Error("expected false when security.allow_env_passphrase allows the env passphrase")
	}
}

func TestUnlockVaultWithTTL_InvalidConfigNonInteractive(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := configpkg.Default()
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}

	// Make the config invalid by setting clipboard.autoClearDuration to < 0
	cfg.Clipboard = &configpkg.ClipboardConfig{
		AutoClearDuration: -1,
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}

	// Try to unlock non-interactively
	_, _, err := UnlockVaultWithTTL(vaultDir, false, 0, false)
	if err == nil {
		t.Fatal("expected error when unlocking with invalid config non-interactively")
	}
	if !strings.Contains(err.Error(), "clipboard.autoClearDuration") {
		t.Errorf("expected error to mention clipboard.autoClearDuration, got: %v", err)
	}
}
