package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// initPassphraseVault creates a vault whose auth method is a plain
// passphrase, so unlock paths under test never reach for Touch ID.
func initPassphraseVault(t *testing.T, passphrase []byte) string {
	t.Helper()
	vaultDir := t.TempDir()
	cfg := configpkg.Default()
	if err := cfg.SetAuthMethod(configpkg.AuthMethodPassphrase); err != nil {
		t.Fatalf("SetAuthMethod() error = %v", err)
	}
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("InitWithPassphrase() error = %v", err)
	}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}
	return vaultDir
}

// The identity entry is renewed by every vault command while the session
// entry is only renewed when the passphrase is actually loaded. If the
// explicit unlock command took the cached-identity shortcut it would report
// success without rewriting the session, so `unlock --check` — and the GUI
// that calls it — would keep seeing a locked vault.
func TestUnlockVaultForSessionIgnoresCachedIdentityAndRewritesSession(t *testing.T) {
	passphrase := []byte("test-passphrase")
	vaultDir := initPassphraseVault(t, passphrase)

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error = %v", err)
	}

	oldLoadIdentity := SessionLoadIdentity
	oldSaveIdentity := SessionSaveIdentity
	oldLoadPassphrase := SessionLoadPassphrase
	oldSavePassphrase := SessionSavePassphrase
	oldLoadBiometric := SessionLoadBiometric
	oldHasGUISession := SessionHasGUISession
	t.Cleanup(func() {
		SessionLoadIdentity = oldLoadIdentity
		SessionSaveIdentity = oldSaveIdentity
		SessionLoadPassphrase = oldLoadPassphrase
		SessionSavePassphrase = oldSavePassphrase
		SessionLoadBiometric = oldLoadBiometric
		SessionHasGUISession = oldHasGUISession
	})

	identityLoaded := false
	SessionLoadIdentity = func(string) (string, error) {
		identityLoaded = true
		return identity.String(), nil
	}
	SessionSaveIdentity = func(string, string, time.Duration) error { return nil }
	SessionHasGUISession = func() bool { return false }
	SessionLoadBiometric = func(context.Context, string) ([]byte, error) {
		return nil, errors.New("biometric unavailable")
	}
	// A still-valid session entry supplies the passphrase, mirroring the
	// real unlock path after a fresh session was cached.
	SessionLoadPassphrase = func(string) ([]byte, error) {
		return append([]byte(nil), passphrase...), nil
	}
	savedSessions := 0
	SessionSavePassphrase = func(string, []byte, time.Duration) error {
		savedSessions++
		return nil
	}

	v, ttl, err := UnlockVaultForSession(vaultDir, false, 0)
	if err != nil {
		t.Fatalf("UnlockVaultForSession() error = %v", err)
	}
	if v == nil {
		t.Fatal("UnlockVaultForSession() returned nil vault")
	}
	if ttl <= 0 {
		t.Fatalf("UnlockVaultForSession() ttl = %v, want > 0", ttl)
	}
	if identityLoaded {
		t.Error("UnlockVaultForSession() consulted the identity cache; it must re-verify the passphrase")
	}
	if savedSessions != 1 {
		t.Errorf("SessionSavePassphrase called %d times, want 1", savedSessions)
	}
}

// Without a passphrase to verify, the explicit unlock must fail loudly
// rather than report success off the cached identity.
func TestUnlockVaultForSessionFailsWithoutPassphrase(t *testing.T) {
	passphrase := []byte("test-passphrase")
	vaultDir := initPassphraseVault(t, passphrase)

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error = %v", err)
	}

	oldLoadIdentity := SessionLoadIdentity
	oldLoadPassphrase := SessionLoadPassphrase
	oldHasGUISession := SessionHasGUISession
	t.Cleanup(func() {
		SessionLoadIdentity = oldLoadIdentity
		SessionLoadPassphrase = oldLoadPassphrase
		SessionHasGUISession = oldHasGUISession
	})

	SessionLoadIdentity = func(string) (string, error) { return identity.String(), nil }
	SessionLoadPassphrase = func(string) ([]byte, error) { return nil, errors.New("expired") }
	SessionHasGUISession = func() bool { return false }

	if _, _, err := UnlockVaultForSession(vaultDir, false, 0); err == nil {
		t.Fatal("UnlockVaultForSession() error = nil, want locked error")
	}
}

// The implicit path (every other command) keeps the shortcut: it is what
// lets a cached identity serve reads without re-deriving the key.
func TestUnlockVaultWithTTLStillUsesCachedIdentity(t *testing.T) {
	passphrase := []byte("test-passphrase")
	vaultDir := initPassphraseVault(t, passphrase)

	oldLoadIdentity := SessionLoadIdentity
	oldLoadPassphrase := SessionLoadPassphrase
	t.Cleanup(func() {
		SessionLoadIdentity = oldLoadIdentity
		SessionLoadPassphrase = oldLoadPassphrase
	})

	cachedIdentity := readVaultIdentity(t, vaultDir, passphrase)
	SessionLoadIdentity = func(string) (string, error) { return cachedIdentity, nil }
	SessionLoadPassphrase = func(string) ([]byte, error) {
		t.Error("SessionLoadPassphrase called; the cached identity should have served this unlock")
		return nil, errors.New("miss")
	}

	if _, _, err := UnlockVaultWithTTL(vaultDir, false, 0, false); err != nil {
		t.Fatalf("UnlockVaultWithTTL() error = %v", err)
	}
}

func readVaultIdentity(t *testing.T, vaultDir string, passphrase []byte) string {
	t.Helper()
	v, err := vaultpkg.OpenWithPassphrase(vaultDir, append([]byte(nil), passphrase...))
	if err != nil {
		t.Fatalf("OpenWithPassphrase() error = %v", err)
	}
	if v.Identity == nil {
		t.Fatal("OpenWithPassphrase() returned a vault without an identity")
	}
	return v.Identity.String()
}
