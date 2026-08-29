package cli

import (
	"testing"
	"time"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestConfiguredSessionMaxLifetimeUsesVaultConfig(t *testing.T) {
	if got := ConfiguredSessionMaxLifetime(nil); got != configpkg.Default().SessionMaxLifetime {
		t.Fatalf("ConfiguredSessionMaxLifetime(nil) = %v, want default %v", got, configpkg.Default().SessionMaxLifetime)
	}
	want := 37 * time.Minute
	v := &vaultpkg.Vault{Config: &configpkg.Config{SessionMaxLifetime: want}}
	if got := ConfiguredSessionMaxLifetime(v); got != want {
		t.Fatalf("ConfiguredSessionMaxLifetime() = %v, want %v", got, want)
	}
}

func TestSaveSessionHelpersUseCustomMaxLifetime(t *testing.T) {
	oldSavePassphrase := SessionSavePassphrase
	oldSavePassphraseWithMaxLifetime := SessionSavePassphraseWithMaxLifetime
	oldSaveIdentity := SessionSaveIdentity
	oldSaveIdentityWithMaxLifetime := SessionSaveIdentityWithMaxLifetime
	t.Cleanup(func() {
		SessionSavePassphrase = oldSavePassphrase
		SessionSavePassphraseWithMaxLifetime = oldSavePassphraseWithMaxLifetime
		SessionSaveIdentity = oldSaveIdentity
		SessionSaveIdentityWithMaxLifetime = oldSaveIdentityWithMaxLifetime
	})

	const vaultDir = "/tmp/vault-custom-session-lifetime"
	const identity = "AGE-SECRET-KEY-TEST"
	ttl := time.Hour
	maxLifetime := 37 * time.Minute
	passphraseCalled := false
	identityCalled := false
	SessionSavePassphrase = func(string, []byte, time.Duration) error {
		t.Fatal("default passphrase saver should not be used for a custom lifetime")
		return nil
	}
	SessionSaveIdentity = func(string, string, time.Duration) error {
		t.Fatal("default identity saver should not be used for a custom lifetime")
		return nil
	}
	SessionSavePassphraseWithMaxLifetime = func(gotDir string, gotPassphrase []byte, gotTTL, gotMaxLifetime time.Duration) error {
		passphraseCalled = true
		if gotDir != vaultDir || string(gotPassphrase) != "passphrase" || gotTTL != ttl || gotMaxLifetime != maxLifetime {
			t.Errorf("custom passphrase saver args = %q, %q, %v, %v", gotDir, gotPassphrase, gotTTL, gotMaxLifetime)
		}
		return nil
	}
	SessionSaveIdentityWithMaxLifetime = func(gotDir, gotIdentity string, gotTTL, gotMaxLifetime time.Duration) error {
		identityCalled = true
		if gotDir != vaultDir || gotIdentity != identity || gotTTL != ttl || gotMaxLifetime != maxLifetime {
			t.Errorf("custom identity saver args = %q, %q, %v, %v", gotDir, gotIdentity, gotTTL, gotMaxLifetime)
		}
		return nil
	}

	if err := saveSessionPassphrase(vaultDir, []byte("passphrase"), ttl, maxLifetime); err != nil {
		t.Fatalf("saveSessionPassphrase() error = %v", err)
	}
	if err := saveSessionIdentity(vaultDir, identity, ttl, maxLifetime); err != nil {
		t.Fatalf("saveSessionIdentity() error = %v", err)
	}
	if !passphraseCalled || !identityCalled {
		t.Fatalf("custom savers called passphrase=%v identity=%v", passphraseCalled, identityCalled)
	}
}

func TestUnlockVaultWithTTLRecordsInvalidCachedIdentityAsMiss(t *testing.T) {
	passphrase := []byte("test-passphrase")
	vaultDir := initPassphraseVault(t, passphrase)

	oldLoadIdentity := SessionLoadIdentity
	oldLoadPassphrase := SessionLoadPassphrase
	oldSavePassphrase := SessionSavePassphrase
	oldSaveIdentity := SessionSaveIdentity
	t.Cleanup(func() {
		SessionLoadIdentity = oldLoadIdentity
		SessionLoadPassphrase = oldLoadPassphrase
		SessionSavePassphrase = oldSavePassphrase
		SessionSaveIdentity = oldSaveIdentity
	})

	SessionLoadIdentity = func(string) (string, error) { return "invalid identity", nil }
	SessionLoadPassphrase = func(string) ([]byte, error) {
		return append([]byte(nil), passphrase...), nil
	}
	SessionSavePassphrase = func(string, []byte, time.Duration) error { return nil }
	SessionSaveIdentity = func(string, string, time.Duration) error { return nil }

	if _, _, err := UnlockVaultWithTTL(vaultDir, false, 0, false); err != nil {
		t.Fatalf("UnlockVaultWithTTL() error = %v", err)
	}
}
