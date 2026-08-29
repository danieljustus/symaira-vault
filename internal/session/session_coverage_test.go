package session

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type sessionMetadataErrorKeyring struct {
	inner *fakeKeyring
	key   string
	err   error
}

func (k *sessionMetadataErrorKeyring) Get(key string) (string, error) {
	if key == k.key {
		return "", k.err
	}
	return k.inner.Get(key)
}

func (k *sessionMetadataErrorKeyring) Set(key, value string) error {
	return k.inner.Set(key, value)
}

func (k *sessionMetadataErrorKeyring) Delete(key string) error {
	return k.inner.Delete(key)
}

func TestLoadIdentity_PropagatesSessionMetadataErrors(t *testing.T) {
	fake := newFakeKeyring()
	vaultDir := "/tmp/vault-identity-session-error"
	setupTestWrapKey(t, fake, vaultDir)
	mgr := NewManager(&sessionMetadataErrorKeyring{
		inner: fake,
		key:   keyFor(serviceNameForVault(vaultDir), sessionAccount),
		err:   errors.New("session metadata unavailable"),
	}, nil)
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}

	_, err := mgr.LoadIdentity(vaultDir)
	if err == nil || !strings.Contains(err.Error(), "session metadata unavailable") {
		t.Fatalf("LoadIdentity() error = %v, want session metadata error", err)
	}
}

func TestLoadIdentity_RejectsMalformedSessionMetadata(t *testing.T) {
	mgr, fake := newTestManager(t)
	vaultDir := "/tmp/vault-identity-malformed-session"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), sessionAccount), "not-json"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	_, err := mgr.LoadIdentity(vaultDir)
	if err == nil || !strings.Contains(err.Error(), "decode session metadata") {
		t.Fatalf("LoadIdentity() error = %v, want decode error", err)
	}
}

func TestLoadIdentity_EnforcesSharedMaximumLifetime(t *testing.T) {
	mgr, fake := newTestManager(t)
	vaultDir := "/tmp/vault-identity-max-lifetime"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SavePassphraseWithMaxLifetime(vaultDir, []byte("passphrase"), time.Hour, time.Hour); err != nil {
		t.Fatalf("SavePassphraseWithMaxLifetime() error = %v", err)
	}
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}

	key := keyFor(serviceNameForVault(vaultDir), sessionAccount)
	raw, err := fake.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	var sess storedSession
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	sess.SavedAt = time.Now().UTC().Add(-2 * time.Hour)
	sess.LastAccess = time.Now().UTC()
	updated, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if err := fake.Set(key, string(updated)); err != nil {
		t.Fatalf("store session: %v", err)
	}

	if _, err := mgr.LoadIdentity(vaultDir); err == nil || !strings.Contains(err.Error(), "maximum lifetime") {
		t.Fatalf("LoadIdentity() error = %v, want maximum-lifetime expiry", err)
	}
	if _, err := fake.Get(key); !errors.Is(err, ErrKeyringNotFound) {
		t.Fatalf("expired session remains cached, get error = %v", err)
	}
}

func TestIsIdentityExpired_HandlesMalformedIdentityAndSessionErrors(t *testing.T) {
	t.Run("malformed identity", func(t *testing.T) {
		mgr, fake := newTestManager(t)
		vaultDir := "/tmp/vault-identity-malformed"
		setupTestWrapKey(t, fake, vaultDir)
		if err := fake.Set(keyFor(serviceNameForVault(vaultDir), identityAccount), "not-json"); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		if !mgr.IsIdentityExpired(vaultDir) {
			t.Fatal("IsIdentityExpired() = false, want true for malformed identity")
		}
	})

	t.Run("session backend error", func(t *testing.T) {
		fake := newFakeKeyring()
		vaultDir := "/tmp/vault-identity-session-backend-error"
		setupTestWrapKey(t, fake, vaultDir)
		mgr := NewManager(&sessionMetadataErrorKeyring{
			inner: fake,
			key:   keyFor(serviceNameForVault(vaultDir), sessionAccount),
			err:   errors.New("session metadata unavailable"),
		}, nil)
		if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
			t.Fatalf("SaveIdentity() error = %v", err)
		}
		if !mgr.IsIdentityExpired(vaultDir) {
			t.Fatal("IsIdentityExpired() = false, want true when session metadata cannot be read")
		}
	})
}

func TestLoadIdentityFallsBackToSavedAtWhenLastAccessIsZero(t *testing.T) {
	mgr, fake := newTestManager(t)
	vaultDir := "/tmp/vault-identity-zero-last-access"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}

	key := keyFor(serviceNameForVault(vaultDir), identityAccount)
	raw, err := fake.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	var ident storedIdentity
	if err := json.Unmarshal([]byte(raw), &ident); err != nil {
		t.Fatalf("unmarshal identity: %v", err)
	}
	ident.LastAccess = time.Time{}
	ident.SavedAt = time.Now().UTC()
	updated, err := json.Marshal(ident)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	if err := fake.Set(key, string(updated)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if _, err := mgr.LoadIdentity(vaultDir); err != nil {
		t.Fatalf("LoadIdentity() error = %v, want fallback to SavedAt", err)
	}
}

func TestPackageLevelLifetimeAndIdentityHelpers(t *testing.T) {
	original := DefaultManager()
	t.Cleanup(func() { SetDefaultManager(original) })
	mgr, fake := newTestManager(t)
	SetDefaultManager(mgr)
	vaultDir := "/tmp/vault-package-lifetime"
	setupTestWrapKey(t, fake, vaultDir)

	if err := SavePassphraseWithMaxLifetime(vaultDir, []byte("passphrase"), time.Hour, 2*time.Hour); err != nil {
		t.Fatalf("SavePassphraseWithMaxLifetime() error = %v", err)
	}
	if err := SaveIdentityWithMaxLifetime(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour, 2*time.Hour); err != nil {
		t.Fatalf("SaveIdentityWithMaxLifetime() error = %v", err)
	}
	if _, err := PeekIdentity(vaultDir); err != nil {
		t.Fatalf("PeekIdentity() error = %v", err)
	}
	if IsIdentityExpired(vaultDir) {
		t.Fatal("IsIdentityExpired() = true, want false for fresh identity")
	}
}
