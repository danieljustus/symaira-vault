package session

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIsIdentityExpired_NoIdentity(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-missing"
	setupTestWrapKey(t, fake, vaultDir)

	if !mgr.IsIdentityExpired(vaultDir) {
		t.Error("IsIdentityExpired() = false, want true when no identity is cached")
	}
}

func TestIsIdentityExpired_ValidIdentity(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-valid"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}

	if mgr.IsIdentityExpired(vaultDir) {
		t.Error("IsIdentityExpired() = true, want false for a fresh identity")
	}
}

func TestIsIdentityExpired_ExpiredIdentity(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-expired"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Millisecond); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	if !mgr.IsIdentityExpired(vaultDir) {
		t.Error("IsIdentityExpired() = false, want true past the TTL")
	}
}

func TestIsIdentityExpired_ZeroTTL(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-zerottl"
	setupTestWrapKey(t, fake, vaultDir)
	payload := `{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","encrypted_identity":"x","nonce":"y","ttl_ns":0}`
	if err := fake.Set(keyFor(serviceNameForVault(vaultDir), identityAccount), payload); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if !mgr.IsIdentityExpired(vaultDir) {
		t.Error("IsIdentityExpired() = false, want true for a zero TTL")
	}
}

// IsIdentityExpired must not renew the entry it inspects: a caller that only
// probes the cache must not keep the identity alive forever.
func TestIsIdentityExpired_DoesNotRefreshLastAccess(t *testing.T) {
	mgr, fake := newTestManager(t)

	vaultDir := "/tmp/vault-identity-norefresh"
	setupTestWrapKey(t, fake, vaultDir)
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}

	key := keyFor(serviceNameForVault(vaultDir), identityAccount)
	before, err := fake.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	_ = mgr.IsIdentityExpired(vaultDir)

	after, err := fake.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if before != after {
		t.Error("IsIdentityExpired() rewrote the identity entry; it must be read-only")
	}
}

func TestIsIdentityExpired_UsesSessionMaximumLifetime(t *testing.T) {
	mgr, fake := newTestManager(t)
	vaultDir := "/tmp/vault-identity-session-clock"
	setupTestWrapKey(t, fake, vaultDir)

	if err := mgr.SavePassphraseWithMaxLifetime(vaultDir, []byte("passphrase"), time.Hour, time.Hour); err != nil {
		t.Fatalf("SavePassphraseWithMaxLifetime() error = %v", err)
	}
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}

	sessionKey := keyFor(serviceNameForVault(vaultDir), sessionAccount)
	raw, err := fake.Get(sessionKey)
	if err != nil {
		t.Fatalf("Get(session) error = %v", err)
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
	if err := fake.Set(sessionKey, string(updated)); err != nil {
		t.Fatalf("Set(session) error = %v", err)
	}

	if !mgr.IsIdentityExpired(vaultDir) {
		t.Error("IsIdentityExpired() = false, want true when the shared session max lifetime elapsed")
	}
}

func TestLoadIdentityRefreshesSessionAndIdentityTogether(t *testing.T) {
	mgr, fake := newTestManager(t)
	vaultDir := "/tmp/vault-identity-shared-refresh"
	setupTestWrapKey(t, fake, vaultDir)

	if err := mgr.SavePassphrase(vaultDir, []byte("passphrase"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}
	time.Sleep(time.Millisecond)

	sessionKey := keyFor(serviceNameForVault(vaultDir), sessionAccount)
	identityKey := keyFor(serviceNameForVault(vaultDir), identityAccount)
	beforeSession, _ := fake.Get(sessionKey)
	beforeIdentity, _ := fake.Get(identityKey)
	var sessionBefore storedSession
	var identityBefore storedIdentity
	_ = json.Unmarshal([]byte(beforeSession), &sessionBefore)
	_ = json.Unmarshal([]byte(beforeIdentity), &identityBefore)

	if _, err := mgr.LoadIdentity(vaultDir); err != nil {
		t.Fatalf("LoadIdentity() error = %v", err)
	}
	afterSession, _ := fake.Get(sessionKey)
	afterIdentity, _ := fake.Get(identityKey)
	var sessionAfter storedSession
	var identityAfter storedIdentity
	_ = json.Unmarshal([]byte(afterSession), &sessionAfter)
	_ = json.Unmarshal([]byte(afterIdentity), &identityAfter)

	if !sessionAfter.LastAccess.After(sessionBefore.LastAccess) || !identityAfter.LastAccess.After(identityBefore.LastAccess) {
		t.Fatal("LoadIdentity() did not refresh both cache entries")
	}
	if !sessionAfter.LastAccess.Equal(identityAfter.LastAccess) {
		t.Errorf("cache refresh timestamps differ: session=%v identity=%v", sessionAfter.LastAccess, identityAfter.LastAccess)
	}
}

func TestPeekIdentityDoesNotRefreshSession(t *testing.T) {
	mgr, fake := newTestManager(t)
	vaultDir := "/tmp/vault-identity-peek"
	setupTestWrapKey(t, fake, vaultDir)

	if err := mgr.SavePassphrase(vaultDir, []byte("passphrase"), time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}
	if err := mgr.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Hour); err != nil {
		t.Fatalf("SaveIdentity() error = %v", err)
	}
	before, _ := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))

	if _, err := mgr.PeekIdentity(vaultDir); err != nil {
		t.Fatalf("PeekIdentity() error = %v", err)
	}
	after, _ := fake.Get(keyFor(serviceNameForVault(vaultDir), sessionAccount))
	if before != after {
		t.Error("PeekIdentity() rewrote the session entry; it must be read-only")
	}
}
