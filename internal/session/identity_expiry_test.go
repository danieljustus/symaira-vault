package session

import (
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
