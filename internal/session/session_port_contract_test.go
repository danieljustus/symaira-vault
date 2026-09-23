package session

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSessionPortCacheMetadataContract(t *testing.T) {
	const vault = "port-contract-vault"
	t.Run("zero TTL precedes legacy detection and does not delete", func(t *testing.T) {
		mgr, keyring := newTestManager(t)
		key := keyFor(serviceNameForVault(vault), sessionAccount)
		payload := `{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"legacy","ttl_ns":0}`
		if err := keyring.Set(key, payload); err != nil {
			t.Fatal(err)
		}
		_, err := mgr.LoadPassphrase(vault)
		if err == nil || !strings.Contains(err.Error(), "TTL is zero or negative") {
			t.Fatalf("expected zero-TTL error before legacy error, got %v", err)
		}
		if actual, err := keyring.Get(key); err != nil || actual != payload {
			t.Fatalf("zero-TTL probe changed cache entry: err=%v", err)
		}
	})
	t.Run("elapsed TTL precedes legacy detection and evicts", func(t *testing.T) {
		mgr, keyring := newTestManager(t)
		key := keyFor(serviceNameForVault(vault), sessionAccount)
		payload := `{"saved_at":"2024-01-01T00:00:00Z","last_access":"2024-01-01T00:00:00Z","passphrase":"legacy","ttl_ns":1}`
		if err := keyring.Set(key, payload); err != nil {
			t.Fatal(err)
		}
		_, err := mgr.LoadPassphrase(vault)
		if err == nil || !strings.Contains(err.Error(), "last activity") {
			t.Fatalf("expected elapsed-TTL error before legacy error, got %v", err)
		}
		if _, err := keyring.Get(key); err == nil {
			t.Fatal("elapsed TTL must evict the cache entry")
		}
	})
	t.Run("identity takes only positive session metadata", func(t *testing.T) {
		mgr, keyring := newTestManager(t)
		key := keyFor(serviceNameForVault(vault), sessionAccount)
		payload := `{"saved_at":"0001-01-01T00:00:00Z","last_access":"0001-01-01T00:00:00Z","ttl_ns":0,"max_lifetime_ns":0}`
		if err := keyring.Set(key, payload); err != nil {
			t.Fatal(err)
		}
		if err := mgr.SaveIdentityWithMaxLifetime(vault, "test-identity", time.Hour, 2*time.Hour); err != nil {
			t.Fatal(err)
		}
		raw, err := keyring.Get(keyFor(serviceNameForVault(vault), identityAccount))
		if err != nil {
			t.Fatal(err)
		}
		var identity storedIdentity
		if err := json.Unmarshal([]byte(raw), &identity); err != nil {
			t.Fatal(err)
		}
		if identity.SavedAt.IsZero() || identity.TTL != int64(time.Hour) || identity.MaxLifetime != int64(2*time.Hour) {
			t.Fatalf("identity incorrectly inherited zero session metadata: savedAtZero=%v ttl=%v max=%v", identity.SavedAt.IsZero(), identity.TTL, identity.MaxLifetime)
		}
	})
	t.Run("Unix epoch is not Go zero time", func(t *testing.T) {
		mgr, keyring := newTestManager(t)
		key := keyFor(serviceNameForVault(vault), sessionAccount)
		payload := `{"saved_at":"1970-01-01T00:00:00Z","last_access":"1970-01-01T00:00:00Z","ttl_ns":1,"max_lifetime_ns":1}`
		if err := keyring.Set(key, payload); err != nil {
			t.Fatal(err)
		}
		if err := mgr.SaveIdentityWithMaxLifetime(vault, "test-identity", time.Hour, 2*time.Hour); err != nil {
			t.Fatal(err)
		}
		raw, err := keyring.Get(keyFor(serviceNameForVault(vault), identityAccount))
		if err != nil {
			t.Fatal(err)
		}
		var identity storedIdentity
		if err := json.Unmarshal([]byte(raw), &identity); err != nil {
			t.Fatal(err)
		}
		if !identity.SavedAt.Equal(time.Unix(0, 0).UTC()) || identity.TTL != 1 || identity.MaxLifetime != 1 {
			t.Fatalf("epoch metadata lost: savedAt=%v ttl=%v max=%v", identity.SavedAt, identity.TTL, identity.MaxLifetime)
		}
	})
}
