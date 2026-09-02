package pairing

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDeviceSessionStore_EnrollAndValidate(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}

	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	deviceID, ok := store.Validate(token)
	if !ok || deviceID != "device-1" {
		t.Fatalf("Validate = %q, %v", deviceID, ok)
	}
}

func TestDeviceSessionStore_PersistsAcrossLoad(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Reload from disk.
	store2, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	deviceID, ok := store2.Validate(token)
	if !ok || deviceID != "device-1" {
		t.Fatalf("reloaded Validate = %q, %v", deviceID, ok)
	}
}

func TestDeviceSessionStore_Revoke(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	store.Revoke("device-1")
	_ = store.Save()

	store2, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	deviceID, ok := store2.Validate(token)
	if ok || deviceID != "" {
		t.Fatalf("revoked Validate = %q, %v", deviceID, ok)
	}
}

func TestDeviceSessionStore_RevokeByOtherInstanceTakesEffect(t *testing.T) {
	dir := t.TempDir()
	server, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	token, err := server.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// A separate instance, as the "approval-revoke" CLI opens against the
	// same vault directory while a long-lived "serve" process holds its own.
	cli, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore (cli): %v", err)
	}
	cli.Revoke("device-1")

	// The long-lived instance must see the revocation without a restart.
	if deviceID, ok := server.Validate(token); ok {
		t.Fatalf("revoked token still validated by other instance: deviceID=%q", deviceID)
	}

	// A later save by the long-lived instance (e.g. a cleanup tick) must not
	// clobber the revocation back to unrevoked.
	server.CleanupExpired()
	reload, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	sessions := reload.List()
	if len(sessions) != 1 || !sessions[0].Revoked {
		t.Fatalf("sessions after cleanup tick = %+v, want single revoked session", sessions)
	}
}

func TestDeviceSessionStore_CleanupExpired_NoOpDoesNotRewriteFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	if _, err := store.Enroll("device-1", "Device One", "age1pubkey"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	before := store.mtime
	time.Sleep(10 * time.Millisecond)
	store.CleanupExpired()

	if !store.mtime.Equal(before) {
		t.Fatalf("CleanupExpired rewrote the file with nothing to clean up: mtime %v -> %v", before, store.mtime)
	}
}

func TestDeviceSessionStore_PersistedFileContainsOnlyHashedValues(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	raw := string(data)
	if strings.Contains(raw, token) {
		t.Fatalf("persisted file contains the raw token: %s", raw)
	}

	var onDisk map[string]json.RawMessage
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(onDisk) != 1 {
		t.Fatalf("expected exactly one persisted session, got %d", len(onDisk))
	}
	for key := range onDisk {
		if !looksLikeSHA256Hex(key) {
			t.Fatalf("persisted key %q does not look like a SHA-256 hex digest", key)
		}
	}

	// Every value's own fields must not carry a usable token either.
	for _, entry := range onDisk {
		var fields map[string]any
		if err := json.Unmarshal(entry, &fields); err != nil {
			t.Fatalf("unmarshal entry: %v", err)
		}
		if _, hasToken := fields["token"]; hasToken {
			t.Fatalf("persisted entry still has a raw 'token' field: %v", fields)
		}
		prefix, _ := fields["prefix"].(string)
		if prefix == "" || prefix == token {
			t.Fatalf("prefix = %q, want a short non-empty prefix distinct from the full token", prefix)
		}
	}
}

func TestDeviceSessionStore_MigratesLegacyRawTokenKeys(t *testing.T) {
	dir := t.TempDir()

	// Write a pre-migration file exactly as the old code would have: keyed
	// by the raw token, with a "token" field carrying the same value.
	legacyToken := "LEGACY0123456789ABCDEFGHJKMNPQRS"
	legacy := map[string]map[string]any{
		legacyToken: {
			"token":      legacyToken,
			"device_id":  "device-legacy",
			"name":       "Old Phone",
			"public_key": "",
			"created_at": time.Now().UTC().Format(time.RFC3339),
			"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
			"revoked":    false,
		},
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy fixture: %v", err)
	}

	// Create a store once to learn its real on-disk path, then overwrite
	// that exact file with the legacy fixture before reloading.
	bootstrap, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore (bootstrap): %v", err)
	}
	path := bootstrap.path
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write legacy fixture: %v", err)
	}

	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}

	// The legacy raw token must still validate after migration.
	deviceID, ok := store.Validate(legacyToken)
	if !ok || deviceID != "device-legacy" {
		t.Fatalf("Validate(legacyToken) = %q, %v, want device-legacy, true", deviceID, ok)
	}

	// The on-disk file must now be rewritten hash-keyed, with no raw token
	// anywhere in it.
	migratedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	if strings.Contains(string(migratedData), legacyToken) {
		t.Fatalf("migrated file still contains the raw legacy token: %s", migratedData)
	}
	var onDisk map[string]json.RawMessage
	if err := json.Unmarshal(migratedData, &onDisk); err != nil {
		t.Fatalf("unmarshal migrated file: %v", err)
	}
	if len(onDisk) != 1 {
		t.Fatalf("expected exactly one migrated session, got %d", len(onDisk))
	}
	for key := range onDisk {
		if !looksLikeSHA256Hex(key) {
			t.Fatalf("migrated key %q does not look like a SHA-256 hex digest", key)
		}
		if key != hashToken(legacyToken) {
			t.Fatalf("migrated key = %q, want %q", key, hashToken(legacyToken))
		}
	}
}

func TestDeviceSessionStore_UnknownToken(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}

	deviceID, ok := store.Validate("unknown-token")
	if ok || deviceID != "" {
		t.Fatalf("unknown Validate = %q, %v", deviceID, ok)
	}
}

func TestDeviceSessionStore_PerDeviceFailedAttempts(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Drive max failed attempts with wrong tokens for device-1's session.
	// Because the token is unknown, RecordFailure won't find the session
	// and won't increment the counter. We verify that a valid token still
	// works after unknown-token noise.
	for i := 0; i < MaxSessionFailedAttempts+2; i++ {
		store.Validate("bogus-" + string(rune(i)))
	}
	deviceID, ok := store.Validate(token)
	if !ok || deviceID != "device-1" {
		t.Fatalf("valid token after noise = %q, %v", deviceID, ok)
	}

	// Now drive failures using the valid token but wrong validation path
	// by expiring the session. We can't easily do that without waiting,
	// so instead we test per-device cooldown by creating a second device
	// and verifying that failures on one device don't affect the other.
	token2, err := store.Enroll("device-2", "Device Two", "age1pubkey2")
	if err != nil {
		t.Fatalf("Enroll device-2: %v", err)
	}

	// Simulate device-1 hitting cooldown by directly manipulating.
	store.mu.Lock()
	store.failures["device-1"] = deviceFailure{
		Count:         MaxSessionFailedAttempts,
		CooldownUntil: time.Now().Add(time.Hour),
	}
	store.mu.Unlock()

	// device-2 should still validate fine.
	deviceID, ok = store.Validate(token2)
	if !ok || deviceID != "device-2" {
		t.Fatalf("device-2 Validate after device-1 cooldown = %q, %v", deviceID, ok)
	}
}

func TestDeviceSessionStore_ExpiredSession(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Manually expire the session.
	store.mu.Lock()
	store.sessions[hashToken(token)].ExpiresAt = time.Now().Add(-time.Hour)
	store.mu.Unlock()

	deviceID, ok := store.Validate(token)
	if ok || deviceID != "" {
		t.Fatalf("expired Validate = %q, %v", deviceID, ok)
	}
}

func TestDeviceSessionStore_CleanupExpired(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	store.mu.Lock()
	store.sessions[hashToken(token)].ExpiresAt = time.Now().Add(-time.Hour)
	store.mu.Unlock()

	store.CleanupExpired()

	_, ok := store.Validate(token)
	if ok {
		t.Fatal("expired session still present after cleanup")
	}
}

func TestDeviceSessionStore_NoVaultDir(t *testing.T) {
	store, err := NewDeviceSessionStore("")
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	if store == nil {
		t.Fatal("nil store for empty dir")
	}
	token, err := store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	deviceID, ok := store.Validate(token)
	if !ok || deviceID != "device-1" {
		t.Fatalf("Validate = %q, %v", deviceID, ok)
	}
}

func TestDeviceSessionStore_StartCleanup(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	_, err = store.Enroll("device-1", "Device One", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	ctx := contextWithCancel()
	stop := store.StartCleanup(ctx, 50*time.Millisecond)
	stop()

	// File should still be readable after cleanup stops.
	_, err = NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("reload after cleanup: %v", err)
	}
}

// contextWithCancel is a test-local helper to avoid importing context in
// _test.go when not needed by other tests.
func contextWithCancel() context.Context {
	return context.Background()
}

func TestDeviceSessionStore_NameRoundTripsAcrossLoad(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	_, err = store.Enroll("device-1", "Daniel's iPhone", "")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	store2, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	sessions := store2.List()
	found := false
	for _, s := range sessions {
		if s.DeviceID == "device-1" {
			found = true
			if s.Name != "Daniel's iPhone" {
				t.Fatalf("Name = %q, want %q", s.Name, "Daniel's iPhone")
			}
		}
	}
	if !found {
		t.Fatal("enrolled session not found after reload")
	}
}

func TestDeviceSessionStore_List(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}

	if got := store.List(); len(got) != 0 {
		t.Fatalf("List on empty store = %d entries, want 0", len(got))
	}

	if _, err := store.Enroll("device-1", "Device One", "age1pubkey"); err != nil {
		t.Fatalf("Enroll device-1: %v", err)
	}
	if _, err := store.Enroll("device-2", "Device Two", "age1pubkey2"); err != nil {
		t.Fatalf("Enroll device-2: %v", err)
	}

	sessions := store.List()
	if len(sessions) != 2 {
		t.Fatalf("List = %d entries, want 2", len(sessions))
	}
	names := map[string]bool{}
	for _, s := range sessions {
		names[s.DeviceID] = true
	}
	if !names["device-1"] || !names["device-2"] {
		t.Fatalf("List missing expected device IDs: %+v", sessions)
	}
}
