package pairing

import (
	"context"
	"testing"
	"time"
)

func TestDeviceSessionStore_EnrollAndValidate(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}

	token, err := store.Enroll("device-1", "age1pubkey")
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
	token, err := store.Enroll("device-1", "age1pubkey")
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
	token, err := store.Enroll("device-1", "age1pubkey")
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
	token, err := store.Enroll("device-1", "age1pubkey")
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
	token2, err := store.Enroll("device-2", "age1pubkey2")
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
	token, err := store.Enroll("device-1", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Manually expire the session.
	store.mu.Lock()
	store.sessions[token].ExpiresAt = time.Now().Add(-time.Hour)
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
	token, err := store.Enroll("device-1", "age1pubkey")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	store.mu.Lock()
	store.sessions[token].ExpiresAt = time.Now().Add(-time.Hour)
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
	token, err := store.Enroll("device-1", "age1pubkey")
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
	_, err = store.Enroll("device-1", "age1pubkey")
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
	ctx, _ := context.WithCancel(context.Background())
	return ctx
}
