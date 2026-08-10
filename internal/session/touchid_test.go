//go:build darwin && cgo

package session

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestBiometricServiceName(t *testing.T) {
	vaultDir := "/home/user/.symvault"
	got := biometricServiceName(vaultDir)
	want := "symvault-biometric:/home/user/.symvault"
	if got != want {
		t.Errorf("biometricServiceName(%q) = %q, want %q", vaultDir, got, want)
	}
}

func TestTouchIDAuthenticate_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := touchIDAuthenticate(ctx, "test")
	if err == nil {
		t.Fatal("touchIDAuthenticate with canceled context should return error")
	}
}

func TestTouchIDAuthenticate_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	err := touchIDAuthenticate(ctx, "test")
	if err == nil {
		t.Fatal("touchIDAuthenticate with expired timeout should return error")
	}
}

// TestTouchIDPassphraseStore_IsAvailable exercises the real (non-mock)
// touchIDPassphraseStore.IsAvailable, which must delegate to the same
// package-level touchIDAvailable() check as the authenticator. This is
// safe on any machine: canEvaluatePolicy is a capability query, it never
// prompts for biometric authentication.
func TestTouchIDPassphraseStore_IsAvailable(t *testing.T) {
	store := &touchIDPassphraseStore{}
	if got, want := store.IsAvailable(), touchIDAvailable(); got != want {
		t.Errorf("touchIDPassphraseStore.IsAvailable() = %v, want %v (touchIDAvailable())", got, want)
	}
}

// TestTouchIDPassphraseStore_Save_CancelledContext exercises Save's
// context-cancellation guard. It never reaches the Keychain: a canceled
// context is checked before touchIDAvailable(), so this is safe and
// deterministic regardless of whether the host has Touch ID hardware.
func TestTouchIDPassphraseStore_Save_CancelledContext(t *testing.T) {
	store := &touchIDPassphraseStore{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := store.Save(ctx, "/tmp/does-not-matter", []byte("secret"))
	if err == nil {
		t.Fatal("Save with a canceled context should return an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Save with a canceled context = %v, want context.Canceled", err)
	}
}

// TestTouchIDPassphraseStore_Load_NotConfigured exercises Load and
// loadFromService end to end against a vault directory that has never
// had a passphrase stored for it. The Keychain item-existence check
// (SecItemCopyMatching) reports "not found" before any biometric
// authentication is requested, so this never prompts and is safe on
// machines with real Touch ID hardware enrolled.
func TestTouchIDPassphraseStore_Load_NotConfigured(t *testing.T) {
	store := &touchIDPassphraseStore{}
	if !store.IsAvailable() {
		t.Skip("Touch ID hardware not available on this host")
	}
	vaultDir := fmt.Sprintf("/tmp/symvault-coverage-test-%d-never-saved", time.Now().UnixNano())
	_, err := store.Load(context.Background(), vaultDir)
	if !errors.Is(err, ErrBiometricNotConfigured) {
		t.Errorf("Load(%q) with no stored passphrase = %v, want ErrBiometricNotConfigured", vaultDir, err)
	}
}

// TestTouchIDPassphraseStore_Delete_NoOp exercises Delete and
// deleteFromService against a Keychain entry that does not exist.
// SecItemDelete returning errSecItemNotFound is mapped to success, so
// deleting a never-stored entry is a safe, deterministic no-op.
func TestTouchIDPassphraseStore_Delete_NoOp(t *testing.T) {
	store := &touchIDPassphraseStore{}
	vaultDir := fmt.Sprintf("/tmp/symvault-coverage-test-%d-never-saved", time.Now().UnixNano())
	if err := store.Delete(vaultDir); err != nil {
		t.Errorf("Delete(%q) on a never-stored entry = %v, want nil", vaultDir, err)
	}
}
