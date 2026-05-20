//go:build darwin || linux || windows || netbsd || openbsd || ((freebsd || dragonfly) && cgo)

package session

import (
	"testing"
	"time"
)

func TestFallback_KeyringOperations(t *testing.T) {
	oldSet := keyringSet
	oldGet := keyringGet
	oldDelete := keyringDelete
	oldFallbackActive := fallbackActive
	oldFallback := fallback

	fallbackMu.Lock()
	fallbackActive = true
	fallback = &memoryKeyring{}
	fallbackMu.Unlock()

	keyringSet = setWithFallback
	keyringGet = getWithFallback
	keyringDelete = deleteWithFallback

	t.Cleanup(func() {
		keyringSet = oldSet
		keyringGet = oldGet
		keyringDelete = oldDelete
		fallbackMu.Lock()
		fallbackActive = oldFallbackActive
		fallback = oldFallback
		fallbackMu.Unlock()
	})

	vaultDir := "/tmp/vault-fallback"
	passphrase := []byte("fallback-secret")

	if err := SavePassphrase(vaultDir, passphrase, time.Hour); err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != string(passphrase) {
		t.Errorf("LoadPassphrase() = %q, want %q", got, passphrase)
	}

	if err := ClearSession(vaultDir); err != nil {
		t.Fatalf("ClearSession() error = %v", err)
	}

	_, err = LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() after ClearSession error = nil, want not found")
	}
}

func TestFallback_Set_WrapsForKeyringPath(t *testing.T) {
	oldSet := keyringSet
	oldFallbackActive := fallbackActive
	oldFallback := fallback
	oldGet := keyringGet
	oldDelete := keyringDelete

	fallbackMu.Lock()
	fallbackActive = false
	fallback = &memoryKeyring{}
	fallbackMu.Unlock()

	keyringSet = setWithFallback
	keyringGet = getWithFallback
	keyringDelete = deleteWithFallback

	t.Cleanup(func() {
		keyringSet = oldSet
		keyringGet = oldGet
		keyringDelete = oldDelete
		fallbackMu.Lock()
		fallbackActive = oldFallbackActive
		fallback = oldFallback
		fallbackMu.Unlock()
	})

	vaultDir := "/tmp/vault-fallback-real"
	passphrase := []byte("real-keyring-test")

	err := SavePassphrase(vaultDir, passphrase, time.Hour)
	if err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != string(passphrase) {
		t.Errorf("LoadPassphrase() = %q, want %q", got, passphrase)
	}
}

func TestFallback_Delete_ThroughFallback(t *testing.T) {
	oldSet := keyringSet
	oldGet := keyringGet
	oldDelete := keyringDelete
	oldFallbackActive := fallbackActive
	oldFallback := fallback

	fallbackMu.Lock()
	fallbackActive = true
	fallback = &memoryKeyring{}
	fallbackMu.Unlock()

	keyringSet = setWithFallback
	keyringGet = getWithFallback
	keyringDelete = deleteWithFallback

	t.Cleanup(func() {
		keyringSet = oldSet
		keyringGet = oldGet
		keyringDelete = oldDelete
		fallbackMu.Lock()
		fallbackActive = oldFallbackActive
		fallback = oldFallback
		fallbackMu.Unlock()
	})

	vaultDir := "/tmp/vault-delete-fallback"
	err := SavePassphrase(vaultDir, []byte("secret"), time.Hour)
	if err != nil {
		t.Fatalf("SavePassphrase() error = %v", err)
	}

	got, err := LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("LoadPassphrase() error = %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("LoadPassphrase() = %q, want %q", got, "secret")
	}

	if err := ClearSession(vaultDir); err != nil {
		t.Fatalf("ClearSession() error = %v", err)
	}

	_, err = LoadPassphrase(vaultDir)
	if err == nil {
		t.Fatal("LoadPassphrase() after ClearSession should fail")
	}
}

func TestFallback_Get_NotFound(t *testing.T) {
	oldGet := keyringGet
	oldFallbackActive := fallbackActive
	oldFallback := fallback

	fallbackMu.Lock()
	fallbackActive = true
	fallback = &memoryKeyring{}
	fallbackMu.Unlock()

	keyringGet = getWithFallback

	t.Cleanup(func() {
		keyringGet = oldGet
		fallbackMu.Lock()
		fallbackActive = oldFallbackActive
		fallback = oldFallback
		fallbackMu.Unlock()
	})

	_, err := LoadPassphrase("/tmp/vault-fallback-notfound")
	if err == nil {
		t.Fatal("LoadPassphrase() error = nil, want not found")
	}
}
