package auth

import (
	"errors"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/session"
)

func TestLock_HappyPathClearsSession(t *testing.T) {
	vaultDir, passphrase := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	saveTestSession(t, vaultDir, passphrase)

	cmd := newLockCmd()
	stderr := captureStderr(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("lock error = %v", err)
		}
	})
	if !strings.Contains(stderr, "Vault locked") {
		t.Errorf("stderr = %q, want lock confirmation", stderr)
	}

	// The cached passphrase must be gone after locking.
	if _, err := session.LoadPassphrase(vaultDir); err == nil {
		t.Fatal("session still present after lock")
	}
}

func TestLock_NotInitialized(t *testing.T) {
	cli.Vault = t.TempDir()
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newLockCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for uninitialized vault, got nil")
	}
	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("error = %T, want *errorspkg.CLIError", err)
	}
	if cliErr.Code != errorspkg.ExitNotInitialized {
		t.Errorf("exit code = %d, want %d", cliErr.Code, errorspkg.ExitNotInitialized)
	}
}

func TestLock_KeyringUnavailable(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{fail: true}, true)

	cmd := newLockCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error when keyring is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "cannot clear session") {
		t.Errorf("error = %v, want cannot-clear-session message", err)
	}
	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("error = %T, want *errorspkg.CLIError", err)
	}
	if cliErr.Code != errorspkg.ExitGeneralError {
		t.Errorf("exit code = %d, want %d", cliErr.Code, errorspkg.ExitGeneralError)
	}
}
