package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/session"
)

func TestUnlock_HappyPath(t *testing.T) {
	vaultDir, passphrase := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newAuthUnlockCmd()
	stderr := captureStderr(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("unlock error = %v", err)
		}
	})
	if !strings.Contains(stderr, "Vault unlocked") {
		t.Errorf("stderr = %q, want unlock confirmation", stderr)
	}

	// The passphrase must now be cached in the session manager.
	got, err := session.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("load cached session: %v", err)
	}
	if string(got) != string(passphrase) {
		t.Errorf("cached passphrase = %q, want %q", got, passphrase)
	}
}

func TestUnlock_TTLOverride(t *testing.T) {
	vaultDir, _ := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newAuthUnlockCmd()
	if err := cmd.Flags().Set("ttl", "15m"); err != nil {
		t.Fatalf("set ttl flag: %v", err)
	}

	stderr := captureStderr(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("unlock error = %v", err)
		}
	})
	if !strings.Contains(stderr, "session TTL: 15m0s") {
		t.Errorf("stderr = %q, want overridden TTL", stderr)
	}

	sess, err := session.LoadPassphrase(vaultDir)
	if err != nil {
		t.Fatalf("load cached session: %v", err)
	}
	_ = sess
}

func TestUnlock_MemoryOnlyCacheRejected(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, false)

	cmd := newAuthUnlockCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error for memory-only cache, got nil")
	}
	if !strings.Contains(err.Error(), "memory-only") {
		t.Errorf("error = %v, want memory-only message", err)
	}
	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("error = %T, want *errorspkg.CLIError", err)
	}
	if cliErr.Code != errorspkg.ExitLocked {
		t.Errorf("exit code = %d, want %d", cliErr.Code, errorspkg.ExitLocked)
	}
}

func TestUnlock_KeyringUnavailable(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{fail: true}, true)

	cmd := newAuthUnlockCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error when keyring is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "save session") {
		t.Errorf("error = %v, want save-session failure", err)
	}
}

func TestUnlock_NotInitialized(t *testing.T) {
	cli.Vault = t.TempDir()
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newAuthUnlockCmd()
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

func TestUnlock_CheckActiveSession(t *testing.T) {
	vaultDir, passphrase := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	saveTestSession(t, vaultDir, passphrase)

	cmd := newAuthUnlockCmd()
	if err := cmd.Flags().Set("check", "true"); err != nil {
		t.Fatalf("set check flag: %v", err)
	}

	stderr := captureStderr(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("unlock --check error = %v", err)
		}
	})
	if !strings.Contains(stderr, "Session active") {
		t.Errorf("stderr = %q, want session-active message", stderr)
	}
}

func TestUnlock_CheckNoSession(t *testing.T) {
	setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)

	cmd := newAuthUnlockCmd()
	if err := cmd.Flags().Set("check", "true"); err != nil {
		t.Fatalf("set check flag: %v", err)
	}

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected error when no session is active, got nil")
	}
	if !strings.Contains(err.Error(), "no active session") {
		t.Errorf("error = %v, want no-active-session message", err)
	}
	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("error = %T, want *errorspkg.CLIError", err)
	}
	if cliErr.Code != errorspkg.ExitLocked {
		t.Errorf("exit code = %d, want %d", cliErr.Code, errorspkg.ExitLocked)
	}
}

// A cached age identity opens the vault without prompting exactly as a
// cached passphrase does. Reporting "no active session" for it sent the
// macOS app back to its unlock screen after every successful unlock.
func TestUnlock_CheckAcceptsCachedIdentity(t *testing.T) {
	vaultDir, _ := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	if err := session.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", 30*time.Minute); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	cmd := newAuthUnlockCmd()
	if err := cmd.Flags().Set("check", "true"); err != nil {
		t.Fatalf("set check flag: %v", err)
	}

	stderr := captureStderr(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("unlock --check error = %v", err)
		}
	})
	if !strings.Contains(stderr, "Session active") {
		t.Errorf("stderr = %q, want session-active message", stderr)
	}
}

// An expired identity must not keep the vault looking unlocked.
func TestUnlock_CheckRejectsExpiredIdentity(t *testing.T) {
	vaultDir, _ := setupTestVault(t)
	swapSessionManager(t, &testKeyring{store: map[string]string{}}, true)
	if err := session.SaveIdentity(vaultDir, "AGE-SECRET-KEY-TEST", time.Millisecond); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	cmd := newAuthUnlockCmd()
	if err := cmd.Flags().Set("check", "true"); err != nil {
		t.Fatalf("set check flag: %v", err)
	}

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("unlock --check error = nil, want locked error")
	}
	var cliErr *errorspkg.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("error = %T, want *errorspkg.CLIError", err)
	}
	if cliErr.Code != errorspkg.ExitLocked {
		t.Errorf("exit code = %d, want %d", cliErr.Code, errorspkg.ExitLocked)
	}
}
