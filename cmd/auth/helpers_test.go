package auth

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/session"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// captureStdout runs fn while capturing everything written to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()
	return buf.String()
}

// captureStderr runs fn while capturing everything written to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()
	return buf.String()
}

// pipeStdin replaces os.Stdin with a pipe pre-filled with input.
func pipeStdin(t *testing.T, input string) func() {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	_, _ = w.WriteString(input)
	_ = w.Close()
	return func() {
		os.Stdin = oldStdin
		_ = r.Close()
	}
}

// setupTestVault initializes a temp vault, points the global --vault flag and
// the SYMVAULT_VAULT env var at it, and opts into env-passphrase unlocking for
// the duration of the test — the same fixture shape cmd/file uses.
func setupTestVault(t *testing.T) (string, []byte) {
	t.Helper()
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, configpkg.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	t.Cleanup(vaultpkg.FlushManifestUpdates)

	origVault := cli.Vault
	var origChanged bool
	if cli.VaultFlag != nil {
		origChanged = cli.VaultFlag.Changed
	}
	cli.Vault = vaultDir
	if cli.VaultFlag != nil {
		_ = cli.VaultFlag.Value.Set(vaultDir)
		cli.VaultFlag.Changed = true
	}
	t.Cleanup(func() {
		cli.Vault = origVault
		if cli.VaultFlag != nil {
			_ = cli.VaultFlag.Value.Set(origVault)
			cli.VaultFlag.Changed = origChanged
		}
	})
	t.Setenv("SYMVAULT_VAULT", vaultDir)
	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	t.Setenv("SYMVAULT_PASSPHRASE", string(passphrase))
	t.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	return vaultDir, passphrase
}

// testKeyring is a minimal in-memory KeyringBackend used to swap the session
// manager in tests. When fail is set every operation fails, which lets tests
// reach the keyring-error branches deterministically.
type testKeyring struct {
	mu    sync.Mutex
	store map[string]string
	fail  bool
}

func (k *testKeyring) Get(key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return "", session.ErrKeyringUnavailable
	}
	v, ok := k.store[key]
	if !ok {
		return "", session.ErrKeyringNotFound
	}
	return v, nil
}

func (k *testKeyring) Set(key, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return session.ErrKeyringUnavailable
	}
	if k.store == nil {
		k.store = map[string]string{}
	}
	k.store[key] = value
	return nil
}

func (k *testKeyring) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return session.ErrKeyringUnavailable
	}
	delete(k.store, key)
	return nil
}

// swapSessionManager installs a session manager backed by a testKeyring with
// the given persistence status and restores the previous manager on cleanup.
// This is the seam used to exercise both the keyring-available ("persistent")
// and keyring-unavailable ("memory-only") branches of the auth commands.
func swapSessionManager(t *testing.T, backend *testKeyring, persistent bool) {
	t.Helper()
	orig := session.DefaultManager()
	status := session.CacheStatus{
		Backend:    session.CacheBackendMemory,
		Persistent: persistent,
		Message:    "test session cache",
	}
	if persistent {
		status.Backend = session.CacheBackendOSKeyring
	}
	session.SetDefaultManager(session.NewManager(backend, func() session.CacheStatus { return status }))
	t.Cleanup(func() { session.SetDefaultManager(orig) })
}

// testBiometricStore is a fake BiometricPassphraseStore that records the
// saved passphrase, mirroring the cmd package's cmdRecordingBiometricStore.
type testBiometricStore struct {
	available bool
	saved     []byte
}

func (s *testBiometricStore) IsAvailable() bool { return s.available }
func (s *testBiometricStore) Save(_ context.Context, _ string, passphrase []byte) error {
	s.saved = append([]byte(nil), passphrase...)
	return nil
}
func (s *testBiometricStore) Load(context.Context, string) ([]byte, error) {
	return nil, session.ErrBiometricNotConfigured
}
func (s *testBiometricStore) Delete(string) error { return nil }

// setOutputFormat changes the global output format and restores it on cleanup.
func setOutputFormat(t *testing.T, format string) {
	t.Helper()
	orig := cli.OutputFormat
	cli.OutputFormat = format
	t.Cleanup(func() { cli.OutputFormat = orig })
}

// setQuietMode changes the global quiet mode and restores it on cleanup.
func setQuietMode(t *testing.T, quiet bool) {
	t.Helper()
	orig := cli.QuietMode
	cli.QuietMode = quiet
	t.Cleanup(func() { cli.QuietMode = orig })
}

// saveTestSession stores a passphrase in the currently active session manager
// so unlock/lock tests can assert against a real cached session.
func saveTestSession(t *testing.T, vaultDir string, passphrase []byte) {
	t.Helper()
	if err := session.SavePassphrase(vaultDir, passphrase, 30*time.Minute); err != nil {
		t.Fatalf("save session: %v", err)
	}
}
