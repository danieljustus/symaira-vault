package cmd

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/session"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func resetVaultFlag(t *testing.T) {
	t.Helper()

	origVault := vault
	origChanged := false
	if vaultFlag != nil {
		origChanged = vaultFlag.Changed
	}

	t.Cleanup(func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	})
}

func stubSessionFuncs(t *testing.T) func() {
	t.Helper()

	oldLoad := sessionLoadPassphrase
	oldSave := sessionSavePassphrase
	oldIsExpired := sessionIsExpired
	oldLoadBiometric := sessionLoadBiometric
	oldSaveBiometric := sessionSaveBiometric
	oldSaveIdentity := sessionSaveIdentity
	oldGetCacheStatus := sessionGetCacheStatus
	sessionLoadBiometric = func(context.Context, string) ([]byte, error) { return nil, errors.New("not configured") }
	sessionSaveBiometric = func(context.Context, string, []byte) error { return nil }
	sessionSaveIdentity = func(string, string, time.Duration) error { return nil }
	sessionGetCacheStatus = func() session.CacheStatus { return session.CacheStatus{Persistent: true} }

	return func() {
		sessionLoadPassphrase = oldLoad
		sessionSavePassphrase = oldSave
		sessionIsExpired = oldIsExpired
		sessionLoadBiometric = oldLoadBiometric
		sessionSaveBiometric = oldSaveBiometric
		sessionSaveIdentity = oldSaveIdentity
		sessionGetCacheStatus = oldGetCacheStatus
	}
}

// TestVaultPathErrorWhenHomeDirNotAvailable verifies that vaultPath returns an error
// when the vault path starts with ~ but the home directory cannot be determined.
func TestVaultPathErrorWhenHomeDirNotAvailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env var behavior differs")
	}
	resetVaultFlag(t)

	// Save original env vars and restore after test
	origHome := os.Getenv("HOME")
	origVault := os.Getenv("OPENPASS_VAULT")
	defer func() {
		_ = os.Setenv("HOME", origHome)
		_ = os.Setenv("OPENPASS_VAULT", origVault)
	}()

	// Clear HOME to simulate UserHomeDir failure
	_ = os.Unsetenv("HOME")
	// Ensure OPENPASS_VAULT is not set so we use the global vault variable
	_ = os.Unsetenv("OPENPASS_VAULT")

	// Save original vault value and restore after test
	origVaultFlag := vault
	defer func() {
		vault = origVaultFlag
	}()

	// Set vault to a path starting with ~ which requires home directory expansion
	vault = "~/.openpass"

	// Call vaultPath and verify it returns an error
	path, err := vaultPath()
	if err == nil {
		t.Errorf("vaultPath() should return error when home directory is unavailable, got path: %s", path)
	}
}

// TestVaultPathSuccessWithTildeExpansion verifies that vaultPath correctly expands
// tilde paths when home directory is available.
func TestVaultPathSuccessWithTildeExpansion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	resetVaultFlag(t)

	// Save original env vars and restore after test
	origHome := os.Getenv("HOME")
	origVault := os.Getenv("OPENPASS_VAULT")
	defer func() {
		_ = os.Setenv("HOME", origHome)
		_ = os.Setenv("OPENPASS_VAULT", origVault)
	}()

	// Set a known HOME
	_ = os.Setenv("HOME", "/Users/testuser")
	// Ensure OPENPASS_VAULT is not set so we use the global vault variable
	_ = os.Unsetenv("OPENPASS_VAULT")

	// Save original vault value and restore after test
	origVaultFlag := vault
	defer func() {
		vault = origVaultFlag
	}()

	// Set vault to a path starting with ~
	vault = "~/.openpass"

	// Call vaultPath and verify it returns the expanded path
	path, err := vaultPath()
	if err != nil {
		t.Errorf("vaultPath() should not return error, got: %v", err)
	}
	if path != "/Users/testuser/.openpass" {
		t.Errorf("vaultPath() = %s, want /Users/testuser/.openpass", path)
	}
}

// TestVaultPathSuccessWithoutTilde verifies that vaultPath works correctly
// when vault path does not start with ~.
func TestVaultPathSuccessWithoutTilde(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	resetVaultFlag(t)

	// Save original env vars and restore after test
	origHome := os.Getenv("HOME")
	origVault := os.Getenv("OPENPASS_VAULT")
	defer func() {
		_ = os.Setenv("HOME", origHome)
		_ = os.Setenv("OPENPASS_VAULT", origVault)
	}()

	// Ensure HOME is set (shouldn't matter for this test)
	_ = os.Setenv("HOME", "/Users/testuser")
	// Ensure OPENPASS_VAULT is not set so we use the global vault variable
	_ = os.Unsetenv("OPENPASS_VAULT")

	// Save original vault value and restore after test
	origVaultFlag := vault
	defer func() {
		vault = origVaultFlag
	}()

	// Set vault to an absolute path without tilde
	vault = "/custom/vault/path"

	// Call vaultPath and verify it returns the path as-is
	path, err := vaultPath()
	if err != nil {
		t.Errorf("vaultPath() should not return error, got: %v", err)
	}
	if path != "/custom/vault/path" {
		t.Errorf("vaultPath() = %s, want /custom/vault/path", path)
	}
}

func TestVaultPathUsesEnvWhenFlagUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	resetVaultFlag(t)

	origEnv := os.Getenv("OPENPASS_VAULT")
	defer func() { _ = os.Setenv("OPENPASS_VAULT", origEnv) }()

	vault = "~/.openpass"
	_ = os.Setenv("OPENPASS_VAULT", "/env/vault")

	path, err := vaultPath()
	if err != nil {
		t.Fatalf("vaultPath() unexpected error = %v", err)
	}
	if path != "/env/vault" {
		t.Fatalf("vaultPath() = %s, want /env/vault", path)
	}
}

func TestVaultPathPrefersExplicitFlagOverEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	resetVaultFlag(t)

	origEnv := os.Getenv("OPENPASS_VAULT")
	defer func() { _ = os.Setenv("OPENPASS_VAULT", origEnv) }()

	_ = os.Setenv("OPENPASS_VAULT", "/env/vault")
	if err := vaultFlag.Value.Set("/flag/vault"); err != nil {
		t.Fatalf("set vault flag: %v", err)
	}
	vaultFlag.Changed = true
	vault = "/flag/vault"

	path, err := vaultPath()
	if err != nil {
		t.Fatalf("vaultPath() unexpected error = %v", err)
	}
	if path != "/flag/vault" {
		t.Fatalf("vaultPath() = %s, want /flag/vault", path)
	}
}

// TestExecute_Error verifies that Execute() calls osExit(1) when rootCmd.Execute() returns an error.
func TestExecute_Error(t *testing.T) {
	// Save and restore original osExit
	origOsExit := osExit
	var exitCode int
	osExit = func(code int) {
		exitCode = code
	}
	defer func() { osExit = origOsExit }()

	// Save and restore rootCmd args and settings
	origArgs := rootCmd.Args
	origSilenceUsage := rootCmd.SilenceUsage
	origSilenceErrors := rootCmd.SilenceErrors
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.SetArgs([]string{"__nonexistent_subcommand__"})
	defer func() {
		rootCmd.Args = origArgs
		rootCmd.SilenceUsage = origSilenceUsage
		rootCmd.SilenceErrors = origSilenceErrors
		rootCmd.SetArgs(nil)
	}()

	Execute()

	if exitCode != 1 {
		t.Errorf("Execute() called osExit(%d), want osExit(1)", exitCode)
	}
}

// TestUnlockVault_InteractivePrompt verifies that unlockVault reads the passphrase
// from stdin when no keyring session and no env var are available.
func TestUnlockVault_InteractivePrompt(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	restoreSessionFuncs := stubSessionFuncs(t)
	sessionLoadPassphrase = func(string) ([]byte, error) { return nil, errors.New("not found") }
	sessionSavePassphrase = func(string, []byte, time.Duration) error { return nil }
	defer restoreSessionFuncs()

	// Ensure no env var is set
	origPass := os.Getenv("OPENPASS_PASSPHRASE")
	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	defer func() {
		if origPass != "" {
			_ = os.Setenv("OPENPASS_PASSPHRASE", origPass)
		}
	}()

	// Pipe passphrase via stdin
	restore := pipeStdin(t, string(passphrase)+"\n")
	defer restore()

	v, err := unlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlockVault interactive: %v", err)
	}
	if v == nil {
		t.Fatal("unlockVault returned nil vault")
	}
}

func TestUnlockVault_UsesConfiguredSessionTimeout(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := config.Default()
	cfg.SessionTimeout = 2 * time.Minute
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	restoreSessionFuncs := stubSessionFuncs(t)
	var savedPassphrase string
	var savedTTL time.Duration
	sessionLoadPassphrase = func(string) ([]byte, error) {
		return nil, errors.New("not found")
	}
	sessionSavePassphrase = func(_ string, passphrase []byte, ttl time.Duration) error {
		savedPassphrase = string(passphrase)
		savedTTL = ttl
		return nil
	}
	defer restoreSessionFuncs()

	t.Setenv("OPENPASS_PASSPHRASE", "")
	restoreStdin := pipeStdin(t, string(passphrase)+"\n")
	defer restoreStdin()

	v, err := unlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlockVault interactive: %v", err)
	}
	if v == nil {
		t.Fatal("unlockVault returned nil vault")
	}
	if savedPassphrase != string(passphrase) {
		t.Fatalf("saved passphrase = %q, want %q", savedPassphrase, passphrase)
	}
	if savedTTL != cfg.SessionTimeout {
		t.Fatalf("saved TTL = %s, want configured sessionTimeout %s", savedTTL, cfg.SessionTimeout)
	}
}

func TestUnlockCommand_UsesConfiguredSessionTimeoutByDefault(t *testing.T) {
	resetVaultFlag(t)

	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := config.Default()
	cfg.SessionTimeout = 3 * time.Minute
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	restoreSessionFuncs := stubSessionFuncs(t)
	var savedTTL time.Duration
	sessionLoadPassphrase = func(string) ([]byte, error) {
		return nil, errors.New("not found")
	}
	sessionSavePassphrase = func(_ string, _ []byte, ttl time.Duration) error {
		savedTTL = ttl
		return nil
	}
	defer restoreSessionFuncs()

	t.Setenv("OPENPASS_PASSPHRASE", "")
	restoreStdin := pipeStdin(t, string(passphrase)+"\n")
	defer restoreStdin()

	ttlFlag := unlockCmd.Flags().Lookup("ttl")
	origTTLChanged := ttlFlag.Changed
	origTTLValue := ttlFlag.Value.String()
	checkFlag := unlockCmd.Flags().Lookup("check")
	origCheckChanged := checkFlag.Changed
	origCheckValue := checkFlag.Value.String()
	_ = ttlFlag.Value.Set(defaultSessionTTL().String())
	ttlFlag.Changed = false
	_ = checkFlag.Value.Set("false")
	checkFlag.Changed = false
	t.Cleanup(func() {
		_ = ttlFlag.Value.Set(origTTLValue)
		ttlFlag.Changed = origTTLChanged
		_ = checkFlag.Value.Set(origCheckValue)
		checkFlag.Changed = origCheckChanged
	})

	rootCmd.SetArgs([]string{"--vault", vaultDir, "unlock"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStderr(func() {
		execErr = rootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("unlock command: %v", execErr)
	}
	if savedTTL != cfg.SessionTimeout {
		t.Fatalf("saved TTL = %s, want configured sessionTimeout %s", savedTTL, cfg.SessionTimeout)
	}
	if !strings.Contains(output, "session TTL: 3m0s") {
		t.Fatalf("unlock output = %q, want configured TTL", output)
	}
}

// TestUnlockVault_InteractivePrompt_ReadError verifies that unlockVault returns
// an error when stdin is empty/closed during interactive prompt.
func TestUnlockVault_InteractivePrompt_ReadError(t *testing.T) {
	vaultDir, _ := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	// Ensure no env var is set
	origPass := os.Getenv("OPENPASS_PASSPHRASE")
	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	defer func() {
		if origPass != "" {
			_ = os.Setenv("OPENPASS_PASSPHRASE", origPass)
		}
	}()

	// Create a pipe with no input (immediately closed)
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	_ = w.Close() // Close write end immediately → EOF on read
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
		_ = r.Close()
	}()

	_, err := unlockVault(vaultDir, true)
	if err == nil {
		t.Fatal("unlockVault should fail with empty stdin")
	}
	if !strings.Contains(err.Error(), "read passphrase") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUnlockVault_NonInteractive_NoSession verifies that unlockVault returns
// an error when interactive=false and no passphrase is available.
func TestUnlockVault_NonInteractive_NoSession(t *testing.T) {
	vaultDir, _ := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	// Ensure no env var is set
	origPass := os.Getenv("OPENPASS_PASSPHRASE")
	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	defer func() {
		if origPass != "" {
			_ = os.Setenv("OPENPASS_PASSPHRASE", origPass)
		}
	}()

	_, err := unlockVault(vaultDir, false)
	if err == nil {
		t.Fatal("unlockVault should fail when interactive=false and no passphrase available")
	}
	if !strings.Contains(err.Error(), "vault locked") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUnlockVault_EnvVar verifies that unlockVault uses OPENPASS_PASSPHRASE env var.
func TestUnlockVault_EnvVar(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	v, err := unlockVault(vaultDir, false)
	if err != nil {
		t.Fatalf("unlockVault with env var: %v", err)
	}
	if v == nil {
		t.Fatal("unlockVault returned nil vault")
	}
}

// TestUnlockVault_WrongPassphrase verifies that unlockVault returns an error
// when the passphrase is incorrect.
func TestUnlockVault_WrongPassphrase(t *testing.T) {
	vaultDir, _ := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	_ = os.Setenv("OPENPASS_PASSPHRASE", "wrong-passphrase")
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	_, err := unlockVault(vaultDir, false)
	if err == nil {
		t.Fatal("unlockVault should fail with wrong passphrase")
	}
	if !strings.Contains(err.Error(), "open vault") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUnlockVault_HiddenInput verifies that unlockVault uses term.ReadPassword
// (via readHiddenInput) for hidden passphrase input and falls back to stdin
// when term.ReadPassword fails.
func TestUnlockVault_HiddenInput(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	defer setupVaultFlag(t, vaultDir)()

	restoreSessionFuncs := stubSessionFuncs(t)
	sessionLoadPassphrase = func(string) ([]byte, error) { return nil, errors.New("not found") }
	sessionSavePassphrase = func(string, []byte, time.Duration) error { return nil }
	defer restoreSessionFuncs()

	origPass := os.Getenv("OPENPASS_PASSPHRASE")
	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	defer func() {
		if origPass != "" {
			_ = os.Setenv("OPENPASS_PASSPHRASE", origPass)
		}
	}()

	restore := pipeStdin(t, string(passphrase)+"\n")
	defer restore()

	v, err := unlockVault(vaultDir, true)
	if err != nil {
		t.Fatalf("unlockVault with hidden input: %v", err)
	}
	if v == nil {
		t.Fatal("unlockVault returned nil vault")
	}
}

func TestConfiguredSessionTTL_WithOverride(t *testing.T) {
	override := 30 * time.Minute
	ttl := configuredSessionTTL(nil, override)
	if ttl != override {
		t.Fatalf("configuredSessionTTL() = %v, want %v", ttl, override)
	}
}

func TestConfiguredSessionTTL_WithVaultConfig(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := config.Default()
	cfg.SessionTimeout = 45 * time.Minute
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	ttl := configuredSessionTTL(v, 0)
	if ttl != cfg.SessionTimeout {
		t.Fatalf("configuredSessionTTL() = %v, want %v", ttl, cfg.SessionTimeout)
	}
}

func TestConfiguredSessionTTL_NilVault(t *testing.T) {
	ttl := configuredSessionTTL(nil, 0)
	if ttl != defaultSessionTTL() {
		t.Fatalf("configuredSessionTTL() = %v, want %v", ttl, defaultSessionTTL())
	}
}

func TestConfiguredSessionTTL_VaultWithNilConfig(t *testing.T) {
	v := &vaultpkg.Vault{}
	ttl := configuredSessionTTL(v, 0)
	if ttl != defaultSessionTTL() {
		t.Fatalf("configuredSessionTTL() = %v, want %v", ttl, defaultSessionTTL())
	}
}

func TestConfiguredSessionTTL_ZeroSessionTimeout(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	cfg := config.Default()
	cfg.SessionTimeout = 0
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	ttl := configuredSessionTTL(v, 0)
	if ttl != defaultSessionTTL() {
		t.Fatalf("configuredSessionTTL() = %v, want %v", ttl, defaultSessionTTL())
	}
}

func TestReadHiddenInput_TerminalEOF(t *testing.T) {
	oldReadPassword := readPasswordFunc
	oldIsTerminal := isTerminalFunc
	readPasswordFunc = func(int) ([]byte, error) {
		return nil, io.EOF
	}
	isTerminalFunc = func(int) bool { return true }
	defer func() {
		readPasswordFunc = oldReadPassword
		isTerminalFunc = oldIsTerminal
	}()

	_, err := readHiddenInput("Password: ", nil)
	if err == nil {
		t.Fatal("expected error for terminal EOF")
	}
	if !strings.Contains(err.Error(), "read Password") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadHiddenInput_TerminalInterrupt(t *testing.T) {
	oldReadPassword := readPasswordFunc
	oldIsTerminal := isTerminalFunc
	readPasswordFunc = func(int) ([]byte, error) {
		return nil, errors.New("interrupted")
	}
	isTerminalFunc = func(int) bool { return true }
	defer func() {
		readPasswordFunc = oldReadPassword
		isTerminalFunc = oldIsTerminal
	}()

	_, err := readHiddenInput("Password: ", nil)
	if err == nil {
		t.Fatal("expected error for terminal interrupt")
	}
	if !strings.Contains(err.Error(), "read Password") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadHiddenInput_ReaderEOF(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(""))
	_, err := readHiddenInput("Password: ", reader)
	if err == nil {
		t.Fatal("expected error for reader EOF")
	}
	if !strings.Contains(err.Error(), "read Password") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadHiddenInput_StdinEOF(t *testing.T) {
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_ = w.Close()
	defer func() {
		os.Stdin = oldStdin
		_ = r.Close()
	}()

	_, err := readHiddenInput("Password: ", nil)
	if err == nil {
		t.Fatal("expected error for stdin EOF")
	}
	if !strings.Contains(err.Error(), "read Password") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWarnPipeRead_OnceAndSilenced(t *testing.T) {
	oldEmitted := pipeWarningEmitted
	oldNoPipe := noPipeWarning
	oldQuiet := quietMode
	defer func() {
		pipeWarningEmitted = oldEmitted
		noPipeWarning = oldNoPipe
		quietMode = oldQuiet
	}()

	// Suppressed when --no-pipe-warning is set.
	pipeWarningEmitted = false
	noPipeWarning = true
	warnPipeRead("Passphrase")
	if pipeWarningEmitted {
		t.Errorf("warning fired despite --no-pipe-warning")
	}

	// Suppressed when OPENPASS_NO_PIPE_WARNING is set.
	pipeWarningEmitted = false
	noPipeWarning = false
	t.Setenv("OPENPASS_NO_PIPE_WARNING", "1")
	warnPipeRead("Passphrase")
	if pipeWarningEmitted {
		t.Errorf("warning fired despite OPENPASS_NO_PIPE_WARNING")
	}
	t.Setenv("OPENPASS_NO_PIPE_WARNING", "0")

	// Suppressed in quiet mode.
	pipeWarningEmitted = false
	quietMode = true
	warnPipeRead("Passphrase")
	if pipeWarningEmitted {
		t.Errorf("warning fired despite --quiet")
	}
	quietMode = false

	// Fires once when not suppressed.
	pipeWarningEmitted = false
	warnPipeRead("Passphrase")
	if !pipeWarningEmitted {
		t.Errorf("warning did not fire when expected")
	}

	// Already emitted → second call is silent (idempotent).
	warnPipeRead("Passphrase")
}
