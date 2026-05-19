package cmd

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"

	crud "github.com/danieljustus/OpenPass/cmd/crud"
)

func TestAddCommand_HiddenPassword(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	restore := pipeStdin(t, "myuser\nsecret-password\n\n\n\n")
	defer restore()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "test-entry"})
	defer rootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("add command failed: %v", err)
		}
	})

	if !strings.Contains(output, "Entry created") {
		t.Errorf("expected 'Entry created' in output, got: %s", output)
	}
}

func TestAddCommand_InvalidTOTPSecretRejected(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "bad-totp-entry",
			"--value", "StrongP@ssw0rd123", "--totp-secret", "not-valid-base32!!!"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})

	if !strings.Contains(stderr, "TOTP secret must be Base32-encoded") {
		t.Errorf("expected TOTP validation error, got: %s", stderr)
	}
	if strings.Contains(stderr, "not-valid-base32!!!") {
		t.Error("error message must not contain the secret value")
	}
}

func TestAddCommand_ValidTOTPSecretAccepted(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "add", "valid-totp-entry",
		"--value", "StrongP@ssw0rd123", "--totp-secret", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if !strings.Contains(out, "Entry created") {
		t.Errorf("expected Entry created, got: %s", out)
	}
}

func TestAddCommand_TOTPSecretWithSpacesAccepted(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "add", "spaced-totp-entry",
		"--value", "StrongP@ssw0rd123", "--totp-secret", "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ")
	if !strings.Contains(out, "Entry created") {
		t.Errorf("expected Entry created, got: %s", out)
	}
}

func TestAddCommand_GenerateWithLength(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "generated-entry", "--generate", "--length", "24"})
	defer rootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("add command failed: %v", err)
		}
	})
	if !strings.Contains(output, "Entry created") {
		t.Errorf("expected 'Entry created' in output, got: %s", output)
	}

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	entry, err := vaultpkg.ReadEntry(vaultDir, "generated-entry", v.Identity)
	if err != nil {
		t.Fatalf("read generated entry: %v", err)
	}
	password, ok := entry.Data["password"].(string)
	if !ok {
		t.Fatalf("password has unexpected type %T", entry.Data["password"])
	}
	if len(password) != 24 {
		t.Fatalf("password length = %d, want 24", len(password))
	}
}

func TestCmdAdd_Interactive(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	restore := pipeStdin(t, "myuser\nStrongP@ssw0rd123\n")
	defer restore()
	output := captureStdout(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "interactive-entry",
			"--url", "https://example.com", "--notes", "some notes", "--totp-secret", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(output, "Entry created") {
		t.Errorf("expected Entry created, got: %s", output)
	}
}

func TestCmdAdd_InteractiveStdinError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	restore := pipeStdin(t, "myuser\n")
	defer restore()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "add-stdin-err"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "read password") {
		t.Errorf("expected read password error, got: %s", stderr)
	}
}

func TestCmdAdd_Generate(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "add", "gen-entry", "--generate")
	if !strings.Contains(out, "Entry created") {
		t.Errorf("expected Entry created, got: %s", out)
	}
}

func TestCmdAdd_WithUsernameAndURL(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "add", "tagged-entry",
		"--value", "StrongP@ssw0rd123", "--username", "alice", "--url", "https://example.com")
	if !strings.Contains(out, "Entry created") {
		t.Errorf("expected Entry created, got: %s", out)
	}
}

func TestCmdAdd_WithTOTPFlags(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "add", "totp-entry",
		"--value", "StrongP@ssw0rd123", "--totp-secret", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "--totp-issuer", "GitHub", "--totp-account", "alice")
	if !strings.Contains(out, "Entry created") {
		t.Errorf("expected Entry created, got: %s", out)
	}
}

func TestCmdAdd_Uninitialized(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "x", "--value", "v"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "vault not initialized") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected vault not initialized error, got: %s", stderr)
	}
}

func TestCmdAdd_AlreadyExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx access violation in AcquireWriteLock")
	}
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "existing"}}
	_ = vaultpkg.WriteEntry(vaultDir, "exists", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "exists", "--value", "v"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "already exists") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected already exists error, got: %s", stderr)
	}
}

func TestCmdAdd_Notes(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "add", "notes-entry",
		"--value", "StrongP@ssw0rd123", "--notes", "important note here")
	if !strings.Contains(out, "Entry created") {
		t.Errorf("expected Entry created, got: %s", out)
	}
}

func TestCmdAdd_InteractiveFull(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	restore := pipeStdin(t, "myuser\nStrongP@ssw0rd123\n")
	defer restore()
	output := captureStdout(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "full-interactive",
			"--url", "https://example.com", "--notes", "important notes",
			"--totp-secret", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "--totp-issuer", "GitHub", "--totp-account", "alice"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(output, "Entry created") {
		t.Errorf("expected Entry created, got: %s", output)
	}
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry, err := vaultpkg.ReadEntry(vaultDir, "full-interactive", identity.Identity)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if entry.Data["username"] != "myuser" {
		t.Errorf("expected username myuser, got: %v", entry.Data["username"])
	}
	if entry.Data["password"] != "StrongP@ssw0rd123" {
		t.Errorf("expected password StrongP@ssw0rd123, got: %v", entry.Data["password"])
	}
	if entry.Data["url"] != "https://example.com" {
		t.Errorf("expected url https://example.com, got: %v", entry.Data["url"])
	}
	if entry.Data["notes"] != "important notes" {
		t.Errorf("expected notes, got: %v", entry.Data["notes"])
	}
	totp, ok := entry.Data["totp"].(map[string]any)
	if !ok {
		t.Fatal("expected totp data in entry")
	}
	if totp["secret"] != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Errorf("expected totp secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ, got: %v", totp["secret"])
	}
	if totp["issuer"] != "GitHub" {
		t.Errorf("expected totp issuer GitHub, got: %v", totp["issuer"])
	}
	if totp["account_name"] != "alice" {
		t.Errorf("expected totp account_name alice, got: %v", totp["account_name"])
	}
}

func TestCmdAdd_InteractiveURLPrompt(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	restore := pipeStdin(t, "testuser\nStrongP@ssw0rd123\n")
	defer restore()
	output := captureStdout(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "url-prompt-entry",
			"--url", "https://mysite.com", "--totp-secret", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(output, "Entry created") {
		t.Errorf("expected Entry created, got: %s", output)
	}
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry, err := vaultpkg.ReadEntry(vaultDir, "url-prompt-entry", identity.Identity)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if entry.Data["url"] != "https://mysite.com" {
		t.Errorf("expected url https://mysite.com, got: %v", entry.Data["url"])
	}
	if entry.Data["username"] != "testuser" {
		t.Errorf("expected username testuser, got: %v", entry.Data["username"])
	}
}

func TestCmdAdd_AutoCommitError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: stderr capture not reliable")
	}
	vaultDir, passphrase := initVault(t)
	setupGitWithBrokenObjects(t, vaultDir)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "add", "autocommit-add", "--value", "StrongP@ssw0rd123"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "auto-commit failed") {
		t.Errorf("expected auto-commit warning in stderr: %s", stderr)
	}
}

func TestAdd_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	tests := []struct {
		setupFunc  func()
		name       string
		errContain string
		args       []string
		wantErr    bool
	}{
		{
			name: "uninitialized vault",
			setupFunc: func() {
				tmpDir := t.TempDir()
				_ = os.Setenv("OPENPASS_VAULT", tmpDir)
			},
			args:       []string{"--vault", os.TempDir() + "/nonexistent", "add", "test"},
			wantErr:    true,
			errContain: "not initialized",
		},
		{
			name: "entry already exists",
			setupFunc: func() {
				tmpDir := t.TempDir()
				_ = os.Setenv("OPENPASS_VAULT", tmpDir)
				cfg := config.Default()
				identity, _ := vaultpkg.InitWithPassphrase(tmpDir, []byte("testpass"), cfg)
				_ = os.Setenv("OPENPASS_PASSPHRASE", "testpass")
				_ = vaultpkg.WriteEntry(tmpDir, "existing", &vaultpkg.Entry{Data: map[string]any{"password": "secret"}}, identity)
			},
			args:       []string{"add", "existing", "--value", "new"},
			wantErr:    true,
			errContain: "already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")

			if tt.setupFunc != nil {
				tt.setupFunc()
			}

			vault = ""
			if vaultFlag != nil {
				_ = vaultFlag.Value.Set("")
				vaultFlag.Changed = false
			}

			rootCmd.SetArgs(tt.args)
			defer rootCmd.SetArgs(nil)

			err := rootCmd.Execute()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContain)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAdd_InteractiveMode(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

	// Reset all add flags to ensure we're in interactive mode
	crud.AddValue = ""
	crud.AddGenerate = false
	crud.AddUsername = ""
	crud.AddURL = ""
	crud.AddNotes = ""
	crud.AddTOTPSecret = ""
	crud.AddTOTPIssuer = ""
	crud.AddTOTPAccount = ""

	// Create pipe for stdin with interactive input
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	// Provide interactive input:
	// 1. Username
	// 2. Password
	// 3. URL
	// 4. Notes (line1, line2, empty line to end)
	// 5. TOTP Secret
	// 6. TOTP Issuer
	// 7. TOTP Account
	go func() {
		_, _ = w.WriteString("myuser\n")
		_, _ = w.WriteString("StrongP@ssw0rd123\n")
		_, _ = w.WriteString("https://example.com\n")
		_, _ = w.WriteString("note1\n")
		_, _ = w.WriteString("note2\n")
		_, _ = w.WriteString("\n")
		_, _ = w.WriteString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
		_, _ = w.WriteString("Example\n")
		_, _ = w.WriteString("myaccount\n")
		_ = w.Close()
	}()

	rootCmd.SetArgs([]string{"--vault", tmpDir, "add", "interactive-test"})
	defer rootCmd.SetArgs(nil)

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	os.Stdin = oldStdin
	_ = r.Close()

	if !strings.Contains(output, "Entry created") {
		t.Errorf("expected 'Entry created', got: %s", output)
	}
}

func TestAdd_InteractiveReadErrors(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

	crud.AddValue = ""
	crud.AddGenerate = false

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_ = w.Close()

	rootCmd.SetArgs([]string{"--vault", tmpDir, "add", "test"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	os.Stdin = oldStdin
	_ = r.Close()

	if err == nil || !strings.Contains(err.Error(), "read username") {
		t.Errorf("expected 'read username' error, got: %v", err)
	}
}
