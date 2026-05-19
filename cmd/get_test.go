//go:build test_headless

package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	crud "github.com/danieljustus/OpenPass/cmd/crud"
	clipboardapp "github.com/danieljustus/OpenPass/internal/clipboard"
	"github.com/danieljustus/OpenPass/internal/config"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestGetAutoClearDuration(t *testing.T) {
	t.Run("returns default when vaultPath fails", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping on windows: HOME env behavior differs")
		}
		origVault := vault
		origFlagChanged := vaultFlag.Changed
		defer func() {
			vault = origVault
			vaultFlag.Changed = origFlagChanged
		}()

		origHome := os.Getenv("HOME")
		defer func() { _ = os.Setenv("HOME", origHome) }()
		_ = os.Unsetenv("HOME")
		_ = os.Unsetenv("OPENPASS_VAULT")

		vault = "~/.openpass"

		duration := getAutoClearDuration()
		if duration != 30 {
			t.Errorf("duration = %d, want 30", duration)
		}
	})

	t.Run("returns default when config file missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		origVault := vault
		origFlagChanged := vaultFlag.Changed
		defer func() {
			vault = origVault
			vaultFlag.Changed = origFlagChanged
		}()

		vault = tmpDir

		duration := getAutoClearDuration()
		if duration != 30 {
			t.Errorf("duration = %d, want 30", duration)
		}
	})

	t.Run("returns default when clipboard config nil", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfgPath := filepath.Join(tmpDir, "config.yaml")
		yamlContent := `mcp:
  bind: 127.0.0.1
`
		if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		origVault := vault
		origFlagChanged := vaultFlag.Changed
		defer func() {
			vault = origVault
			vaultFlag.Changed = origFlagChanged
		}()

		vault = tmpDir

		duration := getAutoClearDuration()
		if duration != 30 {
			t.Errorf("duration = %d, want 30", duration)
		}
	})

	t.Run("returns config value when set", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfgPath := filepath.Join(tmpDir, "config.yaml")
		yamlContent := `clipboard:
  auto_clear_duration: 60
`
		if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		origVault := vault
		origFlagChanged := vaultFlag.Changed
		defer func() {
			vault = origVault
			vaultFlag.Changed = origFlagChanged
		}()

		vault = tmpDir

		duration := getAutoClearDuration()
		if duration != 60 {
			t.Errorf("duration = %d, want 60", duration)
		}
	})
}

func TestGetAutoClearDurationFromConfig(t *testing.T) {
	t.Run("zero means disabled", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfgPath := filepath.Join(tmpDir, "config.yaml")
		yamlContent := `clipboard:
  auto_clear_duration: 0
`
		if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		origVault := vault
		origFlagChanged := vaultFlag.Changed
		defer func() {
			vault = origVault
			vaultFlag.Changed = origFlagChanged
		}()

		vault = tmpDir

		duration := getAutoClearDuration()
		if duration != 0 {
			t.Errorf("duration = %d, want 0", duration)
		}
	})

	t.Run("custom value", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfgPath := filepath.Join(tmpDir, "config.yaml")
		yamlContent := `clipboard:
  auto_clear_duration: 120
`
		if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		origVault := vault
		origFlagChanged := vaultFlag.Changed
		defer func() {
			vault = origVault
			vaultFlag.Changed = origFlagChanged
		}()

		vault = tmpDir

		duration := getAutoClearDuration()
		if duration != 120 {
			t.Errorf("duration = %d, want 120", duration)
		}
	})
}

func TestLoadConfigForGetAutoClearDuration(t *testing.T) {
	t.Run("load valid config with clipboard", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfgPath := filepath.Join(tmpDir, "config.yaml")
		yamlContent := `
clipboard:
  auto_clear_duration: 45
agents:
  test:
    allowedPaths: ["*"]
    canWrite: true
`
		if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("load config: %v", err)
		}
		if cfg.Clipboard == nil {
			t.Fatal("clipboard config is nil")
		}
		if cfg.Clipboard.AutoClearDuration != 45 {
			t.Errorf("autoClearDuration = %d, want 45", cfg.Clipboard.AutoClearDuration)
		}
	})
}

func TestCmdGet_WholeEntry(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "mypass", "username": "bob"}}
	_ = vaultpkg.WriteEntry(vaultDir, "full-entry", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "get", "full-entry")
	if !strings.Contains(out, "full-entry") || !strings.Contains(out, "mypass") {
		t.Errorf("expected full entry output, got: %s", out)
	}
}

func TestCmdGet_FieldNotFound(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "mypass"}}
	_ = vaultpkg.WriteEntry(vaultDir, "getfield", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "get", "getfield.nofield"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "field not found") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected field not found, got: %s", stderr)
	}
}

func TestCmdGet_NotFound(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "get", "ghost-entry"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "not found") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected entry not found, got: %s", stderr)
	}
}

func TestCmdGet_FuzzyMultipleMatches(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	e := &vaultpkg.Entry{Data: map[string]any{"password": "p"}}
	_ = vaultpkg.WriteEntry(vaultDir, "work/aws", e, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "work/gcp", e, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	allOutput := captureStdout(func() {
		captureStderr(func() {
			rootCmd.SetArgs([]string{"--vault", vaultDir, "get", "work"})
			_ = rootCmd.Execute()
			rootCmd.SetArgs(nil)
		})
	})
	_ = allOutput
}

func TestCmdGet_TOTP(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{
		Data: map[string]any{
			"password": "pass",
			"totp": map[string]any{
				"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			},
		},
	}
	_ = vaultpkg.WriteEntry(vaultDir, "totp-get", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "get", "totp-get")
	if !strings.Contains(out, "totp-get") {
		t.Errorf("expected entry path in output, got: %s", out)
	}
}

func TestCmdGet_Uninitialized(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "get", "x"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "vault not initialized") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected vault not initialized, got: %s", stderr)
	}
}

func TestCmdGet_FuzzySingleMatch(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	e := &vaultpkg.Entry{Data: map[string]any{"password": "p"}}
	_ = vaultpkg.WriteEntry(vaultDir, "workstation", e, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "get", "workstat")
	if !strings.Contains(out, "workstation") {
		t.Errorf("expected fuzzy match output, got: %s", out)
	}
}

func TestCmdGet_TOTPDisplay(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{
		Data: map[string]any{
			"password": "pass",
			"totp": map[string]any{
				"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			},
		},
	}
	_ = vaultpkg.WriteEntry(vaultDir, "totp-display", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	rootCmd.SetArgs([]string{"--vault", vaultDir, "get", "totp-display"})
	defer rootCmd.SetArgs(nil)
	out := captureStderr(func() {
		_ = rootCmd.Execute()
	})
	if !strings.Contains(out, "TOTP Code") {
		t.Errorf("expected TOTP Code in output, got: %s", out)
	}
	if !strings.Contains(out, "expires in") {
		t.Errorf("expected 'expires in' in output, got: %s", out)
	}
}

func TestCmdGet_FieldTTY_DefaultClipboard(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	if err := os.WriteFile(filepath.Join(vaultDir, "config.yaml"), []byte("clipboard:\n  auto_clear_duration: 0\n"), 0o600); err != nil {
		t.Fatalf("disable clipboard auto-clear: %v", err)
	}
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "clip-pass-123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "clip-entry", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	clipboardapp.SetClipboard(clipboardapp.NewNullClipboard())
	t.Cleanup(func() { clipboardapp.SetClipboard(nil) })

	oldIsTerminal := isTerminalFunc
	isTerminalFunc = func(int) bool { return true }
	defer func() { isTerminalFunc = oldIsTerminal }()

	var stdout string
	var execErr error
	stderr := captureStderr(func() {
		stdout = captureStdout(func() {
			rootCmd.SetArgs([]string{"--vault", vaultDir, "get", "clip-entry.password"})
			execErr = rootCmd.Execute()
			rootCmd.SetArgs(nil)
		})
	})
	if execErr != nil {
		t.Fatalf("get command failed: %v", execErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty when TTY defaults to clipboard", stdout)
	}
	copied, _ := clipboardapp.DefaultClipboard().Read()
	if copied != "clip-pass-123" {
		t.Fatalf("copied = %q, want clip-pass-123", copied)
	}
	if !strings.Contains(stderr, "[copied to clipboard]") {
		t.Fatalf("stderr = %q, want copied status", stderr)
	}
}

func TestCmdGet_FieldPipe_DefaultPrint(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "pipe-pass-456"}}
	_ = vaultpkg.WriteEntry(vaultDir, "pipe-entry", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	oldIsTerminal := isTerminalFunc
	isTerminalFunc = func(int) bool { return false }
	defer func() { isTerminalFunc = oldIsTerminal }()

	out := execWithStdout("--vault", vaultDir, "get", "pipe-entry.password")
	if strings.TrimSpace(out) != "pipe-pass-456" {
		t.Fatalf("stdout = %q, want pipe-pass-456", out)
	}
}

func TestCmdGet_FieldPrintFlag_OverridesTTY(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "print-pass-789"}}
	_ = vaultpkg.WriteEntry(vaultDir, "print-entry", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	oldIsTerminal := isTerminalFunc
	isTerminalFunc = func(int) bool { return true }
	defer func() { isTerminalFunc = oldIsTerminal }()

	out := execWithStdout("--vault", vaultDir, "get", "print-entry.password", "--print")
	if strings.TrimSpace(out) != "print-pass-789" {
		t.Fatalf("stdout = %q, want print-pass-789", out)
	}
}

func TestCmdGet_FuzzyFieldLookup(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "secret123", "username": "admin"}}
	_ = vaultpkg.WriteEntry(vaultDir, "work/aws", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "get", "work/aws.password")
	if !strings.Contains(out, "secret123") {
		t.Errorf("expected secret123 in output: %s", out)
	}
}

func TestCmdGet_TOTPGenerationError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{
		Data: map[string]any{
			"password": "pass",
			"totp": map[string]any{
				"secret": "INVALID!!!SECRET!!!",
			},
		},
	}
	_ = vaultpkg.WriteEntry(vaultDir, "bad-totp", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	stderr := captureStderr(func() {
		_ = execWithStdout("--vault", vaultDir, "get", "bad-totp")
	})
	if !strings.Contains(stderr, "Warning: could not generate TOTP code") {
		t.Errorf("expected TOTP warning in stderr, got: %s", stderr)
	}
}

func TestGet_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	tests := []struct {
		setupFunc  func() string
		name       string
		errContain string
		args       []string
	}{
		{
			name: "uninitialized vault",
			setupFunc: func() string {
				tmpDir := t.TempDir()
				_ = os.Setenv("OPENPASS_VAULT", tmpDir)
				return tmpDir
			},
			args:       []string{"get", "test"},
			errContain: "not initialized",
		},
		{
			name: "entry not found",
			setupFunc: func() string {
				tmpDir := t.TempDir()
				_ = os.Setenv("OPENPASS_VAULT", tmpDir)
				cfg := config.Default()
				_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)
				_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
				return tmpDir
			},
			args:       []string{"get", "nonexistent"},
			errContain: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
			vault = ""
			if vaultFlag != nil {
				_ = vaultFlag.Value.Set("")
				vaultFlag.Changed = false
			}

			vaultDir := tt.setupFunc()

			rootCmd.SetArgs(append([]string{"--vault", vaultDir}, tt.args...))
			defer rootCmd.SetArgs(nil)

			err := rootCmd.Execute()
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.errContain) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContain)
			}
		})
	}
}
