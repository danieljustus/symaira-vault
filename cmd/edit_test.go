package cmd

import (
	"os"
	"runtime"
	"strings"
	"testing"

	crud "github.com/danieljustus/OpenPass/cmd/crud"
	"github.com/danieljustus/OpenPass/internal/config"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestCmdEdit_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: shell script editor not supported")
	}
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "original"}}
	_ = vaultpkg.WriteEntry(vaultDir, "edit-me", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	editor := fakeEditorWithContent(t,
		`{"data":{"password":"edited_pass"},"meta":{"created":"0001-01-01T00:00:00Z","updated":"0001-01-01T00:00:00Z","version":0}}`)
	origEditor := os.Getenv("EDITOR")
	_ = os.Setenv("EDITOR", editor)
	defer func() { _ = os.Setenv("EDITOR", origEditor) }()
	out := execWithStdout("--vault", vaultDir, "edit", "edit-me")
	if !strings.Contains(out, "Entry updated") {
		t.Errorf("expected Entry updated, got: %s", out)
	}
}

func TestCmdEdit_NotFound(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "edit", "ghost"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "not found") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected not found, got: %s", stderr)
	}
}

func TestCmdEdit_EditorNotFound(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "x"}}
	_ = vaultpkg.WriteEntry(vaultDir, "ed-nf", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	origEditor := os.Getenv("EDITOR")
	_ = os.Setenv("EDITOR", "nonexistent_editor_xyz_abc")
	defer func() { _ = os.Setenv("EDITOR", origEditor) }()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "edit", "ed-nf"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "not found") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected editor not found error, got: %s", stderr)
	}
}

//nolint:dupl // test coverage helper with similar structure to invalid JSON test
func TestCmdEdit_EmptyFile(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "x"}}
	_ = vaultpkg.WriteEntry(vaultDir, "empty-edit", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	origEditor := os.Getenv("EDITOR")
	_ = os.Setenv("EDITOR", fakeEditorEmpty(t))
	defer func() { _ = os.Setenv("EDITOR", origEditor) }()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "edit", "empty-edit"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "empty") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected empty file error, got: %s", stderr)
	}
}

//nolint:dupl // test coverage helper with similar structure to empty file test
func TestCmdEdit_InvalidJSON(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "x"}}
	_ = vaultpkg.WriteEntry(vaultDir, "bad-json", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	origEditor := os.Getenv("EDITOR")
	_ = os.Setenv("EDITOR", fakeEditorInvalid(t))
	defer func() { _ = os.Setenv("EDITOR", origEditor) }()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "edit", "bad-json"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "invalid JSON") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected invalid JSON error, got: %s", stderr)
	}
}

func TestCmdEdit_EditorRunError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "x"}}
	_ = vaultpkg.WriteEntry(vaultDir, "edit-err", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	origEditor := os.Getenv("EDITOR")
	_ = os.Setenv("EDITOR", "false")
	defer func() { _ = os.Setenv("EDITOR", origEditor) }()

	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "edit", "edit-err"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "editor failed") {
		t.Errorf("expected 'editor failed' in stderr: %s", stderr)
	}
}

func TestCmdEdit_Uninitialized(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "edit", "x"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "vault not initialized") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected vault not initialized, got: %s", stderr)
	}
}

func TestCmdEdit_TempFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: permission model differs")
	}
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "original"}}
	_ = vaultpkg.WriteEntry(vaultDir, "perm-test", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	editor := fakeEditorWithContent(t,
		`{"data":{"password":"edited"},"meta":{"created":"0001-01-01T00:00:00Z","updated":"0001-01-01T00:00:00Z","version":0}}`)
	origEditor := os.Getenv("EDITOR")
	_ = os.Setenv("EDITOR", editor)
	defer func() { _ = os.Setenv("EDITOR", origEditor) }()

	// Track temp file before editor runs
	var tmpPath string
	origCreateTemp := crud.OSCreateTemp
	crud.OSCreateTemp = func(dir, pattern string) (*os.File, error) {
		f, err := origCreateTemp(dir, pattern)
		if err == nil {
			tmpPath = f.Name()
		}
		return f, err
	}
	defer func() { crud.OSCreateTemp = origCreateTemp }()

	out := execWithStdout("--vault", vaultDir, "edit", "perm-test")
	if !strings.Contains(out, "Entry updated") {
		t.Errorf("expected Entry updated, got: %s", out)
	}

	if tmpPath != "" {
		info, err := os.Stat(tmpPath)
		if err == nil {
			perm := info.Mode().Perm()
			if perm != 0o600 {
				t.Errorf("expected temp file permissions 0600, got %#o", perm)
			}
		}
	}
}

func TestCmdEdit_AutoCommitError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: stderr capture not reliable")
	}
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "original"}}
	_ = vaultpkg.WriteEntry(vaultDir, "autocommit-edit", entry, identity.Identity)
	setupGitWithBrokenObjects(t, vaultDir)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	editor := fakeEditorWithContent(t,
		`{"data":{"password":"edited"},"meta":{"created":"0001-01-01T00:00:00Z","updated":"0001-01-01T00:00:00Z","version":0}}`)
	origEditor := os.Getenv("EDITOR")
	_ = os.Setenv("EDITOR", editor)
	defer func() { _ = os.Setenv("EDITOR", origEditor) }()

	stderr := captureStderr(func() {
		_ = execWithStdout("--vault", vaultDir, "edit", "autocommit-edit")
	})
	if !strings.Contains(stderr, "auto-commit failed") {
		t.Errorf("expected auto-commit warning in stderr: %s", stderr)
	}
}

func TestEdit_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	tests := []struct {
		name       string
		setupFunc  func() string
		errContain string
	}{
		{
			name: "uninitialized vault",
			setupFunc: func() string {
				tmpDir := t.TempDir()
				_ = os.Setenv("OPENPASS_VAULT", tmpDir)
				return tmpDir
			},
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

			rootCmd.SetArgs([]string{"--vault", vaultDir, "edit", "nonexistent"})
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
