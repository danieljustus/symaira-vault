package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cli "github.com/danieljustus/OpenPass/internal/cli"
	"github.com/danieljustus/OpenPass/internal/config"
	gitpkg "github.com/danieljustus/OpenPass/internal/git"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func resetCmdFlags() {
	resetCommandTestState()
}

func resetVaultState(t *testing.T) {
	t.Helper()
	resetCommandTestState()
	t.Cleanup(resetCommandTestState)
}

func vaultFlagReset(t *testing.T) {
	t.Helper()
	origVault := vault
	origChanged := false
	if vaultFlag != nil {
		origChanged = vaultFlag.Changed
	}
	t.Cleanup(func() {
		cli.Vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	})
}

func setupVaultFlag(t *testing.T, vaultDir string) func() {
	t.Helper()
	origVault := vault
	origChanged := vaultFlag.Changed
	_ = vaultFlag.Value.Set(vaultDir)
	vaultFlag.Changed = true
	cli.Vault = vaultDir
	return func() {
		cli.Vault = origVault
		_ = vaultFlag.Value.Set(origVault)
		vaultFlag.Changed = origChanged
	}
}

func initVault(t *testing.T) (string, []byte) {
	t.Helper()
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	return vaultDir, passphrase
}

func setPassEnv(t *testing.T, passphrase string) {
	t.Helper()
	_ = os.Setenv("OPENPASS_PASSPHRASE", passphrase)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })
}

func fakeEditorWithContent(t *testing.T, content string) string {
	t.Helper()
	contentFile := filepath.Join(t.TempDir(), "edited.json")
	if err := os.WriteFile(contentFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write content file: %v", err)
	}
	editorFile := filepath.Join(t.TempDir(), "fake_editor")
	script := fmt.Sprintf("#!/bin/sh\ncp '%s' \"$1\"\n", contentFile)
	if err := os.WriteFile(editorFile, []byte(script), 0o755); err != nil {
		t.Fatalf("write editor: %v", err)
	}
	return editorFile
}

func fakeEditorEmpty(t *testing.T) string {
	t.Helper()
	editorFile := filepath.Join(t.TempDir(), "empty_editor")
	script := "#!/bin/sh\nprintf '' > \"$1\"\n"
	if err := os.WriteFile(editorFile, []byte(script), 0o755); err != nil {
		t.Fatalf("write editor: %v", err)
	}
	return editorFile
}

func fakeEditorInvalid(t *testing.T) string {
	t.Helper()
	editorFile := filepath.Join(t.TempDir(), "invalid_editor")
	script := "#!/bin/sh\nprintf '{not valid json}' > \"$1\"\n"
	if err := os.WriteFile(editorFile, []byte(script), 0o755); err != nil {
		t.Fatalf("write editor: %v", err)
	}
	return editorFile
}

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

func setupGitWithBrokenObjects(t *testing.T, vaultDir string) {
	t.Helper()
	if err := gitpkg.Init(vaultDir); err != nil {
		t.Fatalf("init git: %v", err)
	}
	objectsDir := filepath.Join(vaultDir, ".git", "objects")
	if err := os.Chmod(objectsDir, 0o000); err != nil {
		t.Fatalf("chmod objects dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(objectsDir, 0o700)
	})
}
