package cmd

import (
	"os"
	"strings"
	"testing"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestCmdFind_NoMatches(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "find", "nomatch_xyz_abc"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "No matches") {
		t.Errorf("expected No matches, got: %s", stderr)
	}
}

func TestCmdFind_WithFieldMatches(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "uniquevalue123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "find-me", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "find", "find-me")
	if !strings.Contains(out, "find-me") {
		t.Errorf("expected find-me in output, got: %s", out)
	}
}

func TestCmdFind_SearchAlias(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "searchval"}}
	_ = vaultpkg.WriteEntry(vaultDir, "search-me", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "search", "search-me")
	if !strings.Contains(out, "search-me") {
		t.Errorf("expected search-me in output, got: %s", out)
	}
}

func TestCmdFind_Uninitialized(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "find", "x"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "vault not initialized") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected vault not initialized, got: %s", stderr)
	}
}

func TestFind_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("uninitialized vault", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "find", "test"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %v", err)
		}
	})
}
