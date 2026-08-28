package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/danieljustus/symaira-vault/internal/config"
	gitpkg "github.com/danieljustus/symaira-vault/internal/git"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestInitCommand_HiddenPassphrase(t *testing.T) {
	root := NewRootCmd()
	vaultDir := t.TempDir()
	passphrase := []byte("test-hidden-passphrase")

	cli.SetCachedEnvPassphrase(passphrase)
	defer cli.SetCachedEnvPassphrase(nil)

	root.SetArgs([]string{"init", vaultDir})
	defer root.SetArgs(nil)

	output := captureStdout(func() {
		if err := root.Execute(); err != nil {
			t.Fatalf("init command failed: %v", err)
		}
	})

	if !strings.Contains(output, "Vault initialized") {
		t.Errorf("expected 'Vault initialized' in output, got: %s", output)
	}

	if !strings.Contains(output, "Public key:") {
		t.Errorf("expected 'Public key:' in output, got: %s", output)
	}

	cfgPath := filepath.Join(vaultDir, "config.yaml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Errorf("config.yaml not created at %s", cfgPath)
	}

	identityPath := filepath.Join(vaultDir, "identity.age")
	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		t.Errorf("identity.age not created at %s", identityPath)
	}

	_ = gitpkg.Init(vaultDir)
	gitDir := filepath.Join(vaultDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		t.Errorf(".git directory not created at %s", gitDir)
	}
}

func TestCmdInit_Success(t *testing.T) {
	root := NewRootCmd()
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	cli.SetCachedEnvPassphrase([]byte("supersecretpassphrase123"))
	defer cli.SetCachedEnvPassphrase(nil)

	root.SetArgs([]string{"--vault", vaultDir, "init"})
	t.Cleanup(func() { root.SetArgs(nil) })

	output := captureStdout(func() {
		_ = root.Execute()
	})

	if !strings.Contains(output, "Vault initialized") {
		t.Errorf("init output missing success message: %q", output)
	}
}

func TestCmdInit_AlreadyInitialized(t *testing.T) {
	root := NewRootCmd()
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte("supersecretpassphrase123"), config.Default()); err != nil {
		t.Fatalf("pre-init vault: %v", err)
	}

	cli.SetCachedEnvPassphrase([]byte("supersecretpassphrase123"))
	defer cli.SetCachedEnvPassphrase(nil)

	root.SetArgs([]string{"--vault", vaultDir, "init"})
	t.Cleanup(func() { root.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = root.Execute()
	})

	if execErr == nil {
		t.Error("expected error for already initialized vault")
	}
	if !strings.Contains(execErr.Error(), "already initialized") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdInit_ShortPassphrase(t *testing.T) {
	root := NewRootCmd()
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	cli.SetCachedEnvPassphrase([]byte("short"))
	defer cli.SetCachedEnvPassphrase(nil)

	root.SetArgs([]string{"--vault", vaultDir, "init"})
	t.Cleanup(func() { root.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = root.Execute()
	})

	if execErr == nil {
		t.Error("expected error for short passphrase")
	}
}

func TestInit_ErrorPaths(t *testing.T) {
	root := NewRootCmd()
	resetVaultState(t)
	t.Run("already initialized", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		_ = os.Setenv("SYMVAULT_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("SYMVAULT_VAULT") }()

		cli.SetCachedEnvPassphrase([]byte("test"))
		defer cli.SetCachedEnvPassphrase(nil)

		root.SetArgs([]string{"--vault", tmpDir, "init"})
		defer root.SetArgs(nil)

		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), "already initialized") {
			t.Errorf("expected 'already initialized' error, got: %v", err)
		}
	})
}
