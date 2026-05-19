package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/danieljustus/OpenPass/internal/config"
	gitpkg "github.com/danieljustus/OpenPass/internal/git"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestInitCommand_HiddenPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("test-hidden-passphrase")

	restore := pipeStdin(t, string(passphrase)+"\n")
	defer restore()

	cli.RootCmd.SetArgs([]string{"init", vaultDir})
	defer cli.RootCmd.SetArgs(nil)

	output := captureStdout(func() {
		if err := cli.RootCmd.Execute(); err != nil {
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
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.WriteString("supersecretpassphrase123\n")
	_ = w.Close()
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
	})

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "init"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = cli.RootCmd.Execute()
	})

	if !strings.Contains(output, "Vault initialized") {
		t.Errorf("init output missing success message: %q", output)
	}
}

func TestCmdInit_AlreadyInitialized(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, []byte("supersecretpassphrase123"), config.Default()); err != nil {
		t.Fatalf("pre-init vault: %v", err)
	}

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "init"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = cli.RootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for already initialized vault")
	}
	if !strings.Contains(execErr.Error(), "already initialized") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdInit_ShortPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.WriteString("short\n")
	_ = w.Close()
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
	})

	cli.RootCmd.SetArgs([]string{"--vault", vaultDir, "init"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = cli.RootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for short passphrase")
	}
}

func TestInit_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("already initialized", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

		cli.RootCmd.SetArgs([]string{"--vault", tmpDir, "init"})
		defer cli.RootCmd.SetArgs(nil)

		err := cli.RootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "already initialized") {
			t.Errorf("expected 'already initialized' error, got: %v", err)
		}
	})
}
