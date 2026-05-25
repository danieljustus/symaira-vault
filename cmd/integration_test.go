//go:build integration

package cmd

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/git"
	"github.com/danieljustus/symaira-vault/internal/session"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestCmdGitPush_NoRemote(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_VAULT") })

	if err := git.Init(vaultDir); err != nil {
		t.Fatalf("git init: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "git", "push"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "Pushed") {
		t.Logf("push output: %q (no remote → skipped, still ok)", output)
	}
}

func TestCmdGitPull_NoRemote(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_VAULT") })

	if err := git.Init(vaultDir); err != nil {
		t.Fatalf("git init: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "git", "pull"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "Pulled") {
		t.Logf("pull output: %q (no remote → skipped, still ok)", output)
	}
}

func TestCmdGitLog_Success(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	if err := git.Init(vaultDir); err != nil {
		t.Fatalf("git init: %v", err)
	}
	if err := git.CreateGitignore(vaultDir); err != nil {
		t.Fatalf("git createGitignore: %v", err)
	}
	if err := os.WriteFile(vaultDir+"/dummy.txt", []byte("test"), 0o644); err != nil {
		t.Fatalf("write dummy: %v", err)
	}
	if err := git.AutoCommit(vaultDir, "initial commit"); err != nil {
		t.Fatalf("auto commit: %v", err)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", passphrase)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "git", "log"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})

	if len(strings.TrimSpace(output)) == 0 {
		t.Errorf("git log output is empty, expected commit history")
	}
}

func TestCmdGitUnknownAction(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_VAULT") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "git", "unknown"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for unknown git action")
	}
	if !strings.Contains(execErr.Error(), "unknown action") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdLock_Success(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	if err := session.SavePassphrase(vaultDir, passphrase, time.Hour); err != nil {
		t.Skipf("keyring unavailable: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "lock"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStderr(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "Vault locked") {
		t.Errorf("lock output missing expected message: %q", output)
	}
}

func TestCmdUnlock_CheckExpired(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	t.Cleanup(func() { _ = unlockCmd.Flags().Set("check", "false") })

	rootCmd.SetArgs([]string{"--vault", vaultDir, "unlock", "--check"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for expired/missing session")
	}
	if !strings.Contains(execErr.Error(), "no active session") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdUnlock_CheckActive(t *testing.T) {
	vaultDir := t.TempDir()
	passphrase := []byte("correcthorsebatterystaple")
	vaultFlagReset(t)

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	if err := session.SavePassphrase(vaultDir, passphrase, time.Hour); err != nil {
		t.Skipf("keyring unavailable: %v", err)
	}

	t.Cleanup(func() {
		_ = unlockCmd.Flags().Set("check", "false")
		_ = session.ClearSession(vaultDir)
	})

	rootCmd.SetArgs([]string{"--vault", vaultDir, "unlock", "--check"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	output := captureStderr(func() {
		_ = rootCmd.Execute()
	})

	if !strings.Contains(output, "Session active") {
		t.Errorf("unlock --check output: %q", output)
	}
}

func TestLock_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("uninitialized vault", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "lock"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %v", err)
		}
	})
}

func TestUnlock_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("uninitialized vault", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "unlock"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %v", err)
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		_ = os.Setenv("OPENPASS_PASSPHRASE", "wrong-password")
		defer func() {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "unlock"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil {
			t.Error("expected error for wrong passphrase")
		}
	})
}
