package cmd

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestCmdRun_Basic(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run", "--", "echo", "hello")
	if !strings.Contains(out, "hello") {
		t.Errorf("expected 'hello' in stdout, got: %q", out)
	}
}

func TestCmdRun_SecretInjection(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"api_key": "secret123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "github", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run", "--env", "API_KEY=github.api_key", "--", "sh", "-c", "echo $API_KEY")
	if !strings.Contains(out, "secret123") {
		t.Errorf("expected 'secret123' in stdout, got: %q", out)
	}
}

func TestCmdRun_MissingSecretRef(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--env", "FOO=missing.value", "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for missing secret ref, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "secret ref not found") && !strings.Contains(errStr, "not found") {
			t.Errorf("expected 'not found' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_Timeout(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--timeout", "100ms", "--", "sleep", "10"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected timeout error, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "timed out") && !strings.Contains(errStr, "timeout") && !strings.Contains(errStr, "deadline") {
			t.Errorf("expected timeout-related error, got: %q", errStr)
		}
	}
}

func TestCmdRun_WorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	tmpDir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	out := execWithStdout("--vault", vaultDir, "run", "--working-dir", tmpDir, "--", "pwd")
	out = strings.TrimSpace(out)
	outResolved, err := filepath.EvalSymlinks(out)
	if err != nil {
		t.Fatalf("eval symlinks on pwd output: %v", err)
	}
	if outResolved != resolvedDir {
		t.Errorf("expected pwd output %q, got: %q (resolved: %q)", tmpDir, out, outResolved)
	}
}

func TestCmdRun_MultipleEnvFlags(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry1 := &vaultpkg.Entry{Data: map[string]any{"token": "tok1"}}
	entry2 := &vaultpkg.Entry{Data: map[string]any{"secret": "sec1"}}
	_ = vaultpkg.WriteEntry(vaultDir, "svc1", entry1, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "svc2", entry2, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run",
		"--env", "TOKEN=svc1.token",
		"--env", "SECRET=svc2.secret",
		"--", "sh", "-c", "echo TOKEN=$TOKEN SECRET=$SECRET")
	if !strings.Contains(out, "TOKEN=tok1") {
		t.Errorf("expected TOKEN=tok1 in stdout, got: %q", out)
	}
	if !strings.Contains(out, "SECRET=sec1") {
		t.Errorf("expected SECRET=sec1 in stdout, got: %q", out)
	}
}

func TestCmdRun_NonZeroExit(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--", "sh", "-c", "exit 42"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected non-zero exit error, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "exited with code") && !strings.Contains(errStr, "42") {
			t.Errorf("expected exit code 42 in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_UninitializedVault(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for uninitialized vault, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "not initialized") {
			t.Errorf("expected 'not initialized' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_TooManyEnvironmentVariables(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)

	for _, svc := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		entry := &vaultpkg.Entry{Data: map[string]any{"key": svc}}
		_ = vaultpkg.WriteEntry(vaultDir, svc, entry, identity.Identity)
	}

	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run",
		"--env", "A=a.key", "--env", "B=b.key", "--env", "C=c.key",
		"--env", "D=d.key", "--env", "E=e.key", "--env", "F=f.key",
		"--env", "G=g.key", "--env", "H=h.key", "--env", "I=i.key",
		"--env", "J=j.key",
		"--", "sh", "-c", "echo ALL_SET"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCmdRun_EnvWithBareRef(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "thepass"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run", "--env", "DB_PASSWORD=db.password", "--", "sh", "-c", "echo $DB_PASSWORD")
	if !strings.Contains(out, "thepass") {
		t.Errorf("expected 'thepass' in stdout, got: %q", out)
	}
}

func TestCmdRun_StdoutStderrPassthrough(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	var stdout, stderr string

	stdout = captureStdout(func() {
		stderr = captureStderr(func() {
			rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--", "sh", "-c", "echo stdout; echo stderr >&2"})
			_ = rootCmd.Execute()
			rootCmd.SetArgs(nil)
		})
	})

	if !strings.Contains(stdout, "stdout") {
		t.Errorf("expected 'stdout' in stdout, got: %q", stdout)
	}
	if !strings.Contains(stderr, "stderr") {
		t.Errorf("expected 'stderr' in stderr, got: %q", stderr)
	}
}

func TestCmdRun_NoArgsError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error when no command provided, got nil")
	}
}

func TestCmdRun_InvalidEnvFormat(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--env", "NOEQUALSIGN", "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid --env format, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "invalid --env format") {
			t.Errorf("expected 'invalid --env format' in error, got: %q", errStr)
		}
	}
}
