package cmd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func runBinResult(t *testing.T, binPath string, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("exec %s: %v", strings.Join(args, " "), err)
		}
	}
	return stdout.String(), stderr.String(), exitCode
}

func buildAndInitVault(t *testing.T) (string, string, []string) {
	t.Helper()
	binPath := buildBinary(t)
	vaultDir := t.TempDir()
	passphrase := "correct horse battery staple"
	env := []string{
		"GOWORK=off",
		"OPENPASS_PASSPHRASE=" + passphrase,
	}

	initCmd := exec.Command(binPath, "init", vaultDir)
	initCmd.Env = append(os.Environ(), env...)
	initCmd.Stdin = strings.NewReader(passphrase + "\n")
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, output)
	}

	return binPath, vaultDir, env
}

func TestScriptingGet_Unlocked_Field(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow scripting test in short mode")
	}
	binPath, vaultDir, env := buildAndInitVault(t)

	setOut := runBin(t, binPath, env, "", "--vault", vaultDir, "set", "github.token", "--value", "ghp_secret123")
	if !strings.Contains(setOut, "Entry saved") {
		t.Fatalf("set output: %s", setOut)
	}

	stdout, stderr, exitCode := runBinResult(t, binPath, env, "--vault", vaultDir, "get", "github.token", "--print")
	if exitCode != 0 {
		t.Fatalf("get exit code = %d, want 0\nstderr: %s", exitCode, stderr)
	}
	if strings.TrimSpace(stdout) != "ghp_secret123" {
		t.Errorf("stdout = %q, want ghp_secret123", stdout)
	}
}

func TestScriptingGet_Locked_NoPassphrase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow scripting test in short mode")
	}
	binPath := buildBinary(t)
	vaultDir := t.TempDir()
	passphrase := "correct horse battery staple"

	initCmd := exec.Command(binPath, "init", vaultDir)
	initCmd.Env = append(os.Environ(), "GOWORK=off", "OPENPASS_PASSPHRASE="+passphrase)
	initCmd.Stdin = strings.NewReader(passphrase + "\n")
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, output)
	}

	setEnv := []string{"GOWORK=off", "OPENPASS_PASSPHRASE=" + passphrase}
	_ = runBin(t, binPath, setEnv, "", "--vault", vaultDir, "set", "secret.key", "--value", "mysecret")

	lockedEnv := []string{"GOWORK=off"}
	stdout, stderr, exitCode := runBinResult(t, binPath, lockedEnv, "--vault", vaultDir, "get", "secret.key", "--print")
	if exitCode != 4 {
		t.Errorf("locked get exit code = %d, want 4 (ExitLocked)", exitCode)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty when locked", stdout)
	}
	if !strings.Contains(stderr, "locked") && !strings.Contains(stderr, "Locked") {
		t.Errorf("stderr = %q, want 'locked' message", stderr)
	}
}

func TestScriptingGet_EntryNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow scripting test in short mode")
	}
	binPath, vaultDir, env := buildAndInitVault(t)

	stdout, stderr, exitCode := runBinResult(t, binPath, env, "--vault", vaultDir, "get", "nonexistent.entry", "--print")
	if exitCode != 2 {
		t.Errorf("not-found get exit code = %d, want 2 (ExitNotFound)", exitCode)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty when not found", stdout)
	}
	if !strings.Contains(stderr, "not found") && !strings.Contains(stderr, "Not Found") {
		t.Errorf("stderr = %q, want 'not found' message", stderr)
	}
}

func TestScriptingGet_Uninitialized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow scripting test in short mode")
	}
	binPath := buildBinary(t)
	vaultDir := t.TempDir()

	_, stderr, exitCode := runBinResult(t, binPath, []string{"GOWORK=off"}, "--vault", vaultDir, "get", "anything", "--print")
	if exitCode != 3 {
		t.Errorf("uninitialized get exit code = %d, want 3 (ExitNotInitialized)", exitCode)
	}
	if !strings.Contains(stderr, "not initialized") && !strings.Contains(stderr, "Not Initialized") {
		t.Errorf("stderr = %q, want 'not initialized' message", stderr)
	}
}

func TestScriptingGet_NoHangOnLocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow scripting test in short mode")
	}
	binPath := buildBinary(t)
	vaultDir := t.TempDir()
	passphrase := "correct horse battery staple"

	initCmd := exec.Command(binPath, "init", vaultDir)
	initCmd.Env = append(os.Environ(), "GOWORK=off", "OPENPASS_PASSPHRASE="+passphrase)
	initCmd.Stdin = strings.NewReader(passphrase + "\n")
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, output)
	}

	lockedEnv := []string{"GOWORK=off"}
	cmd := exec.Command(binPath, "--vault", vaultDir, "get", "anything", "--print")
	cmd.Env = append(os.Environ(), lockedEnv...)
	cmd.Stdin = strings.NewReader("")

	done := make(chan struct{})
	var exitCode int
	go func() {
		err := cmd.Run()
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		close(done)
	}()

	select {
	case <-done:
		if exitCode != 4 {
			t.Errorf("exit code = %d, want 4 (ExitLocked)", exitCode)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("symvault get hung waiting for passphrase input (non-TTY should not prompt)")
		_ = cmd.Process.Kill()
	}
}

func TestScriptingGet_WholeEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow scripting test in short mode")
	}
	binPath, vaultDir, env := buildAndInitVault(t)

	_ = runBin(t, binPath, env, "", "--vault", vaultDir, "set", "db.host", "--value", "localhost")
	_ = runBin(t, binPath, env, "", "--vault", vaultDir, "set", "db.port", "--value", "5432")

	stdout, stderr, exitCode := runBinResult(t, binPath, env, "--vault", vaultDir, "get", "db")
	if exitCode != 0 {
		t.Fatalf("get whole entry exit code = %d, want 0\nstderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "host: localhost") || !strings.Contains(stdout, "port: 5432") {
		t.Errorf("stdout missing entries: %s", stdout)
	}
}

func TestScriptingGet_JSONOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow scripting test in short mode")
	}
	binPath, vaultDir, env := buildAndInitVault(t)

	_ = runBin(t, binPath, env, "", "--vault", vaultDir, "set", "api.key", "--value", "sk-123")

	stdout, stderr, exitCode := runBinResult(t, binPath, env, "--vault", vaultDir, "get", "api.key", "--output", "json")
	if exitCode != 0 {
		t.Fatalf("json get exit code = %d, want 0\nstderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "sk-123") {
		t.Errorf("json stdout missing secret: %s", stdout)
	}
}
