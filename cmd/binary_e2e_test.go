package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "symvault")
	build := exec.Command("go", "build", "-o", binPath, "..")
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build symvault: %v\n%s", err, output)
	}
	return binPath
}

func runBin(t *testing.T, binPath string, env []string, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.Output()
	if err != nil {
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		t.Fatalf("%s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, output, stderr)
	}
	return string(output)
}

func TestBinaryE2E_Flow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow binary e2e test in short mode")
	}
	binPath := buildBinary(t)
	vaultDir := t.TempDir()
	passphrase := []byte("correct horse battery staple")
	env := []string{
		"GOWORK=off",
		"SYMVAULT_PASSPHRASE=" + string(passphrase),
		// Test binaries must never touch the developer's real OS keychain
		// (issue #801): force the in-memory keyring in the child binary too.
		"SYMVAULT_TEST_KEYRING=memory",
	}

	initCmd := exec.Command(binPath, "init", vaultDir)
	initCmd.Env = append(os.Environ(), env...)
	initCmd.Stdin = strings.NewReader(string(passphrase) + "\n")
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, output)
	}

	output := runBin(t, binPath, env, "", "--vault", vaultDir, "set", "demo.password", "--value", "StrongP@ssw0rd123")
	if !strings.Contains(output, "Entry saved") {
		t.Errorf("set output: %s", output)
	}

	output = runBin(t, binPath, env, "", "--vault", vaultDir, "get", "demo.password")
	if strings.TrimSpace(output) != "StrongP@ssw0rd123" {
		t.Errorf("get output: %q", output)
	}

	output = runBin(t, binPath, env, "", "--vault", vaultDir, "list")
	if !strings.Contains(output, "demo") {
		t.Errorf("list output: %s", output)
	}

	output = runBin(t, binPath, env, "", "--vault", vaultDir, "find", "StrongP@ssw0rd123")
	if !strings.Contains(output, "demo") {
		t.Errorf("find output: %s", output)
	}

	output = runBin(t, binPath, env, "", "--vault", vaultDir, "generate", "--length", "16", "--store", "gen.pass")
	if !strings.Contains(output, "Password stored at") {
		t.Errorf("generate output: %s", output)
	}

	_ = runBin(t, binPath, env, "y\n", "--vault", vaultDir, "delete", "gen.pass")
}

func TestBinaryE2E_AuditRotateKeyBootstraps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow binary e2e test in short mode")
	}
	binPath := buildBinary(t)
	vaultDir := t.TempDir()
	passphrase := []byte("correct horse battery staple")
	env := []string{
		"GOWORK=off",
		"SYMVAULT_PASSPHRASE=" + string(passphrase),
		"SYMVAULT_TEST_KEYRING=memory",
	}

	initCmd := exec.Command(binPath, "init", vaultDir)
	initCmd.Env = append(os.Environ(), env...)
	initCmd.Stdin = strings.NewReader(string(passphrase) + "\n")
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, output)
	}

	// Issue #803: rotating a vault that has no HMAC key yet must succeed
	// (bootstrap) instead of erroring, must report that it bootstrapped, and
	// must not write an archive file. Informational output is routed to
	// stderr when stdin is not a terminal, so capture both streams.
	stdout, stderr, exitCode := runBinResult(t, binPath, env, "--vault", vaultDir, "audit", "rotate-key")
	if exitCode != 0 {
		t.Fatalf("rotate-key exit code = %d, want 0\nstderr: %s", exitCode, stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "bootstrapped") {
		t.Errorf("rotate-key output should report bootstrap, got stdout=%q stderr=%q", stdout, stderr)
	}
	if strings.Contains(combined, "archived") {
		t.Errorf("bootstrap output should not mention archiving, got: %s", combined)
	}
	matches, err := filepath.Glob(filepath.Join(vaultDir, "audit-hmac-key.rotated.*"))
	if err != nil {
		t.Fatalf("glob archive files: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("bootstrap must not write archive files, got %v", matches)
	}
}

func TestBinaryE2E_Recipients(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow binary e2e test in short mode")
	}
	binPath := buildBinary(t)
	vaultDir := t.TempDir()
	passphrase := []byte("correct horse battery staple")
	env := []string{
		"GOWORK=off",
		"SYMVAULT_PASSPHRASE=" + string(passphrase),
		"SYMVAULT_TEST_KEYRING=memory",
	}

	initCmd := exec.Command(binPath, "init", vaultDir)
	initCmd.Env = append(os.Environ(), env...)
	initCmd.Stdin = strings.NewReader(string(passphrase) + "\n")
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, output)
	}

	output := runBin(t, binPath, env, "", "--vault", vaultDir, "recipients", "list")
	if !strings.Contains(output, "No recipients") {
		t.Errorf("recipients list output: %s", output)
	}
}
