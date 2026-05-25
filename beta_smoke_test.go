//go:build smoke

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBetaSmokeFlow(t *testing.T) {
	binDir := t.TempDir()
	binName := "symvault"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(binDir, binName)

	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = repoRoot(t)
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build symvault: %v\n%s", err, output)
	}

	vaultDir := filepath.Join(t.TempDir(), "vault")
	passphrase := "correct horse battery staple"

	initCmd := exec.Command(binPath, "init", vaultDir)
	initCmd.Dir = repoRoot(t)
	initCmd.Stdin = strings.NewReader(passphrase + "\n")
	if output, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init vault: %v\n%s", err, output)
	}

	run := func(args ...string) string {
		t.Helper()

		cmd := exec.Command(binPath, args...)
		cmd.Dir = repoRoot(t)
		cmd.Env = append(os.Environ(),
			"GOWORK=off",
			"OPENPASS_PASSPHRASE="+passphrase,
		)
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

	run("--vault", vaultDir, "set", "demo.password", "--value", "xK9#mP2$vL7@nQ4")

	if output := strings.TrimSpace(run("--vault", vaultDir, "get", "demo.password")); output != "xK9#mP2$vL7@nQ4" {
		t.Fatalf("get demo.password = %q, want xK9#mP2$vL7@nQ4", output)
	}

	listOutput := run("--vault", vaultDir, "list")
	if !strings.Contains(listOutput, "demo") {
		t.Fatalf("list output missing entry: %s", listOutput)
	}

	findOutput := run("--vault", vaultDir, "find", "xK9#mP2$vL7@nQ4")
	if !strings.Contains(findOutput, "demo") {
		t.Fatalf("find output missing match: %s", findOutput)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return root
}
