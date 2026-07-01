package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunCommand_EmptyCommand(t *testing.T) {
	_, err := RunCommand(RunOptions{Command: nil})
	if err == nil {
		t.Fatal("expected error for nil command")
	}
	if err.Error() != "command must have at least one element" {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = RunCommand(RunOptions{Command: []string{}})
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestRunCommand_BasicExecution(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"echo", "hello"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "hello") {
		t.Fatalf("Stdout = %q, want hello", result.Stdout)
	}
	if result.Duration <= 0 {
		t.Fatal("expected positive duration")
	}
}

func TestRunCommand_NonZeroExit(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", "exit 42"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Fatalf("ExitCode = %d, want 42", result.ExitCode)
	}
}

func TestRunCommand_EnvInjection(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", "echo $TEST_VAR"},
		Env:     map[string]string{"TEST_VAR": "injected_value"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "injected_value") {
		t.Fatalf("Stdout = %q, want injected_value", result.Stdout)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
}

func TestRunCommand_EnvOverlay(t *testing.T) {
	home := os.Getenv("HOME")

	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", "echo $HOME"},
		Env:     map[string]string{"HOME": "/custom/home"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	if strings.TrimSpace(result.Stdout) != "/custom/home" {
		t.Fatalf("Stdout = %q, want /custom/home (original HOME was %s)", result.Stdout, home)
	}
}

func TestRunCommand_Timeout(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"sleep", "10"},
		Timeout: 100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error message does not mention timeout: %v", err)
	}
	if result.ExitCode != -1 {
		t.Fatalf("ExitCode = %d, want -1", result.ExitCode)
	}
}

func TestRunCommand_OutputCap(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", "i=0; while [ $i -lt 2000 ]; do printf '%-100s\n' 'x'; i=$((i+1)); done"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}

	const maxOutput = 100 * 1024
	if len(result.Stdout) != maxOutput {
		t.Fatalf("Stdout length = %d, want exactly %d (capped)", len(result.Stdout), maxOutput)
	}
	if len(result.Stderr) > maxOutput {
		t.Fatalf("Stderr length = %d exceeds cap %d", len(result.Stderr), maxOutput)
	}
}

func TestRunCommand_WorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	wd := t.TempDir()
	subDir := filepath.Join(wd, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	result, err := RunCommand(RunOptions{
		Command:    []string{"pwd"},
		WorkingDir: subDir,
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	got := strings.TrimSpace(result.Stdout)
	resolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", got, err)
	}
	want, err := filepath.EvalSymlinks(subDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", subDir, err)
	}
	if resolved != want {
		t.Fatalf("pwd = %q (resolved: %q), want %q (resolved: %q)", got, resolved, subDir, want)
	}
}

func TestRunCommand_StderrCapture(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", "echo stdout; echo stderr >&2"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "stdout") {
		t.Fatalf("Stdout = %q, want stdout", result.Stdout)
	}
	if !strings.Contains(result.Stderr, "stderr") {
		t.Fatalf("Stderr = %q, want stderr", result.Stderr)
	}
}

func TestRunCommand_Args(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"echo", "arg1", "arg2", "arg3"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "arg1 arg2 arg3") {
		t.Fatalf("Stdout = %q, want 'arg1 arg2 arg3'", result.Stdout)
	}
}

func TestRunCommand_StdinForwarding(t *testing.T) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdin = r
	_, _ = w.WriteString("heredoc_data")
	_ = w.Close()

	result, err := RunCommand(RunOptions{
		Command: []string{"cat"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "heredoc_data") {
		t.Errorf("expected 'heredoc_data' in stdout from stdin forwarding, got: %q", result.Stdout)
	}
}
