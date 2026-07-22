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
	if !result.StdoutTruncated {
		t.Fatal("StdoutTruncated = false, want true for output exceeding the cap")
	}
}

func TestRunCommand_StderrOutputCap(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", "i=0; while [ $i -lt 2000 ]; do printf '%-100s\n' 'x' >&2; i=$((i+1)); done"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}

	const maxOutput = 100 * 1024
	if len(result.Stderr) != maxOutput {
		t.Fatalf("Stderr length = %d, want exactly %d (capped)", len(result.Stderr), maxOutput)
	}
	if !result.StderrTruncated {
		t.Fatal("StderrTruncated = false, want true for output exceeding the cap")
	}
	if result.StdoutTruncated {
		t.Fatal("StdoutTruncated = true, want false when stdout stayed under the cap")
	}
}

func TestRunCommand_OutputUnderCapNotTruncated(t *testing.T) {
	result, err := RunCommand(RunOptions{
		Command: []string{"echo", "small"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if result.StdoutTruncated || result.StderrTruncated {
		t.Fatalf("expected no truncation for small output, got stdout=%v stderr=%v",
			result.StdoutTruncated, result.StderrTruncated)
	}
}

func TestBoundedBuffer_DrainsBeyondCapWithoutGrowing(t *testing.T) {
	const max = 16
	b := newBoundedBuffer(max)

	chunk := make([]byte, 1024)
	for i := range chunk {
		chunk[i] = 'x'
	}

	var totalWritten int
	for i := 0; i < 100; i++ {
		n, err := b.Write(chunk)
		if err != nil {
			t.Fatalf("Write() unexpected error: %v", err)
		}
		if n != len(chunk) {
			t.Fatalf("Write() returned n = %d, want %d (child must never see a short write)", n, len(chunk))
		}
		totalWritten += n
	}

	if len(b.data) != max {
		t.Fatalf("retained data length = %d, want exactly %d", len(b.data), max)
	}
	if cap(b.data) != max {
		t.Fatalf("retained data capacity = %d, want exactly %d (must not grow past the cap)", cap(b.data), max)
	}
	if !b.truncated {
		t.Fatal("truncated = false, want true after writing far beyond the cap")
	}
	if totalWritten <= max {
		t.Fatalf("totalWritten = %d, want > %d to actually exercise draining", totalWritten, max)
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

func TestRunCommand_Passthrough(t *testing.T) {
	t.Setenv("SYMVAULT_TEST_PASSTHROUGH_VAR", "from_parent")

	result, err := RunCommand(RunOptions{
		Command:     []string{"sh", "-c", "echo $SYMVAULT_TEST_PASSTHROUGH_VAR"},
		Passthrough: []string{"SYMVAULT_TEST_PASSTHROUGH_VAR"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "from_parent") {
		t.Errorf("expected passthrough env var 'from_parent' in stdout, got: %q", result.Stdout)
	}
}

func TestRunCommand_PassthroughMultiple(t *testing.T) {
	t.Setenv("SYMVAULT_TEST_PT_A", "alpha")
	t.Setenv("SYMVAULT_TEST_PT_B", "beta")

	result, err := RunCommand(RunOptions{
		Command:     []string{"sh", "-c", "echo $SYMVAULT_TEST_PT_A $SYMVAULT_TEST_PT_B"},
		Passthrough: []string{"SYMVAULT_TEST_PT_A", "SYMVAULT_TEST_PT_B"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "alpha beta") {
		t.Errorf("expected 'alpha beta' in stdout, got: %q", result.Stdout)
	}
}

func TestRunCommand_NonExitError(t *testing.T) {
	_, err := RunCommand(RunOptions{
		Command: []string{"symvault_nonexistent_command_xyz"},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent command, got nil")
	}
	if !strings.Contains(err.Error(), "failed to run command") {
		t.Errorf("expected 'failed to run command' in error, got: %q", err.Error())
	}
}

// --- Files (ephemeral file injection, issue #671) ---

func TestRunCommand_FileInjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on sh")
	}
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", `cat "$SYMVAULT_FILE_CERT"`},
		Files:   map[string]string{"CERT": "certificate-bytes"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "certificate-bytes") {
		t.Fatalf("Stdout = %q, want file content 'certificate-bytes'", result.Stdout)
	}
}

func TestRunCommand_FileInjection_RemovedAfterSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on sh")
	}
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", `echo "$SYMVAULT_FILE_CERT"`},
		Files:   map[string]string{"CERT": "x"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	path := strings.TrimSpace(result.Stdout)
	if path == "" {
		t.Fatal("SYMVAULT_FILE_CERT was empty")
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("SYMVAULT_FILE_CERT = %q, want absolute path", path)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("expected ephemeral file %q removed after RunCommand returns, stat err = %v", path, statErr)
	}
}

func TestRunCommand_FileInjection_RemovedAfterNonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on sh")
	}
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", `echo "$SYMVAULT_FILE_CERT"; exit 7`},
		Files:   map[string]string{"CERT": "x"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7", result.ExitCode)
	}
	path := strings.TrimSpace(result.Stdout)
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("expected ephemeral file removed after non-zero exit, stat err = %v", statErr)
	}
}

func TestRunCommand_FileInjection_RemovedAfterTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on sh")
	}
	result, err := RunCommand(RunOptions{
		// exec replaces the shell with sleep in-place (no forked grandchild),
		// so the context-timeout kill lands on the actual sleeping process and
		// its stdout/stderr pipes close immediately instead of staying open
		// until a forked "sh -c '...; sleep 10'" grandchild exits on its own.
		Command: []string{"sh", "-c", `echo "$SYMVAULT_FILE_CERT"; exec sleep 10`},
		Files:   map[string]string{"CERT": "x"},
		Timeout: 200 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error message does not mention timeout: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result on timeout")
	}
	path := strings.TrimSpace(result.Stdout)
	if path == "" {
		t.Fatal("expected the child to have printed the file path before being killed")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("expected ephemeral file removed after timeout kill, stat err = %v", statErr)
	}
}

func TestMaterializeFiles_Empty(t *testing.T) {
	env, cleanup, err := materializeFiles(nil)
	if err != nil {
		t.Fatalf("materializeFiles(nil) error = %v", err)
	}
	if len(env) != 0 {
		t.Fatalf("env = %v, want empty", env)
	}
	cleanup() // must not panic on a no-op cleanup
}

func TestMaterializeFiles_InvalidName(t *testing.T) {
	for _, name := range []string{"", "../etc/passwd", "a/b", "a b", "a.b", "a$b"} {
		if _, _, err := materializeFiles(map[string]string{name: "x"}); err == nil {
			t.Errorf("materializeFiles(%q) expected error, got nil", name)
		}
	}
}

func TestMaterializeFiles_WritesAndCleansUp(t *testing.T) {
	env, cleanup, err := materializeFiles(map[string]string{"CERT": "hello"})
	if err != nil {
		t.Fatalf("materializeFiles() error = %v", err)
	}
	path := env["SYMVAULT_FILE_CERT"]
	if path == "" {
		t.Fatal("env[SYMVAULT_FILE_CERT] is empty")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile(%q): %v", path, readErr)
	}
	if string(data) != "hello" {
		t.Fatalf("content = %q, want %q", data, "hello")
	}

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("Stat(%q): %v", path, statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", info.Mode().Perm())
		}
	}

	cleanup()
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("expected file removed after cleanup, stat err = %v", statErr)
	}
}

func TestMaterializeFiles_BinaryContentPreserved(t *testing.T) {
	content := string([]byte{0x00, 0xFF, 0x10, 0x89, 0x50, 0x4E, 0x47})
	env, cleanup, err := materializeFiles(map[string]string{"BIN": content})
	if err != nil {
		t.Fatalf("materializeFiles() error = %v", err)
	}
	defer cleanup()

	data, readErr := os.ReadFile(env["SYMVAULT_FILE_BIN"])
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(data) != content {
		t.Fatalf("content mismatch: got %d bytes, want %d bytes", len(data), len(content))
	}
}

func TestRunCommand_RejectsSensitivePassthrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on sh")
	}
	t.Setenv("MY_APP_PASSPHRASE", "should_never_reach_child")

	result, err := RunCommand(RunOptions{
		Command:     []string{"sh", "-c", "echo VAL=[$MY_APP_PASSPHRASE]"},
		Passthrough: []string{"MY_APP_PASSPHRASE"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if strings.Contains(result.Stdout, "should_never_reach_child") {
		t.Fatalf("sensitive passthrough var leaked to child: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "VAL=[]") {
		t.Fatalf("expected empty var in child, got: %q", result.Stdout)
	}
	if !contains(result.RejectedEnvVars, "MY_APP_PASSPHRASE") {
		t.Errorf("RejectedEnvVars = %v, want MY_APP_PASSPHRASE", result.RejectedEnvVars)
	}
}

// TestRunCommand_OptsEnvSensitiveNamesStillDelivered proves opts.Env is
// never subject to the sensitive-name reject: it is caller-supplied,
// already-resolved data (e.g. a vault secret execute_with_secret injects
// under a name like AWS_SECRET_ACCESS_KEY), not an ambient parent-env
// forward. Rejecting it by name would silently break that feature for any
// secret whose generated env var name contains KEY/SECRET/TOKEN/PASSWORD —
// which is the common case.
func TestRunCommand_OptsEnvSensitiveNamesStillDelivered(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on sh")
	}
	result, err := RunCommand(RunOptions{
		Command: []string{"sh", "-c", "echo VAL=[$API_TOKEN]"},
		Env:     map[string]string{"API_TOKEN": "resolved_secret_value"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "VAL=[resolved_secret_value]") {
		t.Fatalf("expected opts.Env value to reach child regardless of sensitive-looking name, got: %q", result.Stdout)
	}
	if len(result.RejectedEnvVars) != 0 {
		t.Errorf("RejectedEnvVars = %v, want none (opts.Env is never rejected by name)", result.RejectedEnvVars)
	}
}

func TestRunCommand_NonSensitiveEnvAndPassthroughStillWork(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: relies on sh")
	}
	t.Setenv("MY_CUSTOM_FLAG", "on")

	result, err := RunCommand(RunOptions{
		Command:     []string{"sh", "-c", "echo A=[$MY_CUSTOM_FLAG] B=[$OTHER_VAR]"},
		Passthrough: []string{"MY_CUSTOM_FLAG"},
		Env:         map[string]string{"OTHER_VAR": "plain_value"},
	})
	if err != nil {
		t.Fatalf("RunCommand() unexpected error: %v", err)
	}
	if !strings.Contains(result.Stdout, "A=[on]") {
		t.Errorf("expected MY_CUSTOM_FLAG to pass through, got: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "B=[plain_value]") {
		t.Errorf("expected OTHER_VAR to pass through, got: %q", result.Stdout)
	}
	if len(result.RejectedEnvVars) != 0 {
		t.Errorf("RejectedEnvVars = %v, want none", result.RejectedEnvVars)
	}
}
