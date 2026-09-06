package diff

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestRunAndCompareIdenticalHelper(t *testing.T) {
	if os.Getenv("SYMVAULT_PORT_HELPER") == "1" {
		helperProcess()
		return
	}
	caseSpec := Case{
		ID:           "helper",
		Args:         []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:          map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_OUTPUT": "${WORKSPACE}/out.txt"},
		CompareFiles: true,
	}
	left, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(caseSpec, left, right); err != nil {
		t.Fatal(err)
	}
}

func TestCompareDetectsStreamMismatchWithoutLeakingContent(t *testing.T) {
	testCase := Case{ID: "mismatch"}
	err := Compare(testCase, Result{Stdout: []byte("secret-left")}, Result{Stdout: []byte("secret-right")})
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if got := err.Error(); contains(got, "secret-left") || contains(got, "secret-right") {
		t.Fatalf("mismatch exposed stream content: %s", got)
	}
}

func TestRunTimesOutAndTerminatesProcess(t *testing.T) {
	caseSpec := Case{
		ID:        "timeout",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": "hang"},
		TimeoutMS: 50,
	}
	result, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut {
		t.Fatal("expected process timeout")
	}
}

func TestCommandTimedOutRequiresEffectiveTreeCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	for _, test := range []struct {
		name      string
		effective bool
		want      bool
	}{
		{name: "natural success", effective: false, want: false},
		{name: "natural nonzero exit", effective: false, want: false},
		{name: "effective kill", effective: true, want: true},
		{name: "active lingering descendant", effective: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := commandTimedOut(ctx, test.effective); got != test.want {
				t.Fatalf("commandTimedOut(effective=%t) = %t, want %t", test.effective, got, test.want)
			}
		})
	}
}

func TestClassifyWaitErrorPreservesWaitDelayWithoutTimeout(t *testing.T) {
	err := classifyWaitError(exec.ErrWaitDelay, false, false, false, false, false)
	if err == nil {
		t.Fatal("non-timeout ErrWaitDelay was suppressed")
	}
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("error = %v, want ErrWaitDelay", err)
	}
}

func TestRunNormalExit(t *testing.T) {
	result, err := Run(os.Args[0], Case{
		ID:        "normal-exit",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_OUTPUT": "${WORKSPACE}/out.txt"},
		TimeoutMS: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TimedOut {
		t.Fatal("normal process was marked timed out")
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}
	if got := string(result.Stdout); got != "ok\nPASS\n" {
		t.Fatalf("stdout = %q, want helper output", got)
	}
}

func TestRunNaturalNonzeroExitIsNotTimedOut(t *testing.T) {
	result, err := Run(os.Args[0], Case{
		ID:        "natural-nonzero-exit",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": "exit-nonzero"},
		TimeoutMS: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TimedOut {
		t.Fatal("natural nonzero exit was marked timed out")
	}
	if result.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", result.ExitCode)
	}
}

func TestRunDeadlineWithoutEffectiveTreeCancellationPreservesNaturalExit(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     string
		exitCode int
	}{
		{name: "success", mode: "delayed-success", exitCode: 0},
		{name: "nonzero", mode: "delayed-nonzero", exitCode: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			originalFactory := processTreeFactory
			var fakeTree *timeoutTestProcessTree
			processTreeFactory = func(cmd *exec.Cmd) (processTree, error) {
				fakeTree = &timeoutTestProcessTree{cmd: cmd}
				return fakeTree, nil
			}
			t.Cleanup(func() { processTreeFactory = originalFactory })

			result, err := Run(os.Args[0], Case{
				ID:        "deadline-natural-" + test.name,
				Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
				Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": test.mode},
				TimeoutMS: 50,
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.TimedOut {
				t.Fatal("natural exit after ineffective cancellation was marked timed out")
			}
			if result.ExitCode != test.exitCode {
				t.Fatalf("exit code = %d, want %d", result.ExitCode, test.exitCode)
			}
			if fakeTree == nil || fakeTree.killCalls != 1 {
				t.Fatalf("tree.Kill calls = %d, want 1", fakeTree.killCalls)
			}
		})
	}
}

func TestRunTimeoutWaitsForInheritedPipeCleanup(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "child.pid")
	stopPath := filepath.Join(t.TempDir(), "stop")
	donePath := filepath.Join(t.TempDir(), "done")
	originalFactory := processTreeFactory
	var fakeTree *timeoutTestProcessTree
	processTreeFactory = func(cmd *exec.Cmd) (processTree, error) {
		// Leave the controlled descendant alive so this test exercises
		// os/exec's pipe-copy timeout rather than process-tree termination.
		fakeTree = &timeoutTestProcessTree{cmd: cmd, killEffective: true}
		return fakeTree, nil
	}
	stopDescendant := func() {
		_ = os.WriteFile(stopPath, []byte("stop\n"), 0o600)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(donePath); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		if pidBytes, err := os.ReadFile(pidPath); err == nil {
			if pid, parseErr := strconv.Atoi(string(pidBytes)); parseErr == nil {
				if process, findErr := os.FindProcess(pid); findErr == nil {
					_ = process.Kill()
				}
			}
		}
		t.Errorf("controlled descendant did not acknowledge cleanup")
	}
	t.Cleanup(func() {
		stopDescendant()
		processTreeFactory = originalFactory
	})

	started := time.Now()
	result, err := Run(os.Args[0], Case{
		ID:   "timeout-inherited-pipes",
		Args: []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env: map[string]string{
			"SYMVAULT_PORT_HELPER": "1",
			"PORT_HELPER_MODE":     "pipe-leak",
			"PORT_CHILD_PID":       pidPath,
			"PORT_CHILD_STOP":      stopPath,
			"PORT_CHILD_DONE":      donePath,
		},
		TimeoutMS: 100,
	})
	if elapsed := time.Since(started); elapsed > processWaitDelay+time.Second {
		t.Fatalf("Run exceeded timeout+WaitDelay bound: %s", elapsed)
	}
	if err != nil {
		t.Fatalf("bounded inherited-pipe cleanup: %v", err)
	}
	if !result.TimedOut {
		t.Fatal("expected process timeout")
	}
	if fakeTree == nil {
		t.Fatal("process-tree factory was not called")
	}
	if fakeTree.killCalls != 1 {
		t.Fatalf("process-tree cleanup calls = %d, want 1", fakeTree.killCalls)
	}
	pidBytes, readErr := os.ReadFile(pidPath)
	if readErr != nil {
		t.Fatalf("read controlled descendant PID: %v", readErr)
	}
	if _, parseErr := strconv.Atoi(string(pidBytes)); parseErr != nil {
		t.Fatalf("parse controlled descendant PID %q: %v", string(pidBytes), parseErr)
	}
	stopDescendant()
}

func TestRunPreservesWaitDelayWhenTreeIsAlreadyGone(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "child.pid")
	stopPath := filepath.Join(t.TempDir(), "stop")
	donePath := filepath.Join(t.TempDir(), "done")
	originalFactory := processTreeFactory
	var fakeTree *timeoutTestProcessTree
	processTreeFactory = func(cmd *exec.Cmd) (processTree, error) {
		fakeTree = &timeoutTestProcessTree{cmd: cmd}
		return fakeTree, nil
	}
	stopDescendant := func() {
		_ = os.WriteFile(stopPath, []byte("stop\n"), 0o600)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(donePath); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		if pidBytes, err := os.ReadFile(pidPath); err == nil {
			if pid, parseErr := strconv.Atoi(string(pidBytes)); parseErr == nil {
				if process, findErr := os.FindProcess(pid); findErr == nil {
					_ = process.Kill()
				}
			}
		}
		t.Errorf("controlled descendant did not acknowledge cleanup")
	}
	t.Cleanup(func() {
		stopDescendant()
		processTreeFactory = originalFactory
	})

	started := time.Now()
	_, err := Run(os.Args[0], Case{
		ID:   "natural-exit-inherited-pipes",
		Args: []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env: map[string]string{
			"SYMVAULT_PORT_HELPER": "1",
			"PORT_HELPER_MODE":     "pipe-leak-natural",
			"PORT_CHILD_PID":       pidPath,
			"PORT_CHILD_STOP":      stopPath,
			"PORT_CHILD_DONE":      donePath,
		},
		TimeoutMS: 100,
	})
	if elapsed := time.Since(started); elapsed > processWaitDelay+time.Second {
		t.Fatalf("Run exceeded timeout+WaitDelay bound: %s", elapsed)
	}
	if err == nil || !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("wait-delay error = %v, want ErrWaitDelay", err)
	}
	if fakeTree == nil {
		t.Fatal("process-tree factory was not called")
	}
	if fakeTree.killCalls > 1 {
		t.Fatalf("process-tree cleanup calls = %d, want at most 1", fakeTree.killCalls)
	}
	stopDescendant()
}

func TestRunTimeoutPreservesTreeAndCloseErrorsAfterWaitDelay(t *testing.T) {
	treeErr := errors.New("job termination failed")
	closeErr := errors.New("job close failed")
	originalFactory := processTreeFactory
	var fakeTree *timeoutTestProcessTree
	processTreeFactory = func(cmd *exec.Cmd) (processTree, error) {
		// Return an error without terminating the process. CommandContext's
		// WaitDelay fallback must still kill it and let the synchronous Wait end.
		fakeTree = &timeoutTestProcessTree{cmd: cmd, killEffective: true, killErr: treeErr, closeErr: closeErr}
		return fakeTree, nil
	}
	t.Cleanup(func() { processTreeFactory = originalFactory })

	started := time.Now()
	_, err := Run(os.Args[0], Case{
		ID:        "timeout-cleanup-errors",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": "hang"},
		TimeoutMS: 20,
	})
	if elapsed := time.Since(started); elapsed > processWaitDelay+time.Second {
		t.Fatalf("WaitDelay fallback exceeded bound: %s", elapsed)
	}
	if err == nil {
		t.Fatal("expected timeout cleanup errors")
	}
	if !errors.Is(err, treeErr) {
		t.Fatalf("timeout error did not preserve tree termination error: %v", err)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("timeout error did not preserve tree close error: %v", err)
	}
	if fakeTree.killCalls != 1 {
		t.Fatalf("tree.Kill calls = %d, want 1", fakeTree.killCalls)
	}
}

type timeoutTestProcessTree struct {
	cmd           *exec.Cmd
	assignErr     error
	killErr       error
	closeErr      error
	killEffective bool
	killProcess   bool
	killCalls     int
}

func (t *timeoutTestProcessTree) Assign() error { return t.assignErr }
func (t *timeoutTestProcessTree) Kill() (bool, error) {
	t.killCalls++
	if t.killProcess {
		return true, t.cmd.Process.Kill()
	}
	return t.killEffective, t.killErr
}
func (t *timeoutTestProcessTree) Close() error { return t.closeErr }

func TestRunAssignmentFailureCleansUpSynchronously(t *testing.T) {
	assignErr := errors.New("job assignment failed")
	originalFactory := processTreeFactory
	var fakeTree *timeoutTestProcessTree
	processTreeFactory = func(cmd *exec.Cmd) (processTree, error) {
		// Simulate a tree operation that cannot see the unassigned process;
		// Run must fall back to command.Process.Kill immediately.
		fakeTree = &timeoutTestProcessTree{cmd: cmd, assignErr: assignErr}
		return fakeTree, nil
	}
	t.Cleanup(func() { processTreeFactory = originalFactory })

	started := time.Now()
	_, err := Run(os.Args[0], Case{
		ID:        "assignment-failure",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": "hang"},
		TimeoutMS: 5 * 1000,
	})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("assignment cleanup did not directly kill the suspended child: %s", elapsed)
	}
	if err == nil || !errors.Is(err, assignErr) {
		t.Fatalf("assignment failure = %v, want %v", err, assignErr)
	}
	if fakeTree == nil || fakeTree.killCalls != 1 {
		t.Fatalf("tree.Kill calls = %d, want 1", fakeTree.killCalls)
	}
}

func TestRunCapturesSideEffectsOutsideWorkspace(t *testing.T) {
	caseSpec := Case{
		ID:   "home-side-effect",
		Args: []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:  map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_OUTPUT": "${HOME}/out.txt"},
	}
	result, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Files {
		if entry.Path == "home/out.txt" && entry.Type == "file" {
			return
		}
	}
	t.Fatalf("HOME side effect missing from sandbox manifest: %#v", result.Files)
}

func TestConsoleComparisonNormalizesRootsAndCRLF(t *testing.T) {
	testCase := Case{StdoutMode: "console_text"}
	left := Result{Stdout: []byte("path=/tmp/left/file\r\n"), SandboxRoot: "/tmp/left"}
	right := Result{Stdout: []byte("path=/tmp/right/file\n"), SandboxRoot: "/tmp/right"}
	if err := Compare(testCase, left, right); err != nil {
		t.Fatal(err)
	}
}

func TestBuildManifestIsDeterministicAndDetectsContent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "entry"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("manifest is not deterministic: %#v != %#v", first, second)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "entry"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first, changed) {
		t.Fatal("manifest did not detect content change")
	}
}

func TestSafeWorkspacePathRejectsEscape(t *testing.T) {
	if _, err := safeWorkspacePath(t.TempDir(), "../escape"); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestIsolatedEnvRejectsSandboxAndKeyringOverrides(t *testing.T) {
	replacements := map[string]string{"${HOME}": "/isolated/home"}
	for _, key := range []string{"HOME", "xdg_data_home", "TMPDIR", "SYMVAULT_TEST_KEYRING", "SYMVAULT_SECUREUI"} {
		_, err := isolatedEnv("/isolated/home", "/isolated/tmp", "/isolated/runtime", "/isolated/state", map[string]string{key: "host-value"}, replacements)
		if err == nil {
			t.Fatalf("expected override %q to be rejected", key)
		}
	}
}

func helperProcess() {
	switch os.Getenv("PORT_HELPER_MODE") {
	case "hang":
		time.Sleep(30 * time.Second)
		return
	case "exit-nonzero":
		os.Exit(7)
	case "delayed-success":
		time.Sleep(200 * time.Millisecond)
		return
	case "delayed-nonzero":
		time.Sleep(200 * time.Millisecond)
		os.Exit(7)
	case "pipe-leak":
		child := exec.Command(os.Args[0], "-test.run=TestRunAndCompareIdenticalHelper")
		child.Env = append(os.Environ(), "SYMVAULT_PORT_HELPER=1", "PORT_HELPER_MODE=hold-pipes")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("PORT_CHILD_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			os.Exit(3)
		}
		for {
			time.Sleep(5 * time.Millisecond)
		}
	case "pipe-leak-natural":
		child := exec.Command(os.Args[0], "-test.run=TestRunAndCompareIdenticalHelper")
		child.Env = append(os.Environ(), "SYMVAULT_PORT_HELPER=1", "PORT_HELPER_MODE=hold-pipes")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("PORT_CHILD_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			os.Exit(3)
		}
		return
	case "hold-pipes":
		for {
			if _, err := os.Stat(os.Getenv("PORT_CHILD_STOP")); err == nil {
				_ = os.WriteFile(os.Getenv("PORT_CHILD_DONE"), []byte("done\n"), 0o600)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	case "child":
		child := exec.Command(os.Args[0], "-test.run=TestRunAndCompareIdenticalHelper")
		child.Env = append(os.Environ(), "SYMVAULT_PORT_HELPER=1", "PORT_HELPER_MODE=hang")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintf(os.Stdout, "%d\n", child.Process.Pid)
		_ = child.Wait()
		return
	}
	path := os.Getenv("PORT_OUTPUT")
	_ = os.WriteFile(path, []byte("deterministic\n"), 0o600)
	_, _ = os.Stdout.WriteString("ok\n")
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
