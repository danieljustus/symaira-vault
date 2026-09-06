//go:build windows

package diff

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestRunTimeoutKillsDescendantJobObject(t *testing.T) {
	caseSpec := Case{
		ID:   "timeout-child-windows",
		Args: []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env: map[string]string{
			"SYMVAULT_PORT_HELPER": "1",
			"PORT_HELPER_MODE":     "child",
		},
		TimeoutMS: 500,
	}
	result, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut {
		t.Fatal("expected process timeout")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(result.Stdout)))
	if err != nil {
		t.Fatalf("parse helper child PID from %q: %v", string(result.Stdout), err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		hProc, openErr := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
			false,
			uint32(pid),
		)
		if openErr != nil {
			// Process handle cannot be opened; process has exited and terminated.
			return
		}
		event, waitErr := windows.WaitForSingleObject(hProc, 0)
		_ = windows.CloseHandle(hProc)
		if waitErr == nil && event == windows.WAIT_OBJECT_0 {
			// Process has terminated.
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant process %d survived job object termination", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunAssignmentFailureKillsUnassignedSuspendedProcess(t *testing.T) {
	originalFactory := processTreeFactory
	processTreeFactory = func(cmd *exec.Cmd) (processTree, error) {
		tree, err := newProcessTree(cmd)
		if err != nil {
			return nil, err
		}
		nativeTree := tree.(*windowsProcessTree)
		if err := windows.CloseHandle(nativeTree.job); err != nil {
			return nil, fmt.Errorf("close test job handle: %w", err)
		}
		nativeTree.job = 0
		return nativeTree, nil
	}
	t.Cleanup(func() { processTreeFactory = originalFactory })

	started := time.Now()
	_, err := Run(os.Args[0], Case{
		ID:        "assignment-failure-windows-native",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": "hang"},
		TimeoutMS: 5000,
	})
	if elapsed := time.Since(started); elapsed > processWaitDelay+time.Second {
		t.Fatalf("native assignment cleanup exceeded WaitDelay bound: %s; error: %v", elapsed, err)
	}
	if err == nil || !strings.Contains(err.Error(), "assign process to tree") {
		t.Fatalf("assignment failure = %v, want native assignment error", err)
	}
}

func TestWindowsProcessTreeLifecycleAndErrors(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	existingSysProcAttr := &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	cmd.SysProcAttr = existingSysProcAttr
	tree, err := newProcessTree(cmd)
	if err != nil {
		t.Fatalf("newProcessTree: %v", err)
	}
	started := false
	t.Cleanup(func() {
		if started {
			_, _ = tree.Kill()
			_ = cmd.Wait()
		}
		if closeErr := tree.Close(); closeErr != nil {
			t.Errorf("tree.Close cleanup: %v", closeErr)
		}
	})

	if cmd.SysProcAttr != existingSysProcAttr {
		t.Fatal("newProcessTree replaced the existing SysProcAttr")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Fatal("newProcessTree dropped the existing creation flags")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_SUSPENDED == 0 {
		t.Fatal("newProcessTree did not request suspended process creation")
	}

	// Assigning before Start (when cmd.Process == nil) must fail.
	if err := tree.Assign(); err == nil {
		t.Fatal("expected error assigning nil process")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	started = true

	if err := tree.Assign(); err != nil {
		t.Fatalf("tree.Assign: %v", err)
	}
	if err := tree.Assign(); err == nil {
		t.Fatal("expected error assigning an already-assigned process tree")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cmd.Wait: %v", err)
	}
	started = false

	if err := tree.Close(); err != nil {
		t.Fatalf("tree.Close: %v", err)
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("second tree.Close: %v", err)
	}
	if err := tree.Assign(); err == nil {
		t.Fatal("expected error assigning after close")
	}
}

func TestWindowsProcessTreeKillReportsActiveJob(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "ping 127.0.0.1 -n 30 >NUL")
	tree, err := newProcessTree(cmd)
	if err != nil {
		t.Fatalf("newProcessTree: %v", err)
	}
	started := false
	t.Cleanup(func() {
		if started {
			_, _ = tree.Kill()
			_ = cmd.Wait()
		}
		_ = tree.Close()
	})
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	started = true
	if err := tree.Assign(); err != nil {
		t.Fatalf("tree.Assign: %v", err)
	}

	effective, err := tree.Kill()
	if err != nil {
		t.Fatalf("tree.Kill: %v", err)
	}
	if !effective {
		t.Fatal("tree.Kill reported no effective termination for active job")
	}
	_ = cmd.Wait()
	started = false
}

func TestWindowsProcessTreeKillReportsEmptyJob(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	tree, err := newProcessTree(cmd)
	if err != nil {
		t.Fatalf("newProcessTree: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	if err := tree.Assign(); err != nil {
		t.Fatalf("tree.Assign: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cmd.Wait: %v", err)
	}

	effective, err := tree.Kill()
	if err != nil {
		t.Fatalf("tree.Kill: %v", err)
	}
	if effective {
		t.Fatal("tree.Kill reported effective termination for an empty job")
	}
}

func TestWindowsClassifyAlreadyGoneWaitDelayEINVAL(t *testing.T) {
	waitErr := fmt.Errorf("exec: killing Cmd: %w", syscall.EINVAL)
	err := classifyWaitError(waitErr, false, true, true, true, true)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("already-gone wait error = %v, want ErrWaitDelay", err)
	}
	if errors.Is(err, syscall.EINVAL) {
		t.Fatalf("already-gone wait error retained EINVAL: %v", err)
	}

	for _, test := range []struct {
		name                        string
		deadlineExceeded            bool
		treeCancellationIneffective bool
		processExited               bool
		waitErr                     error
	}{
		{name: "no deadline", deadlineExceeded: false, treeCancellationIneffective: true, processExited: true, waitErr: waitErr},
		{name: "effective tree cancellation", deadlineExceeded: true, treeCancellationIneffective: false, processExited: true, waitErr: waitErr},
		{name: "live process", deadlineExceeded: true, treeCancellationIneffective: true, processExited: false, waitErr: waitErr},
		{name: "different EINVAL source", deadlineExceeded: true, treeCancellationIneffective: true, processExited: true, waitErr: fmt.Errorf("wait for process: %w", syscall.EINVAL)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := classifyWaitError(test.waitErr, false, test.processExited, test.deadlineExceeded, test.treeCancellationIneffective, test.processExited)
			if err == nil || !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("error = %v, want preserved EINVAL", err)
			}
			if errors.Is(err, exec.ErrWaitDelay) {
				t.Fatalf("error = %v, unexpectedly classified as ErrWaitDelay", err)
			}
		})
	}
}
