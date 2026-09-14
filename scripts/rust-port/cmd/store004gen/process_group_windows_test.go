//go:build windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const windowsStillActive = 259

func TestWindowsProcessGroupKillsDescendants(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "descendant.pid")
	cmd := exec.Command(os.Args[0], "-test.run=TestWindowsProcessGroupHelper")
	cmd.Env = append(os.Environ(), "STORE004_HELPER=1", "STORE004_READY="+ready)
	configureProcessGroup(cmd)
	if err := startProcessGroup(cmd); err != nil {
		t.Fatal(err)
	}
	defer closeProcessGroup(cmd)

	var childPID uint32
	deadline := time.Now().Add(5 * time.Second)
	for childPID == 0 && time.Now().Before(deadline) {
		data, err := os.ReadFile(ready)
		if err == nil {
			childPID64, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			childPID = uint32(childPID64)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		t.Fatal("helper did not publish descendant PID")
	}
	if killed, err := killProcessGroup(cmd); err != nil || !killed {
		t.Fatalf("killProcessGroup() = (%v, %v), want (true, nil)", killed, err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("group leader unexpectedly exited successfully")
	}
	waitForWindowsProcessGone(t, childPID)
}

func TestWindowsProcessGroupHelper(t *testing.T) {
	if os.Getenv("STORE004_HELPER") != "1" {
		return
	}
	if os.Getenv("STORE004_CHILD") == "1" {
		for {
			time.Sleep(time.Minute)
		}
	}
	child := exec.Command(os.Args[0], "-test.run=TestWindowsProcessGroupHelper")
	child.Env = append(os.Environ(), "STORE004_HELPER=1", "STORE004_CHILD=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("STORE004_READY"), []byte(fmt.Sprint(child.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
}

func waitForWindowsProcessGone(t *testing.T, pid uint32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				return // Windows reports this for a PID that no longer exists.
			}
			t.Fatalf("cannot establish descendant PID %d state: %v", pid, err)
		}
		var code uint32
		err = windows.GetExitCodeProcess(handle, &code)
		_ = windows.CloseHandle(handle)
		if err != nil {
			t.Fatalf("cannot read descendant PID %d exit code: %v", pid, err)
		}
		if code != windowsStillActive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("descendant PID %d remained active after job termination", pid)
}

func TestWindowsAssignmentFailureReapsSuspendedProcess(t *testing.T) {
	original := assignProcessToJobObject
	assignProcessToJobObject = func(windows.Handle, windows.Handle) error { return windows.ERROR_ACCESS_DENIED }
	t.Cleanup(func() { assignProcessToJobObject = original })
	cmd := exec.Command(os.Args[0], "-test.run=TestWindowsProcessGroupHelper")
	cmd.Env = append(os.Environ(), "STORE004_HELPER=1", "STORE004_CHILD=1")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := startProcessGroup(cmd); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("assignment failure = %v", err)
	}
	if cmd.Process == nil || cmd.ProcessState == nil {
		t.Fatal("started suspended process was not reaped")
	}
	waitForWindowsProcessGone(t, uint32(cmd.Process.Pid))
	if _, found := windowsProcessGroups.Load(cmd); found {
		t.Fatal("failed assignment retained a job entry")
	}
}

func TestWindowsProcessGroupCloseFailureIsRetryable(t *testing.T) {
	group := &windowsProcessGroup{job: windows.Handle(1)}
	cmd := &exec.Cmd{}
	windowsProcessGroups.Store(cmd, group)
	original := closeWindowsHandle
	calls := 0
	closeWindowsHandle = func(windows.Handle) error {
		calls++
		if calls == 1 {
			return windows.ERROR_ACCESS_DENIED
		}
		return nil
	}
	t.Cleanup(func() {
		closeWindowsHandle = original
		windowsProcessGroups.Delete(cmd)
	})

	if err := closeProcessGroup(cmd); err == nil {
		t.Fatal("first close unexpectedly succeeded")
	}
	if _, ok := windowsProcessGroups.Load(cmd); !ok {
		t.Fatal("failed close removed retryable job entry")
	}
	if err := closeProcessGroup(cmd); err != nil {
		t.Fatalf("retry close failed: %v", err)
	}
	if _, ok := windowsProcessGroups.Load(cmd); ok {
		t.Fatal("successful retry retained closed job entry")
	}
	if group.job != 0 {
		t.Fatal("successful close did not clear owned handle")
	}
}

func TestWindowsSetupFailureRetainsJobWhenCloseFails(t *testing.T) {
	originalCreate := createJobObject
	originalSet := setInformationJobObject
	originalClose := closeWindowsHandle
	createJobObject = func(*windows.SecurityAttributes, *uint16) (windows.Handle, error) {
		return windows.Handle(1), nil
	}
	setInformationJobObject = func(windows.Handle, uint32, uintptr, uint32) (int, error) {
		return 0, windows.ERROR_INVALID_FUNCTION
	}
	calls := 0
	closeWindowsHandle = func(windows.Handle) error {
		calls++
		if calls == 1 {
			return windows.ERROR_ACCESS_DENIED
		}
		return nil
	}
	t.Cleanup(func() {
		createJobObject = originalCreate
		setInformationJobObject = originalSet
		closeWindowsHandle = originalClose
	})

	cmd := &exec.Cmd{}
	err := startProcessGroup(cmd)
	if !errors.Is(err, windows.ERROR_INVALID_FUNCTION) || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("setup failure = %v, want configuration and close errors", err)
	}
	if _, ok := windowsProcessGroups.Load(cmd); !ok {
		t.Fatal("configuration failure lost retryable job ownership")
	}
	if err := closeProcessGroup(cmd); err != nil {
		t.Fatalf("retry close failed: %v", err)
	}
	if _, ok := windowsProcessGroups.Load(cmd); ok {
		t.Fatal("successful retry retained closed job entry")
	}
}

func TestWindowsStartFailureRetainsJobWhenCloseFails(t *testing.T) {
	originalCreate := createJobObject
	originalSet := setInformationJobObject
	originalClose := closeWindowsHandle
	createJobObject = func(*windows.SecurityAttributes, *uint16) (windows.Handle, error) {
		return windows.Handle(1), nil
	}
	setInformationJobObject = func(windows.Handle, uint32, uintptr, uint32) (int, error) {
		return 0, nil
	}
	calls := 0
	closeWindowsHandle = func(windows.Handle) error {
		calls++
		if calls == 1 {
			return windows.ERROR_ACCESS_DENIED
		}
		return nil
	}
	t.Cleanup(func() {
		createJobObject = originalCreate
		setInformationJobObject = originalSet
		closeWindowsHandle = originalClose
	})

	cmd := exec.Command(filepath.Join(t.TempDir(), "missing-oracle"))
	err := startProcessGroup(cmd)
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("start failure = %v, want start and close errors", err)
	}
	if _, ok := windowsProcessGroups.Load(cmd); !ok {
		t.Fatal("start failure lost retryable job ownership")
	}
	if err := closeProcessGroup(cmd); err != nil {
		t.Fatalf("retry close failed: %v", err)
	}
	if _, ok := windowsProcessGroups.Load(cmd); ok {
		t.Fatal("successful retry retained closed job entry")
	}
}

func TestWindowsAssignmentFailureCloseFailureIsRetryable(t *testing.T) {
	originalAssign := assignProcessToJobObject
	originalClose := closeWindowsHandle
	assignProcessToJobObject = func(windows.Handle, windows.Handle) error { return windows.ERROR_ACCESS_DENIED }
	calls := 0
	closeWindowsHandle = func(windows.Handle) error {
		calls++
		if calls == 1 {
			return windows.ERROR_SHARING_VIOLATION
		}
		return nil
	}
	t.Cleanup(func() {
		assignProcessToJobObject = originalAssign
		closeWindowsHandle = originalClose
	})

	cmd := exec.Command(os.Args[0], "-test.run=TestWindowsProcessGroupHelper")
	cmd.Env = append(os.Environ(), "STORE004_HELPER=1", "STORE004_CHILD=1")
	err := startProcessGroup(cmd)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("assignment failure = %v, want assignment and close errors", err)
	}
	if cmd.ProcessState == nil {
		t.Fatal("assignment failure did not reap started process")
	}
	if _, ok := windowsProcessGroups.Load(cmd); !ok {
		t.Fatal("assignment failure lost retryable job ownership")
	}
	// The injected close has served its purpose; the real job handle is still owned.
	closeWindowsHandle = originalClose
	if err := closeProcessGroup(cmd); err != nil {
		t.Fatalf("retry close failed: %v", err)
	}
	if _, ok := windowsProcessGroups.Load(cmd); ok {
		t.Fatal("successful retry retained closed job entry")
	}
}

func TestWindowsKillProcessGroupHandlesClosedJobRace(t *testing.T) {
	cmd := &exec.Cmd{}
	group := &windowsProcessGroup{}
	windowsProcessGroups.Store(cmd, group)
	t.Cleanup(func() { windowsProcessGroups.Delete(cmd) })
	if killed, err := killProcessGroup(cmd); killed || err != nil {
		t.Fatalf("killProcessGroup() = (%v, %v), want (false, nil)", killed, err)
	}
	if _, ok := windowsProcessGroups.Load(cmd); ok {
		t.Fatal("zero-handle group remained registered")
	}
}
