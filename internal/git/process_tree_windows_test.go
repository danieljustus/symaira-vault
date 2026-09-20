//go:build windows

package git

import (
	"context"
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

const (
	fakeGitEnv       = "SYMVAULT_GIT_TIMEOUT_FAKE"
	helperEnv        = "SYMVAULT_GIT_TIMEOUT_HELPER"
	helperModeEnv    = "SYMVAULT_GIT_TIMEOUT_HELPER_MODE"
	rootPIDEnv       = "SYMVAULT_GIT_TIMEOUT_ROOT_PID_FILE"
	childPIDEnv      = "SYMVAULT_GIT_TIMEOUT_CHILD_PID_FILE"
	grandchildPIDEnv = "SYMVAULT_GIT_TIMEOUT_GRANDCHILD_PID_FILE"
	readyEnv         = "SYMVAULT_GIT_TIMEOUT_READY_FILE"
	sourceBinaryEnv  = "SYMVAULT_GIT_TIMEOUT_SOURCE_BINARY"
)

const (
	fixtureStartupTimeout = 5 * time.Second
	fixtureCleanupTimeout = 5 * time.Second
)

func init() {
	if os.Getenv(fakeGitEnv) != "1" || os.Getenv(helperEnv) != "1" {
		return
	}

	switch os.Getenv(helperModeEnv) {
	case "root":
		writeFixturePID(rootPIDEnv)
		startFixtureChild("child")
	case "child":
		writeFixturePID(childPIDEnv)
		startFixtureChild("grandchild")
	case "grandchild":
		writeFixturePID(grandchildPIDEnv)
		if err := os.WriteFile(os.Getenv(readyEnv), []byte("ready\n"), 0o600); err != nil {
			fixtureFatal("publish fixture readiness", err)
		}
	default:
		fixtureFatal("unknown fixture mode", errors.New("missing helper mode"))
	}

	waitForFixtureKill()
}

func startFixtureChild(mode string) {
	child := exec.Command(os.Getenv(sourceBinaryEnv), "-test.run=TestGitPushTimeoutDescendantHelper")
	child.Env = appendEnv(os.Environ(), map[string]string{
		fakeGitEnv:    "1",
		helperEnv:     "1",
		helperModeEnv: mode,
	})
	if err := child.Start(); err != nil {
		fixtureFatal("start timeout fixture child", err)
	}
}

func writeFixturePID(envName string) {
	if err := os.WriteFile(os.Getenv(envName), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		fixtureFatal("publish fixture PID", err)
	}
}

func fixtureFatal(message string, err error) {
	fmt.Fprintln(os.Stderr, message+":", err)
	os.Exit(1)
}

func waitForFixtureKill() {
	for {
		time.Sleep(time.Hour)
	}
}

func TestStartProcessTreeStartFailureClosesJob(t *testing.T) {
	cmd := exec.Command(filepath.Join(t.TempDir(), "missing-git.exe"))
	if err := configureProcessTree(cmd); err != nil {
		t.Fatalf("configureProcessTree: %v", err)
	}
	if err := startProcessTree(cmd); err == nil {
		t.Fatal("startProcessTree() unexpectedly succeeded")
	}
	if _, ok := windowsProcessTrees.Load(cmd); ok {
		t.Fatal("start failure retained process-tree state")
	}
}

func TestConfigureProcessTreeCreateFailure(t *testing.T) {
	original := createJobObject
	t.Cleanup(func() { createJobObject = original })
	createJobObject = func(*windows.SecurityAttributes, *uint16) (windows.Handle, error) {
		return 0, errors.New("injected job creation failure")
	}

	if err := configureProcessTree(exec.Command("git.exe")); err == nil {
		t.Fatal("configureProcessTree() unexpectedly succeeded")
	}
}

func TestConfigureProcessTreeInformationFailure(t *testing.T) {
	original := setInformationJobObject
	t.Cleanup(func() { setInformationJobObject = original })
	setInformationJobObject = func(windows.Handle, uint32, uintptr, uint32) (int, error) {
		return 0, errors.New("injected job configuration failure")
	}

	if err := configureProcessTree(exec.Command("git.exe")); err == nil {
		t.Fatal("configureProcessTree() unexpectedly succeeded")
	}
}

func TestStartProcessTreeAssignmentFailureReapsSuspendedChild(t *testing.T) {
	original := assignProcessToJobObject
	t.Cleanup(func() { assignProcessToJobObject = original })
	assignProcessToJobObject = func(windows.Handle, windows.Handle) error {
		return errors.New("injected process assignment failure")
	}

	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	if err := configureProcessTree(cmd); err != nil {
		t.Fatalf("configureProcessTree: %v", err)
	}
	err := startProcessTree(cmd)
	if err == nil || !strings.Contains(err.Error(), "injected process assignment failure") {
		t.Fatalf("startProcessTree() error = %v, want injected assignment failure", err)
	}
	if cmd.ProcessState == nil {
		t.Fatal("assignment failure did not reap the suspended child")
	}
	if _, ok := windowsProcessTrees.Load(cmd); ok {
		t.Fatal("assignment failure retained process-tree state")
	}
}

func TestKillProcessTreeAlreadyGone(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	if err := configureProcessTree(cmd); err != nil {
		t.Fatalf("configureProcessTree: %v", err)
	}
	if err := startProcessTree(cmd); err != nil {
		t.Fatalf("startProcessTree: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cmd.Wait: %v", err)
	}
	if err := killProcessTree(cmd); err != nil {
		t.Fatalf("killProcessTree() for an already-gone process: %v", err)
	}
}

func TestPushWithSystemGitTimeoutKillsDescendants(t *testing.T) {
	workDir := t.TempDir()
	sourceBinary, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	fakeGit := filepath.Join(workDir, "git.exe")
	binary, err := os.ReadFile(sourceBinary)
	if err != nil {
		t.Fatalf("read fake git source: %v", err)
	}
	if err := os.WriteFile(fakeGit, binary, 0o700); err != nil {
		t.Fatalf("write fake git: %v", err)
	}

	rootPath := filepath.Join(workDir, "root.pid")
	childPath := filepath.Join(workDir, "child.pid")
	grandchildPath := filepath.Join(workDir, "grandchild.pid")
	readyPath := filepath.Join(workDir, "ready")
	t.Setenv(fakeGitEnv, "1")
	t.Setenv(helperEnv, "1")
	t.Setenv(helperModeEnv, "root")
	t.Setenv(sourceBinaryEnv, sourceBinary)
	t.Setenv(rootPIDEnv, rootPath)
	t.Setenv(childPIDEnv, childPath)
	t.Setenv(grandchildPIDEnv, grandchildPath)
	t.Setenv(readyEnv, readyPath)
	t.Setenv("PATH", workDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	resolved, err := exec.LookPath("git")
	if err != nil || !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(fakeGit)) {
		t.Fatalf("git fixture resolution = %q, %v; want %q", resolved, err, fakeGit)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	done := make(chan struct{})
	var processes []fixtureProcess
	t.Cleanup(func() {
		processes = appendMissingFixtureProcesses(processes,
			fixtureSpec{name: "root", path: rootPath, imagePath: fakeGit},
			fixtureSpec{name: "child", path: childPath, imagePath: sourceBinary},
			fixtureSpec{name: "grandchild", path: grandchildPath, imagePath: sourceBinary},
		)
		cancel()
		select {
		case <-done:
		case <-time.After(fixtureCleanupTimeout):
			t.Errorf("system git callback did not finish after cleanup")
		}
		if err := waitForFixtureProcesses(processes, fixtureCleanupTimeout); err != nil {
			terminateFixtureProcesses(t, processes)
			if err := waitForFixtureProcesses(processes, fixtureCleanupTimeout); err != nil {
				t.Errorf("fixture cleanup: %v", err)
			}
		}
		for _, process := range processes {
			if err := windows.CloseHandle(process.handle); err != nil {
				t.Errorf("close %s process handle: %v", process.name, err)
			}
		}
	})

	go func() {
		defer close(done)
		result <- pushWithSystemGit(ctx, workDir)
	}()

	waitForWindowsFile(t, readyPath, fixtureStartupTimeout)
	for _, spec := range []fixtureSpec{
		{name: "root", path: rootPath, imagePath: fakeGit},
		{name: "child", path: childPath, imagePath: sourceBinary},
		{name: "grandchild", path: grandchildPath, imagePath: sourceBinary},
	} {
		processes = append(processes, openFixtureProcess(t, spec, readWindowsPID(t, spec.path)))
	}

	// Readiness is published only after all three processes are alive. Cancel
	// explicitly so this exercises pushWithSystemGit's context cancellation.
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("pushWithSystemGit() unexpectedly succeeded")
		}
	case <-time.After(fixtureCleanupTimeout):
		t.Fatal("pushWithSystemGit() did not finish after cancellation")
	}
	if err := waitForFixtureProcesses(processes, fixtureCleanupTimeout); err != nil {
		t.Fatal(err)
	}
}

func TestGitPushTimeoutDescendantHelper(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	if os.Getenv(helperModeEnv) == "child" || os.Getenv(helperModeEnv) == "grandchild" {
		return
	}
	t.Skip("fixture helper is launched by init")
}

type fixtureProcess struct {
	name   string
	handle windows.Handle
}

type fixtureSpec struct {
	name      string
	path      string
	imagePath string
}

func openFixtureProcess(t *testing.T, spec fixtureSpec, pid uint32) fixtureProcess {
	t.Helper()
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
		false,
		pid,
	)
	if err != nil {
		t.Fatalf("open %s process %d: %v", spec.name, pid, err)
	}
	if err := checkFixtureImage(handle, spec.imagePath); err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("validate %s process %d: %v", spec.name, pid, err)
	}
	event, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("query %s process %d: %v", spec.name, pid, err)
	}
	if event != uint32(windows.WAIT_TIMEOUT) {
		_ = windows.CloseHandle(handle)
		t.Fatalf("%s process %d was not alive at readiness (wait=%d)", spec.name, pid, event)
	}
	return fixtureProcess{name: spec.name, handle: handle}
}

func appendMissingFixtureProcesses(processes []fixtureProcess, specs ...fixtureSpec) []fixtureProcess {
	seen := make(map[uint32]bool, len(processes))
	for _, process := range processes {
		seen[processPID(process.handle)] = true
	}
	for _, spec := range specs {
		pid, err := readFixturePID(spec.path)
		if err != nil || seen[pid] {
			continue
		}
		handle, err := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
			false,
			pid,
		)
		if err != nil {
			continue
		}
		if err := checkFixtureImage(handle, spec.imagePath); err != nil {
			_ = windows.CloseHandle(handle)
			continue
		}
		processes = append(processes, fixtureProcess{name: spec.name, handle: handle})
		seen[pid] = true
	}
	return processes
}

func checkFixtureImage(handle windows.Handle, want string) error {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return err
	}
	got := filepath.Clean(windows.UTF16ToString(buffer[:size]))
	if !strings.EqualFold(got, filepath.Clean(want)) {
		return fmt.Errorf("image path = %q, want %q", got, want)
	}
	return nil
}

func processPID(handle windows.Handle) uint32 {
	pid, _ := windows.GetProcessId(handle)
	return pid
}

func terminateFixtureProcesses(t *testing.T, processes []fixtureProcess) {
	t.Helper()
	for _, process := range processes {
		if err := windows.TerminateProcess(process.handle, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Errorf("terminate %s fixture: %v", process.name, err)
		}
	}
}

func readWindowsPID(t *testing.T, path string) uint32 {
	t.Helper()
	pid, err := readFixturePID(path)
	if err != nil {
		t.Fatalf("read fixture PID %q: %v", path, err)
	}
	return pid
}

func readFixturePID(path string) (uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(pid), nil
}

func waitForWindowsFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fixture readiness was not published in %q within %s", path, timeout)
}

func waitForFixtureProcesses(processes []fixtureProcess, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for _, process := range processes {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("%s fixture process did not terminate within %s", process.name, timeout)
		}
		event, err := windows.WaitForSingleObject(process.handle, uint32(remaining/time.Millisecond))
		if err != nil {
			return fmt.Errorf("wait for %s fixture process: %w", process.name, err)
		}
		if event != windows.WAIT_OBJECT_0 {
			return fmt.Errorf("%s fixture process survived cleanup", process.name)
		}
	}
	return nil
}

func appendEnv(base []string, values map[string]string) []string {
	env := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if _, replace := values[name]; !replace {
			env = append(env, entry)
		}
	}
	for name, value := range values {
		if value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}
