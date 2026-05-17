//go:build linux

package autotype

import (
	"os/exec"
	"strings"
	"testing"
)

// mockLookPath returns an error for all binaries (simulates nothing installed).
func mockLookPathNone(file string) (string, error) {
	return "", exec.ErrNotFound
}

// mockLookPath returns success only for wtype.
func mockLookPathWtype(file string) (string, error) {
	if file == "wtype" {
		return "/usr/bin/wtype", nil
	}
	return "", exec.ErrNotFound
}

// mockLookPath returns success only for ydotool.
func mockLookPathYdotool(file string) (string, error) {
	if file == "ydotool" {
		return "/usr/bin/ydotool", nil
	}
	return "", exec.ErrNotFound
}

// mockLookPath returns success only for xdotool.
func mockLookPathXdotool(file string) (string, error) {
	if file == "xdotool" {
		return "/usr/bin/xdotool", nil
	}
	return "", exec.ErrNotFound
}

func saveAndRestore() func() {
	origLookPath := lookPath
	origExecCommand := execCommand
	return func() {
		lookPath = origLookPath
		execCommand = origExecCommand
	}
}

func successExec() *exec.Cmd {
	return exec.Command("echo", "ok")
}

func TestLinuxAutotype_X11_NoXdotool(t *testing.T) {
	restore := saveAndRestore()
	defer restore()

	t.Setenv("WAYLAND_DISPLAY", "")
	lookPath = mockLookPathNone

	a := &linuxAutotype{}
	err := a.Type("test123")

	if err == nil {
		t.Fatal("expected error when xdotool is missing, got nil")
	}
	if !strings.Contains(err.Error(), "xdotool not installed") {
		t.Errorf("expected 'xdotool not installed' in error, got: %v", err)
	}
}

func TestLinuxAutotype_X11_XdotoolAvailable(t *testing.T) {
	restore := saveAndRestore()
	defer restore()

	t.Setenv("WAYLAND_DISPLAY", "")
	lookPath = mockLookPathXdotool
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return successExec()
	}

	a := &linuxAutotype{}
	err := a.Type("test123")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLinuxAutotype_Wayland_WtypeAvailable(t *testing.T) {
	restore := saveAndRestore()
	defer restore()

	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	lookPath = mockLookPathWtype
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return successExec()
	}

	a := &linuxAutotype{}
	err := a.Type("test123")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLinuxAutotype_Wayland_YdotoolFallback(t *testing.T) {
	restore := saveAndRestore()
	defer restore()

	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	lookPath = mockLookPathYdotool
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "ydotool" {
			return successExec()
		}
		return exec.Command("false")
	}

	a := &linuxAutotype{}
	err := a.Type("test123")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLinuxAutotype_Wayland_NoToolAvailable(t *testing.T) {
	restore := saveAndRestore()
	defer restore()

	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	lookPath = mockLookPathNone

	a := &linuxAutotype{}
	err := a.Type("test123")

	if err == nil {
		t.Fatal("expected error when no Wayland tool is available, got nil")
	}
	if !strings.Contains(err.Error(), "neither `wtype` nor `ydotool` is installed") {
		t.Errorf("expected 'neither `wtype` nor `ydotool` is installed' in error, got: %v", err)
	}
}

func TestLinuxAutotype_PasswordNotInArgv(t *testing.T) {
	// Regression test for the argv-leak fix: the password text must NEVER
	// appear in command arguments. Local users would otherwise read it via
	// `ps -ef` or /proc/<pid>/cmdline. The password must be passed via stdin.
	cases := []struct {
		name        string
		setupEnv    func(t *testing.T)
		setupLook   func()
		password    string
		expectedBin string
	}{
		{
			name:        "xdotool (X11)",
			setupEnv:    func(t *testing.T) { t.Setenv("WAYLAND_DISPLAY", "") },
			setupLook:   func() { lookPath = mockLookPathXdotool },
			password:    "hunter2-supersecret",
			expectedBin: "xdotool",
		},
		{
			name:        "wtype (Wayland)",
			setupEnv:    func(t *testing.T) { t.Setenv("WAYLAND_DISPLAY", "wayland-0") },
			setupLook:   func() { lookPath = mockLookPathWtype },
			password:    "hunter2-supersecret",
			expectedBin: "wtype",
		},
		{
			name:        "ydotool (Wayland)",
			setupEnv:    func(t *testing.T) { t.Setenv("WAYLAND_DISPLAY", "wayland-0") },
			setupLook:   func() { lookPath = mockLookPathYdotool },
			password:    "hunter2-supersecret",
			expectedBin: "ydotool",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := saveAndRestore()
			defer restore()

			tc.setupEnv(t)
			tc.setupLook()

			var capturedArgs []string
			execCommand = func(name string, arg ...string) *exec.Cmd {
				capturedArgs = append([]string{name}, arg...)
				return successExec()
			}

			a := &linuxAutotype{}
			if err := a.Type(tc.password); err != nil {
				t.Fatalf("Type() error = %v", err)
			}

			for _, a := range capturedArgs {
				if strings.Contains(a, tc.password) {
					t.Errorf("password leaked into argv: arg %q contains password", a)
				}
			}
		})
	}
}

func TestLinuxAutotype_WaylandDetected(t *testing.T) {
	restore := saveAndRestore()
	defer restore()

	t.Setenv("WAYLAND_DISPLAY", "wayland-1")
	lookPath = mockLookPathWtype

	var capturedName string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		capturedName = name
		return successExec()
	}

	a := &linuxAutotype{}
	err := a.Type("test")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedName != "wtype" {
		t.Errorf("expected wtype on Wayland, got: %s", capturedName)
	}
}
