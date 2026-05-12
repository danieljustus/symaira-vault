package secureui

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCapabilityString(t *testing.T) {
	cases := map[Capability]string{
		CapNone: "none",
		CapTTY:  "tty",
		CapGUI:  "gui",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("Capability(%d).String() = %q, want %q", c, got, want)
		}
	}
}

func TestFormatPrompt(t *testing.T) {
	cases := []struct {
		name string
		req  PromptRequest
		want string
	}{
		{"path-field-desc", PromptRequest{Path: "github", Field: "token", Description: "Why?"}, "Why?\n\nEntry: github\nField: token"},
		{"path-field-only", PromptRequest{Path: "github", Field: "token"}, "Entry: github\nField: token"},
		{"desc-only", PromptRequest{Description: "Why?"}, "Why?"},
		{"empty", PromptRequest{}, "OpenPass requires a value."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatPrompt(tc.req); got != tc.want {
				t.Errorf("FormatPrompt() = %q, want %q", got, tc.want)
			}
		})
	}
}

// mockRunner records the last call and returns scripted output.
type mockRunner struct {
	available map[string]string // tool name → fake path
	out       []byte
	err       error

	calledName string
	calledArgs []string
	calledTime time.Duration
}

func (m *mockRunner) lookPath(name string) (string, error) {
	if path, ok := m.available[name]; ok {
		return path, nil
	}
	return "", errors.New("not found")
}

func (m *mockRunner) run(name string, args []string, timeout time.Duration) ([]byte, error) {
	m.calledName = name
	m.calledArgs = args
	m.calledTime = timeout
	return m.out, m.err
}

func TestPrompt_NoneBackend(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "none")
	_, err := Prompt(PromptRequest{Path: "x", Field: "y"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Prompt() err = %v, want ErrUnavailable", err)
	}
}

func TestPrompt_DefaultsTimeout(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	mr := &mockRunner{
		available: guiAvailableMap(),
		out:       []byte("secret\n"),
	}
	defaultRunner = mr

	value, err := Prompt(PromptRequest{Path: "p", Field: "f"})
	if err != nil {
		t.Fatalf("Prompt() err = %v", err)
	}
	if value != "secret" {
		t.Errorf("Prompt() value = %q, want %q", value, "secret")
	}
	if mr.calledTime != defaultTimeout {
		t.Errorf("default timeout not applied: got %v, want %v", mr.calledTime, defaultTimeout)
	}
}

func TestPrompt_EmptyResultIsCanceled(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		out:       []byte(""),
	}

	_, err := Prompt(PromptRequest{Path: "p", Field: "f"})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("Prompt() err = %v, want ErrCanceled", err)
	}
}

func TestPrompt_CancelExitStatus(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		err:       errors.New("exit status 1"),
	}

	_, err := Prompt(PromptRequest{Path: "p", Field: "f"})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("Prompt() err = %v, want ErrCanceled", err)
	}
}

func TestPrompt_TTYOverride_NoTTY(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "tty")
	oldOpen := openTTYDevice
	defer func() { openTTYDevice = oldOpen }()
	openTTYDevice = func() (ttyDevice, error) { return nil, errors.New("no tty") }

	_, err := Prompt(PromptRequest{Path: "p", Field: "f"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Prompt() err = %v, want ErrUnavailable", err)
	}
}

func TestPrompt_TTYBackend_Success(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "tty")
	oldOpen := openTTYDevice
	defer func() { openTTYDevice = oldOpen }()
	openTTYDevice = func() (ttyDevice, error) {
		return &fakeTTY{value: "tty-secret"}, nil
	}

	value, err := Prompt(PromptRequest{Path: "p", Field: "f"})
	if err != nil {
		t.Fatalf("Prompt() err = %v", err)
	}
	if value != "tty-secret" {
		t.Errorf("Prompt() value = %q, want tty-secret", value)
	}
}

func TestBuildTTYPrompt(t *testing.T) {
	out := buildTTYPrompt(PromptRequest{Path: "github", Field: "api_key", Description: "for CI"})
	for _, want := range []string{"github", "api_key", "for CI", "SECURE INPUT REQUIRED"} {
		if !strings.Contains(out, want) {
			t.Errorf("buildTTYPrompt missing %q in:\n%s", want, out)
		}
	}
}

// guiAvailableMap declares fake paths for every GUI tool the platform-specific
// backends might probe for. The OS-specific newGUIBackend picks the first one
// it recognizes, so this single map works across all platforms.
func guiAvailableMap() map[string]string {
	return map[string]string{
		"osascript":      "/usr/bin/osascript",
		"zenity":         "/usr/bin/zenity",
		"kdialog":        "/usr/bin/kdialog",
		"powershell.exe": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}
}

// fakeTTY is a no-side-effect TTY for unit tests.
type fakeTTY struct{ value string }

func (f *fakeTTY) ReadString() (string, error) { return f.value, nil }
func (*fakeTTY) Input() *os.File               { return nil }
func (*fakeTTY) Output() *os.File              { return nil }
func (*fakeTTY) Close() error                  { return nil }
