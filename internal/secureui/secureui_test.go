package secureui

import (
	"errors"
	"os"
	"strings"
	"syscall"
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
		{"empty", PromptRequest{}, "Symaira Vault requires a value."},
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

func TestPrompt_TTYOverride_NoTTY(t *testing.T) {
	t.Setenv("SYMVAULT_SECUREUI", "tty")
	oldOpen := openTTYDevice
	defer func() { openTTYDevice = oldOpen }()
	openTTYDevice = func() (ttyDevice, error) { return nil, errors.New("no tty") }

	_, err := Prompt(PromptRequest{Path: "p", Field: "f"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Prompt() err = %v, want ErrUnavailable", err)
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
type fakeTTY struct {
	value string
	// block, if non-nil, makes ReadString wait on this channel so tests can
	// exercise the SIGINT-cancel path. Sending on closeCh closes the device,
	// unblocking the read.
	block   chan struct{}
	closeCh chan struct{}
}

func (f *fakeTTY) ReadString() (string, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-f.closeCh:
			return "", errors.New("device closed")
		}
	}
	return f.value, nil
}
func (*fakeTTY) Input() *os.File  { return nil }
func (*fakeTTY) Output() *os.File { return nil }
func (f *fakeTTY) Close() error {
	if f.closeCh != nil {
		select {
		case <-f.closeCh:
		default:
			close(f.closeCh)
		}
	}
	return nil
}

func TestPrompt_TTYBackend_SignalCancel(t *testing.T) {
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			t.Setenv("SYMVAULT_SECUREUI", "tty")

			oldOpen := openTTYDevice
			defer func() { openTTYDevice = oldOpen }()

			// newTTYBackend probes the device on construction, then ttyBackend.prompt
			// opens it again for the actual read. Only the second open should block.
			var dev *fakeTTY
			openCalls := 0
			openTTYDevice = func() (ttyDevice, error) {
				openCalls++
				if openCalls == 1 {
					return &fakeTTY{value: ""}, nil
				}
				dev = &fakeTTY{
					value:   "should-not-be-read",
					block:   make(chan struct{}),
					closeCh: make(chan struct{}),
				}
				return dev, nil
			}

			registered := make(chan chan<- os.Signal, 1)
			stopped := make(chan chan<- os.Signal, 1)
			oldNotify := signalNotify
			oldStop := signalStop
			defer func() {
				signalNotify = oldNotify
				signalStop = oldStop
			}()
			signalNotify = func(ch chan<- os.Signal, got ...os.Signal) {
				if len(got) != 2 || got[0] != os.Interrupt || got[1] != syscall.SIGTERM {
					t.Errorf("signalNotify registered %v, want interrupt and SIGTERM", got)
				}
				registered <- ch
			}
			signalStop = func(ch chan<- os.Signal) { stopped <- ch }

			type result struct {
				val string
				err error
			}
			done := make(chan result, 1)
			go func() {
				v, err := Prompt(PromptRequest{Path: "p", Field: "f"})
				done <- result{val: v, err: err}
			}()

			var sigCh chan<- os.Signal
			select {
			case sigCh = <-registered:
			case <-time.After(2 * time.Second):
				t.Fatal("signal handler never registered")
			}
			sigCh <- signal

			select {
			case res := <-done:
				if !errors.Is(res.err, ErrCanceled) || res.val != "" {
					t.Fatalf("Prompt() = (%q, %v), want empty value and ErrCanceled", res.val, res.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Prompt() did not return after %s", signal)
			}

			select {
			case <-dev.closeCh:
			default:
				t.Fatal("signal cancellation did not close the TTY to unblock ReadString")
			}
			select {
			case stoppedCh := <-stopped:
				if stoppedCh != sigCh {
					t.Fatal("signalStop received a different channel from signalNotify")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("signalStop was not called after cancellation")
			}
		})
	}
}

func TestPrompt_NoneBackend_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_SECUREUI", "none")
	_, err := Prompt(PromptRequest{Path: "x", Field: "y"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Prompt() err = %v, want ErrUnavailable", err)
	}
}

func TestPrompt_DefaultsTimeout_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_SECUREUI", "gui")
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

func TestPrompt_EmptyResultIsCanceled_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_SECUREUI", "gui")
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

func TestPrompt_CancelExitStatus_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		err:       errors.New("exit status 1"),
	}

	_, err := Prompt(PromptRequest{Path: "p", Field: "f"})
	// With the new implementation, a plain "exit status 1" error without stderr
	// content is treated as cancellation for backward compatibility.
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("Prompt() err = %v, want ErrCanceled", err)
	}
}

func TestPrompt_TTYBackend_Success_Symvault(t *testing.T) {
	t.Setenv("SYMVAULT_SECUREUI", "tty")
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
