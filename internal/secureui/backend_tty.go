package secureui

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-tty"

	"github.com/danieljustus/symaira-vault/internal/ui/theme"
)

// signalNotify is the indirection point so tests can drive cancellation
// without delivering a real OS signal. Production code wires it to signal.Notify.
var signalNotify = func(ch chan<- os.Signal, sigs ...os.Signal) {
	signal.Notify(ch, sigs...)
}

var signalStop = func(ch chan<- os.Signal) {
	signal.Stop(ch)
}

// ttyDevice abstracts a TTY for testability.
type ttyDevice interface {
	ReadString() (string, error)
	Input() *os.File
	Output() *os.File
	Close() error
}

type ttyWrapper struct{ *tty.TTY }

func (w *ttyWrapper) Input() *os.File  { return w.TTY.Input() }
func (w *ttyWrapper) Output() *os.File { return w.TTY.Output() }

// openTTYDevice opens a TTY device. Variable so tests can override.
var openTTYDevice = func() (ttyDevice, error) {
	dev, err := tty.Open()
	if err != nil {
		return nil, err
	}
	return &ttyWrapper{TTY: dev}, nil
}

type ttyBackend struct{}

// newTTYBackend returns a TTY backend if a TTY is currently usable, else nil.
func newTTYBackend() backend {
	dev, err := openTTYDevice()
	if err != nil {
		return nil
	}
	_ = dev.Close()
	return &ttyBackend{}
}

func (*ttyBackend) capability() Capability { return CapTTY }

func (*ttyBackend) prompt(req PromptRequest) (string, error) {
	dev, err := openTTYDevice()
	if err != nil {
		return "", fmt.Errorf("secure input requires an interactive terminal: %w", err)
	}
	defer func() { _ = dev.Close() }()

	if out := dev.Output(); out != nil {
		if warning := CapsLockWarning(); warning != "" {
			_, _ = out.WriteString(warning)
		}
		if _, werr := out.WriteString(buildTTYPrompt(req)); werr != nil {
			return "", fmt.Errorf("write tty: %w", werr)
		}
	}

	value, rerr := readTTY(dev, req.Timeout)
	if rerr != nil {
		if errors.Is(rerr, ErrCanceled) {
			if out := dev.Output(); out != nil {
				_, _ = fmt.Fprintln(out, "\nAborted.")
			}
			return "", ErrCanceled
		}
		if isTimeout(rerr) {
			return "", ErrTimeout
		}
		return "", fmt.Errorf("read tty: %w", rerr)
	}

	if out := dev.Output(); out != nil {
		_, _ = fmt.Fprintln(out)
	}
	return strings.TrimSpace(value), nil
}

func readTTY(d ttyDevice, timeout time.Duration) (string, error) {
	if in := d.Input(); in != nil {
		if err := in.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", err
		}
		defer func() { _ = in.SetReadDeadline(time.Time{}) }()
	}

	sigCh := make(chan os.Signal, 1)
	signalNotify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signalStop(sigCh)

	type readResult struct {
		value string
		err   error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		v, e := d.ReadString()
		resultCh <- readResult{v, e}
	}()

	select {
	case res := <-resultCh:
		return res.value, res.err
	case <-sigCh:
		// Close the device to unblock the in-flight ReadString. The caller's
		// own defer will Close() again, but Close on an already-closed handle
		// is harmless (returns an error we discard).
		_ = d.Close()
		<-resultCh
		return "", ErrCanceled
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func buildTTYPrompt(req PromptRequest) string {
	if theme.ScreenReaderMode() {
		return buildPlainTTYPrompt(req)
	}
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║           SECURE INPUT REQUIRED — AGENT CANNOT SEE          ║\n")
	sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	if req.Path != "" {
		fmt.Fprintf(&sb, "║ Entry:    %-50s ║\n", truncate(req.Path, 50))
	}
	if req.Field != "" {
		fmt.Fprintf(&sb, "║ Field:    %-50s ║\n", truncate(req.Field, 50))
	}
	if req.Description != "" {
		fmt.Fprintf(&sb, "║ Details:  %-50s ║\n", truncate(req.Description, 50))
	}
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n")
	sb.WriteString("Enter value (input hidden): ")
	return sb.String()
}

// buildPlainTTYPrompt skips the box-drawing characters that screen readers
// announce as long runs of garbage. NVDA, VoiceOver, and Orca all speak
// the "Label: value" form intelligibly.
func buildPlainTTYPrompt(req PromptRequest) string {
	var sb strings.Builder
	sb.WriteString("\nSecure input required. The connected agent cannot see this value.\n")
	if req.Path != "" {
		fmt.Fprintf(&sb, "Entry: %s\n", req.Path)
	}
	if req.Field != "" {
		fmt.Fprintf(&sb, "Field: %s\n", req.Field)
	}
	if req.Description != "" {
		fmt.Fprintf(&sb, "Details: %s\n", req.Description)
	}
	sb.WriteString("Enter value, input hidden: ")
	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
