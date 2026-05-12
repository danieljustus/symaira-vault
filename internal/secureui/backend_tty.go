package secureui

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-tty"
)

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
		if _, werr := out.WriteString(buildTTYPrompt(req)); werr != nil {
			return "", fmt.Errorf("write tty: %w", werr)
		}
	}

	value, rerr := readTTY(dev, req.Timeout)
	if rerr != nil {
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
	return d.ReadString()
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func buildTTYPrompt(req PromptRequest) string {
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
