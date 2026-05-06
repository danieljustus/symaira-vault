package cliout

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = old }()

	fn()

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestErrorf(t *testing.T) {
	SetQuiet(false)
	out := captureStderr(t, func() {
		Errorf("test error %d", 42)
	})
	if !strings.Contains(out, "test error 42") {
		t.Errorf("Errorf output = %q, want to contain 'test error 42'", out)
	}
}

func TestErrorfQuiet(t *testing.T) {
	SetQuiet(true)
	out := captureStderr(t, func() {
		Errorf("should not appear")
	})
	if out != "" {
		t.Errorf("Errorf in quiet mode output = %q, want empty", out)
	}
	SetQuiet(false)
}

func TestWarnf(t *testing.T) {
	SetQuiet(false)
	out := captureStderr(t, func() {
		Warnf("test warning")
	})
	if !strings.Contains(out, "test warning") {
		t.Errorf("Warnf output = %q, want to contain 'test warning'", out)
	}
}

func TestHintf(t *testing.T) {
	SetQuiet(false)
	out := captureStderr(t, func() {
		Hintf("test hint")
	})
	if !strings.Contains(out, "test hint") {
		t.Errorf("Hintf output = %q, want to contain 'test hint'", out)
	}
}

func TestNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	SetQuiet(false)
	out := captureStderr(t, func() {
		Errorf("no color")
	})
	if strings.Contains(out, "\033[") {
		t.Errorf("Errorf with NO_COLOR should not contain ANSI codes, got %q", out)
	}
	os.Unsetenv("NO_COLOR")
}

func TestColorWithCodes(t *testing.T) {
	os.Unsetenv("NO_COLOR")
	SetQuiet(false)
	out := captureStderr(t, func() {
		Errorf("with color")
	})
	if !strings.Contains(out, "\033[") {
		t.Errorf("Errorf without NO_COLOR should contain ANSI codes, got %q", out)
	}
}
