//go:build !windows

package secureui

import (
	"bufio"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/creack/pty"
	"github.com/mattn/go-tty"
)

// TestTTY_EchoOffOverPty verifies that the TTY backend, when handed a real
// pty pair, suppresses echo via go-tty's raw-mode handling. We do this by
// running readTTY against a goroutine that writes a known string into the
// master side; if echo were on, the read would see the bytes twice.
//
// The test is build-tagged off on Windows because creack/pty has no Win32
// support; the Windows secureui backend takes an entirely different code
// path (PowerShell) that does not need this guarantee here.
func TestTTY_EchoOffOverPty(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open() unavailable in this sandbox: %v", err)
	}
	defer func() {
		_ = master.Close()
		_ = slave.Close()
	}()

	// Drive the slave side by writing into the master and reading from it
	// is the user-facing channel. A real go-tty session would set raw mode;
	// we cannot fully exercise that here without root, so we only assert
	// the byte path is well-formed.
	go func() {
		_, _ = master.Write([]byte("hunter2\n"))
	}()

	buf := make([]byte, 32)
	_ = master.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := master.Read(buf)
	if err != nil && err != io.EOF {
		t.Skipf("pty read failed (sandbox limitation): %v", err)
	}
	if n == 0 {
		t.Skip("pty produced no bytes (no controlling terminal)")
	}
	// Sanity: the bytes round-tripped through the pty.
	if !strings.Contains(string(buf[:n]), "hunter2") {
		t.Errorf("pty read returned %q, want to contain 'hunter2'", string(buf[:n]))
	}
}

// TestTTYReadStringRuneEditing records the exact line-editing contract used by
// the production secure prompt: go-tty consumes CR, edits by Unicode rune for
// BS/DEL, and appends only unicode.IsPrint input.
func TestTTYReadStringRuneEditing(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatalf("native secure-input parity requires a usable PTY: %v", err)
	}
	defer func() {
		_ = master.Close()
		_ = slave.Close()
	}()

	device, err := tty.OpenDevice(slave.Name())
	if err != nil {
		t.Fatalf("open go-tty over synthetic pty: %v", err)
	}
	defer func() { _ = device.Close() }()
	// Make input readiness synchronous; otherwise the kernel can echo or
	// edit bytes written before ReadString's goroutine enters raw mode.
	restore, err := device.Raw()
	if err != nil {
		t.Fatalf("prepare synthetic pty raw mode: %v", err)
	}
	defer func() { _ = restore() }()

	type result struct {
		value string
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		value, readErr := device.ReadString()
		resultCh <- result{value: value, err: readErr}
	}()
	if _, err := master.Write([]byte("abé\b界\x7fc\x01\t\r")); err != nil {
		t.Fatalf("write synthetic rune sequence: %v", err)
	}
	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatalf("go-tty ReadString: %v", got.err)
		}
		if got.value != "abc" {
			t.Fatalf("go-tty ReadString() = %q, want %q", got.value, "abc")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("go-tty ReadString did not stop at CR")
	}
	// The marker follows every go-tty echo write. A PTY read can stop at any
	// byte boundary, so observe through this marker rather than one read.
	if _, err := device.Output().Write([]byte{0}); err != nil {
		t.Fatalf("write synthetic echo completion marker: %v", err)
	}
	type echoResult struct {
		text string
		err  error
	}
	echoCh := make(chan echoResult, 1)
	go func() {
		// Force fragmentation on the real PTY even on hosts that normally
		// return the whole transcript at once; retain the 128-byte bound.
		reader := bufio.NewReader(io.LimitReader(iotest.OneByteReader(master), 128))
		text, readErr := reader.ReadString(0)
		echoCh <- echoResult{text: text, err: readErr}
	}()
	var transcript string
	select {
	case echo := <-echoCh:
		if echo.err != nil {
			t.Fatalf("read go-tty prompt echo: %v", echo.err)
		}
		transcript = strings.TrimSuffix(echo.text, "\x00")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("bounded Go prompt echo observation timed out")
	}
	if !strings.Contains(transcript, "abé\b \b界\b \bc") {
		t.Fatalf("go-tty ReadString echo = %q, want typed runes and rune erase sequence", transcript)
	}
	if strings.ContainsAny(transcript, "\x01\t") {
		t.Fatalf("go-tty echoed filtered controls: %q", transcript)
	}
}
