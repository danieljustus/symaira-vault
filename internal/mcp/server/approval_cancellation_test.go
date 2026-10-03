package server

import (
	"bufio"
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

type cancellationApprovalTTY struct {
	input, output *os.File
	entered       chan struct{}
	once          sync.Once
	lateCancel    context.CancelFunc
}

func (t *cancellationApprovalTTY) Input() *os.File  { return t.input }
func (t *cancellationApprovalTTY) Output() *os.File { return t.output }
func (t *cancellationApprovalTTY) Raw() (func(), error) {
	return func() {}, nil
}
func (t *cancellationApprovalTTY) Close() error { return t.input.Close() }
func (t *cancellationApprovalTTY) ReadString() (string, error) {
	t.once.Do(func() { close(t.entered) })
	if t.lateCancel != nil {
		t.lateCancel()
		return "yes", nil
	}
	return bufio.NewReader(t.input).ReadString('\n')
}

func TestApprovalCancellationDeniesPendingAndLateReply(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows anonymous pipes do not support read deadlines; the separate fail-closed contract covers this terminal")
	}
	for _, late := range []bool{false, true} {
		name := "blocked-read"
		if late {
			name = "late-yes"
		}
		t.Run(name, func(t *testing.T) {
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close(); _ = writer.Close() }()
			output, err := os.CreateTemp(t.TempDir(), "approval-output-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = output.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			terminal := &cancellationApprovalTTY{input: input, output: output, entered: make(chan struct{})}
			if late {
				terminal.lateCancel = cancel
			}
			oldOpen := openTTYDevice
			openTTYDevice = func() (ttyDevice, error) { return terminal, nil }
			defer func() { openTTYDevice = oldOpen }()
			done := make(chan ApprovalResult, 1)
			go func() {
				done <- RequestApprovalContext(ctx, ApprovalRequest{Operation: "synthetic-control", Timeout: 5 * time.Second})
			}()
			select {
			case <-terminal.entered:
			case <-time.After(time.Second):
				t.Fatal("approval did not reach the actual pipe read")
			}
			cancel()
			select {
			case result := <-done:
				if result.Approved || result.Remembered || !errors.Is(result.Error, context.Canceled) {
					t.Fatalf("canceled approval escaped denial: %+v", result)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt and join the approval read")
			}
		})
	}
}

func TestApprovalUninterruptibleTerminalFailsClosed(t *testing.T) {
	input, err := os.CreateTemp(t.TempDir(), "uninterruptible-terminal-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	output, err := os.CreateTemp(t.TempDir(), "approval-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = output.Close() }()
	terminal := &cancellationApprovalTTY{input: input, output: output, entered: make(chan struct{})}
	oldOpen := openTTYDevice
	openTTYDevice = func() (ttyDevice, error) { return terminal, nil }
	defer func() { openTTYDevice = oldOpen }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan ApprovalResult, 1)
	go func() { done <- RequestApprovalContext(ctx, ApprovalRequest{Operation: "synthetic-control"}) }()
	select {
	case result := <-done:
		if result.Approved || result.Remembered || !errors.Is(result.Error, os.ErrNoDeadline) {
			t.Fatalf("uninterruptible terminal did not fail closed: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("uninterruptible terminal blocked the approval")
	}
	select {
	case <-terminal.entered:
		t.Fatal("uninterruptible terminal entered its blocking read")
	default:
	}
}
