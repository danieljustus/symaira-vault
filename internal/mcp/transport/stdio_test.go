package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type errReader struct {
	err error
}

func (r *errReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

type delayedErrReader struct {
	err   error
	delay time.Duration
	once  sync.Once
	done  chan struct{}
}

func (r *delayedErrReader) Read(_ []byte) (int, error) {
	r.once.Do(func() {
		if r.done != nil {
			close(r.done)
		}
	})
	time.Sleep(r.delay)
	return 0, r.err
}

func TestStdioTransport_StartAlreadyRunning_ReturnsError(t *testing.T) {
	pr, _ := io.Pipe()
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(pr, out)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	go func() {
		close(started)
		_ = transport.Start(ctx, func(context.Context, *Message) (*Message, error) {
			return nil, nil
		})
	}()

	<-started
	time.Sleep(10 * time.Millisecond)

	err := transport.Start(context.Background(), func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error when starting already-running transport, got nil")
	}
	if err.Error() != "transport already running" {
		t.Errorf("expected 'transport already running', got %q", err.Error())
	}

	cancel()
}

func TestStdioTransport_Start_NonEOFReadError(t *testing.T) {
	reader := &errReader{err: errors.New("simulated read error")}
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(reader, out)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := transport.Start(ctx, func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error for non-EOF read error, got nil")
	}
	if !strings.Contains(err.Error(), "read error") {
		t.Errorf("expected error containing 'read error', got %q", err.Error())
	}
}

func TestStdioTransport_Start_EOF(t *testing.T) {
	in := strings.NewReader("")
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(in, out)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := transport.Start(ctx, func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected no error on EOF, got %v", err)
	}
}

func TestStdioTransport_Start_StopChTriggeredDuringRead(t *testing.T) {
	pr, pw := io.Pipe()
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(pr, out)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = transport.Stop(ctx)
		_ = pw.Close()
	}()

	err := transport.Start(ctx, func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected no error when stopCh triggered during read, got %v", err)
	}
	// Memory barrier: ensure Stop() completed before test goroutine accesses transport
	runtime.KeepAlive(transport)
}

func TestStdioTransport_Start_StopChTriggeredDuringReadError(t *testing.T) {
	reader := &delayedErrReader{delay: 100 * time.Millisecond, err: errors.New("boom")}
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(reader, out)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = transport.Stop(ctx)
	}()

	err := transport.Start(ctx, func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected nil error when stopCh closed before read error, got %v", err)
	}
	// Memory barrier: ensure Stop() completed before test goroutine accesses transport
	runtime.KeepAlive(transport)
}

func TestStdioTransport_Stop_ContextDone(t *testing.T) {
	pr, pw := io.Pipe()
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(pr, out)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	go func() {
		close(started)
		_ = transport.Start(ctx, func(context.Context, *Message) (*Message, error) {
			return nil, nil
		})
	}()

	<-started
	time.Sleep(10 * time.Millisecond)

	alreadyCanceledCtx, alreadyCancel := context.WithCancel(context.Background())
	alreadyCancel()

	err := transport.Stop(alreadyCanceledCtx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	_ = pw.Close()
}

//nolint:dupl // test helper with shared stdio validation pattern
func TestStdioTransport_handleLine_InvalidJSONRPCVersion(t *testing.T) {
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(strings.NewReader(""), out)

	line := `{"jsonrpc":"1.0","id":1,"method":"test"}`
	transport.handleLine(context.Background(), line, func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})

	output := out.String()
	if output == "" {
		t.Fatal("expected error output")
	}

	var response Message
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected error response")
	}
	if response.Error.Code != ErrCodeInvalidRequest {
		t.Errorf("expected error code %d, got %d", ErrCodeInvalidRequest, response.Error.Code)
	}
	if response.Error.Message != "Invalid Request" {
		t.Errorf("expected error message 'Invalid Request', got %q", response.Error.Message)
	}
}

func TestStdioTransport_handleLine_NotificationHandlerError(t *testing.T) {
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(strings.NewReader(""), out)

	line := `{"jsonrpc":"2.0","method":"notify"}`
	transport.handleLine(context.Background(), line, func(context.Context, *Message) (*Message, error) {
		return nil, errors.New("handler error")
	})

	output := out.String()
	if output != "" {
		t.Errorf("expected no output for notification with handler error, got %q", output)
	}
}

//nolint:dupl // test helper with shared stdio validation pattern
func TestStdioTransport_handleLine_EmptyMethod(t *testing.T) {
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(strings.NewReader(""), out)

	line := `{"jsonrpc":"2.0","id":1}`
	transport.handleLine(context.Background(), line, func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})

	output := out.String()
	if output == "" {
		t.Fatal("expected error output")
	}

	var response Message
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected error response")
	}
	if response.Error.Code != ErrCodeInvalidRequest {
		t.Errorf("expected error code %d, got %d", ErrCodeInvalidRequest, response.Error.Code)
	}
	if response.Error.Message != "Invalid Request" {
		t.Errorf("expected error message 'Invalid Request', got %q", response.Error.Message)
	}
}

func TestStdioTransport_handleLine_HandlerReturnsGenericError(t *testing.T) {
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(strings.NewReader(""), out)

	line := `{"jsonrpc":"2.0","id":1,"method":"test"}`
	transport.handleLine(context.Background(), line, func(context.Context, *Message) (*Message, error) {
		return nil, errors.New("something went wrong")
	})

	output := out.String()
	if output == "" {
		t.Fatal("expected error output")
	}

	var response Message
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected error response")
	}
	if response.Error.Code != ErrCodeInternalError {
		t.Errorf("expected error code %d, got %d", ErrCodeInternalError, response.Error.Code)
	}
	if response.Error.Message != "Internal error" {
		t.Errorf("expected error message 'Internal error', got %q", response.Error.Message)
	}
}

//nolint:dupl // test helper with shared stdio validation pattern
func TestStdioTransport_handleLine_HandlerReturnsNilResponse(t *testing.T) {
	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(strings.NewReader(""), out)

	line := `{"jsonrpc":"2.0","id":1,"method":"test"}`
	transport.handleLine(context.Background(), line, func(context.Context, *Message) (*Message, error) {
		return nil, nil
	})

	output := out.String()
	if output == "" {
		t.Fatal("expected output")
	}

	var response Message
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected error response for nil response")
	}
	if response.Error.Code != ErrCodeInternalError {
		t.Errorf("expected error code %d, got %d", ErrCodeInternalError, response.Error.Code)
	}
	if response.Error.Message != "Internal error" {
		t.Errorf("expected error message 'Internal error', got %q", response.Error.Message)
	}
}

type failingWriter struct{}

func (f *failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestStdioTransport_writeMessage_WriteError(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	transport := NewStdioTransportWithIO(strings.NewReader(""), &failingWriter{})

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Result:  json.RawMessage(`{"ok": true}`),
	}

	transport.writeMessage(msg)

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	stderrOutput := buf.String()

	if !strings.Contains(stderrOutput, "failed to write message") {
		t.Errorf("expected stderr to contain 'failed to write message', got %q", stderrOutput)
	}
}

func TestStdioTransport_writeMessage_JSONMarshalError(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	out := &bytes.Buffer{}
	transport := NewStdioTransportWithIO(strings.NewReader(""), out)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Error: &RPCError{
			Code:    ErrCodeInternalError,
			Message: "test",
			Data:    make(chan int),
		},
	}

	transport.writeMessage(msg)

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	stderrOutput := buf.String()

	if !strings.Contains(stderrOutput, "failed to marshal response") {
		t.Errorf("expected stderr to contain 'failed to marshal response', got %q", stderrOutput)
	}
	if out.String() != "" {
		t.Errorf("expected no stdout output, got %q", out.String())
	}
}
