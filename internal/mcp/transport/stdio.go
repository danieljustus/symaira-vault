package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

// StdioTransport implements MCP transport over stdin/stdout
type StdioTransport struct {
	writer  io.Writer
	reader  *bufio.Reader
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	running atomic.Bool
	stopped atomic.Bool
}

// NewStdioTransport creates a new stdio transport that reads from stdin and writes to stdout
func NewStdioTransport() *StdioTransport {
	return NewStdioTransportWithIO(os.Stdin, os.Stdout)
}

// NewStdioTransportWithIO creates a new stdio transport with custom input/output streams
func NewStdioTransportWithIO(input io.Reader, output io.Writer) *StdioTransport {
	return &StdioTransport{
		reader: bufio.NewReader(input),
		writer: output,
		stopCh: make(chan struct{}),
	}
}

// Start begins reading from stdin and handling messages
func (t *StdioTransport) Start(ctx context.Context, handler MessageHandler) error {
	t.wg.Add(1)
	defer t.wg.Done()

	if !t.running.CompareAndSwap(false, true) {
		return fmt.Errorf("transport already running")
	}

	defer t.running.Store(false)

	t.stopCh = make(chan struct{})
	t.stopped.Store(false)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-t.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.stopCh:
			return nil
		default:
		}

		line, err := t.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			select {
			case <-t.stopCh:
				return nil
			default:
				return fmt.Errorf("read error: %w", err)
			}
		}

		if len(line) == 0 {
			continue
		}

		t.handleLine(ctx, line, handler)
	}
}

// Stop gracefully shuts down the transport
func (t *StdioTransport) Stop(ctx context.Context) error {
	if !t.running.Load() {
		return nil
	}

	if t.stopped.CompareAndSwap(false, true) {
		close(t.stopCh)
	}

	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *StdioTransport) handleLine(ctx context.Context, line string, handler MessageHandler) {
	var msg Message
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		t.writeError(nil, ErrCodeParseError, "Parse error", err.Error())
		return
	}

	if msg.JSONRPC != "2.0" {
		t.writeError(msg.ID, ErrCodeInvalidRequest, "Invalid Request", "jsonrpc must be 2.0")
		return
	}

	if msg.IsNotification() {
		_, err := handler(ctx, &msg)
		if err != nil {
			cliout.Errorf("failed to handle notification: %v", err)
		}
		return
	}

	if msg.Method == "" {
		t.writeError(msg.ID, ErrCodeInvalidRequest, "Invalid Request", "method is required")
		return
	}

	response, err := handler(ctx, &msg)
	if err != nil {
		t.writeError(msg.ID, ErrCodeInternalError, "Internal error", err.Error())
		return
	}

	if response == nil {
		response = NewErrorResponse(msg.ID, ErrCodeInternalError, "Internal error", nil)
	}

	if response.ID == nil {
		response.ID = msg.ID
	}

	t.writeMessage(response)
}

func (t *StdioTransport) writeMessage(msg *Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		cliout.Errorf("failed to marshal response: %v", err)
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, err := fmt.Fprintln(t.writer, string(data)); err != nil {
		cliout.Errorf("failed to write message: %v", err)
	}
}

func (t *StdioTransport) writeError(id json.RawMessage, code int, message string, data any) {
	errMsg := NewErrorResponse(id, code, message, data)
	t.writeMessage(errMsg)
}
