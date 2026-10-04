package serverbootstrap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestHTTPShutdownPartialRequestDoesNotReachFactory(t *testing.T) {
	v := newTestVault(t)
	v.Config.MCP.ShutdownTimeout = 150 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	//nolint:unparam // The production factory signature includes a server; partial requests must never construct it.
	factory := func(*vaultpkg.Vault, string, string) (*mcpserver.Server, error) {
		calls.Add(1)
		return nil, fmt.Errorf("incomplete request must not construct a handler")
	}
	done := make(chan error, 1)
	go func() { done <- RunHTTPServerOnListener(ctx, listener, v, v.Dir, "dev", factory) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// A completed response proves this is an accepted server connection before
	// the following authenticated request stalls in its incomplete JSON body.
	if _, err := fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: %s\r\n\r\n", listener.Addr()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if _, err := fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: 500\r\n\r\n{", listener.Addr(), testMCPToken(t, v.Dir)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("incomplete request escaped bounded shutdown")
	}
	// The server may write a parse-error response before closing. The stream
	// must terminate rather than retaining the partial body reader.
	_, err = io.Copy(io.Discard, reader)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.ECONNABORTED) {
		t.Fatalf("partial request transport did not close: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("incomplete request reached the credential factory")
	}
}

func TestHTTPShutdownCleanupRetainsActiveOwnership(t *testing.T) {
	var owners httpCallbackOwners
	if !owners.begin() {
		t.Fatal("initial callback not admitted")
	}
	cleaned := make(chan struct{})
	var calls atomic.Int32
	err := drainHTTP(&http.Server{}, &owners, 20*time.Millisecond, func() {
		calls.Add(1)
		close(cleaned)
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uncooperative callback must report a deadline: %v", err)
	}
	if owners.begin() {
		owners.active.Done()
		t.Fatal("shutdown admitted a new callback")
	}
	select {
	case <-cleaned:
		t.Fatal("resource cleanup ran underneath an active callback")
	default:
	}
	owners.active.Done()
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("late callback did not release its retained resources")
	}
	if calls.Load() != 1 {
		t.Fatal("cleanup did not run exactly once")
	}
}
