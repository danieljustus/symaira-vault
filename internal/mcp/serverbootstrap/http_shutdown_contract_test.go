package serverbootstrap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// Executes the production HTTP lifecycle without an identity or OS keyring.
// This proves only discovery/idle transport shutdown, not in-flight tool calls.
func TestHTTPShutdownIdleTransportContract(t *testing.T) {
	v := newTestVault(t)
	factory := func(*vaultpkg.Vault, string, string) (*mcpserver.Server, error) {
		return nil, fmt.Errorf("discovery must not construct a credential handler")
	}
	start := func(listener net.Listener) (context.CancelFunc, <-chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- RunHTTPServerOnListener(ctx, listener, v, v.Dir, "dev", factory)
		}()
		t.Cleanup(func() {
			cancel()
			_ = listener.Close()
		})
		return cancel, done
	}
	request := func(address string) net.Conn {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(conn, "GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: %s\r\n\r\n", address); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("discovery status: %d", response.StatusCode)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["resource"] != "http://"+address+"/mcp" {
			t.Fatalf("unexpected discovery resource: %v", payload["resource"])
		}
		return conn
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	cancel, done := start(listener)
	conn := request(address)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not return after cancellation")
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	n, err := conn.Read(one[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("idle transport must reach EOF, got n=%d error=%v", n, err)
	}
	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	cancelAgain, doneAgain := start(rebound)
	followUp := request(address)
	_ = followUp.Close()
	cancelAgain()
	select {
	case err := <-doneAgain:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replacement HTTP server did not return")
	}
	t.Log("production Go: discovery success, cancellation return, idle EOF, exact endpoint rebind, following discovery success")
}
