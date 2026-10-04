package serverbootstrap

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// Exercise the corrected production lifecycle with a real authenticated request.
// Clean drain waits for callbacks; deadline returns explicitly and closes transports.
func TestHTTPShutdownActiveFactoryContract(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "drain"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) { exerciseActiveFactoryShutdown(t, deadline) })
	}
}

func exerciseActiveFactoryShutdown(t *testing.T, deadline bool) {
	v := newTestVault(t)
	if deadline {
		v.Config.MCP.ShutdownTimeout = 150 * time.Millisecond
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	callbackDone := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	//nolint:unparam // Production factory signature requires a server result; this observation always exercises its error path.
	factory := func(*vaultpkg.Vault, string, string) (*mcpserver.Server, error) {
		close(entered)
		<-release
		close(callbackDone)
		return nil, errors.New("isolated test handler released")
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- RunHTTPServerOnListener(ctx, listener, v, v.Dir, "dev", factory) }()
	t.Cleanup(func() {
		cancel()
		releaseCallback()
		_ = listener.Close()
	})
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://"+listener.Addr().String()+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	setValidMCPHeaders(request, testMCPToken(t, v.Dir))
	requestDone := make(chan error, 1)
	go func() {
		response, err := newTestHTTPClient().Do(request)
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real authenticated request never entered factory")
	}
	var incomplete *HTTPShutdownError
	cancel()
	if deadline {
		select {
		case err := <-serverDone:
			if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &incomplete) {
				t.Fatalf("shutdown error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("shutdown exceeded its explicit deadline")
		}
	} else {
		select {
		case err := <-serverDone:
			t.Fatalf("server returned before its callback drained: %v", err)
		case <-time.After(80 * time.Millisecond):
		}
	}
	select {
	case <-callbackDone:
		t.Fatal("callback unexpectedly finished before its explicit release")
	default:
	}
	releaseCallback()
	select {
	case <-callbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("callback not reaped after release")
	}
	select {
	case err := <-requestDone:
		if err != nil && !deadline {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request goroutine not reaped")
	}
	if deadline {
		select {
		case <-incomplete.Drained:
		case <-time.After(2 * time.Second):
			t.Fatal("late callback cleanup did not signal complete drain")
		}
	}
	if !deadline {
		select {
		case err := <-serverDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("server did not return after callbacks drained")
		}
	}
	rebound, err := net.Listen("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("endpoint unavailable after shutdown: %v", err)
	}
	_ = rebound.Close()
	t.Log("authenticated active callback: explicit drain/deadline, joined request and endpoint rebind")
}
