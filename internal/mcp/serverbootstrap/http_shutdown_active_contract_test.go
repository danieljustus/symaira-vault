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

// Record production semantics before choosing Rust callback ownership. The Go
// caller returns while an already admitted factory callback remains running.
// This is an observation, not a claim of graceful draining or safe cutover.
func TestHTTPShutdownActiveFactoryContract(t *testing.T) {
	v := newTestVault(t)
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
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Go server did not return while factory remained blocked")
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
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request goroutine not reaped")
	}
	t.Log("production Go returns after context cancellation without waiting for the already admitted factory callback; callback remains alive until explicit release")
}
