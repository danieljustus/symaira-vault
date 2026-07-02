package mcp

import (
	"net"
	"net/http"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

func startTestHealthServer(t *testing.T, statusCode int) int {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
	})
	srv := &http.Server{Handler: mux}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return port
}

func TestCheckRuntimePortHealth_Success(t *testing.T) {
	port := startTestHealthServer(t, http.StatusOK)
	err := CheckRuntimePortHealth("127.0.0.1", port)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckRuntimePortHealth_NonOKStatus(t *testing.T) {
	port := startTestHealthServer(t, http.StatusInternalServerError)
	err := CheckRuntimePortHealth("127.0.0.1", port)
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
	if !strings.Contains(err.Error(), "health check returned HTTP 500") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCheckRuntimePortHealth_ConnectionRefused(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	err := CheckRuntimePortHealth("127.0.0.1", port)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCheckRuntimePortHealth_BindAll(t *testing.T) {
	port := startTestHealthServer(t, http.StatusOK)
	err := CheckRuntimePortHealth("0.0.0.0", port)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckRuntimePortHealth_IPv6Bind(t *testing.T) {
	port := startTestHealthServer(t, http.StatusOK)
	err := CheckRuntimePortHealth("::", port)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveHTTPPort_RuntimePortHealthy(t *testing.T) {
	tmpDir := t.TempDir()
	port := startTestHealthServer(t, http.StatusOK)
	if err := cli.SaveRuntimePort(tmpDir, port); err != nil {
		t.Fatalf("cli.SaveRuntimePort failed: %v", err)
	}
	resolved, err := ResolveHTTPPort(tmpDir, "127.0.0.1", 8080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != port {
		t.Errorf("expected port %d, got %d", port, resolved)
	}
}

func TestResolveHTTPPort_RuntimePortStale(t *testing.T) {
	tmpDir := t.TempDir()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	if err := cli.SaveRuntimePort(tmpDir, port); err != nil {
		t.Fatalf("cli.SaveRuntimePort failed: %v", err)
	}
	_, err := ResolveHTTPPort(tmpDir, "127.0.0.1", 8080)
	if err == nil {
		t.Fatal("expected error for stale runtime port")
	}
	if !strings.Contains(err.Error(), "stale runtime port") {
		t.Errorf("expected stale runtime port error, got: %v", err)
	}
}

func TestResolveHTTPPort_ConfiguredPort(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := ResolveHTTPPort(tmpDir, "127.0.0.1", 9090)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != 9090 {
		t.Errorf("expected port 9090, got %d", resolved)
	}
}

func TestResolveHTTPPort_DefaultPort(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := ResolveHTTPPort(tmpDir, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != 8080 {
		t.Errorf("expected default port 8080, got %d", resolved)
	}
}
