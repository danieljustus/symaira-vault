package cmd

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcpcmd "github.com/danieljustus/OpenPass/cmd/mcp"
)

func TestFindAvailablePort(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		preferredPort := getFreePort(t)

		port, isPreferred, err := findAvailablePort("127.0.0.1", preferredPort)
		if err != nil {
			t.Fatalf("findAvailablePort failed: %v", err)
		}
		if isPreferred && port == preferredPort {
			return
		}
	}
	t.Fatal("findAvailablePort did not return the preferred free port after repeated attempts")
}

func TestFindAvailablePort_WhenInUse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to occupy port: %v", err)
	}
	defer func() { _ = listener.Close() }()

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("failed to get TCP address from listener")
	}
	preferredPort := tcpAddr.Port

	port, isPreferred, err := findAvailablePort("127.0.0.1", preferredPort)
	if err != nil {
		t.Fatalf("findAvailablePort failed: %v", err)
	}
	if isPreferred {
		t.Errorf("expected alternative port when preferred is in use")
	}
	if port == preferredPort {
		t.Errorf("expected different port when preferred is in use, got %d", port)
	}
	if port <= 0 {
		t.Errorf("expected valid port, got %d", port)
	}
}

func TestRuntimePortPersistence(t *testing.T) {
	tmpDir := t.TempDir()

	if _, ok := loadRuntimePort(tmpDir); ok {
		t.Error("expected no runtime port for empty directory")
	}

	testPort := 9999
	if err := saveRuntimePort(tmpDir, testPort); err != nil {
		t.Fatalf("saveRuntimePort failed: %v", err)
	}

	port, ok := loadRuntimePort(tmpDir)
	if !ok {
		t.Error("expected to load saved runtime port")
	}
	if port != testPort {
		t.Errorf("expected port %d, got %d", testPort, port)
	}

	if err := clearRuntimePort(tmpDir); err != nil {
		t.Fatalf("clearRuntimePort failed: %v", err)
	}

	if _, ok := loadRuntimePort(tmpDir); ok {
		t.Error("expected runtime port to be cleared")
	}
}

func TestResolvePort(t *testing.T) {
	tmpDir := t.TempDir()

	port := resolvePort(tmpDir, 0)
	if port != 8080 {
		t.Errorf("expected default port 8080, got %d", port)
	}

	port = resolvePort(tmpDir, 9090)
	if port != 9090 {
		t.Errorf("expected configured port 9090, got %d", port)
	}

	if err := saveRuntimePort(tmpDir, 7777); err != nil {
		t.Fatalf("saveRuntimePort failed: %v", err)
	}

	port = resolvePort(tmpDir, 9090)
	if port != 7777 {
		t.Errorf("expected runtime port 7777 to override configured port, got %d", port)
	}
}

func TestClearRuntimePort_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()

	if err := clearRuntimePort(tmpDir); err != nil {
		t.Errorf("clearRuntimePort on non-existent file should not error, got: %v", err)
	}
}

func TestSaveRuntimePort_InvalidDirectory(t *testing.T) {
	nonExistentDir := filepath.Join(t.TempDir(), "does-not-exist")
	err := saveRuntimePort(nonExistentDir, 8080)
	if err == nil {
		t.Error("expected error when saving to non-existent directory")
	}
}

func TestLoadRuntimePort_InvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	portFile := filepath.Join(tmpDir, runtimePortFileName)

	if err := os.WriteFile(portFile, []byte("not-a-number"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	if _, ok := loadRuntimePort(tmpDir); ok {
		t.Error("expected load to fail with invalid content")
	}
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("failed to get TCP address from listener")
	}
	port := tcpAddr.Port
	if err := l.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return port
}

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
	err := mcpcmd.CheckRuntimePortHealth("127.0.0.1", port)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckRuntimePortHealth_NonOKStatus(t *testing.T) {
	port := startTestHealthServer(t, http.StatusInternalServerError)
	err := mcpcmd.CheckRuntimePortHealth("127.0.0.1", port)
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
	err := mcpcmd.CheckRuntimePortHealth("127.0.0.1", port)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCheckRuntimePortHealth_BindAll(t *testing.T) {
	port := startTestHealthServer(t, http.StatusOK)
	err := mcpcmd.CheckRuntimePortHealth("0.0.0.0", port)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckRuntimePortHealth_IPv6Bind(t *testing.T) {
	port := startTestHealthServer(t, http.StatusOK)
	err := mcpcmd.CheckRuntimePortHealth("::", port)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveHTTPPort_RuntimePortHealthy(t *testing.T) {
	tmpDir := t.TempDir()
	port := startTestHealthServer(t, http.StatusOK)
	if err := saveRuntimePort(tmpDir, port); err != nil {
		t.Fatalf("saveRuntimePort failed: %v", err)
	}
	resolved, err := mcpcmd.ResolveHTTPPort(tmpDir, "127.0.0.1", 8080)
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
	if err := saveRuntimePort(tmpDir, port); err != nil {
		t.Fatalf("saveRuntimePort failed: %v", err)
	}
	_, err := mcpcmd.ResolveHTTPPort(tmpDir, "127.0.0.1", 8080)
	if err == nil {
		t.Fatal("expected error for stale runtime port")
	}
	if !strings.Contains(err.Error(), "stale runtime port") {
		t.Errorf("expected stale runtime port error, got: %v", err)
	}
}

func TestResolveHTTPPort_ConfiguredPort(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := mcpcmd.ResolveHTTPPort(tmpDir, "127.0.0.1", 9090)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != 9090 {
		t.Errorf("expected port 9090, got %d", resolved)
	}
}

func TestResolveHTTPPort_DefaultPort(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := mcpcmd.ResolveHTTPPort(tmpDir, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != 8080 {
		t.Errorf("expected default port 8080, got %d", resolved)
	}
}
