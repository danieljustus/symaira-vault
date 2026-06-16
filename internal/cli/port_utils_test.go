package cli

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFindAvailablePort_PreferredAvailable(t *testing.T) {
	// Pick an unlikely-used high port
	port, isPreferred, err := FindAvailablePort("127.0.0.1", 49152)
	if err != nil {
		t.Fatalf("FindAvailablePort() error = %v", err)
	}
	if !isPreferred {
		t.Errorf("expected preferred port, got fallback port %d", port)
	}
	if port != 49152 {
		t.Errorf("port = %d, want 49152", port)
	}
}

func TestFindAvailablePort_PreferredOccupied_FallsBack(t *testing.T) {
	// Occupy a port
	ln, err := net.Listen("tcp", "127.0.0.1:49153")
	if err != nil {
		t.Fatalf("failed to occupy port: %v", err)
	}
	defer ln.Close()

	port, isPreferred, err := FindAvailablePort("127.0.0.1", 49153)
	if err != nil {
		t.Fatalf("FindAvailablePort() error = %v", err)
	}
	if isPreferred {
		t.Error("expected non-preferred port since 49153 is occupied")
	}
	if port == 49153 {
		t.Errorf("expected fallback port, got occupied port %d", port)
	}
	if port <= 0 {
		t.Errorf("expected positive fallback port, got %d", port)
	}
}

func TestSaveAndLoadRuntimePort(t *testing.T) {
	dir := t.TempDir()

	if err := SaveRuntimePort(dir, 9090); err != nil {
		t.Fatalf("SaveRuntimePort() error = %v", err)
	}

	port, ok := LoadRuntimePort(dir)
	if !ok {
		t.Fatal("LoadRuntimePort() returned false, want true")
	}
	if port != 9090 {
		t.Errorf("port = %d, want 9090", port)
	}
}

func TestLoadRuntimePort_NoFile(t *testing.T) {
	dir := t.TempDir()

	port, ok := LoadRuntimePort(dir)
	if ok {
		t.Error("LoadRuntimePort() returned true for empty dir, want false")
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestLoadRuntimePort_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, RuntimePortFileName)
	if err := os.WriteFile(path, []byte("not-a-number"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	port, ok := LoadRuntimePort(dir)
	if ok {
		t.Error("LoadRuntimePort() returned true for invalid content, want false")
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestClearRuntimePort(t *testing.T) {
	dir := t.TempDir()

	if err := SaveRuntimePort(dir, 8080); err != nil {
		t.Fatalf("SaveRuntimePort() error = %v", err)
	}

	if err := ClearRuntimePort(dir); err != nil {
		t.Fatalf("ClearRuntimePort() error = %v", err)
	}

	_, ok := LoadRuntimePort(dir)
	if ok {
		t.Error("LoadRuntimePort() returned true after ClearRuntimePort, want false")
	}
}

func TestClearRuntimePort_NoFile(t *testing.T) {
	dir := t.TempDir()

	// Clearing a non-existent file should not error
	if err := ClearRuntimePort(dir); err != nil {
		t.Fatalf("ClearRuntimePort() error = %v", err)
	}
}

func TestResolvePort_RuntimePortTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := SaveRuntimePort(dir, 7777); err != nil {
		t.Fatalf("SaveRuntimePort() error = %v", err)
	}

	port := ResolvePort(dir, 8080)
	if port != 7777 {
		t.Errorf("port = %d, want 7777 (runtime port should take precedence)", port)
	}
}

func TestResolvePort_ConfiguredPort(t *testing.T) {
	dir := t.TempDir()

	port := ResolvePort(dir, 3000)
	if port != 3000 {
		t.Errorf("port = %d, want 3000 (configured port should be used)", port)
	}
}

func TestResolvePort_DefaultPort(t *testing.T) {
	dir := t.TempDir()

	port := ResolvePort(dir, 0)
	if port != 8080 {
		t.Errorf("port = %d, want 8080 (default port should be used)", port)
	}
}

func TestSaveRuntimePort_PathTraversalPrevention(t *testing.T) {
	dir := t.TempDir()

	// Attempt to write outside the vault dir
	err := SaveRuntimePort(dir+"/subdir/../../etc", 8080)
	if err == nil {
		t.Error("SaveRuntimePort() should reject path traversal, got nil")
	}
}

func TestLoadRuntimePort_PathTraversalPrevention(t *testing.T) {
	dir := t.TempDir()

	port, ok := LoadRuntimePort(dir + "/subdir/../../etc")
	if ok {
		t.Error("LoadRuntimePort() should return false for path traversal")
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestSaveRuntimePort_SecurityBits(t *testing.T) {
	dir := t.TempDir()

	if err := SaveRuntimePort(dir, 8080); err != nil {
		t.Fatalf("SaveRuntimePort() error = %v", err)
	}

	portFile := filepath.Join(dir, RuntimePortFileName)
	info, err := os.Stat(portFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Should not be world-readable (mode should be 0600)
	if info.Mode().Perm() != 0600 {
		t.Errorf("port file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadRuntimePort_TrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	portFile := filepath.Join(dir, RuntimePortFileName)
	if err := os.WriteFile(portFile, []byte("  8888\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	port, ok := LoadRuntimePort(dir)
	if !ok {
		t.Fatal("LoadRuntimePort() returned false")
	}
	if port != 8888 {
		t.Errorf("port = %d, want 8888 (whitespace should be trimmed)", port)
	}
}

func TestResolvePort_NegativeConfiguredPort(t *testing.T) {
	dir := t.TempDir()

	// Negative configured port should fall back to default
	port := ResolvePort(dir, -1)
	if port != 8080 {
		t.Errorf("port = %d, want 8080 (negative configured port should fall back)", port)
	}
}

func TestSaveRuntimePort_DirCreation(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub", "dir")

	err := SaveRuntimePort(subDir, 8080)
	// Should fail because the subdirectory doesn't exist
	if err == nil {
		t.Error("SaveRuntimePort() should fail for non-existent subdirectory")
	}
}

func TestLoadRuntimePort_NonNumericContent(t *testing.T) {
	dir := t.TempDir()
	portFile := filepath.Join(dir, RuntimePortFileName)
	if err := os.WriteFile(portFile, []byte("abc123"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	port, ok := LoadRuntimePort(dir)
	if ok {
		t.Error("LoadRuntimePort() returned true for non-numeric content")
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestRuntimePortRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ports := []int{1, 80, 443, 8080, 30000, 65535}

	for _, p := range ports {
		if err := SaveRuntimePort(dir, p); err != nil {
			t.Fatalf("SaveRuntimePort(%d) error = %v", p, err)
		}

		loaded, ok := LoadRuntimePort(dir)
		if !ok {
			t.Fatalf("LoadRuntimePort() returned false for port %d", p)
		}
		if loaded != p {
			t.Errorf("round-trip: got %d, want %d", loaded, p)
		}
	}
}

func TestSaveRuntimePort_PortFileContent(t *testing.T) {
	dir := t.TempDir()

	if err := SaveRuntimePort(dir, 9999); err != nil {
		t.Fatalf("SaveRuntimePort() error = %v", err)
	}

	portFile := filepath.Join(dir, RuntimePortFileName)
	data, err := os.ReadFile(portFile)
	if err != nil {
		t.Fatalf("read port file: %v", err)
	}

	expected := strconv.Itoa(9999)
	if string(data) != expected {
		t.Errorf("port file content = %q, want %q", string(data), expected)
	}
}

func TestFindAvailablePort_InvalidBind(t *testing.T) {
	_, _, err := FindAvailablePort("999.999.999.999", 8080)
	if err == nil {
		t.Error("FindAvailablePort() should error for invalid bind address")
	}
}

func TestFindAvailablePort_PortZeroFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	occupiedAddr := ln.Addr().(*net.TCPAddr)
	occupiedPort := occupiedAddr.Port
	defer ln.Close()

	port, isPreferred, err := FindAvailablePort("127.0.0.1", occupiedPort)
	if err != nil {
		t.Fatalf("FindAvailablePort() error = %v", err)
	}
	if isPreferred {
		t.Error("expected non-preferred since port is occupied")
	}
	if port <= 0 {
		t.Errorf("expected positive port, got %d", port)
	}
	if port == occupiedPort {
		t.Errorf("expected different port than occupied %d", occupiedPort)
	}
}

func TestRuntimePortFileName(t *testing.T) {
	if RuntimePortFileName != ".runtime-port" {
		t.Errorf("RuntimePortFileName = %q, want %q", RuntimePortFileName, ".runtime-port")
	}
}

func TestLoadRuntimePort_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	portFile := filepath.Join(dir, RuntimePortFileName)
	if err := os.WriteFile(portFile, []byte(""), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	port, ok := LoadRuntimePort(dir)
	if ok {
		t.Error("LoadRuntimePort() returned true for empty file")
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestClearRuntimePort_Idempotent(t *testing.T) {
	dir := t.TempDir()

	if err := SaveRuntimePort(dir, 8080); err != nil {
		t.Fatalf("SaveRuntimePort() error = %v", err)
	}

	// Clear twice should not error
	if err := ClearRuntimePort(dir); err != nil {
		t.Fatalf("first ClearRuntimePort() error = %v", err)
	}
	if err := ClearRuntimePort(dir); err != nil {
		t.Fatalf("second ClearRuntimePort() error = %v", err)
	}
}

func TestLoadRuntimePort_LargePort(t *testing.T) {
	dir := t.TempDir()
	portFile := filepath.Join(dir, RuntimePortFileName)
	if err := os.WriteFile(portFile, []byte(strings.TrimSpace(strconv.Itoa(65535))), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	port, ok := LoadRuntimePort(dir)
	if !ok {
		t.Fatal("LoadRuntimePort() returned false")
	}
	if port != 65535 {
		t.Errorf("port = %d, want 65535", port)
	}
}
