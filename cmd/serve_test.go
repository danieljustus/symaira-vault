package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/mcp/serverbootstrap"
	"github.com/danieljustus/OpenPass/internal/session"
	"github.com/danieljustus/OpenPass/internal/testutil"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

// testTokens stores pre-created MCP tokens for test vaults, keyed by vault
// directory. LoadTokenSystem migrates legacy mcp-token files to the registry
// and deletes the original file, so tests need a way to retrieve the token
// after the server has started.
var testTokens sync.Map            // map[string]string
var reservedTestListeners sync.Map // map[int]net.Listener

func newTestHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
	}
}

func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port //nolint:errcheck // net.Listener.Addr() does not return an error
	_ = l.Close()
	return port
}

func reserveFreePort(t *testing.T) int {
	t.Helper()
	return reserveFreePortForBind(t, "127.0.0.1")
}

func reserveFreePortForBind(t *testing.T, bind string) int {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		t.Fatalf("reserve free port on %s: %v", bind, err)
	}
	port := l.Addr().(*net.TCPAddr).Port //nolint:errcheck // listener uses tcp addr
	reservedTestListeners.Store(port, l)
	t.Cleanup(func() {
		if value, ok := reservedTestListeners.LoadAndDelete(port); ok {
			_ = value.(net.Listener).Close()
		}
	})
	return port
}

func newTestVault(t *testing.T) *vaultpkg.Vault {
	t.Helper()
	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	if vaultFlag != nil {
		vaultFlag.Changed = false
	}

	_, err := vaultpkg.InitWithPassphrase(tmpDir, []byte("test-passphrase"), config.Default())
	if err != nil {
		t.Fatalf("init vault: %v", err)
	}

	// Pre-create a legacy token so LoadTokenSystem can migrate it. The token
	// is stored in testTokens because the file is deleted during migration.
	token := "test-token-" + tmpDir[len(tmpDir)-8:]
	testTokens.Store(tmpDir, token)
	if err := os.WriteFile(filepath.Join(tmpDir, "mcp-token"), []byte(token), 0o600); err != nil {
		t.Fatalf("write test token: %v", err)
	}

	v, err := vaultpkg.OpenWithPassphrase(tmpDir, []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	return v
}

func runHTTPServerAsyncWithFactory(ctx context.Context, t *testing.T, bind string, port int, v *vaultpkg.Vault, factory func(*vaultpkg.Vault, string, string) (*mcp.Server, error)) func() {
	t.Helper()
	var listener net.Listener
	if value, ok := reservedTestListeners.LoadAndDelete(port); ok {
		listener = value.(net.Listener)
	} else if bind == "127.0.0.1" {
		l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bind, port))
		if err != nil {
			t.Fatalf("reserve HTTP listener: %v", err)
		}
		listener = l
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		vaultDir, _ := vaultPath()
		var err error
		if listener != nil {
			err = serverbootstrap.RunHTTPServerOnListener(ctx, listener, v, vaultDir, "dev", factory)
		} else {
			err = serverbootstrap.RunHTTPServer(ctx, bind, port, v, vaultDir, "dev", factory)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("runHTTPServer error: %v", err)
		}
	}()
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	client := newTestHTTPClient()
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i := 0; i < 20; i++ {
		resp, err := client.Get(fmt.Sprintf("http://%s/health", addr))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return wg.Wait
}

func runHTTPServerAsyncWithBind(ctx context.Context, t *testing.T, bind string, port int, v *vaultpkg.Vault) func() {
	return runHTTPServerAsyncWithFactory(ctx, t, bind, port, v, mcp.New)
}

func runHTTPServerAsync(ctx context.Context, t *testing.T, port int, v *vaultpkg.Vault) func() {
	return runHTTPServerAsyncWithFactory(ctx, t, "127.0.0.1", port, v, mcp.New)
}

func testMCPToken(t *testing.T) string {
	t.Helper()
	vaultDir, _ := vaultPath()
	// Try the legacy token file first; if it was migrated and deleted,
	// fall back to the token stored in testTokens.
	tokenBytes, err := os.ReadFile(filepath.Join(vaultDir, "mcp-token"))
	if err == nil {
		return strings.TrimSpace(string(tokenBytes))
	}
	if token, ok := testTokens.Load(vaultDir); ok {
		return token.(string)
	}
	t.Fatalf("read token: %v", err)
	return ""
}

func setValidMCPHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "default")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
}

func TestRunHTTPServer_HealthEndpoint(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	client := newTestHTTPClient()
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("health Content-Type = %q, want application/json", contentType)
	}

	var healthResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		t.Fatalf("decode health response: %v", err)
	}

	if healthResp["status"] != "healthy" {
		t.Errorf("health status = %v, want healthy", healthResp["status"])
	}
	if healthResp["version"] == "" {
		t.Error("health version is empty")
	}
	if healthResp["timestamp"] == "" {
		t.Error("health timestamp is empty")
	}
	if healthResp["port"] == nil {
		t.Error("health port is missing")
	}
}

func TestRunHTTPServer_MCPEndpoint_Auth(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	token := testMCPToken(t)

	resp, err := newTestHTTPClient().Post(baseURL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing agent header status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestRunHTTPServer_MCPEndpoint_WithAgent(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0.0"},
		},
	}
	payload, _ := json.Marshal(msg)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "default")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should get some response (initialize handler returns a result even with nil server)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("mcp status = %d, want %d or %d", resp.StatusCode, http.StatusOK, http.StatusInternalServerError)
	}
}

func TestRunHTTPServer_MethodNotAllowed(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "default")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("mcp GET request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /mcp status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestRunHTTPServer_InvalidJSON(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader("{broken"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "default")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid JSON status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var errResp mcp.Message
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	if errResp.Error == nil {
		t.Fatal("expected error in response")
	}
	if errResp.Error.Code != mcp.ErrCodeParseError {
		t.Errorf("error code = %d, want %d", errResp.Error.Code, mcp.ErrCodeParseError)
	}
	if !strings.Contains(errResp.Error.Message, "invalid JSON") {
		t.Errorf("error message = %q, want contains 'invalid JSON'", errResp.Error.Message)
	}
}

func TestRunHTTPServer_HTTPTransportHeaderValidation(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	payload := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}`)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", payload)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "default")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("missing content-type request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("missing Content-Type status = %d, want %d", resp.StatusCode, http.StatusUnsupportedMediaType)
	}

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "default")
	req.Header.Set("Content-Type", "application/json")
	resp, err = newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("missing accept request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("missing Accept status = %d, want %d", resp.StatusCode, http.StatusNotAcceptable)
	}
}

func TestRunHTTPServer_NotificationReturnsAccepted(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	setValidMCPHeaders(req, token)
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("notification request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	if strings.TrimSpace(body.String()) != "" {
		t.Fatalf("notification response body = %q, want empty", body.String())
	}
}

func TestRunHTTPServer_BadOriginForbidden(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	setValidMCPHeaders(req, token)
	req.Header.Set("Origin", "https://evil.example")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("bad origin request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad Origin status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestRunHTTPServer_UnsupportedProtocolHeader(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	setValidMCPHeaders(req, token)
	req.Header.Set("MCP-Protocol-Version", "1999-01-01")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("unsupported protocol request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsupported protocol status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestRunHTTPServer_HandlerCreationError(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	factory := func(_ *vaultpkg.Vault, _ string, _ string) (*mcp.Server, error) {
		return nil, errors.New("agent not found")
	}

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsyncWithFactory(ctx, t, "127.0.0.1", port, v, factory)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	}
	payload, _ := json.Marshal(msg)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "test-agent")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("handler creation error status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	var errResp mcp.Message
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	if errResp.Error == nil {
		t.Fatal("expected error in response")
	}
	if errResp.Error.Code != mcp.ErrCodeInternalError {
		t.Errorf("error code = %d, want %d", errResp.Error.Code, mcp.ErrCodeInternalError)
	}
	if !strings.Contains(errResp.Error.Message, "agent not found") {
		t.Errorf("error message = %q, want contains 'agent not found'", errResp.Error.Message)
	}
}

func TestRunHTTPServer_HandlerCacheHit(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	var callCount int
	factory := func(vault *vaultpkg.Vault, agentName string, transport string) (*mcp.Server, error) {
		callCount++
		return mcp.New(vault, agentName, transport)
	}

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsyncWithFactory(ctx, t, "127.0.0.1", port, v, factory)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0.0"},
		},
	}
	payload, _ := json.Marshal(msg)

	req1, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	req1.Header.Set("Authorization", "Bearer "+token)
	req1.Header.Set("X-OpenPass-Agent", "default")
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Accept", "application/json, text/event-stream")

	resp1, err := newTestHTTPClient().Do(req1)
	if err != nil {
		t.Fatalf("first mcp request failed: %v", err)
	}
	_ = resp1.Body.Close()

	req2, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("X-OpenPass-Agent", "default")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")

	resp2, err := newTestHTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("second mcp request failed: %v", err)
	}
	_ = resp2.Body.Close()

	if callCount != 1 {
		t.Errorf("factory called %d times, want 1 (cache hit expected)", callCount)
	}
}

func TestRunHTTPServer_CustomTokenPath(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	customTokenPath := filepath.Join(t.TempDir(), "custom-token")
	tokenContent := "custom-test-token-12345"
	if err := os.WriteFile(customTokenPath, []byte(tokenContent+"\n"), 0o600); err != nil {
		t.Fatalf("write custom token: %v", err)
	}

	v.Config.MCP = &config.MCPConfig{
		HTTPTokenFile: customTokenPath,
	}

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tokenContent)
	req.Header.Set("X-OpenPass-Agent", "default")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("custom token auth failed: status = %d, want not %d", resp.StatusCode, http.StatusUnauthorized)
	}

	req2, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader("{}"))
	req2.Header.Set("Authorization", "Bearer wrong-token")
	req2.Header.Set("X-OpenPass-Agent", "default")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")

	resp2, err := newTestHTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want %d", resp2.StatusCode, http.StatusUnauthorized)
	}
}

func TestRunHTTPServer_HandleMessageError(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "list_entries",
			"arguments": map[string]any{},
		},
	}
	payload, _ := json.Marshal(msg)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-OpenPass-Agent", "default")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("mcp request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("tools/call status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var errResp mcp.Message
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if errResp.Error == nil {
		t.Fatal("expected error in response for uninitialized tools/call")
	}
	if errResp.Error.Code != mcp.ErrCodeServerError {
		t.Errorf("error code = %d, want %d", errResp.Error.Code, mcp.ErrCodeServerError)
	}
}

func TestServeCommand_StdioOnlyDoesNotStartHTTP(t *testing.T) {
	resetCommandTestState()
	t.Cleanup(resetCommandTestState)

	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	var stdioStarted bool
	var httpStarted bool
	runStdioServerFunc = func(_ context.Context, _ *vaultpkg.Vault, agentName string) error {
		stdioStarted = true
		if agentName != "default" {
			t.Errorf("agentName = %q, want default", agentName)
		}
		return nil
	}
	runHTTPServerFunc = func(_ context.Context, _ string, _ int, _ *vaultpkg.Vault) error {
		httpStarted = true
		return nil
	}
	serveSignalNotify = func(_ chan<- os.Signal, _ ...os.Signal) {}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--stdio", "--agent", "default"})
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("serve command failed: %v", err)
	}
	if !stdioStarted {
		t.Fatal("stdio server was not started")
	}
	if httpStarted {
		t.Fatal("http server must not start in stdio-only mode")
	}
}

// setupServeCommandTest prepares the common test infrastructure for serve command
// session tests. It returns the vault directory and a cleanup function that must
// be deferred by the caller.
func setupServeCommandTest(t *testing.T) (vaultDir string, cleanup func()) {
	t.Helper()
	resetCommandTestState()
	t.Cleanup(resetCommandTestState)
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	cleanup = setupVaultFlag(t, vaultDir)
	runHTTPServerFunc = func(_ context.Context, _ string, _ int, _ *vaultpkg.Vault) error {
		return nil
	}
	serveSignalNotify = func(_ chan<- os.Signal, _ ...os.Signal) {}
	return vaultDir, cleanup
}

func TestServeCommand_ActiveSessionUsesNonInteractiveUnlock(t *testing.T) {
	vaultDir, cleanup := setupServeCommandTest(t)
	defer cleanup()

	sessionIsExpired = func(string) bool { return false }
	defer func() { sessionIsExpired = session.IsSessionExpired }()

	var unlockCalls []bool
	serveUnlockVault = func(_ string, interactive bool) (*vaultpkg.Vault, error) {
		unlockCalls = append(unlockCalls, interactive)
		return &vaultpkg.Vault{}, nil
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--port", "18080"})
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("serve command failed: %v", err)
	}

	if len(unlockCalls) != 1 {
		t.Fatalf("expected 1 unlock call, got %d: %v", len(unlockCalls), unlockCalls)
	}
	if unlockCalls[0] != false {
		t.Errorf("expected non-interactive unlock (interactive=false) for active session, got interactive=%v", unlockCalls[0])
	}
}

func TestServeCommand_ExpiredSessionUsesInteractiveUnlock(t *testing.T) {
	vaultDir, cleanup := setupServeCommandTest(t)
	defer cleanup()

	sessionIsExpired = func(string) bool { return true }
	defer func() { sessionIsExpired = session.IsSessionExpired }()

	var unlockCalls []bool
	serveUnlockVault = func(_ string, interactive bool) (*vaultpkg.Vault, error) {
		unlockCalls = append(unlockCalls, interactive)
		return nil, nil
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--port", "18081"})
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("serve command failed: %v", err)
	}

	if len(unlockCalls) != 1 {
		t.Fatalf("expected 1 unlock call, got %d: %v", len(unlockCalls), unlockCalls)
	}
	if unlockCalls[0] != true {
		t.Errorf("expected interactive unlock (interactive=true) for expired session, got interactive=%v", unlockCalls[0])
	}
}

func TestServeCommand_ActiveSessionFallbackToInteractive(t *testing.T) {
	vaultDir, cleanup := setupServeCommandTest(t)
	defer cleanup()

	sessionIsExpired = func(string) bool { return false }
	defer func() { sessionIsExpired = session.IsSessionExpired }()

	var unlockCalls []bool
	serveUnlockVault = func(_ string, interactive bool) (*vaultpkg.Vault, error) {
		unlockCalls = append(unlockCalls, interactive)
		if !interactive {
			return nil, fmt.Errorf("non-interactive unlock failed")
		}
		return nil, nil
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--port", "18082"})
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("serve command failed: %v", err)
	}

	if len(unlockCalls) != 2 {
		t.Fatalf("expected 2 unlock calls (non-interactive + fallback), got %d: %v", len(unlockCalls), unlockCalls)
	}
	if unlockCalls[0] != false {
		t.Errorf("expected first call to be non-interactive, got interactive=%v", unlockCalls[0])
	}
	if unlockCalls[1] != true {
		t.Errorf("expected second call to be interactive fallback, got interactive=%v", unlockCalls[1])
	}
}

func TestRunStdioServer_WithNilVault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Replace os.Stdin / os.Stdout so stdio transport doesn't block on real TTY
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdin = r
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Cancel immediately so transport.Start returns quickly
		cancel()
		_ = serverbootstrap.RunStdioServer(ctx, nil, "", mcp.New)
	}()

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("RunStdioServer did not return in time")
	}

	wg.Wait()

	os.Stdin = oldStdin
	os.Stdout = oldStdout
	_ = r.Close()
	_ = w.Close()
	_ = pr.Close()
	_ = pw.Close()
}

func TestRunHTTPServer_HealthEndpoint_NonLoopback(t *testing.T) {
	v := newTestVault(t)
	v.Config.MCP = &config.MCPConfig{AllowInsecureBind: true}
	port := reserveFreePortForBind(t, "0.0.0.0")

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsyncWithBind(ctx, t, "0.0.0.0", port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	resp, err := newTestHTTPClient().Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestCmdServe_EmptyBind(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_VAULT") })

	t.Cleanup(func() {
		_ = serveCmd.Flags().Set("bind", "127.0.0.1")
		_ = serveCmd.Flags().Set("stdio", "false")
	})

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--bind", ""})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for empty bind address")
	}
	if !strings.Contains(execErr.Error(), "bind") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestCmdServe_MissingAgentInStdioMode(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)
	_ = os.Setenv("OPENPASS_VAULT", vaultDir)
	t.Cleanup(func() { _ = os.Unsetenv("OPENPASS_VAULT") })

	t.Cleanup(func() {
		_ = serveCmd.Flags().Set("bind", "127.0.0.1")
		_ = serveCmd.Flags().Set("stdio", "false")
		_ = serveCmd.Flags().Set("agent", "")
	})
	_ = serveCmd.Flags().Set("agent", "")

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--bind", "127.0.0.1", "--stdio"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for missing --agent in stdio mode")
	}
	if !strings.Contains(execErr.Error(), "--agent") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestServe_RunE_HTTPWithAgent(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	vaultFlagReset(t)

	const port = 18080

	origFindAvailablePort := findAvailablePortFunc
	findAvailablePortFunc = func(bind string, preferredPort int) (int, bool, error) {
		if bind != "127.0.0.1" {
			t.Errorf("port allocator bind = %q, want 127.0.0.1", bind)
		}
		if preferredPort != port {
			t.Errorf("preferred port = %d, want %d", preferredPort, port)
		}
		return preferredPort, true, nil
	}
	t.Cleanup(func() { findAvailablePortFunc = origFindAvailablePort })

	serveSignals := make(chan chan<- os.Signal, 1)
	origNotify := serveSignalNotify
	serveSignalNotify = func(c chan<- os.Signal, sigs ...os.Signal) {
		serveSignals <- c
	}
	t.Cleanup(func() { serveSignalNotify = origNotify })

	origUnlock := serveUnlockVault
	serveUnlockVault = func(vaultDir string, interactive bool) (*vaultpkg.Vault, error) {
		if !interactive {
			t.Error("HTTP mode should request interactive unlock")
		}
		return &vaultpkg.Vault{Dir: vaultDir, Identity: identity, Config: cfg}, nil
	}
	t.Cleanup(func() { serveUnlockVault = origUnlock })

	started := make(chan struct{})
	origHTTP := runHTTPServerFunc
	runHTTPServerFunc = func(ctx context.Context, bind string, gotPort int, v *vaultpkg.Vault) error {
		if bind != "127.0.0.1" {
			t.Errorf("bind = %q, want 127.0.0.1", bind)
		}
		if gotPort != port {
			t.Errorf("port = %d, want %d", gotPort, port)
		}
		if v == nil || v.Identity == nil {
			t.Error("expected unlocked vault with identity")
		}
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return nil
	}
	t.Cleanup(func() { runHTTPServerFunc = origHTTP })

	t.Cleanup(func() {
		_ = serveCmd.Flags().Set("bind", "127.0.0.1")
		_ = serveCmd.Flags().Set("stdio", "false")
		_ = serveCmd.Flags().Set("agent", "")
	})

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--agent", "test-agent", "--port", fmt.Sprintf("%d", port)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rootCmd.Execute()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not start in time")
	}

	select {
	case sigCh := <-serveSignals:
		sigCh <- syscall.SIGTERM
	case <-time.After(2 * time.Second):
		t.Fatal("serve command did not install signal handler")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve command did not shut down after test signal")
	}
}

func TestCmdServe_UninitializedVault(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	_ = serveCmd.Flags().Set("bind", "127.0.0.1")
	_ = serveCmd.Flags().Set("stdio", "false")

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--bind", "127.0.0.1"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Error("expected error for uninitialized vault")
	}
	if !strings.Contains(execErr.Error(), "vault not initialized") {
		t.Errorf("unexpected error: %v", execErr)
	}
}

func TestServe_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("uninitialized vault", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "serve", "--port", "0"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %v", err)
		}
	})

	t.Run("stdio without agent", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
		defer func() {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "serve", "--stdio"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "--agent is required") {
			t.Errorf("expected '--agent is required' error, got: %v", err)
		}
	})

	t.Run("empty bind address", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := config.Default()
		_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
		defer func() {
			_ = os.Unsetenv("OPENPASS_VAULT")
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
		}()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "serve", "--bind", ""})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "bind") {
			t.Errorf("expected bind error, got: %v", err)
		}
	})
}

func TestServe_HTTPSignalShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow integration server test in short mode")
	}
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

	_ = serveCmd.Flags().Set("bind", "127.0.0.1")
	_ = serveCmd.Flags().Set("stdio", "false")

	port := findFreePort(t)

	origNotify := serveSignalNotify
	t.Cleanup(func() { serveSignalNotify = origNotify })
	serveSignalNotify = func(c chan<- os.Signal, sigs ...os.Signal) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			c <- syscall.SIGTERM
		}()
	}

	rootCmd.SetArgs([]string{"--vault", tmpDir, "serve", "--port", fmt.Sprintf("%d", port)})
	defer rootCmd.SetArgs(nil)

	done := make(chan struct{})
	go func() {
		_ = rootCmd.Execute()
		close(done)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not exit after signal")
	}
}

func TestIsLocalhostBind(t *testing.T) {
	tests := []struct {
		bind string
		want bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"", false},
		{"::", false},
	}
	for _, tt := range tests {
		got := isLocalhostBind(tt.bind)
		if got != tt.want {
			t.Errorf("isLocalhostBind(%q) = %v, want %v", tt.bind, got, tt.want)
		}
	}
}

func TestCmdServe_NonLoopbackWarning(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	vaultFlagReset(t)

	const port = 18181
	httpDone := make(chan struct{}, 1)

	origFindAvailablePort := findAvailablePortFunc
	findAvailablePortFunc = func(bind string, preferredPort int) (int, bool, error) {
		return preferredPort, true, nil
	}
	defer func() { findAvailablePortFunc = origFindAvailablePort }()

	serveSignals := make(chan chan<- os.Signal, 1)
	origNotify := serveSignalNotify
	serveSignalNotify = func(c chan<- os.Signal, sigs ...os.Signal) {
		serveSignals <- c
	}
	defer func() { serveSignalNotify = origNotify }()

	origUnlock := serveUnlockVault
	serveUnlockVault = func(vaultDir string, interactive bool) (*vaultpkg.Vault, error) {
		return &vaultpkg.Vault{Dir: vaultDir, Identity: identity, Config: cfg}, nil
	}
	defer func() { serveUnlockVault = origUnlock }()

	origHTTP := runHTTPServerFunc
	runHTTPServerFunc = func(ctx context.Context, bind string, gotPort int, v *vaultpkg.Vault) error {
		<-ctx.Done()
		httpDone <- struct{}{}
		return nil
	}
	defer func() { runHTTPServerFunc = origHTTP }()

	_ = serveCmd.Flags().Set("stdio", "false")
	_ = serveCmd.Flags().Set("agent", "")
	_ = serveCmd.Flags().Set("port", fmt.Sprintf("%d", port))
	_ = serveCmd.Flags().Set("bind", "0.0.0.0")

	rootCmd.SetArgs([]string{"--vault", vaultDir, "serve", "--bind", "0.0.0.0", "--port", fmt.Sprintf("%d", port)})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		_ = serveCmd.Flags().Set("bind", "127.0.0.1")
	})

	done := make(chan struct{})
	stderr := captureStderr(func() {
		go func() {
			_ = rootCmd.Execute()
			close(done)
		}()
		sigCh := <-serveSignals
		sigCh <- syscall.SIGINT
		<-httpDone
		<-done
	})

	if !strings.Contains(stderr, "Warning:") || !strings.Contains(stderr, "unencrypted") {
		t.Errorf("expected TLS warning on stderr for non-loopback bind, got: %s", stderr)
	}
}

func TestServe_StdioError(t *testing.T) {
	resetVaultState(t)

	tmpDir := t.TempDir()
	_ = os.Setenv("OPENPASS_VAULT", tmpDir)
	_ = os.Setenv("OPENPASS_PASSPHRASE", "test")
	defer func() {
		_ = os.Unsetenv("OPENPASS_VAULT")
		_ = os.Unsetenv("OPENPASS_PASSPHRASE")
	}()

	cfg := config.Default()
	_, _ = vaultpkg.InitWithPassphrase(tmpDir, []byte("test"), cfg)

	_ = serveCmd.Flags().Set("bind", "127.0.0.1")
	_ = serveCmd.Flags().Set("stdio", "false")
	_ = serveCmd.Flags().Set("agent", "")

	port := findFreePort(t)

	origRunStdio := runStdioServerFunc
	runStdioServerFunc = func(_ context.Context, _ *vaultpkg.Vault, _ string) error {
		return fmt.Errorf("mock stdio error")
	}
	defer func() { runStdioServerFunc = origRunStdio }()

	rootCmd.SetArgs([]string{"--vault", tmpDir, "serve", "--stdio", "--agent", "test-agent", "--port", fmt.Sprintf("%d", port)})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mock stdio error") {
		t.Errorf("expected mock stdio error, got: %v", err)
	}
}
