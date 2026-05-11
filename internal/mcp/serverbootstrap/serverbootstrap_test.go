package serverbootstrap

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
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/metrics"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

// testTokens stores pre-created MCP tokens for test vaults, keyed by vault
// directory. LoadTokenSystem migrates legacy mcp-token files to the registry
// and deletes the original file, so tests need a way to retrieve the token
// after the server has started.
var testTokens sync.Map            // map[string]string
var reservedTestListeners sync.Map // map[int]net.Listener

func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port //nolint:errcheck
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
	// Pre-create a legacy token so LoadTokenSystem can migrate it. The token
	// is stored in testTokens because the file is deleted during migration.
	token := "test-token-" + tmpDir[len(tmpDir)-8:]
	testTokens.Store(tmpDir, token)
	if err := os.WriteFile(filepath.Join(tmpDir, "mcp-token"), []byte(token), 0o600); err != nil {
		t.Fatalf("write test token: %v", err)
	}
	return &vaultpkg.Vault{
		Dir:    tmpDir,
		Config: config.Default(),
	}
}

func newTestHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
	}
}

func runHTTPServerAsync(ctx context.Context, t *testing.T, bind string, port int, v *vaultpkg.Vault, factory func(*vaultpkg.Vault, string, string) (*mcp.Server, error)) func() {
	t.Helper()
	var listener net.Listener
	if value, ok := reservedTestListeners.LoadAndDelete(port); ok {
		listener = value.(net.Listener)
	} else if bind == "127.0.0.1" {
		l, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("reserve HTTP listener: %v", err)
		}
		listener = l
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		vaultDir := ""
		if v != nil {
			vaultDir = v.Dir
		}
		var err error
		if listener != nil {
			err = RunHTTPServerOnListener(ctx, listener, v, vaultDir, "dev", factory)
		} else {
			err = RunHTTPServer(ctx, bind, port, v, vaultDir, "dev", factory)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("RunHTTPServer error: %v", err)
		}
	}()

	healthURL := "http://" + net.JoinHostPort(bind, strconv.Itoa(port)) + "/health"
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL) //nolint:noctx
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	return wg.Wait
}

func testMCPToken(t *testing.T, vaultDir string) string {
	t.Helper()
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

func TestRunStdioServer_NilVault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	r, _, _ := os.Pipe()
	os.Stdin = r
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cancel()
		_ = RunStdioServer(ctx, nil, "", mcp.New)
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunStdioServer did not return in time")
	}

	os.Stdin = oldStdin
	os.Stdout = oldStdout
	_ = r.Close()
	_ = pr.Close()
	_ = pw.Close()
}

func TestRunStdioServer_FactoryError(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	factory := func(_ *vaultpkg.Vault, _ string, _ string) (*mcp.Server, error) {
		return nil, errors.New("agent not found")
	}

	err := RunStdioServer(ctx, v, "default", factory)
	if err == nil {
		t.Fatal("RunStdioServer expected error, got nil")
	}
	if !strings.Contains(err.Error(), "agent not found") {
		t.Errorf("error = %q, want contains 'agent not found'", err.Error())
	}
}

func TestRunStdioServer_Success(t *testing.T) {
	v := newTestVault(t)
	ctx, cancel := context.WithCancel(context.Background())

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
		_ = RunStdioServer(ctx, v, "default", mcp.New)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunStdioServer did not shut down in time")
	}

	os.Stdin = oldStdin
	os.Stdout = oldStdout
	_ = r.Close()
	_ = w.Close()
	_ = pr.Close()
	_ = pw.Close()
}

func TestRunHTTPServer_ContextCancelled(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)

	cancel()
	waitForServer()
}

func TestRunHTTPServer_HealthEndpoint(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
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

func TestRunHTTPServer_MetricsEndpoint(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	metrics.RecordMCPRequest("test_tool", "test_agent", "success", 100*time.Millisecond)

	client := newTestHTTPClient()
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("metrics status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("metrics Content-Type = %q, want text/plain", contentType)
	}

	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	bodyStr := body.String()

	if !strings.Contains(bodyStr, "go_goroutines") {
		t.Error("metrics response missing go_goroutines")
	}
	if !strings.Contains(bodyStr, "openpass_mcp_requests_total") {
		t.Error("metrics response missing openpass_mcp_requests_total")
	}
}

func TestRunHTTPServer_MCPMethodNotAllowed(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t, v.Dir)
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

func TestRunHTTPServer_MCPMediaTypeAndAccept(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		contentType string
		accept      string
		wantStatus  int
	}{
		{
			name:        "missing content-type",
			body:        "{}",
			contentType: "",
			accept:      "application/json, text/event-stream",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "bad accept header",
			body:        `{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
			contentType: "application/json",
			accept:      "",
			wantStatus:  http.StatusNotAcceptable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestVault(t)
			port := reserveFreePort(t)

			ctx, cancel := context.WithCancel(context.Background())
			waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
			defer func() {
				cancel()
				waitForServer()
			}()

			token := testMCPToken(t, v.Dir)
			baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

			req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-OpenPass-Agent", "default")
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}

			resp, err := newTestHTTPClient().Do(req)
			if err != nil {
				t.Fatalf("mcp request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

func TestRunHTTPServer_MCPInvalidJSON(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t, v.Dir)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader("{broken"))
	setValidMCPHeaders(req, token)

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
}

func TestRunHTTPServer_MCPFactoryError(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	factory := func(_ *vaultpkg.Vault, _ string, _ string) (*mcp.Server, error) {
		return nil, errors.New("agent not found")
	}

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, factory)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t, v.Dir)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	})

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	setValidMCPHeaders(req, token)

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

func TestRunHTTPServer_HandlerCache(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	var callCount int
	factory := func(vault *vaultpkg.Vault, agentName string, transport string) (*mcp.Server, error) {
		callCount++
		return mcp.New(vault, agentName, transport)
	}

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, factory)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t, v.Dir)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0.0"},
		},
	})

	req1, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	setValidMCPHeaders(req1, token)

	resp1, err := newTestHTTPClient().Do(req1)
	if err != nil {
		t.Fatalf("first mcp request failed: %v", err)
	}
	_ = resp1.Body.Close()

	req2, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(payload))
	setValidMCPHeaders(req2, token)

	resp2, err := newTestHTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("second mcp request failed: %v", err)
	}
	_ = resp2.Body.Close()

	if callCount != 1 {
		t.Errorf("factory called %d times, want 1 (cache hit expected)", callCount)
	}
}

func TestRunHTTPServer_CustomConfig(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	customTokenPath := filepath.Join(t.TempDir(), "custom-token")
	tokenContent := "custom-test-token-12345"
	if err := os.WriteFile(customTokenPath, []byte(tokenContent+"\n"), 0o600); err != nil {
		t.Fatalf("write custom token: %v", err)
	}

	v.Config.MCP = &config.MCPConfig{
		HTTPTokenFile:       customTokenPath,
		RateLimit:           120,
		ReadHeaderTimeout:   3 * time.Second,
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        5 * time.Second,
		ShutdownTimeout:     2 * time.Second,
		MetricsAuthRequired: false,
	}

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
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
		t.Errorf("custom token auth failed: status = %d", resp.StatusCode)
	}
}

func TestRunHTTPServer_NonLoopbackMetricsRequiresAuth(t *testing.T) {
	v := newTestVault(t)
	// Non-loopback bind without TLS now requires explicit opt-in.
	if v.Config.MCP == nil {
		v.Config.MCP = &config.MCPConfig{MetricsAuthRequired: true}
	} else {
		v.Config.MCP.MetricsAuthRequired = true
	}
	v.Config.MCP.AllowInsecureBind = true
	port := reserveFreePortForBind(t, "0.0.0.0")

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "0.0.0.0", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	resp, err := newTestHTTPClient().Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("metrics without auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	token := testMCPToken(t, v.Dir)
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("metrics request with auth failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("metrics with auth status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestRunHTTPServer_NonLoopbackWithoutTLSRefused(t *testing.T) {
	v := newTestVault(t)
	// Default config: AllowInsecureBind = false, no TLS cert. Non-loopback
	// bind must be refused outright so bearer tokens cannot leak in cleartext.
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	err = RunHTTPServerOnListener(context.Background(), listener, v, v.Dir, "test", mcp.New)
	if err == nil || !strings.Contains(err.Error(), "refusing to serve MCP without TLS") {
		t.Fatalf("expected non-loopback-without-TLS refusal, got %v", err)
	}
}

func TestRunHTTPServer_SecurityHeaders(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		headerName  string
		headerValue string
		wantStatus  int
	}{
		{
			name:        "unsupported protocol version",
			body:        `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			headerName:  "MCP-Protocol-Version",
			headerValue: "1999-01-01",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "bad origin forbidden",
			body:        `{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
			headerName:  "Origin",
			headerValue: "https://evil.example",
			wantStatus:  http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestVault(t)
			port := reserveFreePort(t)

			ctx, cancel := context.WithCancel(context.Background())
			waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
			defer func() {
				cancel()
				waitForServer()
			}()

			token := testMCPToken(t, v.Dir)
			baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

			req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(tc.body))
			setValidMCPHeaders(req, token)
			req.Header.Set(tc.headerName, tc.headerValue)

			resp, err := newTestHTTPClient().Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

func TestRunHTTPServer_NotificationReturnsAccepted(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t, v.Dir)
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

func TestRunHTTPServer_InitializeAndToolsList(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	token := testMCPToken(t, v.Dir)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	initPayload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0.0"},
		},
	})

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(initPayload))
	setValidMCPHeaders(req, token)

	resp, err := newTestHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("initialize request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("initialize status = %d, want %d or %d", resp.StatusCode, http.StatusOK, http.StatusInternalServerError)
	}

	listPayload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})

	req2, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(listPayload))
	setValidMCPHeaders(req2, token)

	resp2, err := newTestHTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("tools/list request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("tools/list status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
}
