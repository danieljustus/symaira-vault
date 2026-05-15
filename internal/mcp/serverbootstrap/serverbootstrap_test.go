package serverbootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
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

//nolint:unparam // bind varies across build tags (metrics build uses "0.0.0.0")
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

func TestRunHTTPServer_OAuthProtectedResource(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	client := newTestHTTPClient()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/.well-known/oauth-protected-resource", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("oauth-protected-resource request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body["resource"] == nil {
		t.Error("resource field is missing")
	} else if resource, ok := body["resource"].(string); !ok {
		t.Error("resource field is not a string")
	} else if !strings.HasSuffix(resource, "/mcp") {
		t.Errorf("resource = %q, want suffix /mcp", resource)
	}

	if body["bearer_methods_supported"] == nil {
		t.Error("bearer_methods_supported field is missing")
	}
	if body["resource_name"] == nil {
		t.Error("resource_name field is missing")
	}
	if _, ok := body["authorization_servers"]; ok {
		t.Error("authorization_servers field must NOT be present")
	}
}

func TestRunHTTPServer_OAuthAuthorizationServer(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	client := newTestHTTPClient()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/.well-known/oauth-authorization-server", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("oauth-authorization-server request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	requiredFields := []string{"issuer", "authorization_endpoint", "token_endpoint",
		"registration_endpoint", "response_types_supported", "code_challenge_methods_supported",
		"token_endpoint_auth_methods_supported", "grant_types_supported"}
	for _, field := range requiredFields {
		if body[field] == nil {
			t.Errorf("%s field is missing", field)
		}
	}
	if regEP, ok := body["registration_endpoint"].(string); ok {
		if !strings.HasSuffix(regEP, "/oauth/register") {
			t.Errorf("registration_endpoint = %q, want suffix /oauth/register", regEP)
		}
	}

	if authEP, ok := body["authorization_endpoint"].(string); ok {
		if !strings.HasSuffix(authEP, "/mcp/oauth/authorize") {
			t.Errorf("authorization_endpoint = %q, want suffix /mcp/oauth/authorize", authEP)
		}
	}
	if tokenEP, ok := body["token_endpoint"].(string); ok {
		if !strings.HasSuffix(tokenEP, "/mcp/oauth/token") {
			t.Errorf("token_endpoint = %q, want suffix /mcp/oauth/token", tokenEP)
		}
	}
}

func TestRunHTTPServer_OAuthEndpoints(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, "127.0.0.1", port, v, mcp.New)
	defer func() {
		cancel()
		waitForServer()
	}()

	client := newTestHTTPClient()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	for _, contentType := range []string{"application/json", "application/json; charset=utf-8"} {
		t.Run("register endpoint success "+contentType, func(t *testing.T) {
			reqBody := `{"redirect_uris": ["http://127.0.0.1:1234/callback"]}`
			req, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/register", strings.NewReader(reqBody))
			req.Header.Set("Content-Type", contentType)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("register request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusCreated {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
			}
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body["client_id"] == nil {
				t.Error("client_id missing from registration response")
			}
			redirectURIs, ok := body["redirect_uris"].([]interface{})
			if !ok {
				t.Fatal("redirect_uris missing from registration response")
			}
			if len(redirectURIs) != 1 || redirectURIs[0] != "http://127.0.0.1:1234/callback" {
				t.Errorf("redirect_uris = %v, want [http://127.0.0.1:1234/callback]", redirectURIs)
			}
		})
	}

	t.Run("register endpoint missing redirect_uris", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/register", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("register request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body["error"] != "invalid_redirect_uri" {
			t.Errorf("error = %v, want invalid_redirect_uri", body["error"])
		}
	})

	t.Run("register endpoint empty redirect_uris", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/register", strings.NewReader(`{"redirect_uris": []}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("register request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body["error"] != "invalid_redirect_uri" {
			t.Errorf("error = %v, want invalid_redirect_uri", body["error"])
		}
	})

	t.Run("register endpoint invalid JSON", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/register", strings.NewReader(`not json`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("register request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("register endpoint wrong content type", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/register", strings.NewReader(`{"redirect_uris": ["http://127.0.0.1:1234/callback"]}`))
		req.Header.Set("Content-Type", "text/plain")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("register request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("authorize rejects missing params", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/mcp/oauth/authorize", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("authorize request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("token rejects missing code", func(t *testing.T) {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {"invalid"}, "code_verifier": {"v"}}
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("token request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", body["error"])
		}
	})
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

func TestRunHTTPServer_OAuthClientPersistenceAcrossRestart(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	ctx1, cancel1 := context.WithCancel(context.Background())
	wait1 := runHTTPServerAsync(ctx1, t, "127.0.0.1", port, v, mcp.New)

	client := newTestHTTPClient()
	reqBody := `{"redirect_uris": ["http://127.0.0.1:9999/callback"]}`
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/register", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	var regResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	clientID, ok := regResp["client_id"].(string)
	if !ok || clientID == "" {
		t.Fatal("client_id missing from registration response")
	}

	clientFilePath := filepath.Join(v.Dir, oauthClientsFileName)
	if _, err := os.Stat(clientFilePath); err != nil {
		t.Fatalf("client store file missing: %v", err)
	}

	cancel1()
	wait1()

	v2 := &vaultpkg.Vault{
		Dir:    v.Dir,
		Config: config.Default(),
	}

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("re-listen: %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() {
		_ = RunHTTPServerOnListener(ctx2, listener, v2, v2.Dir, "dev", mcp.New)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	authURL := fmt.Sprintf("http://127.0.0.1:%d/mcp/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&code_challenge=abc123&code_challenge_method=S256&state=test",
		port, clientID, url.QueryEscape("http://127.0.0.1:9999/callback"))
	authReq, _ := http.NewRequest(http.MethodGet, authURL, nil)
	authReq.Header.Set("Origin", fmt.Sprintf("http://127.0.0.1:%d", port))
	resp2, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("authorize request after restart: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	// After restart the registered client should still be known. If the client
	// were not persisted, the response would be 400 with "invalid_client".
	// A 403 (user consent denied) or 302 (redirect with auth code) both confirm
	// the client was found.
	if resp2.StatusCode == http.StatusBadRequest {
		var errBody map[string]any
		_ = json.NewDecoder(resp2.Body).Decode(&errBody)
		if errBody["error"] == "invalid_client" {
			t.Fatalf("client was not persisted across restart: %v", errBody)
		}
	}
}
