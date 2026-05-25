//go:build metrics

package serverbootstrap

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
)

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
	if !strings.Contains(bodyStr, "symaira_mcp_requests_total") {
		t.Error("metrics response missing symaira_mcp_requests_total")
	}
}

func TestRunHTTPServer_NonLoopbackMetricsRequiresAuth(t *testing.T) {
	v := newTestVault(t)
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
