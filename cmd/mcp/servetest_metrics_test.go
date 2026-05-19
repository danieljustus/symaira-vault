//go:build metrics

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/metrics"
)

func TestRunHTTPServer_MetricsEndpoint(t *testing.T) {
	v := newTestVault(t)
	port := reserveFreePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsync(ctx, t, port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	metrics.RecordMCPRequest("test_tool", "test_agent", "success", 100*time.Millisecond)
	metrics.RecordAuthDenial("test_reason", "test_agent")
	metrics.RecordApproval("test_agent", "granted")
	metrics.RecordVaultOperation("test_operation", "success")

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
	if !strings.Contains(bodyStr, "process_cpu_seconds_total") {
		t.Error("metrics response missing process_cpu_seconds_total")
	}
	if !strings.Contains(bodyStr, "openpass_mcp_requests_total") {
		t.Error("metrics response missing openpass_mcp_requests_total")
	}
	if !strings.Contains(bodyStr, "openpass_mcp_request_duration_seconds") {
		t.Error("metrics response missing openpass_mcp_request_duration_seconds")
	}
	if !strings.Contains(bodyStr, "openpass_mcp_auth_denials_total") {
		t.Error("metrics response missing openpass_mcp_auth_denials_total")
	}
	if !strings.Contains(bodyStr, "openpass_mcp_approvals_total") {
		t.Error("metrics response missing openpass_mcp_approvals_total")
	}
	if !strings.Contains(bodyStr, "openpass_vault_operations_total") {
		t.Error("metrics response missing openpass_vault_operations_total")
	}
}

func TestRunHTTPServer_MetricsEndpoint_NonLoopback_RequiresAuth(t *testing.T) {
	v := newTestVault(t)
	v.Config.MCP = &config.MCPConfig{
		MetricsAuthRequired: true,
		AllowInsecureBind:   true,
	}
	port := reserveFreePortForBind(t, "0.0.0.0")

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsyncWithBind(ctx, t, "0.0.0.0", port, v)
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

	token := testMCPToken(t)
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

func TestRunHTTPServer_MetricsEndpoint_NonLoopback_AllowsWhenDisabled(t *testing.T) {
	v := newTestVault(t)
	v.Config.MCP = &config.MCPConfig{
		MetricsAuthRequired: false,
		AllowInsecureBind:   true,
	}
	port := reserveFreePortForBind(t, "0.0.0.0")

	ctx, cancel := context.WithCancel(context.Background())
	waitForServer := runHTTPServerAsyncWithBind(ctx, t, "0.0.0.0", port, v)
	defer func() {
		cancel()
		waitForServer()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	resp, err := newTestHTTPClient().Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("metrics status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
