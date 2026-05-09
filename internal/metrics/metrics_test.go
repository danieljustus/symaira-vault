package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordMCPRequest(t *testing.T) {
	RecordMCPRequest("list", "default", "success", 100*time.Millisecond)
	RecordMCPRequest("list", "default", "success", 200*time.Millisecond)
	RecordMCPRequest("get", "claude", "error", 50*time.Millisecond)

	count, err := testutil.GatherAndCount(Registry(), "openpass_mcp_requests_total")
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	if count == 0 {
		t.Error("expected non-zero metric count")
	}

	expected := `
		# HELP openpass_mcp_requests_total Total number of MCP tool requests.
		# TYPE openpass_mcp_requests_total counter
		openpass_mcp_requests_total{agent="default",status="success",tool="list"} 2
		openpass_mcp_requests_total{agent="claude",status="error",tool="get"} 1
	`
	if err := testutil.GatherAndCompare(Registry(), strings.NewReader(expected), "openpass_mcp_requests_total"); err != nil {
		t.Errorf("counter mismatch: %v", err)
	}
}

func TestRecordAuthDenial(t *testing.T) {
	RecordAuthDenial("scope_denied", "default")
	RecordAuthDenial("write_denied", "claude")

	expected := `
		# HELP openpass_mcp_auth_denials_total Total number of MCP authentication/authorization denials.
		# TYPE openpass_mcp_auth_denials_total counter
		openpass_mcp_auth_denials_total{agent="default",reason="scope_denied"} 1
		openpass_mcp_auth_denials_total{agent="claude",reason="write_denied"} 1
	`
	if err := testutil.GatherAndCompare(Registry(), strings.NewReader(expected), "openpass_mcp_auth_denials_total"); err != nil {
		t.Errorf("auth denial counter mismatch: %v", err)
	}
}

func TestRecordApproval(t *testing.T) {
	RecordApproval("default", "granted")
	RecordApproval("claude", "denied")

	expected := `
		# HELP openpass_mcp_approvals_total Total number of MCP approval outcomes.
		# TYPE openpass_mcp_approvals_total counter
		openpass_mcp_approvals_total{agent="default",outcome="granted"} 1
		openpass_mcp_approvals_total{agent="claude",outcome="denied"} 1
	`
	if err := testutil.GatherAndCompare(Registry(), strings.NewReader(expected), "openpass_mcp_approvals_total"); err != nil {
		t.Errorf("approval counter mismatch: %v", err)
	}
}

func TestRecordVaultOperation(t *testing.T) {
	RecordVaultOperation("read", "success")
	RecordVaultOperation("write", "success")
	RecordVaultOperation("delete", "error")

	expected := `
		# HELP openpass_vault_operations_total Total number of vault operations.
		# TYPE openpass_vault_operations_total counter
		openpass_vault_operations_total{operation="delete",status="error"} 1
		openpass_vault_operations_total{operation="read",status="success"} 1
		openpass_vault_operations_total{operation="write",status="success"} 1
	`
	if err := testutil.GatherAndCompare(Registry(), strings.NewReader(expected), "openpass_vault_operations_total"); err != nil {
		t.Errorf("vault operation counter mismatch: %v", err)
	}
}

func TestRegistry(t *testing.T) {
	reg := Registry()
	if reg == nil {
		t.Fatal("expected non-nil registry")
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	expectedMetrics := map[string]bool{
		"openpass_mcp_requests_total":           false,
		"openpass_mcp_request_duration_seconds": false,
		"openpass_mcp_auth_denials_total":       false,
		"openpass_mcp_approvals_total":          false,
		"openpass_vault_operations_total":       false,
		"go_goroutines":                         false,
		"process_cpu_seconds_total":             false,
	}

	for _, f := range families {
		if _, ok := expectedMetrics[*f.Name]; ok {
			expectedMetrics[*f.Name] = true
		}
	}

	for name, found := range expectedMetrics {
		if !found {
			t.Errorf("expected metric %q not found in registry", name)
		}
	}
}

func TestMCPRequestDuration(t *testing.T) {
	RecordMCPRequest("get", "default", "success", 150*time.Millisecond)

	count, err := testutil.GatherAndCount(Registry(), "openpass_mcp_request_duration_seconds")
	if err != nil {
		t.Fatalf("gather duration metric: %v", err)
	}
	if count == 0 {
		t.Error("expected duration metric to be present")
	}
}

func TestRecordVaultEntryCount(t *testing.T) {
	RecordVaultEntryCount("/tmp/test-vault", 5)
	count, err := testutil.GatherAndCount(Registry(), "openpass_vault_entries_total")
	if err != nil {
		t.Fatalf("gather metric: %v", err)
	}
	if count == 0 {
		t.Error("expected vault_entries_total metric")
	}
}

func TestRecordVaultOperationDuration(t *testing.T) {
	RecordVaultOperationDuration("open", 10*time.Millisecond)
	RecordVaultOperationDuration("decrypt", 5*time.Millisecond)
	count, err := testutil.GatherAndCount(Registry(), "openpass_vault_operation_duration_seconds")
	if err != nil {
		t.Fatalf("gather metric: %v", err)
	}
	if count == 0 {
		t.Error("expected vault_operation_duration_seconds metric")
	}
}

func TestRecordSessionCacheEvent(t *testing.T) {
	RecordSessionCacheEvent("hit")
	RecordSessionCacheEvent("miss")
	count, err := testutil.GatherAndCount(Registry(), "openpass_session_cache_events_total")
	if err != nil {
		t.Fatalf("gather metric: %v", err)
	}
	if count == 0 {
		t.Error("expected session_cache_events_total metric")
	}
}

func TestRecordIdentityCacheEvent(t *testing.T) {
	RecordIdentityCacheEvent("hit")
	RecordIdentityCacheEvent("evict")
	count, err := testutil.GatherAndCount(Registry(), "openpass_session_identity_cache_events_total")
	if err != nil {
		t.Fatalf("gather metric: %v", err)
	}
	if count == 0 {
		t.Error("expected identity_cache_events_total metric")
	}
}

func TestRecordUpdateCheck(t *testing.T) {
	RecordUpdateCheck("up_to_date")
	RecordUpdateCheck("update_available")
	count, err := testutil.GatherAndCount(Registry(), "openpass_update_check_total")
	if err != nil {
		t.Fatalf("gather metric: %v", err)
	}
	if count == 0 {
		t.Error("expected update_check_total metric")
	}
}

func TestRecordPolicyEvalDuration(t *testing.T) {
	RecordPolicyEvalDuration(1 * time.Millisecond)
	count, err := testutil.GatherAndCount(Registry(), "openpass_policy_eval_duration_seconds")
	if err != nil {
		t.Fatalf("gather metric: %v", err)
	}
	if count == 0 {
		t.Error("expected policy_eval_duration_seconds metric")
	}
}

func TestInitTracing_NoEndpoint(t *testing.T) {
	shutdown, err := InitTracing("", "test-service")
	if err != nil {
		t.Fatalf("InitTracing() with no endpoint: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestTracer_ReturnsNonNil(t *testing.T) {
	tr := Tracer()
	if tr == nil {
		t.Error("expected non-nil tracer")
	}
}

func TestHashEntryPath(t *testing.T) {
	h1 := HashEntryPath("github/token")
	h2 := HashEntryPath("github/token")
	h3 := HashEntryPath("other/path")
	if h1 != h2 {
		t.Error("expected same hash for same input")
	}
	if h1 == h3 {
		t.Error("expected different hash for different input")
	}
	if h1 == "" {
		t.Error("expected non-empty hash")
	}
}

func TestStartSpan(t *testing.T) {
	ctx := context.Background()
	newCtx, span := StartSpan(ctx, "test-span")
	if newCtx == nil {
		t.Error("expected non-nil context")
	}
	if span == nil {
		t.Error("expected non-nil span")
	}
	span.End()
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()
	span := SpanFromContext(ctx)
	if span == nil {
		t.Error("expected non-nil span (should return no-op span)")
	}
}
