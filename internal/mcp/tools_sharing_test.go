package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testShareRequest is a convenience constructor.
func testShareRequest(args map[string]any) CallToolRequest {
	return CallToolRequest{Arguments: args}
}

// testShareServer builds a minimal Server for share handler tests.
// agentName defaults to "test-agent"; allowedPaths defaults to ["vault/secret"].
func testShareServer(t *testing.T, agentName string, allowedPaths []string) *Server {
	t.Helper()
	dir := t.TempDir()
	if agentName == "" {
		agentName = "test-agent"
	}
	if allowedPaths == nil {
		allowedPaths = []string{"vault/secret"}
	}
	store := NewShareStore(filepath.Join(dir, "mcp-shares.json"))
	return &Server{
		agent: &config.AgentProfile{
			Name:         agentName,
			AllowedPaths: allowedPaths,
		},
		shareStore: store,
	}
}

// withMockApprovalTTY replaces the package-level TTY opener so that
// IsTTYPresent() returns true and RequestApproval() reads readValue.
func withMockApprovalTTY(t *testing.T, readValue string, f func()) {
	t.Helper()
	old := openTTYDevice
	outFile := newMockOutputFile(t)
	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return readValue, nil },
			output:     outFile,
		}, nil
	}
	t.Cleanup(func() {
		openTTYDevice = old
	})
	f()
}

// ---------------------------------------------------------------------------
// handleRequestShare tests
// ---------------------------------------------------------------------------

func TestHandleRequestShare_Success(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"to_agent":    "target-agent",
		"secret_path": "vault/secret/password",
	})

	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRequestShare() returned Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRequestShare() returned tool error: %s", result.Text)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(result.Text), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if parsed["status"] != string(SharePending) {
		t.Errorf("status = %v, want %s", parsed["status"], SharePending)
	}
	if parsed["from_agent"] != "test-agent" {
		t.Errorf("from_agent = %v, want test-agent", parsed["from_agent"])
	}
	if parsed["to_agent"] != "target-agent" {
		t.Errorf("to_agent = %v, want target-agent", parsed["to_agent"])
	}
	if parsed["secret_path"] != "vault/secret/password" {
		t.Errorf("secret_path = %v, want vault/secret/password", parsed["secret_path"])
	}
	grantID, ok := parsed["grant_id"]
	if !ok || grantID == "" {
		t.Error("grant_id should be non-empty")
	}
}

func TestHandleRequestShare_WithFieldAndTTL(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"to_agent":     "target-agent",
		"secret_path":  "vault/secret/password",
		"secret_field": "password_field",
		"ttl":          "30m",
	})

	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRequestShare() returned Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRequestShare() returned tool error: %s", result.Text)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(result.Text), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	// Verify grant details via store
	grantID := parsed["grant_id"].(string)
	grant, ok := srv.shareStore.Get(grantID)
	if !ok {
		t.Fatal("grant not found in store after creation")
	}
	if grant.SecretField != "password_field" {
		t.Errorf("SecretField = %q, want %q", grant.SecretField, "password_field")
	}
	if grant.TTL != 30*time.Minute {
		t.Errorf("TTL = %v, want 30m", grant.TTL)
	}
	if grant.ExpiresAt == nil {
		t.Error("ExpiresAt should be set when TTL > 0")
	}
	expectedExpiry := grant.CreatedAt.Add(30 * time.Minute)
	delta := grant.ExpiresAt.Sub(expectedExpiry)
	if delta > time.Second {
		t.Errorf("ExpiresAt delta from expected = %v, want <= 1s", delta)
	}
}

func TestHandleRequestShare_MissingToAgent(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"secret_path": "vault/secret/password",
	})

	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error for missing arg; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for missing to_agent")
	}
	if !strings.Contains(result.Text, "to_agent") {
		t.Errorf("error text = %q, want mention of to_agent", result.Text)
	}
}

func TestHandleRequestShare_MissingSecretPath(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"to_agent": "target-agent",
	})

	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error for missing arg; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for missing secret_path")
	}
	if !strings.Contains(result.Text, "secret_path") {
		t.Errorf("error text = %q, want mention of secret_path", result.Text)
	}
}

func TestHandleRequestShare_ScopeDenied(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"to_agent":    "target-agent",
		"secret_path": "other/namespace/secret",
	})

	_, err := srv.handleRequestShare(context.Background(), req)
	if err == nil {
		t.Fatal("expected Go error for scope denial")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Errorf("error = %v, want scope denial message", err)
	}
}

func TestHandleRequestShare_ScopeDenied_NoAllowedPaths(t *testing.T) {
	srv := testShareServer(t, "", []string{})
	req := testShareRequest(map[string]any{
		"to_agent":    "target-agent",
		"secret_path": "vault/secret/password",
	})

	_, err := srv.handleRequestShare(context.Background(), req)
	if err == nil {
		t.Fatal("expected Go error when no allowed paths configured")
	}
}

func TestHandleRequestShare_InvalidTTL(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"to_agent":    "target-agent",
		"secret_path": "vault/secret/password",
		"ttl":         "not-a-duration",
	})

	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error for invalid TTL; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for invalid TTL")
	}
	if !strings.Contains(result.Text, "invalid ttl") {
		t.Errorf("error text = %q, want mention of invalid ttl", result.Text)
	}
}

func TestHandleRequestShare_NegativeTTL(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"to_agent":    "target-agent",
		"secret_path": "vault/secret/password",
		"ttl":         "-5m",
	})

	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error for negative TTL; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for negative TTL")
	}
}

func TestHandleRequestShare_WildcardScope(t *testing.T) {
	srv := testShareServer(t, "", []string{"*"})
	req := testShareRequest(map[string]any{
		"to_agent":    "target-agent",
		"secret_path": "any/path/at/all",
	})

	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRequestShare() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRequestShare() returned error: %s", result.Text)
	}

	var parsed map[string]any
	json.Unmarshal([]byte(result.Text), &parsed)
	if parsed["secret_path"] != "any/path/at/all" {
		t.Errorf("secret_path = %v, want any/path/at/all", parsed["secret_path"])
	}
}

// ---------------------------------------------------------------------------
// handleApproveShare tests
// ---------------------------------------------------------------------------

func TestHandleApproveShare_MissingGrantID(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{})

	result, err := srv.handleApproveShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error for missing arg; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for missing grant_id")
	}
}

func TestHandleApproveShare_GrantNotFound(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{
		"grant_id": "nonexistent-grant-id",
	})

	result, err := srv.handleApproveShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for nonexistent grant")
	}
	if !strings.Contains(result.Text, "not found") {
		t.Errorf("error text = %q, want 'not found'", result.Text)
	}
}

func TestHandleApproveShare_NotPending(t *testing.T) {
	srv := testShareServer(t, "", nil)
	grant, err := srv.shareStore.Create("test-agent", "target", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Approve first so it's no longer pending.
	if err := srv.shareStore.Approve(grant.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	req := testShareRequest(map[string]any{"grant_id": grant.ID})
	result, err := srv.handleApproveShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for non-pending grant")
	}
	if !strings.Contains(result.Text, "not pending") {
		t.Errorf("error text = %q, want 'not pending'", result.Text)
	}
}

func TestHandleApproveShare_NoTTY(t *testing.T) {
	srv := testShareServer(t, "", nil)
	grant, err := srv.shareStore.Create("test-agent", "target", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	req := testShareRequest(map[string]any{"grant_id": grant.ID})
	result, err := srv.handleApproveShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError when no TTY available")
	}
	if !strings.Contains(result.Text, "TTY") {
		t.Errorf("error text = %q, want 'TTY' message", result.Text)
	}

	// Grant should still be pending.
	updated, _ := srv.shareStore.Get(grant.ID)
	if updated.Status != SharePending {
		t.Errorf("grant status = %q, want pending (unchanged)", updated.Status)
	}
}

func TestHandleApproveShare_Success(t *testing.T) {
	withMockApprovalTTY(t, "y", func() {
		srv := testShareServer(t, "", nil)
		grant, err := srv.shareStore.Create("test-agent", "target", "vault/secret/password", "", 0)
		if err != nil {
			t.Fatal(err)
		}

		req := testShareRequest(map[string]any{"grant_id": grant.ID})
		result, err := srv.handleApproveShare(context.Background(), req)
		if err != nil {
			t.Fatalf("handleApproveShare() returned Go error: %v", err)
		}
		if result.IsError {
			t.Fatalf("handleApproveShare() returned tool error: %s", result.Text)
		}
		if !strings.Contains(result.Text, "approved") {
			t.Errorf("result = %q, want to contain 'approved'", result.Text)
		}

		updated, ok := srv.shareStore.Get(grant.ID)
		if !ok {
			t.Fatal("grant not found after approve")
		}
		if updated.Status != ShareApproved {
			t.Errorf("status = %q, want %q", updated.Status, ShareApproved)
		}
		if updated.ApprovedBy != "human" {
			t.Errorf("ApprovedBy = %q, want human", updated.ApprovedBy)
		}
		if updated.ApprovedAt == nil {
			t.Error("ApprovedAt should be set")
		}
	})
}

func TestHandleApproveShare_Rejected(t *testing.T) {
	withMockApprovalTTY(t, "n", func() {
		srv := testShareServer(t, "", nil)
		grant, err := srv.shareStore.Create("test-agent", "target", "vault/secret/password", "", 0)
		if err != nil {
			t.Fatal(err)
		}

		req := testShareRequest(map[string]any{"grant_id": grant.ID})
		result, err := srv.handleApproveShare(context.Background(), req)
		if err != nil {
			t.Fatalf("handleApproveShare() returned Go error: %v", err)
		}
		if result.IsError {
			t.Fatalf("handleApproveShare() returned tool error: %s", result.Text)
		}
		if !strings.Contains(result.Text, "rejected") {
			t.Errorf("result = %q, want to contain 'rejected'", result.Text)
		}

		updated, _ := srv.shareStore.Get(grant.ID)
		if updated.Status != ShareRejected {
			t.Errorf("status = %q, want %q", updated.Status, ShareRejected)
		}
	})
}

func TestHandleApproveShare_ApprovedWithTTL(t *testing.T) {
	withMockApprovalTTY(t, "y", func() {
		srv := testShareServer(t, "", nil)
		grant, err := srv.shareStore.Create("test-agent", "target", "vault/secret/key", "", 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		req := testShareRequest(map[string]any{"grant_id": grant.ID})
		result, err := srv.handleApproveShare(context.Background(), req)
		if err != nil {
			t.Fatalf("handleApproveShare() error = %v", err)
		}
		if result.IsError {
			t.Fatalf("handleApproveShare() error: %s", result.Text)
		}

		updated, _ := srv.shareStore.Get(grant.ID)
		if updated.ExpiresAt == nil {
			t.Fatal("ExpiresAt should be set after approval with TTL")
		}
		if !updated.ApprovedAt.Before(*updated.ExpiresAt) {
			t.Error("ApprovedAt should be before ExpiresAt")
		}
		// TTL should be extended from approval time.
		expectedExpiry := updated.ApprovedAt.Add(10 * time.Minute)
		delta := updated.ExpiresAt.Sub(expectedExpiry)
		if delta > time.Second {
			t.Errorf("ExpiresAt off by %v, want <=1s from approval+TTL", delta)
		}
	})
}

// ---------------------------------------------------------------------------
// handleRevokeShare tests
// ---------------------------------------------------------------------------

func TestHandleRevokeShare_MissingGrantID(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{})

	result, err := srv.handleRevokeShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for missing grant_id")
	}
}

func TestHandleRevokeShare_GrantNotFound(t *testing.T) {
	srv := testShareServer(t, "", nil)
	req := testShareRequest(map[string]any{"grant_id": "nonexistent"})

	result, err := srv.handleRevokeShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for nonexistent grant")
	}
	if !strings.Contains(result.Text, "not found") {
		t.Errorf("error text = %q, want 'not found'", result.Text)
	}
}

func TestHandleRevokeShare_Unauthorized(t *testing.T) {
	srv := testShareServer(t, "different-agent", nil)
	grant, err := srv.shareStore.Create("original-agent", "target", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	req := testShareRequest(map[string]any{"grant_id": grant.ID})
	result, err := srv.handleRevokeShare(context.Background(), req)
	if err != nil {
		t.Fatalf("should not return Go error; got %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for unauthorized revoke")
	}
	if !strings.Contains(result.Text, "source agent") {
		t.Errorf("error text = %q, want 'source agent' message", result.Text)
	}
}

func TestHandleRevokeShare_UnauthorizedMessage(t *testing.T) {
	srv := testShareServer(t, "attacker", nil)
	grant, err := srv.shareStore.Create("original-agent", "target", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	req := testShareRequest(map[string]any{"grant_id": grant.ID})
	result, _ := srv.handleRevokeShare(context.Background(), req)
	if !strings.Contains(result.Text, "original-agent") {
		t.Errorf("error should mention the original agent name, got %q", result.Text)
	}
}

func TestHandleRevokeShare_Success(t *testing.T) {
	srv := testShareServer(t, "source-agent", nil)
	grant, err := srv.shareStore.Create("source-agent", "target", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Approve first so we have a state to revoke from.
	if err := srv.shareStore.Approve(grant.ID, "admin"); err != nil {
		t.Fatal(err)
	}

	req := testShareRequest(map[string]any{"grant_id": grant.ID})
	result, err := srv.handleRevokeShare(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRevokeShare() returned Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRevokeShare() returned tool error: %s", result.Text)
	}
	if !strings.Contains(result.Text, "revoked") {
		t.Errorf("result = %q, want to contain 'revoked'", result.Text)
	}

	updated, ok := srv.shareStore.Get(grant.ID)
	if !ok {
		t.Fatal("grant should still exist after revoke")
	}
	if updated.Status != ShareRevoked {
		t.Errorf("status = %q, want %q", updated.Status, ShareRevoked)
	}
	if updated.RevokedAt == nil {
		t.Error("RevokedAt should be set")
	}
}

func TestHandleRevokeShare_FromPending(t *testing.T) {
	srv := testShareServer(t, "source-agent", nil)
	grant, err := srv.shareStore.Create("source-agent", "target", "vault/secret/password", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Revoke from pending state (not approved first).
	req := testShareRequest(map[string]any{"grant_id": grant.ID})
	result, err := srv.handleRevokeShare(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRevokeShare() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleRevokeShare() error: %s", result.Text)
	}

	updated, _ := srv.shareStore.Get(grant.ID)
	if updated.Status != ShareRevoked {
		t.Errorf("status = %q, want %q", updated.Status, ShareRevoked)
	}
}

// ---------------------------------------------------------------------------
// handleListShares tests
// ---------------------------------------------------------------------------

func TestHandleListShares_NoFilters(t *testing.T) {
	srv := testShareServer(t, "", nil)
	srv.shareStore.Create("alice", "bob", "path/a", "", 0)
	srv.shareStore.Create("charlie", "dave", "path/b", "", 0)

	req := testShareRequest(map[string]any{})
	result, err := srv.handleListShares(context.Background(), req)
	if err != nil {
		t.Fatalf("handleListShares() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleListShares() returned error: %s", result.Text)
	}

	var grants []*ShareGrant
	if err := json.Unmarshal([]byte(result.Text), &grants); err != nil {
		t.Fatalf("result is not valid JSON array: %v", err)
	}
	if len(grants) != 2 {
		t.Errorf("got %d grants, want 2", len(grants))
	}
}

func TestHandleListShares_StatusFilter(t *testing.T) {
	srv := testShareServer(t, "", nil)
	g, _ := srv.shareStore.Create("alice", "bob", "path/a", "", 0)
	srv.shareStore.Create("charlie", "dave", "path/b", "", 0)
	srv.shareStore.Approve(g.ID, "admin")

	req := testShareRequest(map[string]any{"status": "approved"})
	result, err := srv.handleListShares(context.Background(), req)
	if err != nil {
		t.Fatalf("handleListShares() error = %v", err)
	}

	var grants []*ShareGrant
	json.Unmarshal([]byte(result.Text), &grants)
	if len(grants) != 1 {
		t.Errorf("got %d approved grants, want 1", len(grants))
	}
	if len(grants) > 0 && grants[0].Status != ShareApproved {
		t.Errorf("status = %q, want %q", grants[0].Status, ShareApproved)
	}
}

func TestHandleListShares_AgentFilter(t *testing.T) {
	srv := testShareServer(t, "", nil)
	srv.shareStore.Create("alice", "bob", "path/a", "", 0)
	srv.shareStore.Create("alice", "charlie", "path/b", "", 0)
	srv.shareStore.Create("bob", "alice", "path/c", "", 0)

	t.Run("from_agent", func(t *testing.T) {
		req := testShareRequest(map[string]any{"from_agent": "alice"})
		result, _ := srv.handleListShares(context.Background(), req)
		var grants []*ShareGrant
		json.Unmarshal([]byte(result.Text), &grants)
		if len(grants) != 2 {
			t.Errorf("got %d grants from alice, want 2", len(grants))
		}
	})

	t.Run("to_agent", func(t *testing.T) {
		req := testShareRequest(map[string]any{"to_agent": "charlie"})
		result, _ := srv.handleListShares(context.Background(), req)
		var grants []*ShareGrant
		json.Unmarshal([]byte(result.Text), &grants)
		if len(grants) != 1 {
			t.Errorf("got %d grants to charlie, want 1", len(grants))
		}
	})
}

func TestHandleListShares_PathFilter(t *testing.T) {
	srv := testShareServer(t, "", nil)
	srv.shareStore.Create("alice", "bob", "vault/secret/api-key", "", 0)
	srv.shareStore.Create("alice", "bob", "vault/secret/db-pass", "", 0)
	srv.shareStore.Create("alice", "charlie", "vault/secret/api-key", "", 0)

	req := testShareRequest(map[string]any{"secret_path": "vault/secret/api-key"})
	result, _ := srv.handleListShares(context.Background(), req)
	var grants []*ShareGrant
	json.Unmarshal([]byte(result.Text), &grants)
	if len(grants) != 2 {
		t.Errorf("got %d grants for path, want 2", len(grants))
	}
}

func TestHandleListShares_CombinedFilter(t *testing.T) {
	srv := testShareServer(t, "", nil)
	g, _ := srv.shareStore.Create("alice", "bob", "vault/secret/api-key", "", 0)
	srv.shareStore.Create("alice", "bob", "vault/secret/other", "", 0)
	srv.shareStore.Approve(g.ID, "admin")

	req := testShareRequest(map[string]any{
		"from_agent":  "alice",
		"to_agent":    "bob",
		"secret_path": "vault/secret/api-key",
		"status":      "approved",
	})
	result, _ := srv.handleListShares(context.Background(), req)
	var grants []*ShareGrant
	json.Unmarshal([]byte(result.Text), &grants)
	if len(grants) != 1 {
		t.Errorf("got %d grants with combined filter, want 1", len(grants))
	}
}

func TestHandleListShares_EmptyResults(t *testing.T) {
	srv := testShareServer(t, "", nil)
	// Empty store.
	req := testShareRequest(map[string]any{})
	result, _ := srv.handleListShares(context.Background(), req)
	var grants []*ShareGrant
	json.Unmarshal([]byte(result.Text), &grants)
	if len(grants) != 0 {
		t.Errorf("expected empty list, got %d grants", len(grants))
	}
}

func TestHandleListShares_NonMatchingFilter(t *testing.T) {
	srv := testShareServer(t, "", nil)
	srv.shareStore.Create("alice", "bob", "path/a", "", 0)

	req := testShareRequest(map[string]any{"from_agent": "nonexistent"})
	result, _ := srv.handleListShares(context.Background(), req)
	var grants []*ShareGrant
	json.Unmarshal([]byte(result.Text), &grants)
	if len(grants) != 0 {
		t.Errorf("expected empty list, got %d grants", len(grants))
	}
}

func TestHandleListShares_InvalidStatus(t *testing.T) {
	srv := testShareServer(t, "", nil)
	srv.shareStore.Create("alice", "bob", "path/a", "", 0)

	// An invalid status string still produces a non-nil pointer via
	// shareStatusFromString, so it will filter for status == "bogus".
	req := testShareRequest(map[string]any{"status": "bogus"})
	result, _ := srv.handleListShares(context.Background(), req)
	var grants []*ShareGrant
	json.Unmarshal([]byte(result.Text), &grants)
	if len(grants) != 0 {
		t.Errorf("expected empty list, got %d grants", len(grants))
	}
}

// ---------------------------------------------------------------------------
// Integration: full flow
// ---------------------------------------------------------------------------

func TestShareFlowIntegration(t *testing.T) {
	srv := testShareServer(t, "alice", []string{"*"})

	// Step 1: Alice requests a share.
	req := testShareRequest(map[string]any{
		"to_agent":    "bob",
		"secret_path": "vault/secret/api-key",
		"ttl":         "10m",
	})
	result, err := srv.handleRequestShare(context.Background(), req)
	if err != nil {
		t.Fatalf("step 1 (request): %v", err)
	}
	if result.IsError {
		t.Fatalf("step 1 (request): %s", result.Text)
	}
	var parsed map[string]any
	json.Unmarshal([]byte(result.Text), &parsed)
	grantID := parsed["grant_id"].(string)

	// Verify state: pending.
	grant, ok := srv.shareStore.Get(grantID)
	if !ok {
		t.Fatal("grant not found after request")
	}
	if grant.Status != SharePending {
		t.Fatalf("step 1 status = %q, want pending", grant.Status)
	}

	// Step 2: Approve directly on store (bypasses TTY requirement).
	if err := srv.shareStore.Approve(grantID, "human"); err != nil {
		t.Fatalf("step 2 (approve): %v", err)
	}

	// Verify state: approved.
	grant, _ = srv.shareStore.Get(grantID)
	if grant.Status != ShareApproved {
		t.Fatalf("step 2 status = %q, want approved", grant.Status)
	}

	// Step 3: Bob has access via CheckAccess.
	accessGrant, ok := srv.shareStore.CheckAccess("bob", "vault/secret/api-key")
	if !ok {
		t.Fatal("step 3: Bob should have access after approval")
	}
	if accessGrant.ID != grantID {
		t.Errorf("step 3: grant ID mismatch: %q vs %q", accessGrant.ID, grantID)
	}
	if accessGrant.ExpiresAt == nil {
		t.Error("step 3: ExpiresAt should be set (TTL=10m)")
	}

	// Charlie should NOT have access.
	if _, ok := srv.shareStore.CheckAccess("charlie", "vault/secret/api-key"); ok {
		t.Error("step 3: Charlie should not have access")
	}

	// Step 4: Alice revokes the grant via handler.
	revokeReq := testShareRequest(map[string]any{"grant_id": grantID})
	revokeResult, err := srv.handleRevokeShare(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("step 4 (revoke): %v", err)
	}
	if revokeResult.IsError {
		t.Fatalf("step 4 (revoke): %s", revokeResult.Text)
	}

	// Step 5: Verify Bob no longer has access.
	if _, ok := srv.shareStore.CheckAccess("bob", "vault/secret/api-key"); ok {
		t.Error("step 5: Bob should not have access after revocation")
	}

	// Step 6: Verify final state.
	grant, _ = srv.shareStore.Get(grantID)
	if grant.Status != ShareRevoked {
		t.Errorf("step 6 status = %q, want revoked", grant.Status)
	}
}

// ---------------------------------------------------------------------------
// shareStatusFromString unit tests
// ---------------------------------------------------------------------------

func TestShareStatusFromString(t *testing.T) {
	tests := []struct {
		input string
		want  *ShareStatus
	}{
		{"", nil},
		{"pending", statusPtr(SharePending)},
		{"approved", statusPtr(ShareApproved)},
		{"revoked", statusPtr(ShareRevoked)},
		{"rejected", statusPtr(ShareRejected)},
		{"expired", statusPtr(ShareExpired)},
		{"bogus", statusPtr(ShareStatus("bogus"))},
	}

	for _, tt := range tests {
		got := shareStatusFromString(tt.input)
		if tt.want == nil {
			if got != nil {
				t.Errorf("shareStatusFromString(%q) = %v, want nil", tt.input, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("shareStatusFromString(%q) = nil, want %v", tt.input, *tt.want)
			continue
		}
		if *got != *tt.want {
			t.Errorf("shareStatusFromString(%q) = %v, want %v", tt.input, *got, *tt.want)
		}
	}
}

func statusPtr(s ShareStatus) *ShareStatus { return &s }

// ---------------------------------------------------------------------------
// Concurrent handler safety
// ---------------------------------------------------------------------------

func TestHandleRequestShare_Concurrent(t *testing.T) {
	srv := testShareServer(t, "alice", []string{"*"})

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := testShareRequest(map[string]any{
				"to_agent":    "bob",
				"secret_path": "vault/secret/key",
			})
			_, err := srv.handleRequestShare(context.Background(), req)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent request error: %v", err)
	}

	grants := srv.shareStore.List()
	if len(grants) != 20 {
		t.Errorf("expected 20 grants, got %d", len(grants))
	}
}

// ---------------------------------------------------------------------------
// Error propagation tests
// ---------------------------------------------------------------------------

func TestHandleRequestShare_StoreWriteError(t *testing.T) {
	// Use a path we can't write to.
	store := NewShareStore("/nonexistent-dir-openpass/mcp-shares.json")
	srv := &Server{
		agent: &config.AgentProfile{
			Name:         "test-agent",
			AllowedPaths: []string{"*"},
		},
		shareStore: store,
	}

	req := testShareRequest(map[string]any{
		"to_agent":    "target",
		"secret_path": "any/path",
	})
	_, err := srv.handleRequestShare(context.Background(), req)
	if err == nil {
		t.Fatal("expected Go error for store write failure")
	}
	if !strings.Contains(err.Error(), "failed to create share grant") {
		t.Errorf("error = %v, want 'failed to create share grant'", err)
	}
}
