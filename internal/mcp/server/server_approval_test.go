package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// deviceTokens is a test tokenValidator.
type deviceTokens struct{ valid map[string]string }

func (d *deviceTokens) Validate(token string) (string, bool) {
	id, ok := d.valid[token]
	return id, ok
}

// TestAttachApprovalQueueBlocksUntilDeviceDecides exercises the full loop:
// server authorizer (prompt mode) enqueues → device lists → device approves →
// the blocked authorize call returns nil.
func TestAttachApprovalQueueBlocksUntilDeviceDecides(t *testing.T) {
	dir := t.TempDir()
	canWrite := true
	approvalMode := "prompt"
	identity, err := vault.InitWithPassphrase(dir, []byte("test-passphrase-123"), &config.Config{
		Vault: &config.VaultConfig{FormatVersion: 2},
		Agents: map[string]config.AgentProfile{
			"approval-agent": {
				Name:         "approval-agent",
				AllowedPaths: []string{"*"},
				CanWrite:     &canWrite,
				ApprovalMode: &approvalMode,
			},
		},
	})
	if err != nil {
		t.Fatalf("init vault: %v", err)
	}
	v, err := vault.Open(dir, identity)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	srv, err := New(v, "approval-agent", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	q := approval.NewQueue()
	srv.AttachApprovalQueue(q)
	tokens := &deviceTokens{valid: map[string]string{"device-token-1": "device-1"}}
	handler := approval.NewHTTPHandler(q, tokens)

	// The agent (authorizer) attempts a write that requires approval.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- srv.authorizer.Authorize(ctx, "work/creds", true, false)
	}()

	// The device lists pending requests.
	var reqID string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pending := q.Pending()
		if len(pending) == 1 {
			reqID = pending[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending request appeared")
	}

	listReq := httptest.NewRequest(http.MethodGet, approval.PathApprovals, nil)
	listReq.Header.Set("Authorization", "Bearer device-token-1")
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Requests []approval.Entry `json:"requests"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Requests) != 1 || listResp.Requests[0].Path != "work/creds" {
		t.Fatalf("requests = %+v", listResp.Requests)
	}

	// Device approves via the transport.
	approveReq := httptest.NewRequest(http.MethodPost, approval.PathApprovalAction+reqID+"/approve", nil)
	approveReq.Header.Set("Authorization", "Bearer device-token-1")
	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status = %d: %s", approveRec.Code, approveRec.Body.String())
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("authorize after device approval: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorize did not unblock")
	}
}

func TestApprovalTransportRejectsUnknownDevice(t *testing.T) {
	q := approval.NewQueue()
	handler := approval.NewHTTPHandler(q, &deviceTokens{valid: map[string]string{"ok": "device-1"}})

	req := httptest.NewRequest(http.MethodGet, approval.PathApprovals, nil)
	req.Header.Set("Authorization", "Bearer nope")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "device token") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func boolPtr(b bool) *bool { return &b }
