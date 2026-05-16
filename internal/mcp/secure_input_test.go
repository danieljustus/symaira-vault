package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/secureui"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func mockSecureInputReturn(t *testing.T, value string, err error) {
	t.Helper()
	original := secureInputPromptFn
	secureInputPromptFn = func(_ secureui.PromptRequest) (string, error) {
		return value, err
	}
	t.Cleanup(func() { secureInputPromptFn = original })
}

func TestHandleSecureInput_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockSecureInputReturn(t, "my-secret-api-key", nil)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"field":       "api_key",
			"description": "Enter your GitHub API key",
		},
	}

	result, err := srv.handleSecureInput(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecureInput() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSecureInput() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSecureInput() returned error: %s", result.Text)
	}

	entry, err := vault.ReadEntry(vaultDir, "github", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if entry.Data["api_key"] != "my-secret-api-key" {
		t.Errorf("api_key = %v, want my-secret-api-key", entry.Data["api_key"])
	}
	if strings.Contains(result.Text, "my-secret-api-key") {
		t.Error("result should not contain the secret value")
	}
}

func TestHandleSecureInput_NewEntry(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockSecureInputReturn(t, "new-secret-value", nil)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "new-service",
			"field": "password",
		},
	}

	result, err := srv.handleSecureInput(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecureInput() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleSecureInput() unexpected result: %+v", result)
	}

	entry, err := vault.ReadEntry(vaultDir, "new-service", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if entry.Data["password"] != "new-secret-value" {
		t.Errorf("password = %v, want new-secret-value", entry.Data["password"])
	}
}

func TestHandleSecureInput_WriteDenied(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "api_key",
		},
	}

	_, err := srv.handleSecureInput(context.Background(), req)
	if err == nil {
		t.Fatal("handleSecureInput() expected error for write-denied agent, got nil")
	}
	if err.Error() != "write operations not permitted for this agent" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleSecureInput_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "api_key",
		},
	}

	_, err := srv.handleSecureInput(context.Background(), req)
	if err == nil {
		t.Fatal("handleSecureInput() expected error for out-of-scope path, got nil")
	}
	if err.Error() != `access denied: path "github" outside allowed scope` {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleSecureInput_ApprovalRequired(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "deny",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "api_key",
		},
	}

	_, err := srv.handleSecureInput(context.Background(), req)
	if err == nil {
		t.Fatal("handleSecureInput() expected error for approval-required path, got nil")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleSecureInput_MissingParams(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{Arguments: map[string]any{"path": "github"}}

	result, err := srv.handleSecureInput(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecureInput() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Error("handleSecureInput() expected error result for missing field")
	}
}

func TestHandleSecureInput_Canceled(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockSecureInputReturn(t, "", secureui.ErrCanceled)

	req := CallToolRequest{Arguments: map[string]any{"path": "github", "field": "api_key"}}
	result, err := srv.handleSecureInput(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecureInput() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected error result on cancel, got %+v", result)
	}
	if !strings.Contains(result.Text, "canceled") {
		t.Errorf("expected cancel message, got %q", result.Text)
	}
}

func TestHandleSecureInput_Timeout(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockSecureInputReturn(t, "", secureui.ErrTimeout)

	req := CallToolRequest{Arguments: map[string]any{"path": "github", "field": "api_key"}}
	result, err := srv.handleSecureInput(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecureInput() error = %v", err)
	}
	if result == nil || !result.IsError || !strings.Contains(result.Text, "timed out") {
		t.Errorf("expected timeout result, got %+v", result)
	}
}

func TestHandleSecureInput_Unavailable(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockSecureInputReturn(t, "", secureui.ErrUnavailable)

	req := CallToolRequest{Arguments: map[string]any{"path": "github", "field": "api_key"}}
	_, err := srv.handleSecureInput(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when no secure-input backend is available")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("expected unavailable error, got %v", err)
	}
}

func TestHandleSecureInput_EmptyValue(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockSecureInputReturn(t, "", nil)

	req := CallToolRequest{Arguments: map[string]any{"path": "github", "field": "api_key"}}
	result, err := srv.handleSecureInput(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecureInput() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Error("expected error result for empty value")
	}
}
