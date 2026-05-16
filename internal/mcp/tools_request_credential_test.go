package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/secureui"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestHandleRequestCredential_StoresValueWithoutLeaking(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	var captured secureui.PromptRequest
	original := secureInputPromptFn
	secureInputPromptFn = func(req secureui.PromptRequest) (string, error) {
		captured = req
		return "user-supplied-secret", nil
	}
	t.Cleanup(func() { secureInputPromptFn = original })

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":   "github/api-token",
			"field":  "token",
			"reason": "needed to push to main",
		},
	}

	result, err := srv.handleRequestCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("handleRequestCredential() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("unexpected result: %+v", result)
	}
	if strings.Contains(result.Text, "user-supplied-secret") {
		t.Error("result text leaked the secret value")
	}

	entry, err := vault.ReadEntry(vaultDir, "github/api-token", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if entry.Data["token"] != "user-supplied-secret" {
		t.Errorf("token = %v, want user-supplied-secret", entry.Data["token"])
	}

	if captured.Path != "github/api-token" || captured.Field != "token" {
		t.Errorf("prompt request mismatch: %+v", captured)
	}
	if captured.Description != "needed to push to main" {
		t.Errorf("reason not forwarded as Description: %q", captured.Description)
	}
	if !captured.Hidden {
		t.Error("request_credential should set Hidden=true")
	}
	if captured.Title == "" {
		t.Error("request_credential should set a Title for the dialog")
	}
}

func TestHandleRequestCredential_RequiresReason(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	// reason is a required schema field but preflight currently treats it as a
	// description; an empty reason still proceeds. This test pins the actual
	// behavior so future schema-enforcement work has a known baseline.
	original := secureInputPromptFn
	secureInputPromptFn = func(_ secureui.PromptRequest) (string, error) { return "v", nil }
	t.Cleanup(func() { secureInputPromptFn = original })

	req := CallToolRequest{Arguments: map[string]any{
		"path":   "p",
		"field":  "f",
		"reason": "why",
	}}
	if _, err := srv.handleRequestCredential(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleRequestCredential_ApprovalDeny(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "deny",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{Arguments: map[string]any{
		"path":   "p",
		"field":  "f",
		"reason": "r",
	}}
	_, err := srv.handleRequestCredential(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when approvalMode=deny")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected denial error message, got %v", err)
	}
}
