package mcp

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestHandleDelete_WriteDenied(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	_, err := srv.handleDelete(context.Background(), req)
	if err == nil {
		t.Fatal("handleDelete() expected error for write-denied agent, got nil")
	}
	if !strings.Contains(err.Error(), "delete operations not permitted") {
		t.Fatalf("handleDelete() error = %v, want 'delete operations not permitted'", err)
	}
}

func TestHandleDelete_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleDelete(context.Background(), req)
	if err != nil {
		t.Fatalf("handleDelete() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleDelete() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleDelete() returned error: %s", result.Text)
	}

	// Verify the entry was deleted
	_, err = vault.ReadEntry(vaultDir, "github", identity)
	if err == nil {
		t.Error("expected entry to be deleted")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist error, got %v", err)
	}
}

func TestHandleDelete_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	_, err := srv.handleDelete(context.Background(), req)
	if err == nil {
		t.Fatal("handleDelete() expected error for out-of-scope path, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("handleDelete() error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleDelete_ApprovalRequired(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "deny",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleDelete(context.Background(), req)
	if err != nil {
		t.Fatalf("handleDelete() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("handleDelete() expected IsError for approval-required path")
	}
}

func TestHandleDelete_NotFound(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "nonexistent"},
	}

	result, err := srv.handleDelete(context.Background(), req)
	if err != nil {
		t.Fatalf("handleDelete() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("handleDelete() expected error result for nonexistent entry")
	}
	if !strings.Contains(result.Text, "not found") {
		t.Fatalf("handleDelete() result = %v, want 'not found'", result.Text)
	}
}

func TestHandleDelete_MissingPath(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleDelete(context.Background(), req)
	if err != nil {
		t.Fatalf("handleDelete() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleDelete() returned nil result")
	}
	if !result.IsError {
		t.Error("handleDelete() expected error result for missing path")
	}
}
