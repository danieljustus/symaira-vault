package mcp

import (
	"context"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/autotype"
	"github.com/danieljustus/OpenPass/internal/clipboard"
	"github.com/danieljustus/OpenPass/internal/config"
)

type mockClipboard struct {
	mu   sync.Mutex
	text string
}

func (c *mockClipboard) Copy(text string) error {
	c.mu.Lock()
	c.text = text
	c.mu.Unlock()
	return nil
}

func (c *mockClipboard) Read() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.text, nil
}

type mockAutotype struct {
	mu   sync.Mutex
	text string
}

func (a *mockAutotype) Type(text string) error {
	a.mu.Lock()
	a.text = text
	a.mu.Unlock()
	return nil
}

func TestHandleCopyToClipboard(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:            "test",
			AllowedPaths:    []string{"*"},
			CanUseClipboard: true,
			ApprovalMode:    "none",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		mockClip := &mockClipboard{}
		clipboard.SetClipboard(mockClip)
		defer clipboard.SetClipboard(nil)

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		result, err := srv.handleCopyToClipboard(context.Background(), req)
		if err != nil {
			t.Fatalf("handleCopyToClipboard() error = %v", err)
		}
		if result == nil {
			t.Fatal("handleCopyToClipboard() returned nil result")
		}
		if result.IsError {
			t.Fatalf("handleCopyToClipboard() returned error result: %s", result.Text)
		}

		copied, _ := mockClip.Read()
		if copied != "testpass123" {
			t.Errorf("clipboard = %q, want %q", copied, "testpass123")
		}
	})

	t.Run("permission_denied", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:            "test",
			AllowedPaths:    []string{"*"},
			CanUseClipboard: false,
			ApprovalMode:    "none",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		_, err := srv.handleCopyToClipboard(context.Background(), req)
		if err == nil {
			t.Fatal("handleCopyToClipboard() expected error for denied permission, got nil")
		}
		if !strings.Contains(err.Error(), "clipboard operations not permitted") {
			t.Fatalf("handleCopyToClipboard() error = %v, want 'clipboard operations not permitted'", err)
		}
	})

	t.Run("outside_scope", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:            "test",
			AllowedPaths:    []string{"work/"},
			CanUseClipboard: true,
			ApprovalMode:    "none",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		_, err := srv.handleCopyToClipboard(context.Background(), req)
		if err == nil {
			t.Fatal("handleCopyToClipboard() expected error for out-of-scope path, got nil")
		}
		if !strings.Contains(err.Error(), "outside allowed scope") {
			t.Fatalf("handleCopyToClipboard() error = %v, want 'outside allowed scope'", err)
		}
	})

	t.Run("approval_required", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:            "test",
			AllowedPaths:    []string{"*"},
			CanUseClipboard: true,
			ApprovalMode:    "deny",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		_, err := srv.handleCopyToClipboard(context.Background(), req)
		if err == nil {
			t.Fatal("handleCopyToClipboard() expected error for approval required, got nil")
		}
		if !strings.Contains(err.Error(), "denied") {
			t.Fatalf("handleCopyToClipboard() error = %v, want 'denied'", err)
		}
	})

	t.Run("entry_not_found", func(t *testing.T) {
		dir := t.TempDir()
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generate identity: %v", err)
		}
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:            "test",
			AllowedPaths:    []string{"*"},
			CanUseClipboard: true,
			ApprovalMode:    "none",
		}, "stdio", dir)
		srv.vault.Identity = identity

		req := CallToolRequest{
			Arguments: map[string]any{"path": "nonexistent"},
		}

		result, err := srv.handleCopyToClipboard(context.Background(), req)
		if err != nil {
			t.Fatalf("handleCopyToClipboard() error = %v", err)
		}
		if result == nil {
			t.Fatal("handleCopyToClipboard() returned nil result")
		}
		if !result.IsError {
			t.Fatal("handleCopyToClipboard() expected error result for not found")
		}
	})

	t.Run("missing_path", func(t *testing.T) {
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:            "test",
			AllowedPaths:    []string{"*"},
			CanUseClipboard: true,
			ApprovalMode:    "none",
		}, "stdio", "")

		req := CallToolRequest{
			Arguments: map[string]any{},
		}

		result, err := srv.handleCopyToClipboard(context.Background(), req)
		if err != nil {
			t.Fatalf("handleCopyToClipboard() error = %v", err)
		}
		if result == nil {
			t.Fatal("handleCopyToClipboard() returned nil result")
		}
		if !result.IsError {
			t.Fatal("handleCopyToClipboard() expected error result for missing path")
		}
	})
}

func TestHandleAutotype(t *testing.T) {
	t.Run("success_password_field", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: true,
			ApprovalMode:   "none",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		mockAT := &mockAutotype{}
		autotype.SetAutotype(mockAT)
		defer autotype.SetAutotype(nil)

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		result, err := srv.handleAutotype(context.Background(), req)
		if err != nil {
			t.Fatalf("handleAutotype() error = %v", err)
		}
		if result == nil {
			t.Fatal("handleAutotype() returned nil result")
		}
		if result.IsError {
			t.Fatalf("handleAutotype() returned error result: %s", result.Text)
		}
	})

	t.Run("success_custom_field", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: true,
			ApprovalMode:   "none",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		mockAT := &mockAutotype{}
		autotype.SetAutotype(mockAT)
		defer autotype.SetAutotype(nil)

		req := CallToolRequest{
			Arguments: map[string]any{
				"path":  "github",
				"field": "username",
			},
		}

		result, err := srv.handleAutotype(context.Background(), req)
		if err != nil {
			t.Fatalf("handleAutotype() error = %v", err)
		}
		if result == nil {
			t.Fatal("handleAutotype() returned nil result")
		}
		if result.IsError {
			t.Fatalf("handleAutotype() returned error result: %s", result.Text)
		}
	})

	t.Run("permission_denied", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: false,
			ApprovalMode:   "none",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		_, err := srv.handleAutotype(context.Background(), req)
		if err == nil {
			t.Fatal("handleAutotype() expected error for denied permission, got nil")
		}
		if !strings.Contains(err.Error(), "autotype operations not permitted") {
			t.Fatalf("handleAutotype() error = %v, want 'autotype operations not permitted'", err)
		}
	})

	t.Run("outside_scope", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"work/"},
			CanUseAutotype: true,
			ApprovalMode:   "none",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		_, err := srv.handleAutotype(context.Background(), req)
		if err == nil {
			t.Fatal("handleAutotype() expected error for out-of-scope path, got nil")
		}
		if !strings.Contains(err.Error(), "outside allowed scope") {
			t.Fatalf("handleAutotype() error = %v, want 'outside allowed scope'", err)
		}
	})

	t.Run("approval_required", func(t *testing.T) {
		vaultDir, identity := mockVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: true,
			ApprovalMode:   "deny",
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := CallToolRequest{
			Arguments: map[string]any{"path": "github"},
		}

		_, err := srv.handleAutotype(context.Background(), req)
		if err == nil {
			t.Fatal("handleAutotype() expected error for approval required, got nil")
		}
		if !strings.Contains(err.Error(), "approval required") {
			t.Fatalf("handleAutotype() error = %v, want 'approval required'", err)
		}
	})

	t.Run("missing_path", func(t *testing.T) {
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: true,
			ApprovalMode:   "none",
		}, "stdio", "")

		req := CallToolRequest{
			Arguments: map[string]any{},
		}

		result, err := srv.handleAutotype(context.Background(), req)
		if err != nil {
			t.Fatalf("handleAutotype() error = %v", err)
		}
		if result == nil {
			t.Fatal("handleAutotype() returned nil result")
		}
		if !result.IsError {
			t.Fatal("handleAutotype() expected error result for missing path")
		}
	})
}
