package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestHandleGetAuthStatus(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", t.TempDir())
	cfg := config.Default()
	if err := cfg.SetAuthMethod(config.AuthMethodPassphrase); err != nil {
		t.Fatalf("SetAuthMethod() error = %v", err)
	}
	srv.vault.Config = cfg

	result, err := srv.handleGetAuthStatus(context.Background(), CallToolRequest{})
	if err != nil {
		t.Fatalf("handleGetAuthStatus() error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(result.Text), &payload); err != nil {
		t.Fatalf("status JSON invalid: %v", err)
	}
	if payload["method"] != config.AuthMethodPassphrase {
		t.Fatalf("method = %v, want passphrase", payload["method"])
	}
}

func TestHandleSetAuthMethodRequiresConfigPermission(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", t.TempDir())
	srv.vault.Config = config.Default()

	_, err := srv.handleSetAuthMethod(context.Background(), CallToolRequest{
		Arguments: map[string]any{"method": config.AuthMethodPassphrase},
	})
	if err == nil {
		t.Fatal("handleSetAuthMethod() error = nil, want permission error")
	}
}

func TestHandleSetAuthMethodPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "test",
		AllowedPaths:    []string{"*"},
		CanManageConfig: config.BoolPtr(true),
		ApprovalMode:    config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Config = cfg

	result, err := srv.handleSetAuthMethod(context.Background(), CallToolRequest{
		Arguments: map[string]any{"method": config.AuthMethodPassphrase},
	})
	if err != nil {
		t.Fatalf("handleSetAuthMethod() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleSetAuthMethod() result = %+v, want success", result)
	}
	loaded, err := config.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.EffectiveAuthMethod() != config.AuthMethodPassphrase {
		t.Fatalf("auth method = %q, want passphrase", loaded.EffectiveAuthMethod())
	}
}
