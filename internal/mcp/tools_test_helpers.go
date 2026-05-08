package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

//nolint:unparam // transport always "stdio" in current test suite
func newTestServerWithVault(t *testing.T, profile config.AgentProfile, transport string, vaultDir string) *Server {
	t.Helper()

	auditLog, err := audit.New("test", "")
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}

	var identity *age.X25519Identity
	if vaultDir != "" {
		identity, err = age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generate identity: %v", err)
		}
	}

	return &Server{
		vault: &vault.Vault{
			Dir:      vaultDir,
			Identity: identity,
		},
		agent:     &profile,
		auditLog:  auditLog,
		transport: transport,
	}
}

// mockVault creates a temp vault directory with entries for testing
func mockVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()

	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	// Create an entry
	entry := &vault.Entry{
		Data: map[string]any{
			"password": "testpass123",
			"username": "testuser",
		},
	}
	if err := vault.WriteEntry(dir, "github", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	return dir, identity
}

func TestToolError(t *testing.T) {
	result := toolError("test error")
	if result == nil {
		t.Fatal("toolError() returned nil")
	}
	if !result.IsError {
		t.Error("toolError() expected IsError to be true")
	}
}

func TestExecuteToolUnknownTool(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	// Use empty JSON object instead of nil to avoid parse error
	args := json.RawMessage(`{}`)
	_, err := srv.executeTool(context.Background(), "unknown_tool", args)
	if err == nil {
		t.Fatal("executeTool() expected error for unknown tool, got nil")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("executeTool() error = %v, want 'unknown tool'", err)
	}
}

func TestToolsListPayloadMatchesAvailableRegistry(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "http", "")

	tools := toolsListPayload(srv)
	names := make(map[string]map[string]any, len(tools))
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		names[name] = tool
	}

	for _, def := range availableToolDefinitions(srv) {
		if _, ok := names[def.Name]; !ok {
			t.Fatalf("tools/list missing available tool %q", def.Name)
		}
	}

	for _, name := range []string{"list_entries", "get_entry", "get_entry_value", "get_entry_metadata", "generate_password", "health", "delete_entry", "openpass_delete"} {
		if _, ok := names[name]; !ok {
			t.Fatalf("tools/list missing expected tool %q", name)
		}
	}
	if _, ok := names["secure_input"]; ok {
		t.Fatal("secure_input should not be listed for non-stdio transports")
	}

	getEntrySchema, ok := names["get_entry"]["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("get_entry inputSchema has unexpected type")
	}
	properties, ok := getEntrySchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("get_entry properties have unexpected type")
	}
	if _, ok := properties["include_value"]; !ok {
		t.Fatal("get_entry schema missing include_value")
	}
}
