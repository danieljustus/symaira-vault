package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestResolveToolAlias(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     string
	}{
		{
			name:     "real tool returns itself",
			toolName: "delete_entry",
			want:     "delete_entry",
		},
		{
			name:     "alias resolves to canonical",
			toolName: "openpass_delete",
			want:     "delete_entry",
		},
		{
			name:     "unknown tool returns original",
			toolName: "nonexistent_tool",
			want:     "nonexistent_tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveToolAlias(tt.toolName)
			if got != tt.want {
				t.Errorf("resolveToolAlias(%q) = %q, want %q", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestIsToolAllowed(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	tests := []struct {
		name     string
		token    *ScopedToken
		toolName string
		want     bool
	}{
		{
			name:     "nil token allows all tools",
			token:    nil,
			toolName: "delete_entry",
			want:     true,
		},
		{
			name: "wildcard allows all tools",
			token: &ScopedToken{
				AllowedTools: []string{"*"},
			},
			toolName: "delete_entry",
			want:     true,
		},
		{
			name: "exact match allowed",
			token: &ScopedToken{
				AllowedTools: []string{"delete_entry", "list_entries"},
			},
			toolName: "delete_entry",
			want:     true,
		},
		{
			name: "tool not in allowed list",
			token: &ScopedToken{
				AllowedTools: []string{"list_entries"},
			},
			toolName: "delete_entry",
			want:     false,
		},
		{
			name: "alias allowed when canonical is in list",
			token: &ScopedToken{
				AllowedTools: []string{"delete_entry"},
			},
			toolName: "openpass_delete",
			want:     true,
		},
		{
			name: "canonical allowed when alias is in list",
			token: &ScopedToken{
				AllowedTools: []string{"openpass_delete"},
			},
			toolName: "delete_entry",
			want:     true,
		},
		{
			name: "expired token denies all",
			token: &ScopedToken{
				AllowedTools: []string{"*"},
				ExpiresAt:    &past,
			},
			toolName: "delete_entry",
			want:     false,
		},
		{
			name: "revoked token denies all",
			token: &ScopedToken{
				AllowedTools: []string{"*"},
				Revoked:      true,
			},
			toolName: "delete_entry",
			want:     false,
		},
		{
			name: "empty allowed list denies all",
			token: &ScopedToken{
				AllowedTools: []string{},
			},
			toolName: "delete_entry",
			want:     false,
		},
		{
			name:     "nil token with alias still allows",
			token:    nil,
			toolName: "openpass_delete",
			want:     true,
		},
		{
			name: "non-expired token with exact match allows",
			token: &ScopedToken{
				AllowedTools: []string{"list_entries"},
				ExpiresAt:    &future,
			},
			toolName: "list_entries",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isToolAllowed(tt.token, tt.toolName)
			if got != tt.want {
				t.Errorf("isToolAllowed(token=%v, toolName=%q) = %v, want %v", tt.token, tt.toolName, got, tt.want)
			}
		})
	}
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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

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
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanWrite:         config.BoolPtr(true),
		ApprovalMode:     config.StrPtr("none"),
		ExposeValueTools: config.BoolPtr(true),
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
