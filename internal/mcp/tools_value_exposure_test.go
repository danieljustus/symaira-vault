package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestToolsList_FiltersGetEntryValue_WhenExposeValueToolsFalse(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanReadValues:    true,
		ExposeValueTools: false,
		ApprovalMode:     "prompt",
	}, "http", "")

	tools := toolsListPayload(srv)
	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		names[tool["name"].(string)] = true
	}

	if names["get_entry_value"] {
		t.Error("get_entry_value should NOT be in tools/list when ExposeValueTools=false")
	}
	if !names["get_entry"] {
		t.Error("get_entry should still be in tools/list when ExposeValueTools=false")
	}
	if !names["list_entries"] {
		t.Error("list_entries should still be in tools/list")
	}

	getEntry := findToolByName(t, tools, "get_entry")
	inputSchema, ok := getEntry["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("get_entry inputSchema has unexpected type")
	}
	properties, ok := inputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("get_entry properties have unexpected type")
	}
	if _, ok := properties["include_value"]; ok {
		t.Error("get_entry schema should hide include_value when ExposeValueTools=false")
	}
}

func TestToolsList_ShowsGetEntryValue_WhenExposeValueToolsTrue(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanReadValues:    true,
		ExposeValueTools: true,
		ApprovalMode:     "prompt",
	}, "http", "")

	tools := toolsListPayload(srv)
	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		names[tool["name"].(string)] = true
	}

	if !names["get_entry_value"] {
		t.Error("get_entry_value should be in tools/list when ExposeValueTools=true")
	}

	getEntry := findToolByName(t, tools, "get_entry")
	inputSchema, ok := getEntry["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("get_entry inputSchema has unexpected type")
	}
	properties, ok := inputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("get_entry properties have unexpected type")
	}
	if _, ok := properties["include_value"]; !ok {
		t.Error("get_entry schema should include include_value when ExposeValueTools=true")
	}
}

func TestExecuteTool_BlocksGetEntryValue_WhenExposeValueToolsFalse(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		ExposeValueTools: false,
		ApprovalMode:     "none",
	}, "stdio", "")

	args := json.RawMessage(`{"path": "test"}`)
	_, err := srv.executeTool(context.Background(), "get_entry_value", args)
	if err == nil {
		t.Fatal("executeTool() expected error for get_entry_value when ExposeValueTools=false, got nil")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("executeTool() error = %v, want 'unknown tool'", err)
	}
}

func TestAvailableToolDefinitions_FiltersGetEntryValue_WhenExposeValueToolsFalse(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		ExposeValueTools: false,
		ApprovalMode:     "none",
	}, "http", "")

	defs := availableToolDefinitions(srv)
	names := make(map[string]bool, len(defs))
	for _, def := range defs {
		names[def.Name] = true
	}

	if names["get_entry_value"] {
		t.Error("get_entry_value should NOT be available when ExposeValueTools=false")
	}
	if !names["get_entry"] {
		t.Error("get_entry should still be available when ExposeValueTools=false")
	}
}

func findToolByName(t *testing.T, tools []map[string]any, name string) map[string]any {
	t.Helper()

	for _, tool := range tools {
		if tool["name"] == name {
			return tool
		}
	}

	t.Fatalf("tool %q not found", name)
	return nil
}
