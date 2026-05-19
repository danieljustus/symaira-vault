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
		CanReadValues:    config.BoolPtr(true),
		ExposeValueTools: config.BoolPtr(false),
		ApprovalMode:     config.StrPtr("prompt"),
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
		CanReadValues:    config.BoolPtr(true),
		ExposeValueTools: config.BoolPtr(true),
		ApprovalMode:     config.StrPtr("prompt"),
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
		ExposeValueTools: config.BoolPtr(false),
		ApprovalMode:     config.StrPtr("none"),
	}, "stdio", "")

	args := json.RawMessage(`{"path": "test"}`)
	payload, err := srv.executeTool(context.Background(), "get_entry_value", args)
	if err != nil {
		t.Fatalf("executeTool() should return payload with isError, not Go error; got %v", err)
	}
	if payload == nil {
		t.Fatal("executeTool() returned nil payload for blocked tool")
	}
	isError, _ := payload["isError"].(bool)
	if !isError {
		t.Fatal("executeTool() payload.isError should be true for blocked get_entry_value")
	}
	if content, ok := payload["content"].([]map[string]any); ok && len(content) > 0 {
		if text, ok := content[0]["text"].(string); ok {
			if !strings.Contains(text, "requires tier") && !strings.Contains(text, "not allowed") {
				t.Fatalf("executeTool() error text = %q, want tier/not-allowed message", text)
			}
		}
	}
}

func TestAvailableToolDefinitions_FiltersGetEntryValue_WhenExposeValueToolsFalse(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		ExposeValueTools: config.BoolPtr(false),
		ApprovalMode:     config.StrPtr("none"),
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
