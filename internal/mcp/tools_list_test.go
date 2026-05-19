package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestHandleList_WithPrefix(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"prefix": ""},
	}

	result, err := srv.handleList(context.Background(), req)
	if err != nil {
		t.Fatalf("handleList() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleList() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleList() returned error: %s", result.Text)
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(result.Text), &entries); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected entries, got empty list")
	}

	found := false
	for _, entry := range entries {
		if entry["path"] == "github" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'github' in entries, got %v", entries)
	}
}

func TestHandleList_WithDetailsDisabled(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"prefix": "", "include_details": "false"},
	}

	result, err := srv.handleList(context.Background(), req)
	if err != nil {
		t.Fatalf("handleList() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleList() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleList() returned error: %s", result.Text)
	}

	var entries []string
	if err := json.Unmarshal([]byte(result.Text), &entries); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected entries, got empty list")
	}
}

func TestExecuteTool_ListEntries(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"prefix": ""}`)
	result, err := srv.executeTool(context.Background(), "list_entries", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
	text, ok := content[0]["text"].(string)
	if !ok {
		t.Fatal("content text has unexpected type")
	}
	if !strings.Contains(text, "github") {
		t.Errorf("expected 'github' in result, got %s", text)
	}
}

func TestHandleList_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"prefix": ""},
	}

	_, err := srv.handleList(context.Background(), req)
	if err == nil {
		t.Fatal("handleList() expected error for out-of-scope path, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("handleList() error = %v, want 'outside allowed scope'", err)
	}
}
