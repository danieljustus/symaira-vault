package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

func TestHandleSearchOpenAI_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "test"},
	}

	result, err := srv.handleSearchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSearchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSearchOpenAI() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSearchOpenAI() returned error: %s", result.Text)
	}
	if result.StructuredContent == nil {
		t.Fatal("handleSearchOpenAI() returned nil StructuredContent")
	}

	structured, ok := result.StructuredContent.(openAISearchResponse)
	if !ok {
		t.Fatalf("StructuredContent type = %T, want openAISearchResponse", result.StructuredContent)
	}
	if len(structured.Results) == 0 {
		t.Fatal("expected at least one search result")
	}
	found := false
	for _, r := range structured.Results {
		if r.ID == "github" {
			found = true
			if r.Title == "" {
				t.Error("result title should not be empty")
			}
			if r.URL == "" {
				t.Error("result url should not be empty")
			}
			if !strings.HasPrefix(r.URL, "symvault://") {
				t.Errorf("result url = %q, want symvault:// prefix", r.URL)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find github entry in search results")
	}

	var textResults []openAISearchResult
	if err := json.Unmarshal([]byte(result.Text), &textResults); err != nil {
		t.Fatalf("parse result text: %v", err)
	}
	if len(textResults) != len(structured.Results) {
		t.Errorf("text results count = %d, structured count = %d", len(textResults), len(structured.Results))
	}
}

func TestHandleSearchOpenAI_MissingQuery(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleSearchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSearchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSearchOpenAI() returned nil result")
	}
	if !result.IsError {
		t.Error("handleSearchOpenAI() expected error result for missing query")
	}
}

func TestHandleSearchOpenAI_FiltersByScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "test"},
	}

	result, err := srv.handleSearchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSearchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSearchOpenAI() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSearchOpenAI() returned error: %s", result.Text)
	}

	structured, ok := result.StructuredContent.(openAISearchResponse)
	if !ok {
		t.Fatalf("StructuredContent type = %T, want openAISearchResponse", result.StructuredContent)
	}
	for _, r := range structured.Results {
		if r.ID == "github" {
			t.Error("github should not be in results due to scope filtering")
		}
	}
}

func TestHandleSearchOpenAI_NoResults(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "zzzzz_nomatch"},
	}

	result, err := srv.handleSearchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSearchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSearchOpenAI() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSearchOpenAI() returned error: %s", result.Text)
	}

	structured, ok := result.StructuredContent.(openAISearchResponse)
	if !ok {
		t.Fatalf("StructuredContent type = %T, want openAISearchResponse", result.StructuredContent)
	}
	if len(structured.Results) != 0 {
		t.Errorf("expected no results, got %d", len(structured.Results))
	}
}

func TestHandleFetchOpenAI_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      config.BoolPtr(false),
		CanReadValues: config.BoolPtr(true),
		ApprovalMode:  config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"id": "github"},
	}

	result, err := srv.handleFetchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFetchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleFetchOpenAI() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleFetchOpenAI() returned error: %s", result.Text)
	}
	if result.StructuredContent == nil {
		t.Fatal("handleFetchOpenAI() returned nil StructuredContent")
	}

	structured, ok := result.StructuredContent.(openAIFetchResponse)
	if !ok {
		t.Fatalf("StructuredContent type = %T, want openAIFetchResponse", result.StructuredContent)
	}
	if structured.ID != "github" {
		t.Errorf("id = %q, want github", structured.ID)
	}
	if structured.Title == "" {
		t.Error("title should not be empty")
	}
	if !strings.HasPrefix(structured.URL, "symvault://") {
		t.Errorf("url = %q, want symvault:// prefix", structured.URL)
	}
	if structured.Metadata == nil {
		t.Fatal("expected metadata in response")
	}
	if v, ok := structured.Metadata["version"]; !ok || v == nil {
		t.Error("expected version in metadata")
	}
	if structured.Values == nil {
		t.Fatal("expected values in response when canReadValues is true")
	}
	if _, ok := structured.Values["password"]; !ok {
		t.Error("expected password field in values")
	}

	var textResponse openAIFetchResponse
	if err := json.Unmarshal([]byte(result.Text), &textResponse); err != nil {
		t.Fatalf("parse result text: %v", err)
	}
	if textResponse.ID != structured.ID {
		t.Errorf("text id = %q, want %q", textResponse.ID, structured.ID)
	}
}

func TestHandleFetchOpenAI_NoValues(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      config.BoolPtr(false),
		CanReadValues: config.BoolPtr(false),
		ApprovalMode:  config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"id": "github"},
	}

	result, err := srv.handleFetchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFetchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleFetchOpenAI() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleFetchOpenAI() returned error: %s", result.Text)
	}

	structured, ok := result.StructuredContent.(openAIFetchResponse)
	if !ok {
		t.Fatalf("StructuredContent type = %T, want openAIFetchResponse", result.StructuredContent)
	}
	if structured.Values != nil {
		t.Error("expected nil values when canReadValues is false")
	}
	if structured.Metadata == nil {
		t.Error("expected metadata even without value access")
	}
}

func TestHandleFetchOpenAI_MissingID(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleFetchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFetchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleFetchOpenAI() returned nil result")
	}
	if !result.IsError {
		t.Error("handleFetchOpenAI() expected error result for missing id")
	}
}

func TestHandleFetchOpenAI_NotFound(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"id": "nonexistent"},
	}

	result, err := srv.handleFetchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFetchOpenAI() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("handleFetchOpenAI() expected error result for nonexistent entry")
	}
}

func TestHandleFetchOpenAI_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"id": "github"},
	}

	result, err := srv.handleFetchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFetchOpenAI() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleFetchOpenAI() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleFetchOpenAI() expected error result for out-of-scope path")
	}
	if !strings.Contains(result.Text, "outside allowed scope") {
		t.Errorf("error = %q, want 'outside allowed scope'", result.Text)
	}
}

func TestCallToolResultPayload_StructuredContent(t *testing.T) {
	structured := map[string]any{"results": []map[string]any{
		{"id": "test", "title": "Test", "url": "symvault://entry/test"},
	}}
	result := mcp.NewToolResultStructured(`[{"id":"test","title":"Test","url":"symvault://entry/test"}]`, structured)

	payload := callToolResultPayload(result)

	if payload["structuredContent"] == nil {
		t.Fatal("expected structuredContent in payload")
	}

	sc, ok := payload["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("structuredContent type = %T, want map[string]any", payload["structuredContent"])
	}
	results, ok := sc["results"].([]map[string]any)
	if !ok {
		t.Fatalf("results type = %T, want []map[string]any", sc["results"])
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0]["id"] != "test" {
		t.Errorf("result id = %v, want test", results[0]["id"])
	}

	content, ok := payload["content"].([]map[string]any)
	if !ok {
		t.Fatal("expected content in payload")
	}
	if len(content) == 0 {
		t.Fatal("expected non-empty content")
	}
	if content[0]["type"] != "text" {
		t.Errorf("content type = %v, want text", content[0]["type"])
	}

	if payload["isError"] != false {
		t.Error("expected isError to be false")
	}
}

func TestEntryURL(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"github", "symvault://entry/github"},
		{"work/aws", "symvault://entry/work/aws"},
		{"nested/deep/path", "symvault://entry/nested/deep/path"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := entryURL(tt.path)
			if got != tt.want {
				t.Errorf("entryURL(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestEntryTitle(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"github", "github"},
		{"work/aws", "aws"},
		{"nested/deep/path", "path"},
		{"single", "single"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := entryTitle(tt.path)
			if got != tt.want {
				t.Errorf("entryTitle(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSearchToolRegistered(t *testing.T) {
	defs := toolDefinitions()
	foundSearch := false
	foundFetch := false
	for _, def := range defs {
		if def.Name == "search" {
			foundSearch = true
			if def.RiskLevel != RiskLevelLow {
				t.Errorf("search tool RiskLevel = %v, want RiskLevelLow", def.RiskLevel)
			}
			if !def.ReadOnlyHint {
				t.Error("search tool should have ReadOnlyHint true")
			}
		}
		if def.Name == "fetch" {
			foundFetch = true
			if def.RiskLevel != RiskLevelLow {
				t.Errorf("fetch tool RiskLevel = %v, want RiskLevelLow", def.RiskLevel)
			}
			if !def.ReadOnlyHint {
				t.Error("fetch tool should have ReadOnlyHint true")
			}
		}
	}
	if !foundSearch {
		t.Error("search tool not registered in tool definitions")
	}
	if !foundFetch {
		t.Error("fetch tool not registered in tool definitions")
	}
}

func TestFetchOpenAI_ValuesRespectCanReadValues(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      config.BoolPtr(false),
		CanReadValues: config.BoolPtr(false),
		ApprovalMode:  config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"id": "github"},
	}

	result, err := srv.handleFetchOpenAI(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFetchOpenAI() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleFetchOpenAI() returned error: %s", result.Text)
	}

	structured, ok := result.StructuredContent.(openAIFetchResponse)
	if !ok {
		t.Fatalf("StructuredContent type = %T, want openAIFetchResponse", result.StructuredContent)
	}
	if structured.Values != nil {
		t.Error("Values should be nil when canReadValues is false")
	}
	if structured.Metadata == nil {
		t.Error("Metadata should be present even without value access")
	}
}

func TestExecuteTool_SearchOpenAI(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args, _ := json.Marshal(map[string]any{"query": "test"})
	rawArgs := json.RawMessage(args)
	result, err := srv.executeTool(context.Background(), "search", rawArgs)
	if err != nil {
		t.Fatalf("executeTool(search) error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}

	if _, ok := result["structuredContent"]; !ok {
		t.Error("expected structuredContent in result")
	}
}

func TestExecuteTool_FetchOpenAI(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      config.BoolPtr(false),
		CanReadValues: config.BoolPtr(true),
		ApprovalMode:  config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args, _ := json.Marshal(map[string]any{"id": "github"})
	rawArgs := json.RawMessage(args)
	result, err := srv.executeTool(context.Background(), "fetch", rawArgs)
	if err != nil {
		t.Fatalf("executeTool(fetch) error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}

	if _, ok := result["structuredContent"]; !ok {
		t.Error("expected structuredContent in result")
	}
}
