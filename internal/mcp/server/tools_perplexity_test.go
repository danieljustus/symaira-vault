package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

func newTestPerplexityServer(t *testing.T, searchResponse bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q, want /chat/completions", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-perplexity-key" {
			t.Errorf("Authorization = %q, want Bearer test-perplexity-key", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}

		var reqBody map[string]any
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}

		answer := "The capital of France is Paris."
		if searchResponse {
			answer = "Paris is the capital of France, located in the north-central part of the country."
		}

		resp := map[string]any{
			"id":    "test-chat-id",
			"model": "sonar-pro",
			"choices": []map[string]any{
				{
					"index":         0,
					"finish_reason": "stop",
					"message": map[string]any{
						"role":    "assistant",
						"content": answer,
					},
				},
			},
			"citations": []string{"https://en.wikipedia.org/wiki/Paris", "https://www.britannica.com/place/Paris"},
			"usage": map[string]any{
				"prompt_tokens":     50,
				"completion_tokens": 100,
				"total_tokens":      150,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestHandlePerplexitySearch_Success(t *testing.T) {
	ts := newTestPerplexityServer(t, true)
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "test-perplexity-key",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL:         ts.URL,
				RateLimitPerMin: 100,
			},
		},
	}

	globalPerplexityRL = &perplexityRateLimiter{}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "What is the capital of France?"},
	}

	result, err := srv.handlePerplexitySearch(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexitySearch() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexitySearch() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handlePerplexitySearch() returned error: %s", result.Text)
	}

	var output perplexitySearchResult
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if output.Query != "What is the capital of France?" {
		t.Errorf("query = %q, want %q", output.Query, "What is the capital of France?")
	}
	if output.Answer == "" {
		t.Error("answer should not be empty")
	}
	if !strings.Contains(output.Answer, "Paris") {
		t.Errorf("answer = %q, want to contain 'Paris'", output.Answer)
	}
	if len(output.Citations) == 0 {
		t.Error("expected citations")
	}
	if output.Model == "" {
		t.Error("model should not be empty")
	}
}

func TestHandlePerplexitySearch_MissingQuery(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "test-key",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL: "http://localhost:9999",
			},
		},
	}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handlePerplexitySearch(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexitySearch() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexitySearch() returned nil result")
	}
	if !result.IsError {
		t.Error("handlePerplexitySearch() expected error result for missing query")
	}
}

func TestHandlePerplexitySearch_MissingAPIKey(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "other-entry", map[string]any{
		"password": "some-value",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL: "http://localhost:9999",
			},
		},
	}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "test query"},
	}

	result, err := srv.handlePerplexitySearch(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexitySearch() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexitySearch() returned nil result")
	}
	if !result.IsError {
		t.Error("handlePerplexitySearch() expected error for missing API key")
	}
	if !strings.Contains(result.Text, "API key") {
		t.Errorf("error = %q, want to contain 'API key'", result.Text)
	}
}

func TestHandlePerplexitySearch_APIKeyFromConfig(t *testing.T) {
	ts := newTestPerplexityServer(t, true)
	defer ts.Close()

	vaultDir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				APIKey:          "test-perplexity-key",
				BaseURL:         ts.URL,
				RateLimitPerMin: 100,
			},
		},
	}

	globalPerplexityRL = &perplexityRateLimiter{}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "What is the capital of France?"},
	}

	result, err := srv.handlePerplexitySearch(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexitySearch() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexitySearch() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handlePerplexitySearch() returned error: %s", result.Text)
	}

	var output perplexitySearchResult
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if output.Query != "What is the capital of France?" {
		t.Errorf("query = %q, want %q", output.Query, "What is the capital of France?")
	}
	if output.Answer == "" {
		t.Error("answer should not be empty")
	}
}

func TestHandlePerplexityAsk_Success(t *testing.T) {
	ts := newTestPerplexityServer(t, false)
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "test-perplexity-key",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL:         ts.URL,
				RateLimitPerMin: 100,
			},
		},
	}

	globalPerplexityRL = &perplexityRateLimiter{}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"question": "What is the capital of France?"},
	}

	result, err := srv.handlePerplexityAsk(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexityAsk() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexityAsk() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handlePerplexityAsk() returned error: %s", result.Text)
	}

	var output perplexityAskResult
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if output.Question != "What is the capital of France?" {
		t.Errorf("question = %q, want %q", output.Question, "What is the capital of France?")
	}
	if output.Answer == "" {
		t.Error("answer should not be empty")
	}
	if !strings.Contains(output.Answer, "Paris") {
		t.Errorf("answer = %q, want to contain 'Paris'", output.Answer)
	}
	if len(output.Citations) == 0 {
		t.Error("expected citations")
	}
	if output.Model == "" {
		t.Error("model should not be empty")
	}
}

func TestHandlePerplexityAsk_WithContext(t *testing.T) {
	ts := newTestPerplexityServer(t, false)
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "test-perplexity-key",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL:         ts.URL,
				RateLimitPerMin: 100,
			},
		},
	}

	globalPerplexityRL = &perplexityRateLimiter{}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"question": "What services does AWS provide?",
			"context":  "AWS provides cloud computing services including EC2, S3, Lambda.",
		},
	}

	result, err := srv.handlePerplexityAsk(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexityAsk() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexityAsk() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handlePerplexityAsk() returned error: %s", result.Text)
	}

	var output perplexityAskResult
	if err := json.Unmarshal([]byte(result.Text), &output); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if output.Question != "What services does AWS provide?" {
		t.Errorf("question = %q, want %q", output.Question, "What services does AWS provide?")
	}
	if len(output.Context) == 0 {
		t.Error("expected context in result")
	}
	if output.Answer == "" {
		t.Error("answer should not be empty")
	}
}

func TestHandlePerplexityAsk_MissingQuestion(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "test-key",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL: "http://localhost:9999",
			},
		},
	}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handlePerplexityAsk(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexityAsk() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexityAsk() returned nil result")
	}
	if !result.IsError {
		t.Error("handlePerplexityAsk() expected error result for missing question")
	}
}

func TestPerplexitySearchToolRegistered(t *testing.T) {
	defs := toolDefinitions()
	foundSearch := false
	foundAsk := false
	for _, def := range defs {
		if def.Name == "perplexity_search" {
			foundSearch = true
			if def.RiskLevel != RiskLevelLow {
				t.Errorf("perplexity_search RiskLevel = %v, want RiskLevelLow", def.RiskLevel)
			}
			if !def.ReadOnlyHint {
				t.Error("perplexity_search should have ReadOnlyHint true")
			}
		}
		if def.Name == "perplexity_ask" {
			foundAsk = true
			if def.RiskLevel != RiskLevelLow {
				t.Errorf("perplexity_ask RiskLevel = %v, want RiskLevelLow", def.RiskLevel)
			}
			if !def.ReadOnlyHint {
				t.Error("perplexity_ask should have ReadOnlyHint true")
			}
		}
	}
	if !foundSearch {
		t.Error("perplexity_search tool not registered in tool definitions")
	}
	if !foundAsk {
		t.Error("perplexity_ask tool not registered in tool definitions")
	}
}

func TestPerplexityRateLimiter(t *testing.T) {
	rl := &perplexityRateLimiter{}
	if !rl.Allow(5) {
		t.Error("expected first request to be allowed")
	}
	if !rl.Allow(5) {
		t.Error("expected second request to be allowed")
	}
	for i := 0; i < 3; i++ {
		if !rl.Allow(5) {
			t.Errorf("expected request %d to be allowed", i+3)
		}
	}
	if rl.Allow(5) {
		t.Error("expected 6th request to be denied (limit is 5)")
	}
}

func TestPerplexityRateLimiter_Reset(t *testing.T) {
	rl := &perplexityRateLimiter{}
	rl.count = 5
	rl.resetAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2020, 1, 1, 0, 2, 0, 0, time.UTC)

	rl.mu.Lock()
	if now.After(rl.resetAt) {
		rl.count = 0
		rl.resetAt = now.Add(time.Minute)
	}
	rl.mu.Unlock()

	if !rl.Allow(5) {
		t.Error("expected request after reset to be allowed")
	}
}

func TestResolvePerplexityAPIKey_FromVault(t *testing.T) {
	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "vault-key-123",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	key, err := srv.resolvePerplexityAPIKey(context.Background())
	if err != nil {
		t.Fatalf("resolvePerplexityAPIKey() error = %v", err)
	}
	if key != "vault-key-123" {
		t.Errorf("key = %q, want %q", key, "vault-key-123")
	}
}

func TestResolvePerplexityAPIKey_FromConfig(t *testing.T) {
	vaultDir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				APIKey: "config-key-456",
			},
		},
	}

	key, err := srv.resolvePerplexityAPIKey(context.Background())
	if err != nil {
		t.Fatalf("resolvePerplexityAPIKey() error = %v", err)
	}
	if key != "config-key-456" {
		t.Errorf("key = %q, want %q", key, "config-key-456")
	}
}

func TestResolvePerplexityAPIKey_Missing(t *testing.T) {
	vaultDir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	_, err = srv.resolvePerplexityAPIKey(context.Background())
	if err == nil {
		t.Fatal("resolvePerplexityAPIKey() expected error for missing key")
	}
	if !strings.Contains(err.Error(), "API key") {
		t.Errorf("error = %q, want to contain 'API key'", err.Error())
	}
}

func TestGetPerplexityBaseURL_Default(t *testing.T) {
	vaultDir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name: "test",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	url := srv.getPerplexityBaseURL()
	if url != "https://api.perplexity.ai" {
		t.Errorf("base URL = %q, want %q", url, "https://api.perplexity.ai")
	}
}

func TestGetPerplexityBaseURL_ConfigOverride(t *testing.T) {
	vaultDir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name: "test",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL: "https://custom.perplexity.example.com",
			},
		},
	}

	url := srv.getPerplexityBaseURL()
	if url != "https://custom.perplexity.example.com" {
		t.Errorf("base URL = %q, want %q", url, "https://custom.perplexity.example.com")
	}
}

func TestPerplexitySearch_RateLimited(t *testing.T) {
	ts := newTestPerplexityServer(t, true)
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "test-perplexity-key",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL:         ts.URL,
				RateLimitPerMin: 1,
			},
		},
	}

	globalPerplexityRL = &perplexityRateLimiter{}

	req1 := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "first query"},
	}
	result1, err := srv.handlePerplexitySearch(context.Background(), req1)
	if err != nil {
		t.Fatalf("first request error = %v", err)
	}
	if result1 == nil {
		t.Fatal("first request returned nil result")
	}
	if result1.IsError {
		t.Fatalf("first request returned error: %s", result1.Text)
	}

	req2 := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "second query"},
	}
	result2, err := srv.handlePerplexitySearch(context.Background(), req2)
	if err != nil {
		t.Fatalf("second request error = %v", err)
	}
	if result2 == nil {
		t.Fatal("second request returned nil result")
	}
	if !result2.IsError {
		t.Fatal("expected rate limit error on second request")
	}
	if !strings.Contains(result2.Text, "rate limit") {
		t.Errorf("error = %q, want to contain 'rate limit'", result2.Text)
	}
}

func TestPerplexityAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid_api_key"}`))
	}))
	defer ts.Close()

	vaultDir, identity := mockVaultWithEntry(t, "perplexity", map[string]any{
		"credential": "bad-key",
	})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		MCP: &config.MCPConfig{
			Perplexity: &config.PerplexityConfig{
				BaseURL:         ts.URL,
				RateLimitPerMin: 100,
			},
		},
	}

	globalPerplexityRL = &perplexityRateLimiter{}

	req := mcp.CallToolRequest{
		Arguments: map[string]any{"query": "test"},
	}

	result, err := srv.handlePerplexitySearch(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePerplexitySearch() error = %v", err)
	}
	if result == nil {
		t.Fatal("handlePerplexitySearch() returned nil result")
	}
	if !result.IsError {
		t.Fatal("expected error result for API error")
	}
	if !strings.Contains(result.Text, "401") && !strings.Contains(result.Text, "Unauthorized") {
		t.Errorf("error = %q, want to contain error details", result.Text)
	}
}
