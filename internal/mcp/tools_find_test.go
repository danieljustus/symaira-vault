package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestHandleFind_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"query": "test"},
	}

	result, err := srv.handleFind(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFind() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleFind() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleFind() returned error: %s", result.Text)
	}

	var matches []vault.Match
	if err := json.Unmarshal([]byte(result.Text), &matches); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	// github entry should match since it contains "test" in username
	found := false
	for _, m := range matches {
		if m.Path == "github" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find github entry in matches")
	}
}

func TestHandleFind_MissingQuery(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleFind(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFind() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleFind() returned nil result")
	}
	if !result.IsError {
		t.Error("handleFind() expected error result for missing query")
	}
}

func TestHandleFind_FiltersByScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"}, // Only allow work/ paths
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"query": "test"},
	}

	result, err := srv.handleFind(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFind() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleFind() returned nil result")
	}

	var matches []vault.Match
	if err := json.Unmarshal([]byte(result.Text), &matches); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	// github is not in work/ scope, so should not be in results
	for _, m := range matches {
		if m.Path == "github" {
			t.Error("github should not be in results due to scope filtering")
		}
	}
}

func TestHandleFind_DoesNotDecryptOutOfScopeEntries(t *testing.T) {
	vaultDir, identity := mockVault(t)
	if err := vault.WriteEntry(vaultDir, "work/allowed", &vault.Entry{
		Data: map[string]any{"password": "allowed-secret"},
	}, identity); err != nil {
		t.Fatalf("write allowed entry: %v", err)
	}

	privateDir := filepath.Join(vaultDir, "entries", "private")
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		t.Fatalf("create private dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(privateDir, "broken.age"), []byte("not an age payload"), 0o600); err != nil {
		t.Fatalf("write corrupt out-of-scope entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"query": "allowed"},
	}

	result, err := srv.handleFind(context.Background(), req)
	if err != nil {
		t.Fatalf("handleFind() error = %v", err)
	}

	var matches []vault.Match
	if err := json.Unmarshal([]byte(result.Text), &matches); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(matches) != 1 || matches[0].Path != "work/allowed" {
		t.Fatalf("matches = %#v, want only work/allowed", matches)
	}
}

func TestFindEntries(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	matches, err := srv.findEntries(context.Background(), "test")
	if err != nil {
		t.Fatalf("findEntries() error = %v", err)
	}

	if len(matches) == 0 {
		t.Error("expected matches for 'test' query")
	}
}

func TestFindEntries_NoResults(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	matches, err := srv.findEntries(context.Background(), "zzzzz_nomatch")
	if err != nil {
		t.Fatalf("findEntries() error = %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected no matches, got %d", len(matches))
	}
}

func TestFindEntries_ListFails(t *testing.T) {
	vaultDir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	srv.vault.Dir = filepath.Join(vaultDir, "nonexistent")

	_, err = srv.findEntries(context.Background(), "test")
	if err == nil {
		t.Fatal("findEntries() expected error for nonexistent dir, got nil")
	}
}

func TestCollectFieldMatches(t *testing.T) {
	tests := []struct {
		data     map[string]any
		expected map[string]struct{}
		name     string
		needle   string
	}{
		{
			name: "simple match",
			data: map[string]any{
				"password": "secret123",
			},
			needle:   "secret",
			expected: map[string]struct{}{"password": {}},
		},
		{
			name: "nested match",
			data: map[string]any{
				"credentials": map[string]any{
					"api_key": "key123",
				},
			},
			needle:   "key",
			expected: map[string]struct{}{"credentials.api_key": {}},
		},
		{
			name: "no match",
			data: map[string]any{
				"password": "secret123",
			},
			needle:   "nomatch",
			expected: map[string]struct{}{},
		},
		{
			name:     "empty needle",
			data:     map[string]any{"password": "secret123"},
			needle:   "",
			expected: map[string]struct{}{"password": {}},
		},
		{
			name: "array match",
			data: map[string]any{
				"urls": []any{"https://example.com", "https://test.com"},
			},
			needle:   "example",
			expected: map[string]struct{}{"urls[0]": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := make(map[string]struct{})
			vault.CollectFieldMatches(result, "", tt.data, tt.needle, nil)
			if len(result) != len(tt.expected) {
				t.Errorf("collectFieldMatches() got %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCollectFieldMatches_EdgeCases(t *testing.T) {
	tests := []struct {
		data     map[string]any
		expected map[string]struct{}
		name     string
		needle   string
	}{
		{
			name:     "empty map",
			data:     map[string]any{},
			needle:   "test",
			expected: map[string]struct{}{},
		},
		{
			name: "deeply nested arrays",
			data: map[string]any{
				"deep": []any{
					[]any{
						[]any{"value"},
					},
				},
			},
			needle:   "value",
			expected: map[string]struct{}{"deep[0][0][0]": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := make(map[string]struct{})
			vault.CollectFieldMatches(result, "", tt.data, tt.needle, nil)
			if len(result) != len(tt.expected) {
				t.Errorf("collectFieldMatches() got %v, want %v", result, tt.expected)
			}
			for k := range tt.expected {
				if _, ok := result[k]; !ok {
					t.Errorf("missing key %q", k)
				}
			}
		})
	}

	t.Run("scalar with empty prefix", func(t *testing.T) {
		result := make(map[string]struct{})
		vault.CollectFieldMatches(result, "", "testvalue", "test", nil)
		if len(result) != 0 {
			t.Errorf("collectFieldMatches() with scalar and empty prefix should return empty, got %v", result)
		}
	})
}
