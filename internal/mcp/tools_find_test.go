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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
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
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	srv.vault.Dir = filepath.Join(vaultDir, "nonexistent")

	_, err = srv.findEntries(context.Background(), "test")
	if err == nil {
		t.Fatal("findEntries() expected error for nonexistent dir, got nil")
	}
}

// TestFindPerToolRedact verifies that PerToolRedactFields["find_entries"]
// is applied when handleFind is called. A query matching a redacted field
// must not surface that field in Match.Fields, while non-redacted fields
// that match continue to appear normally.
func TestFindPerToolRedact(t *testing.T) {
	vaultDir, identity := mockVault(t)

	// Override the github entry with a password value we can search for
	entry := &vault.Entry{
		Data: map[string]any{
			"password": "s3cr3tpass",
			"username": "alice",
		},
	}
	if err := vault.WriteEntry(vaultDir, "github", entry, identity); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	srv := &Server{
		vault: &vault.Vault{
			Dir:      vaultDir,
			Identity: identity,
		},
		agent: &config.AgentProfile{
			Name:         "restricted",
			AllowedPaths: []string{"*"},
			CanWrite:     config.BoolPtr(false),
			ApprovalMode: config.StrPtr("none"),
			PerToolRedactFields: map[string][]string{
				"find_entries": {"password"},
			},
		},
		hookRegistry: NewHookRegistry(),
	}

	// Query that matches the password value — should not appear in Fields
	req := CallToolRequest{
		Arguments: map[string]any{"query": "s3cr3tpass"},
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
	if parseErr := json.Unmarshal([]byte(result.Text), &matches); parseErr != nil {
		t.Fatalf("parse result: %v", parseErr)
	}

	// The password value matches the query but password is redacted — no match
	// should be returned for the github entry via that field.
	for _, m := range matches {
		if m.Path == "github" {
			for _, f := range m.Fields {
				if f == "password" {
					t.Errorf("password field should be redacted from find_entries results, but got field %q", f)
				}
			}
		}
	}

	// Now query for a value in the non-redacted username field — must appear
	req2 := CallToolRequest{
		Arguments: map[string]any{"query": "alice"},
	}

	result2, err := srv.handleFind(context.Background(), req2)
	if err != nil {
		t.Fatalf("handleFind() second call error = %v", err)
	}
	if result2 == nil {
		t.Fatal("handleFind() second call returned nil result")
	}
	if result2.IsError {
		t.Fatalf("handleFind() second call returned error: %s", result2.Text)
	}

	var matches2 []vault.Match
	if parseErr := json.Unmarshal([]byte(result2.Text), &matches2); parseErr != nil {
		t.Fatalf("parse second result: %v", parseErr)
	}

	found := false
	for _, m := range matches2 {
		if m.Path == "github" {
			for _, f := range m.Fields {
				if f == "username" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("username field should NOT be redacted and should appear in find_entries results")
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
