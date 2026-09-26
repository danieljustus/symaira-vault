package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const tokenPortFixturePath = "testdata/port/auth/token-lookup.json"

type tokenPortFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        tokenPortOracle   `json:"oracle"`
	Now           string            `json:"now"`
	Registry      TokenRegistryFile `json:"registry"`
	Lookups       []tokenPortLookup `json:"lookups"`
	Scopes        []tokenPortScope  `json:"scopes"`
}

type tokenPortOracle struct {
	GoVersion     string `json:"go_version"`
	SourceFile    string `json:"source_file"`
	SourceDigest  string `json:"source_digest"`
	GeneratorFile string `json:"generator_file"`
	GeneratorHash string `json:"generator_hash"`
}

type tokenPortLookup struct {
	Name    string `json:"name"`
	Bearer  string `json:"bearer"`
	Found   bool   `json:"found"`
	TokenID string `json:"token_id,omitempty"`
}

type tokenPortScope struct {
	Name    string `json:"name"`
	TokenID string `json:"token_id"`
	Tool    string `json:"tool"`
	Allowed bool   `json:"allowed"`
}

func TestTokenPortFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_TOKEN_PORT_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_TOKEN_PORT_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_TOKEN_PORT_FIXTURE=1 or SYMAIRA_CHECK_TOKEN_PORT_FIXTURE=1")
	}
	if runtime.Version() != "go1.26.6" {
		t.Fatalf("fixture requires pinned Go 1.26.6, got %s", runtime.Version())
	}

	root := tokenPortRepoRoot(t)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	activeRaw := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wildcardRaw := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	emptyRaw := "4444444444444444444444444444444444444444444444444444444444444444"
	revokedRaw := "1111111111111111111111111111111111111111111111111111111111111111"
	expiredRaw := "2222222222222222222222222222222222222222222222222222222222222222"
	unknownRaw := "3333333333333333333333333333333333333333333333333333333333333333"

	entry := func(id, raw string, allowed []string, expiresAt *time.Time, revoked bool) TokenRegistryEntry {
		return TokenRegistryEntry{TokenData: TokenData{
			ID: id, Hash: sha256Hex(raw), Prefix: raw[:4], AllowedTools: allowed,
			CreatedAt: now.Add(-time.Hour), ExpiresAt: expiresAt, Revoked: revoked,
		}}
	}
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := map[string]TokenRegistryEntry{
		"tok-active":   entry("tok-active", activeRaw, []string{"list_entries", "get_entry"}, &future, false),
		"tok-wildcard": entry("tok-wildcard", wildcardRaw, []string{"*"}, nil, false),
		"tok-empty":    entry("tok-empty", emptyRaw, []string{}, nil, false),
		"tok-revoked":  entry("tok-revoked", revokedRaw, []string{"list_entries"}, nil, true),
		"tok-expired":  entry("tok-expired", expiredRaw, []string{"list_entries"}, &past, false),
	}
	registry := TokenRegistryFile{Version: 2, Tokens: entries}

	lookups := []tokenPortLookup{
		{Name: "active-hashed-lookup", Bearer: activeRaw, Found: true, TokenID: "tok-active"},
		{Name: "wildcard-token", Bearer: wildcardRaw, Found: true, TokenID: "tok-wildcard"},
		{Name: "empty-scope-token", Bearer: emptyRaw, Found: true, TokenID: "tok-empty"},
		{Name: "revoked-denied", Bearer: revokedRaw},
		{Name: "expired-denied", Bearer: expiredRaw},
		{Name: "unknown-denied", Bearer: unknownRaw},
	}
	for i := range lookups {
		reg := NewTokenRegistry("")
		for _, stored := range entries {
			token := entryToScopedToken(stored)
			reg.entries[token.Hash] = token
		}
		found, ok := reg.Get(sha256Hex(lookups[i].Bearer))
		lookups[i].Found = ok
		if ok {
			lookups[i].TokenID = found.ID
		}
	}

	scopes := []tokenPortScope{
		{Name: "exact-allowed", TokenID: "tok-active", Tool: "list_entries", Allowed: true},
		{Name: "exact-other-allowed", TokenID: "tok-active", Tool: "get_entry", Allowed: true},
		{Name: "exact-denied", TokenID: "tok-active", Tool: "delete_entry"},
		{Name: "wildcard-allowed", TokenID: "tok-wildcard", Tool: "get_entry", Allowed: true},
		{Name: "empty-scope-denied", TokenID: "tok-empty", Tool: "list_entries"},
		{Name: "empty-name-denied", TokenID: "tok-active", Tool: ""},
	}
	for i := range scopes {
		scopes[i].Allowed = entryToScopedToken(entries[scopes[i].TokenID]).IsToolAllowed(scopes[i].Tool)
	}

	sourceDigest := tokenPortDigest(t, root, "internal/mcp/auth/token.go")
	generatorHash := tokenPortGeneratorHash(t)
	fixture := tokenPortFixture{
		SchemaVersion: 1,
		Oracle: tokenPortOracle{
			GoVersion: "go1.26.6", SourceFile: "internal/mcp/auth/token.go",
			SourceDigest: sourceDigest, GeneratorFile: "internal/mcp/auth/token_port_fixture_test.go",
			GeneratorHash: generatorHash,
		},
		Now: now.Format(time.RFC3339), Registry: registry, Lookups: lookups, Scopes: scopes,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal token fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, filepath.FromSlash(tokenPortFixturePath))
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read token fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("token lookup fixture is stale; run with SYMAIRA_GENERATE_TOKEN_PORT_FIXTURE=1")
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create token fixture directory: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write token fixture: %v", err)
	}
}

func tokenPortRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate token fixture generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func tokenPortDigest(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read token oracle source %s: %v", name, err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func tokenPortGeneratorHash(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate token fixture generator")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read token fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}
