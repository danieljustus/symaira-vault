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
	"strconv"
	"strings"
	"testing"
	"time"
)

const tokenPortFixturePath = "testdata/port/auth/token-lookup.json"

type tokenPortFixture struct {
	SchemaVersion int                 `json:"schema_version"`
	Oracle        tokenPortOracle     `json:"oracle"`
	Now           string              `json:"now"`
	Registry      TokenRegistryFile   `json:"registry"`
	Lookups       []tokenPortLookup   `json:"lookups"`
	Scopes        []tokenPortScope    `json:"scopes"`
	Documents     []tokenPortDocument `json:"documents"`
}

// tokenPortDocument records what json.Unmarshal into TokenRegistryFile (the
// call unmarshalEntries makes) produced for a raw registry document: the
// repeated-allowed_tools overlay cases of ADR 0034 item 19.
type tokenPortDocument struct {
	Name     string                           `json:"name"`
	Document string                           `json:"document"`
	Error    bool                             `json:"error"`
	Tokens   map[string]tokenPortDecodedEntry `json:"tokens,omitempty"`
}

type tokenPortDecodedEntry struct {
	AllowedTools []string `json:"allowed_tools"`
	Revoked      bool     `json:"revoked"`
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
		Documents: tokenPortDocuments(),
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

// tokenPortDocuments builds registry documents whose repeated allowed_tools
// members overlay each other, and records Go's decode result for each. The
// generated block uses a fixed LCG, never math/rand, so the fixture does not
// depend on a Go release.
func tokenPortDocuments() []tokenPortDocument {
	str := func(values ...string) string {
		out := make([]string, len(values))
		for i, value := range values {
			out[i] = strconv.Quote(value)
		}
		return "[" + strings.Join(out, ",") + "]"
	}
	tools := func(array string) string { return `"allowed_tools":` + array }
	cases := []struct{ name, members string }{
		{"null-element-keeps-earlier", tools(str("a")) + "," + tools("[null]")},
		{"null-element-after-empty", tools("[]") + "," + tools("[null]")},
		{"null-element-alone", tools("[null]")},
		{"null-and-string-elements", tools(`[null,"x",null]`)},
		{"shorter-then-nulls-reexpose", tools(str("a", "b", "c")) + "," + tools(str("x")) + "," + tools("[null,null,null]")},
		{"nulls-longer-than-backing", tools(str("a", "b")) + "," + tools(str("x")) + "," + tools("[null,null,null,null]")},
		{"nil-drops-backing", tools(str("a", "b")) + "," + tools("null") + "," + tools("[null,null]")},
		{"empty-drops-backing", tools(str("a", "b")) + "," + tools("[]") + "," + tools("[null,null]")},
		{"case-folded-name", tools(str("a")) + `,"ALLOWED_TOOLS":[null]`},
		{"revoked-after-overlay", tools(str("a")) + "," + tools("[null]") + `,"revoked":true`},
		{"revoked-then-overlay", `"revoked":true,` + tools(str("a")) + "," + tools("[null]")},
		{"overlay-then-nil", tools(str("a")) + "," + tools("[null]") + "," + tools("null")},
	}
	// Overlay sequences across capacity boundaries (1, 2, 4, 8, ... and the
	// 1.25x growth past 256): n strings, one short array, then 2n nulls.
	for _, n := range []int{1, 2, 3, 4, 5, 8, 9, 16, 17, 33, 257, 600} {
		long := make([]string, n)
		for i := range long {
			long[i] = fmt.Sprintf("t%d", i)
		}
		nulls := strings.TrimSuffix(strings.Repeat("null,", 2*n), ",")
		cases = append(cases, struct{ name, members string }{
			fmt.Sprintf("capacity-%d", n),
			tools(str(long...)) + "," + tools(str("x")) + "," + tools("["+nulls+"]"),
		})
	}
	state := uint32(20261103)
	next := func(bound uint32) uint32 {
		state = state*1664525 + 1013904223
		return (state >> 8) % bound
	}
	for k := 0; k < 48; k++ {
		var members []string
		for m, count := 0, 1+int(next(4)); m < count; m++ {
			switch next(8) {
			case 0:
				members = append(members, tools("null"))
			case 1:
				members = append(members, tools("[]"))
			default:
				items := make([]string, int(next(9))+1)
				for i := range items {
					if next(5) < 2 {
						items[i] = "null"
					} else {
						items[i] = strconv.Quote(fmt.Sprintf("s%d_%d_%d", k, m, i))
					}
				}
				members = append(members, tools("["+strings.Join(items, ",")+"]"))
			}
		}
		cases = append(cases, struct{ name, members string }{fmt.Sprintf("generated-%02d", k), strings.Join(members, ",")})
	}
	documents := make([]tokenPortDocument, 0, len(cases))
	for _, c := range cases {
		text := `{"version":2,"tokens":{"t":{"id":"t","hash":"h",` + c.members + `}}}`
		var file TokenRegistryFile
		record := tokenPortDocument{Name: c.name, Document: text}
		if err := json.Unmarshal([]byte(text), &file); err != nil {
			record.Error = true
		} else {
			record.Tokens = map[string]tokenPortDecodedEntry{}
			for id, entry := range file.Tokens {
				record.Tokens[id] = tokenPortDecodedEntry{AllowedTools: entry.AllowedTools, Revoked: entry.Revoked}
			}
		}
		documents = append(documents, record)
	}
	return documents
}
