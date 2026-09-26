package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// This opt-in generator drives the production Go tools/call dispatcher against
// a disposable encrypted fixture. It captures list_entries path filtering,
// metadata projection, and scope denial without reading any ambient vault.

type mcpListEntriesFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Oracle        mcpListEntriesOracle `json:"oracle"`
	ServerName    string               `json:"server_name"`
	ServerVersion string               `json:"server_version"`
	Cases         []mcpListEntriesCase `json:"cases"`
}

type mcpListEntriesOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpListEntriesCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

var mcpListEntriesTimestamp = regexp.MustCompile(`20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z`)

var mcpListEntriesSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_list.go",
	"internal/mcp/server/render.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/search.go",
	"internal/vault/service.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
}

func TestGenerateMCPListEntriesFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_LIST_ENTRIES_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_LIST_ENTRIES_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_LIST_ENTRIES_FIXTURE=1 or SYMAIRA_CHECK_MCP_LIST_ENTRIES_FIXTURE=1")
	}

	vaultDir, identity := mcpListEntriesFixtureVault(t)
	serverName := "symvault"
	serverVersion := "0.0.0-list-entries-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	cases := []struct {
		name    string
		profile config.AgentProfile
		call    string
	}{
		{
			name:    "paths",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_entries","arguments":{"prefix":""}}}`,
		},
		{
			name:    "details_prefix",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_entries","arguments":{"prefix":"nested/","include_details":true}}}`,
		},
		{
			name:    "scope_denied",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"nested/*"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_entries","arguments":{"prefix":""}}}`,
		},
	}

	fixtureCases := make([]mcpListEntriesCase, 0, len(cases))
	for _, tc := range cases {
		srv := newTestServerWithVault(t, tc.profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		handler := NewProtocolHandler(serverName, serverVersion, srv)
		inputs := append(append([]string{}, base...), tc.call)
		outputs := make([]json.RawMessage, 0, len(inputs))
		for _, line := range inputs {
			var msg transport.Message
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				t.Fatalf("decode %s input: %v", tc.name, err)
			}
			response, err := handler.HandleMessage(context.Background(), &msg)
			if err != nil {
				t.Fatalf("handle %s: %v", tc.name, err)
			}
			if response == nil {
				continue
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatalf("marshal %s response: %v", tc.name, err)
			}
			var value any
			if err := json.Unmarshal(encoded, &value); err != nil {
				t.Fatalf("decode %s response: %v", tc.name, err)
			}
			value, _ = normalizeMCPCallValue(value, vaultDir)
			normalized, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal normalized %s response: %v", tc.name, err)
			}
			normalized = mcpListEntriesTimestamp.ReplaceAll(normalized, []byte("<fixture-time>"))
			outputs = append(outputs, normalized)
		}
		fixtureCases = append(fixtureCases, mcpListEntriesCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpListRepoRoot(t)
	sourceHash := mcpCallSourceHash(t, mcpListEntriesSourceFiles)
	pinned := mcpListEntriesGitSourceHash(t)
	if sourceHash != pinned {
		t.Fatalf("Go list_entries sources differ from c42b96bb: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpListEntriesFixture{
		SchemaVersion: 1,
		Oracle: mcpListEntriesOracle{
			Commit: "c42b96bb", CommitSHA: "c42b96bb4dd2a2d6cea1ade0770f55650045e5b3",
			SourceFiles: mcpListEntriesSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpListEntriesGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-list-entries.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP list_entries fixture is stale; run with SYMAIRA_GENERATE_MCP_LIST_ENTRIES_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mcpListEntriesFixtureVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate fixture identity: %v", err)
	}
	entries := map[string]*vault.Entry{
		"alpha": {Data: map[string]any{"username": "alice", "password": "synthetic"}},
		"nested/child": {
			Data:           map[string]any{"token": "synthetic"},
			SecretMetadata: vault.SecretMetadata{Type: vault.SecretTypeAPIKey, UsageHint: "API credential", AutoRotate: true},
		},
		"quarantine/bad": {Data: map[string]any{"password": "synthetic"}},
	}
	for path, entry := range entries {
		if err := vault.WriteEntry(dir, path, entry, identity); err != nil {
			t.Fatalf("write fixture entry %s: %v", path, err)
		}
	}
	return dir, identity
}

func mcpListEntriesGitSourceHash(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range mcpListEntriesSourceFiles {
		cmd := exec.Command("git", "show", "c42b96bb:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned list_entries source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpListEntriesGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate list_entries fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read list_entries fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}
