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
	"runtime"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

type mcpDeleteEntryFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Oracle        mcpDeleteEntryOracle `json:"oracle"`
	ServerName    string               `json:"server_name"`
	ServerVersion string               `json:"server_version"`
	Cases         []mcpDeleteEntryCase `json:"cases"`
}

type mcpDeleteEntryOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpDeleteEntryCase struct {
	Name   string              `json:"name"`
	Input  []string            `json:"input"`
	Output []json.RawMessage   `json:"output"`
	State  mcpDeleteEntryState `json:"state"`
}

type mcpDeleteEntryState struct {
	Exists bool `json:"exists"`
}

var mcpDeleteEntrySourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_delete.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/service.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
}

func TestGenerateMCPDeleteEntryFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_DELETE_ENTRY_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_DELETE_ENTRY_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_DELETE_ENTRY_FIXTURE=1 or SYMAIRA_CHECK_MCP_DELETE_ENTRY_FIXTURE=1")
	}

	serverName := "symvault"
	serverVersion := "0.0.0-delete-entry-fixture"
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
			name:    "delete_existing",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_entry","arguments":{"path":"github"}}}`,
		},
		{
			name:    "delete_missing",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_entry","arguments":{"path":"missing"}}}`,
		},
		{
			name:    "delete_denied_write",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(false), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_entry","arguments":{"path":"github"}}}`,
		},
		{
			name:    "delete_denied_tier",
			profile: config.AgentProfile{Name: "fixture", Tier: config.StrPtr("read-only"), AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_entry","arguments":{"path":"github"}}}`,
		},
		{
			name:    "delete_denied_scope",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed/*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"delete_entry","arguments":{"path":"github"}}}`,
		},
		{
			name:    "delete_denied_approval",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("deny")},
			call:    `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_entry","arguments":{"path":"github"}}}`,
		},
		{
			name:    "delete_invalid_path",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"delete_entry","arguments":{}}}`,
		},
	}

	fixtureCases := make([]mcpDeleteEntryCase, 0, len(cases))
	for _, tc := range cases {
		vaultDir, identity := mcpDeleteEntryFixtureVault(t)
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
			outputs = append(outputs, encoded)
		}
		_, err := vault.ReadEntry(vaultDir, "github", identity)
		fixtureCases = append(fixtureCases, mcpDeleteEntryCase{
			Name: tc.name, Input: inputs, Output: outputs,
			State: mcpDeleteEntryState{Exists: err == nil},
		})
	}

	root := mcpListRepoRoot(t)
	sourceHash := mcpCallSourceHash(t, mcpDeleteEntrySourceFiles)
	pinned := mcpDeleteEntryGitSourceHash(t)
	if sourceHash != pinned {
		t.Fatalf("Go delete_entry sources differ from 3232e31f: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpDeleteEntryFixture{
		SchemaVersion: 1,
		Oracle: mcpDeleteEntryOracle{
			Commit: "3232e31f", CommitSHA: "3232e31fb91362b6e6202774f7e95f6d477305d2",
			SourceFiles: mcpDeleteEntrySourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpDeleteEntryGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-delete-entry.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP delete_entry fixture is stale; run with SYMAIRA_GENERATE_MCP_DELETE_ENTRY_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mcpDeleteEntryFixtureVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate fixture identity: %v", err)
	}
	entry := &vault.Entry{Data: map[string]any{
		"username": "fixture-user",
		"password": "StrongP@ssw0rd123",
	}}
	if err := vault.WriteEntry(dir, "github", entry, identity); err != nil {
		t.Fatalf("write fixture entry: %v", err)
	}
	return dir, identity
}

func mcpDeleteEntryGitSourceHash(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range mcpDeleteEntrySourceFiles {
		cmd := exec.Command("git", "show", "3232e31f:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned delete_entry source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpDeleteEntryGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate delete_entry generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read delete_entry generator: %v", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
