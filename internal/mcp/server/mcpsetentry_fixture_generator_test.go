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
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

type mcpSetEntryFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        mcpSetEntryOracle `json:"oracle"`
	ServerName    string            `json:"server_name"`
	ServerVersion string            `json:"server_version"`
	Cases         []mcpSetEntryCase `json:"cases"`
}

type mcpSetEntryOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpSetEntryCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
	State  json.RawMessage   `json:"state"`
}

var mcpSetEntrySourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_set.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/service.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
	"internal/crypto/password.go",
	"internal/crypto/totp.go",
}

func TestGenerateMCPSetEntryFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_SET_ENTRY_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_SET_ENTRY_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_SET_ENTRY_FIXTURE=1 or SYMAIRA_CHECK_MCP_SET_ENTRY_FIXTURE=1")
	}

	serverName := "symvault"
	serverVersion := "0.0.0-set-entry-fixture"
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
			name:    "set_existing",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"username","value":"alice"}}}`,
		},
		{
			name:    "set_password_weak",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"password","value":"short"}}}`,
		},
		{
			name:    "set_totp",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"totp","value":"{\"algorithm\":\"SHA1\",\"digits\":6,\"period\":30,\"secret\":\"JBSWY3DPEHPK3PXP\"}"}}}`,
		},
		{
			name:    "set_totp_partial",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"totp","value":"{\"digits\":8}"}}}`,
		},
		{
			name:    "set_metadata_update",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"username","value":"metadata-user"}}}`,
		},
		{
			name:    "set_field_too_long",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    fmt.Sprintf(`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"username","value":%q}}}`, strings.Repeat("x", vault.MaxFieldLength+1)),
		},
		{
			name:    "set_password_force_weak",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"password","value":"short","force":true}}}`,
		},
		{
			name:    "set_denied_write",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(false), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"username","value":"blocked"}}}`,
		},
		{
			name:    "set_denied_tier",
			profile: config.AgentProfile{Name: "fixture", Tier: config.StrPtr("read-only"), AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"username","value":"blocked"}}}`,
		},
		{
			name:    "set_denied_scope",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed/*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"username","value":"blocked"}}}`,
		},
		{
			name:    "set_denied_approval",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("deny")},
			call:    `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"set_entry_field","arguments":{"path":"github","field":"username","value":"blocked"}}}`,
		},
	}

	fixtureCases := make([]mcpSetEntryCase, 0, len(cases))
	for _, tc := range cases {
		vaultDir, identity := mcpSetEntryFixtureVault(t)
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
		entry, err := vault.ReadEntry(vaultDir, "github", identity)
		if err != nil {
			t.Fatalf("read %s persisted entry: %v", tc.name, err)
		}
		history := make([]map[string]string, 0, len(entry.Metadata.WriteHistory))
		for _, record := range entry.Metadata.WriteHistory {
			history = append(history, map[string]string{"field": record.Field, "action": record.Action})
		}
		state, err := json.Marshal(map[string]any{
			"data":          entry.Data,
			"version":       entry.Metadata.Version,
			"write_history": history,
		})
		if err != nil {
			t.Fatalf("marshal %s state: %v", tc.name, err)
		}
		fixtureCases = append(fixtureCases, mcpSetEntryCase{Name: tc.name, Input: inputs, Output: outputs, State: state})
	}

	root := mcpListRepoRoot(t)
	sourceHash := mcpCallSourceHash(t, mcpSetEntrySourceFiles)
	pinned := mcpSetEntryGitSourceHash(t)
	if sourceHash != pinned {
		t.Fatalf("Go set_entry sources differ from fd55bb73: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpSetEntryFixture{
		SchemaVersion: 1,
		Oracle: mcpSetEntryOracle{
			Commit: "fd55bb73", CommitSHA: "fd55bb7350e67350f709cf60aea1b827cdadd40c",
			SourceFiles: mcpSetEntrySourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpSetEntryGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-set-entry.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP set_entry fixture is stale; run with SYMAIRA_GENERATE_MCP_SET_ENTRY_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mcpSetEntryFixtureVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate fixture identity: %v", err)
	}
	entry := &vault.Entry{Data: map[string]any{
		"username": "fixture-user",
		"password": "StrongP@ssw0rd123",
		"totp": map[string]any{
			"algorithm": "SHA1",
			"digits":    6,
			"period":    30,
			"secret":    "JBSWY3DPEHPK3PXP",
		},
	}}
	if err := vault.WriteEntry(dir, "github", entry, identity); err != nil {
		t.Fatalf("write fixture entry: %v", err)
	}
	return dir, identity
}

func mcpSetEntryGitSourceHash(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range mcpSetEntrySourceFiles {
		cmd := exec.Command("git", "show", "fd55bb73:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned set_entry source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpSetEntryGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate set_entry fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read set_entry fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}
