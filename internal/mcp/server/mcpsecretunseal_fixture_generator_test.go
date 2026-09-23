package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// Source-bound secret_unseal protocol oracle. All secret strings in this file
// and its fixture are synthetic test markers, never developer vault contents.
const mcpSecretUnsealCommit = "0a7946748d0d1f989b268947e04ae7c6d1fc3755"

var mcpSecretUnsealSources = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_unseal.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/approval.go",
	"internal/mcp/server/server.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/entry_readwrite.go",
	"internal/vault/taint/taint.go",
}

type mcpSecretUnsealFixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        mcpCallOracle `json:"oracle"`
	ServerName    string        `json:"server_name"`
	ServerVersion string        `json:"server_version"`
	Cases         []mcpCallCase `json:"cases"`
}

func TestGenerateMCPSecretUnsealFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_SECRET_UNSEAL_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_SECRET_UNSEAL_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_SECRET_UNSEAL_FIXTURE=1 or SYMAIRA_CHECK_MCP_SECRET_UNSEAL_FIXTURE=1")
	}
	vaultDir, identity := mcpSecretUnsealVault(t)
	const serverName, serverVersion = "symvault", "0.0.0-secret-unseal-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	cases := []struct {
		name    string
		profile config.AgentProfile
		call    string
		call2   string
	}{
		{
			name:    "leaf_unsealed",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secret_unseal","arguments":{"handle":"op://allowed/secret/password"}}}`,
		},
		{
			name:    "numeric_scalar",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"secret_unseal","arguments":{"handle":"op://allowed/secret/number"}}}`,
		},
		{
			name:    "go_scope_gap",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secret_unseal","arguments":{"handle":"op://secret/password"}}}`,
		},
		{
			name:    "go_fieldless_handle_exposes_all_fields",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"secret_unseal","arguments":{"handle":"op://allowed"}}}`,
		},
		{
			name:    "approval_denied",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed"}, ApprovalMode: config.StrPtr("deny")},
			call:    `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"secret_unseal","arguments":{"handle":"op://allowed/secret/password"}}}`,
		},
		{
			name:    "go_unremembered_approval_bypass",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"allowed"}, ApprovalMode: config.StrPtr("prompt")},
			call:    `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"secret_unseal","arguments":{"handle":"op://allowed/secret/password"}}}`,
			call2:   `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"secret_unseal","arguments":{"handle":"op://allowed/secret/password"}}}`,
		},
	}
	fixtureCases := make([]mcpCallCase, 0, len(cases))
	for _, tc := range cases {
		srv := newTestServerWithVault(t, tc.profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		srv.approvalCache = newApprovalCache()
		handler := NewProtocolHandler(serverName, serverVersion, srv)
		inputs := append(append([]string{}, base...), tc.call)
		var approvalPrompts int
		if tc.name == "go_unremembered_approval_bypass" {
			original := openTTYDevice
			openTTYDevice = func() (ttyDevice, error) {
				return &mockTTYDevice{
					readString: func() (string, error) {
						approvalPrompts++
						return "y", nil
					},
					output: newMockOutputFile(t),
				}, nil
			}
			inputs = append(inputs, tc.call2)
			defer func() { openTTYDevice = original }()
		}
		outputs := make([]json.RawMessage, 0, len(inputs))
		for _, line := range inputs {
			var message transport.Message
			if err := json.Unmarshal([]byte(line), &message); err != nil {
				t.Fatalf("decode %s input: %v", tc.name, err)
			}
			response, err := handler.HandleMessage(context.Background(), &message)
			if err != nil {
				t.Fatalf("handle %s: %v", tc.name, err)
			}
			if response != nil {
				encoded, err := json.Marshal(response)
				if err != nil {
					t.Fatalf("marshal %s response: %v", tc.name, err)
				}
				outputs = append(outputs, encoded)
			}
		}
		if tc.name == "go_unremembered_approval_bypass" {
			if approvalPrompts != 1 {
				t.Fatalf("Go secret_unseal made %d approvals for two calls after a non-remembered approval; want 1 to pin the source behavior", approvalPrompts)
			}
			if len(outputs) != 3 ||
				!bytes.Contains(outputs[1], []byte("synthetic-unseal-fixture-value")) ||
				!bytes.Contains(outputs[2], []byte("synthetic-unseal-fixture-value")) {
				t.Fatalf("Go secret_unseal no longer repeats successful response after a non-remembered approval")
			}
		}
		fixtureCases = append(fixtureCases, mcpCallCase{Name: tc.name, Input: inputs, Output: outputs, MarkerCounts: make([]int, len(outputs))})
	}
	sourceHash := mcpSecretUnsealHash(t, mcpSecretUnsealSources, "")
	if pinned := mcpSecretUnsealHash(t, mcpSecretUnsealSources, mcpSecretUnsealCommit); sourceHash != pinned {
		t.Fatalf("Go secret_unseal sources differ from %s: got %s, want %s", mcpSecretUnsealCommit, sourceHash, pinned)
	}
	fixture := mcpSecretUnsealFixture{
		SchemaVersion: 1,
		Oracle: mcpCallOracle{
			Commit: "0a794674", CommitSHA: mcpSecretUnsealCommit, SourceFiles: mcpSecretUnsealSources,
			SourceHash: sourceHash, GeneratorHash: mcpSecretUnsealGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(mcpListRepoRoot(t), "testdata", "port", "mcp", "tools-secret-unseal.json")
	if check {
		old, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(old, data) {
			t.Fatal("MCP secret_unseal fixture is stale; run with SYMAIRA_GENERATE_MCP_SECRET_UNSEAL_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mcpSecretUnsealVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]map[string]any{
		"allowed/secret": {"password": "synthetic-unseal-fixture-value", "number": 1234567.0},
		"allowed":        {"password": "synthetic-fieldless-value"},
		"secret":         {"password": "synthetic-scope-gap-value"},
	} {
		if err := vault.WriteEntry(dir, path, &vault.Entry{Data: data}, identity); err != nil {
			t.Fatalf("write synthetic fixture entry: %v", err)
		}
	}
	return dir, identity
}

func mcpSecretUnsealHash(t *testing.T, files []string, revision string) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range files {
		var data []byte
		var err error
		if revision == "" {
			data, err = os.ReadFile(filepath.Join(root, name))
		} else {
			cmd := exec.Command("git", "show", revision+":"+name)
			cmd.Dir = root
			data, err = cmd.Output()
		}
		if err != nil {
			t.Fatalf("read %s source %s: %v", revision, name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpSecretUnsealGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate secret_unseal fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
