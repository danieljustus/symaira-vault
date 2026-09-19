package server

// This opt-in generator executes the production symaira_search protocol
// handler against the static Go registry. It never opens vault data or calls
// a platform provider.

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

	"github.com/danieljustus/symaira-vault/internal/config"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

type mcpSymairaSearchFixture struct {
	SchemaVersion int                    `json:"schema_version"`
	Oracle        mcpSymairaSearchOracle `json:"oracle"`
	ServerName    string                 `json:"server_name"`
	ServerVersion string                 `json:"server_version"`
	Cases         []mcpSymairaSearchCase `json:"cases"`
}

type mcpSymairaSearchOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpSymairaSearchCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

var mcpSymairaSearchSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_search.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
}

func TestGenerateMCPSymairaSearchFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_SYMAIRA_SEARCH_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_SYMAIRA_SEARCH_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_SYMAIRA_SEARCH_FIXTURE=1 or SYMAIRA_CHECK_MCP_SYMAIRA_SEARCH_FIXTURE=1")
	}

	serverName := "symvault"
	serverVersion := "0.0.0-symaira-search-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	cases := []struct {
		name string
		call string
	}{
		{name: "names_case_insensitive", call: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"symaira_search","arguments":{"intent":"PASSWORD","return":"names"}}}`},
		{name: "spec_with_risk_and_cli", call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"symaira_search","arguments":{"intent":"clipboard"}}}`},
		{name: "spec_includes_unavailable_execute_tools", call: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"symaira_search","arguments":{"intent":"execute"}}}`},
		{name: "invalid_return_defaults_to_spec", call: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"symaira_search","arguments":{"intent":"health","return":"unexpected"}}}`},
		{name: "no_matches_is_empty_array", call: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"symaira_search","arguments":{"intent":"no-such-tool"}}}`},
		{name: "missing_intent", call: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"symaira_search","arguments":{}}}`},
		{name: "wrong_intent_type", call: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"symaira_search","arguments":{"intent":null}}}`},
	}

	fixtureCases := make([]mcpSymairaSearchCase, 0, len(cases))
	for _, tc := range cases {
		profile := config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")}
		srv := newTestServerWithVault(t, profile, "stdio", "")
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
		fixtureCases = append(fixtureCases, mcpSymairaSearchCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpSymairaSearchRepoRoot(t)
	sourceHash := mcpSymairaSearchSourceHash(t, mcpSymairaSearchSourceFiles)
	if pinned := mcpSymairaSearchGitSourceHash(t, mcpSymairaSearchSourceFiles); pinned != sourceHash {
		t.Fatalf("Go symaira-search sources differ from fca3f894: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpSymairaSearchFixture{
		SchemaVersion: 1,
		Oracle: mcpSymairaSearchOracle{
			Commit: "fca3f894", CommitSHA: "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles: mcpSymairaSearchSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpSymairaSearchGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-symaira-search.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP symaira-search fixture is stale; run with SYMAIRA_GENERATE_MCP_SYMAIRA_SEARCH_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func mcpSymairaSearchSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpSymairaSearchRepoRoot(t)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpSymairaSearchGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpSymairaSearchRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "fca3f894:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpSymairaSearchGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate symaira-search fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read symaira-search fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

func mcpSymairaSearchRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root")
		}
		dir = parent
	}
}
