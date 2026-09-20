package server

// This opt-in generator executes the production generate_template handler for
// built-in dry-run templates. Dry-run mode never reads a vault value; the
// generated output contains only the handler's fixed mask.

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
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

type mcpGenerateTemplateFixture struct {
	SchemaVersion int                       `json:"schema_version"`
	Oracle        mcpGenerateTemplateOracle `json:"oracle"`
	ServerName    string                    `json:"server_name"`
	ServerVersion string                    `json:"server_version"`
	Cases         []mcpGenerateTemplateCase `json:"cases"`
}

type mcpGenerateTemplateOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpGenerateTemplateCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

var mcpGenerateTemplateSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_template.go",
	"internal/mcp/server/render.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/template/builtins.go",
	"internal/template/engine.go",
	"internal/template/funcs.go",
	"internal/template/resolver.go",
}

func TestGenerateMCPGenerateTemplateFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_GENERATE_TEMPLATE_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_GENERATE_TEMPLATE_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_GENERATE_TEMPLATE_FIXTURE=1 or SYMAIRA_CHECK_MCP_GENERATE_TEMPLATE_FIXTURE=1")
	}

	serverName := "symvault"
	serverVersion := "0.0.0-generate-template-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	cases := []struct {
		name string
		call string
	}{
		{name: "env_dry_run", call: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generate_template","arguments":{"template_type":"env","name":"demo","secret_refs":{"API_KEY":"op://fixture/password","DB_PASS":"fixture.database"},"dry_run":true}}}`},
		{name: "docker_compose_dry_run", call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"generate_template","arguments":{"template_type":"docker-compose","secret_refs":{"API_KEY":"op://fixture/password"},"dry_run":true}}}`},
		{name: "k8s_secret_dry_run", call: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"generate_template","arguments":{"template_type":"k8s-secret","name":"demo-secret","secret_refs":{"API_KEY":"op://fixture/password"},"dry_run":true}}}`},
		{name: "github_actions_dry_run", call: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"generate_template","arguments":{"template_type":"github-actions","name":"demo","secret_refs":{"API_KEY":"op://fixture/password"},"dry_run":true}}}`},
		{name: "terraform_dry_run", call: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"generate_template","arguments":{"template_type":"terraform","name":"demo","secret_refs":{"API_KEY":"op://fixture/password"},"dry_run":true}}}`},
		{name: "empty_refs", call: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"generate_template","arguments":{"template_type":"env","dry_run":true}}}`},
		{name: "unknown_template", call: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"generate_template","arguments":{"template_type":"custom","dry_run":true}}}`},
		{name: "missing_template_type", call: `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"generate_template","arguments":{"dry_run":true}}}`},
	}

	fixtureCases := make([]mcpGenerateTemplateCase, 0, len(cases))
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
			var value any
			if err := json.Unmarshal(encoded, &value); err != nil {
				t.Fatalf("decode %s response: %v", tc.name, err)
			}
			normalized := normalizeMCPGenerateTemplateValue(value)
			encoded, err = json.Marshal(normalized)
			if err != nil {
				t.Fatalf("normalize %s response: %v", tc.name, err)
			}
			outputs = append(outputs, encoded)
		}
		fixtureCases = append(fixtureCases, mcpGenerateTemplateCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpGenerateTemplateRepoRoot(t)
	sourceHash := mcpGenerateTemplateSourceHash(t, mcpGenerateTemplateSourceFiles)
	if pinned := mcpGenerateTemplateGitSourceHash(t, mcpGenerateTemplateSourceFiles); pinned != sourceHash {
		t.Fatalf("Go generate-template sources differ from fca3f894: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpGenerateTemplateFixture{
		SchemaVersion: 1,
		Oracle: mcpGenerateTemplateOracle{
			Commit: "fca3f894", CommitSHA: "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles: mcpGenerateTemplateSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpGenerateTemplateGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-generate-template.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP generate-template fixture is stale; run with SYMAIRA_GENERATE_MCP_GENERATE_TEMPLATE_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

var mcpGenerateTemplateMarker = regexp.MustCompile(`<!-- DATA_([0-9a-f]{16}) label=`)

func normalizeMCPGenerateTemplateValue(value any) any {
	switch typed := value.(type) {
	case string:
		seen := make(map[string]string)
		for {
			loc := mcpGenerateTemplateMarker.FindStringSubmatchIndex(typed)
			if loc == nil {
				return typed
			}
			marker := typed[loc[2]:loc[3]]
			replacement, ok := seen[marker]
			if !ok {
				replacement = fmt.Sprintf("<MARKER_%d>", len(seen)+1)
				seen[marker] = replacement
			}
			typed = typed[:loc[2]] + replacement + typed[loc[3]:]
			typed = strings.Replace(typed, "<!-- /DATA_"+marker+" -->", "<!-- /DATA_"+replacement+" -->", 1)
			typed = strings.Replace(typed, "<!-- /DATA_"+marker+" -- >", "<!-- /DATA_"+replacement+" -- >", 1)
		}
	case []any:
		for index := range typed {
			typed[index] = normalizeMCPGenerateTemplateValue(typed[index])
		}
	case map[string]any:
		for key := range typed {
			typed[key] = normalizeMCPGenerateTemplateValue(typed[key])
		}
	}
	return value
}

func mcpGenerateTemplateSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpGenerateTemplateRepoRoot(t)
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

func mcpGenerateTemplateGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpGenerateTemplateRepoRoot(t)
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

func mcpGenerateTemplateGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate generate-template fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generate-template fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

func mcpGenerateTemplateRepoRoot(t *testing.T) string {
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
