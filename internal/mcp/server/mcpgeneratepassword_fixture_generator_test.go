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

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

type mcpGeneratePasswordFixture struct {
	SchemaVersion int                       `json:"schema_version"`
	Oracle        mcpGeneratePasswordOracle `json:"oracle"`
	ServerName    string                    `json:"server_name"`
	ServerVersion string                    `json:"server_version"`
	Cases         []mcpGeneratePasswordCase `json:"cases"`
}

type mcpGeneratePasswordOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpGeneratePasswordCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

var mcpGeneratedPassword = regexp.MustCompile(`("text":")[^"]{16,1000}(")`)

var mcpGeneratePasswordSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_generate.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/crypto/password.go",
}

func TestGenerateMCPGeneratePasswordFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_GENERATE_PASSWORD_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_GENERATE_PASSWORD_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_GENERATE_PASSWORD_FIXTURE=1 or SYMAIRA_CHECK_MCP_GENERATE_PASSWORD_FIXTURE=1")
	}

	serverName := "symvault"
	serverVersion := "0.0.0-generate-password-fixture"
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
			name:    "default_length_symbols",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generate_password","arguments":{}}}`,
		},
		{
			name:    "custom_length_without_symbols",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"generate_password","arguments":{"length":24,"symbols":false}}}`,
		},
		{
			name:    "invalid_length_falls_back",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"generate_password","arguments":{"length":"invalid","symbols":false}}}`,
		},
		{
			name:    "too_long_is_internal_error",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"generate_password","arguments":{"length":1025}}}`,
		},
	}

	fixtureCases := make([]mcpGeneratePasswordCase, 0, len(cases))
	for _, tc := range cases {
		srv := newTestServerWithVault(t, tc.profile, "stdio", "")
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
			encoded = mcpGeneratedPassword.ReplaceAll(encoded, []byte("$1<generated-password>$2"))
			outputs = append(outputs, encoded)
		}
		fixtureCases = append(fixtureCases, mcpGeneratePasswordCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpListRepoRoot(t)
	sourceHash := mcpCallSourceHash(t, mcpGeneratePasswordSourceFiles)
	pinned := mcpGeneratePasswordGitSourceHash(t)
	if sourceHash != pinned {
		t.Fatalf("Go generate_password sources differ from fca3f894: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpGeneratePasswordFixture{
		SchemaVersion: 1,
		Oracle: mcpGeneratePasswordOracle{
			Commit: "fca3f894", CommitSHA: "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles: mcpGeneratePasswordSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpGeneratePasswordGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-generate-password.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP generate_password fixture is stale; run with SYMAIRA_GENERATE_MCP_GENERATE_PASSWORD_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mcpGeneratePasswordGitSourceHash(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range mcpGeneratePasswordSourceFiles {
		cmd := exec.Command("git", "show", "fca3f894:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned generate_password source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpGeneratePasswordGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate generate_password fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generate_password fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}
