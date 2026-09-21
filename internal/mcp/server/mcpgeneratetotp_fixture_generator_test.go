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

type mcpGenerateTOTPFixture struct {
	SchemaVersion int                   `json:"schema_version"`
	Oracle        mcpGenerateTOTPOracle `json:"oracle"`
	ServerName    string                `json:"server_name"`
	ServerVersion string                `json:"server_version"`
	Cases         []mcpGenerateTOTPCase `json:"cases"`
}

type mcpGenerateTOTPOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpGenerateTOTPCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

var mcpTOTPCode = regexp.MustCompile(`(\\"code\\":\\")[0-9]{6,8}(\\")`)
var mcpTOTPTime = regexp.MustCompile(`20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})`)

var mcpGenerateTOTPSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_totp.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
	"internal/crypto/totp.go",
}

func TestGenerateMCPGenerateTOTPFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_GENERATE_TOTP_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_GENERATE_TOTP_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_GENERATE_TOTP_FIXTURE=1 or SYMAIRA_CHECK_MCP_GENERATE_TOTP_FIXTURE=1")
	}

	vaultDir, identity := mcpGenerateTOTPFixtureVault(t)
	serverName := "symvault"
	serverVersion := "0.0.0-generate-totp-fixture"
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
			name:    "return_allowed",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanReadValues: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generate_totp","arguments":{"path":"totp","destination":"return","return_code":true}}}`,
		},
		{
			name:    "return_missing_flag",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanReadValues: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"generate_totp","arguments":{"path":"totp","destination":"return"}}}`,
		},
		{
			name:    "return_denied_approval",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("deny")},
			call:    `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"generate_totp","arguments":{"path":"totp","destination":"return","return_code":true}}}`,
		},
		{
			name:    "invalid_destination",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanReadValues: config.BoolPtr(true), ApprovalMode: config.StrPtr("none")},
			call:    `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"generate_totp","arguments":{"path":"totp","destination":"other"}}}`,
		},
	}

	fixtureCases := make([]mcpGenerateTOTPCase, 0, len(cases))
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
			encoded = mcpTOTPCode.ReplaceAll(encoded, []byte("$1<totp-code>$2"))
			encoded = mcpTOTPTime.ReplaceAll(encoded, []byte("<fixture-time>"))
			outputs = append(outputs, encoded)
		}
		fixtureCases = append(fixtureCases, mcpGenerateTOTPCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpListRepoRoot(t)
	sourceHash := mcpCallSourceHash(t, mcpGenerateTOTPSourceFiles)
	pinned := mcpGenerateTOTPGitSourceHash(t)
	if sourceHash != pinned {
		t.Fatalf("Go generate_totp sources differ from fd55bb73: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpGenerateTOTPFixture{
		SchemaVersion: 1,
		Oracle: mcpGenerateTOTPOracle{
			Commit: "fd55bb73", CommitSHA: "fd55bb7350e67350f709cf60aea1b827cdadd40c",
			SourceFiles: mcpGenerateTOTPSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpGenerateTOTPGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-generate-totp.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP generate_totp fixture is stale; run with SYMAIRA_GENERATE_MCP_GENERATE_TOTP_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mcpGenerateTOTPFixtureVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate fixture identity: %v", err)
	}
	entry := &vault.Entry{Data: map[string]any{
		"totp": map[string]any{
			"secret":       "JBSWY3DPEHPK3PXP",
			"algorithm":    "SHA1",
			"digits":       float64(6),
			"period":       float64(30),
			"issuer":       "Fixture",
			"account_name": "fixture@example.test",
		},
	}}
	if err := vault.WriteEntry(dir, "totp", entry, identity); err != nil {
		t.Fatalf("write fixture entry: %v", err)
	}
	return dir, identity
}

func mcpGenerateTOTPGitSourceHash(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range mcpGenerateTOTPSourceFiles {
		cmd := exec.Command("git", "show", "fd55bb73:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned generate_totp source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func mcpGenerateTOTPGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate generate_totp fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generate_totp fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}
