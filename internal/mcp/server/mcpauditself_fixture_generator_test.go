package server

// This opt-in generator executes the production MCP protocol and audit-self
// handler against a synthetic log. It never opens the developer's audit log or
// vault and never enables a platform credential provider.

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

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/config"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

type mcpAuditSelfFixture struct {
	SchemaVersion int                `json:"schema_version"`
	Oracle        mcpAuditSelfOracle `json:"oracle"`
	ServerName    string             `json:"server_name"`
	ServerVersion string             `json:"server_version"`
	Cases         []mcpAuditSelfCase `json:"cases"`
}

type mcpAuditSelfOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpAuditSelfCase struct {
	Name        string            `json:"name"`
	Input       []string          `json:"input"`
	AuditLogHex string            `json:"audit_log_hex,omitempty"`
	Output      []json.RawMessage `json:"output"`
}

var mcpAuditSelfSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_audit_self.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/audit/audit.go",
}

func TestGenerateMCPAuditSelfFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_AUDIT_SELF_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_AUDIT_SELF_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_AUDIT_SELF_FIXTURE=1 or SYMAIRA_CHECK_MCP_AUDIT_SELF_FIXTURE=1")
	}

	serverName := "symvault"
	serverVersion := "0.0.0-audit-self-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	entries := []audit.LogEntry{
		{Timestamp: "2026-01-02T03:04:05Z", Agent: "fixture", Action: "find", Path: "alpha", OK: true},
		{Timestamp: "2026-01-02T03:04:06Z", Agent: "fixture", Action: "get", Path: "beta", Reason: "policy_denied", OK: false},
		{Timestamp: "2026-01-02T03:04:07Z", Agent: "fixture", Action: "set", Path: "gamma", Field: "username", OK: true},
		{Timestamp: "2026-01-02T03:04:08Z", Agent: "fixture", Action: "delete", Path: "delta", OK: true},
		{Timestamp: "2026-01-02T03:04:09Z", Action: "legacy"},
	}
	logBytes := make([]byte, 0, len(entries)*128)
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal audit entry: %v", err)
		}
		logBytes = append(logBytes, line...)
		logBytes = append(logBytes, '\n')
	}
	logBytes = append(logBytes, []byte("{\"action\":false}\nnot-json\n")...)
	invalidUTF8Log := []byte("{\"ts\":\"2026-01-02T03:04:10Z\",\"action\":\"bad\xff\",\"ok\":true}\n")
	nullRootLog := []byte("null\n")
	oversizedLog := append([]byte(`{"ts":"2026-01-02T03:04:11Z","action":"oversized","path":"`), bytes.Repeat([]byte("x"), 64*1024)...)
	oversizedLog = append(oversizedLog, []byte(`"}`)...)

	cases := []struct {
		name    string
		call    string
		log     []byte
		withLog bool
	}{
		{name: "default_limit_skips_malformed", call: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{}}}`, log: logBytes, withLog: true},
		{name: "limit_two_returns_tail", call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":2}}}`, log: logBytes, withLog: true},
		{name: "numeric_string_limit_returns_tail", call: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":"2"}}}`, log: logBytes, withLog: true},
		{name: "zero_uses_default", call: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":0}}}`, log: logBytes, withLog: true},
		{name: "fraction_truncates_to_zero", call: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":0.5}}}`, log: logBytes, withLog: true},
		{name: "missing_log_is_empty", call: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, withLog: false},
		{name: "empty_log_is_null", call: `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: []byte{}, withLog: true},
		{name: "null_root_defaults", call: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: nullRootLog, withLog: true},
		{name: "invalid_utf8_replaced", call: `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: invalidUTF8Log, withLog: true},
		{name: "oversized_line_returns_scanner_error", call: `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{}}}`, log: oversizedLog, withLog: true},
	}

	fixtureCases := make([]mcpAuditSelfCase, 0, len(cases))
	for _, tc := range cases {
		vaultDir, _ := mockVault(t)
		if tc.withLog {
			if err := os.WriteFile(filepath.Join(vaultDir, "audit-fixture.log"), tc.log, 0o600); err != nil {
				t.Fatalf("write synthetic audit log: %v", err)
			}
		}
		profile := config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")}
		srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
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
		fixtureCase := mcpAuditSelfCase{Name: tc.name, Input: inputs, Output: outputs}
		if tc.withLog {
			fixtureCase.AuditLogHex = hex.EncodeToString(tc.log)
		}
		fixtureCases = append(fixtureCases, fixtureCase)
	}

	root := mcpAuditSelfRepoRoot(t)
	sourceHash := mcpAuditSelfSourceHash(t, mcpAuditSelfSourceFiles)
	if pinned := mcpAuditSelfGitSourceHash(t, mcpAuditSelfSourceFiles); pinned != sourceHash {
		t.Fatalf("Go audit-self sources differ from fca3f894: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpAuditSelfFixture{
		SchemaVersion: 1,
		Oracle: mcpAuditSelfOracle{
			Commit: "fca3f894", CommitSHA: "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles: mcpAuditSelfSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpAuditSelfGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-audit-self.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP audit-self fixture is stale; run with SYMAIRA_GENERATE_MCP_AUDIT_SELF_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func mcpAuditSelfSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpAuditSelfRepoRoot(t)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpAuditSelfGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpAuditSelfRepoRoot(t)
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
	return hex.EncodeToString(h.Sum(nil))
}

func mcpAuditSelfGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate audit-self fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit-self fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func mcpAuditSelfRepoRoot(t *testing.T) string {
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
