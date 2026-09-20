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

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/policy"
)

// This opt-in generator drives the production Go protocol and pre-call hook
// against a synthetic server. It never opens the user's vault or credentials.
type mcpRateLimitFixture struct {
	SchemaVersion int                `json:"schema_version"`
	Oracle        mcpRateLimitOracle `json:"oracle"`
	ServerName    string             `json:"server_name"`
	ServerVersion string             `json:"server_version"`
	Cases         []mcpRateLimitCase `json:"cases"`
}

type mcpRateLimitOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpRateLimitCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

var mcpRateLimitSourceFiles = []string{
	"internal/mcp/server/hooks_builtin.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/mcptypes.go",
	"internal/mcp/transport/transport.go",
}

const mcpRateLimitPinnedSourceHash = "62c20a71f3e84537473e8fc505eeefe8bf340c9b9454d961d577aa8f0b427331"

func TestGenerateMCPRateLimitFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_RATE_LIMIT_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_RATE_LIMIT_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_RATE_LIMIT_FIXTURE=1 or SYMAIRA_CHECK_MCP_RATE_LIMIT_FIXTURE=1")
	}

	const serverName = "symvault"
	const serverVersion = "0.0.0-rate-limit-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	cases := []struct {
		name        string
		profile     config.AgentProfile
		unknown     bool
		unavailable bool
		policyDeny  bool
	}{
		{
			name:    "allowed_then_rejected",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
		},
		{
			name:    "unknown_before_allowed",
			profile: config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			unknown: true,
		},
		{
			name:        "unavailable_before_allowed",
			profile:     config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none"), CanReadValues: config.BoolPtr(false), CanUseClipboard: config.BoolPtr(false), CanUseAutotype: config.BoolPtr(false)},
			unavailable: true,
		},
		{
			// The pinned Go dispatcher currently returns nil from
			// validateToolAccess for a non-biometric policy error. Keep this
			// case source-bound so the fixture records that observable behavior:
			// the handler runs and the pre-call hook consumes the request.
			name:       "policy_check_error_reaches_handler",
			profile:    config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, ApprovalMode: config.StrPtr("none")},
			policyDeny: true,
		},
	}

	fixtureCases := make([]mcpRateLimitCase, 0, len(cases))
	for index, tc := range cases {
		srv := newTestServerWithVault(t, tc.profile, "stdio", "")
		srv.RegisterPreCallHook(NewRateLimitPreHook(1))
		if tc.policyDeny {
			srv.policyEngine = policy.NewEngine([]*policy.Policy{{
				Version: "1",
				Rules: []policy.Rule{{
					Name:       "deny fixture path",
					Action:     policy.ActionDeny,
					Conditions: policy.Conditions{Path: "github", ActionType: "get"},
				}},
			}})
		}
		handler := NewProtocolHandler(serverName, serverVersion, srv)
		callID := 2 + index*2
		first := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"health"}}`, callID)
		second := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"health"}}`, callID+1)
		inputs := append(append([]string{}, base...), first, second)
		if tc.unknown {
			inputs = append(append([]string{}, base...), fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"unknown_fixture_tool"}}`, callID), first)
		}
		if tc.unavailable {
			inputs = append(append([]string{}, base...), fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"generate_totp","arguments":{"path":"github"}}}`, callID), first)
		}
		if tc.policyDeny {
			inputs = append(append([]string{}, base...), fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"get_entry_metadata","arguments":{"path":"github"}}}`, callID), first)
		}
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
		fixtureCases = append(fixtureCases, mcpRateLimitCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpRateLimitRepoRoot(t)
	sourceHash := mcpRateLimitSourceHash(t, mcpRateLimitSourceFiles)
	if sourceHash != mcpRateLimitPinnedSourceHash {
		t.Fatalf("Go MCP rate-limit sources drifted from pinned oracle: got %s, want %s", sourceHash, mcpRateLimitPinnedSourceHash)
	}
	if pinned := mcpRateLimitGitSourceHash(t, mcpRateLimitSourceFiles); pinned != sourceHash {
		t.Fatalf("working Go MCP rate-limit sources differ from fca3f894: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpRateLimitFixture{
		SchemaVersion: 1,
		Oracle: mcpRateLimitOracle{
			Commit: "fca3f894", CommitSHA: "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles: mcpRateLimitSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpRateLimitGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-rate-limit.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP rate-limit fixture is stale; run with SYMAIRA_GENERATE_MCP_RATE_LIMIT_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func mcpRateLimitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpRateLimitRepoRoot(t)
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

func mcpRateLimitGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, name := range files {
		data, err := exec.Command("git", "show", "fca3f894:"+name).Output()
		if err != nil {
			t.Fatalf("read pinned source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpRateLimitGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate rate-limit fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rate-limit fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func mcpRateLimitRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("find repository root: %v", err)
	}
	return filepath.Clean(string(bytes.TrimSpace(root)))
}
