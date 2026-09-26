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
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/secureui"
)

// This generator calls the production MCP protocol handler with a synthetic
// encrypted vault created by mockVault. It is opt-in so normal Go tests never
// rewrite tracked artifacts, and it never reads the developer's real vault.

type mcpCallFixture struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        mcpCallOracle `json:"oracle"`
	ServerName    string        `json:"server_name"`
	ServerVersion string        `json:"server_version"`
	Cases         []mcpCallCase `json:"cases"`
}

type mcpCallOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpCallCase struct {
	Name         string            `json:"name"`
	Input        []string          `json:"input"`
	Output       []json.RawMessage `json:"output"`
	MarkerCounts []int             `json:"marker_counts"`
}

var mcpCallSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_health.go",
	"internal/mcp/server/tools_find.go",
	"internal/mcp/server/tools_get.go",
	"internal/mcp/server/tools_whoami.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/search.go",
}

const mcpCallPinnedSourceHash = "33f58a6ad963dc4a00c31905430ed239df07cbec71368d90e4fd96211061b6fb"

func TestGenerateMCPCallFixture(t *testing.T) {
	g := os.Getenv("SYMAIRA_GENERATE_MCP_CALL_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_CALL_FIXTURE") == "1"
	if !g && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_CALL_FIXTURE=1 or SYMAIRA_CHECK_MCP_CALL_FIXTURE=1")
	}

	// Pin the advertised capability, as the tools/list oracle does. Host GUI/TTY
	// availability must not change protocol fixtures; no prompt is invoked.
	originalSecure := secureInputCapabilityFn
	secureInputCapabilityFn = func() secureui.Capability { return secureui.CapTTY }
	t.Cleanup(func() { secureInputCapabilityFn = originalSecure })

	vaultDir, identity := mockVault(t)
	profile := config.AgentProfile{
		Name:         "fixture",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}
	srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
	srv.vault.Identity = identity

	const serverName = "symvault"
	const serverVersion = "0.0.0-fixture"
	inputs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"symaira_whoami"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"find_entries","arguments":{"query":"test"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_entry_metadata","arguments":{"path":"github"}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_entry","arguments":{"path":"github"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"NaMe":"health","ArGuMeNtS":{"ignored":null}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"find_entries","arguments":{"query":null}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"health","NAME":"symaira_whoami"}}`,
	}

	handler := NewProtocolHandler(serverName, serverVersion, srv)
	outputs := make([]json.RawMessage, 0, len(inputs))
	markerCounts := make([]int, 0, len(inputs))
	for _, line := range inputs {
		var msg transport.Message
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("decode input: %v", err)
		}
		response, err := handler.HandleMessage(context.Background(), &msg)
		if err != nil {
			t.Fatalf("handle %s: %v", msg.Method, err)
		}
		if response == nil {
			continue
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("marshal response: %v", err)
		}
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("decode response for normalization: %v", err)
		}
		value, markers := normalizeMCPCallValue(value, vaultDir)
		normalized, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal normalized response: %v", err)
		}
		outputs = append(outputs, json.RawMessage(normalized))
		markerCounts = append(markerCounts, markers)
	}

	sourceHash := mcpCallSourceHash(t, mcpCallSourceFiles)
	if mcpCallPinnedSourceHash != "" && sourceHash != mcpCallPinnedSourceHash {
		t.Fatalf("Go MCP call sources drifted from pinned oracle: got %s, want %s", sourceHash, mcpCallPinnedSourceHash)
	}
	if pinnedHash := mcpCallGitSourceHash(t, mcpCallSourceFiles); pinnedHash != sourceHash {
		t.Fatalf("working Go MCP call sources differ from c42b96bb: got %s, want %s", sourceHash, pinnedHash)
	}

	fixture := mcpCallFixture{
		SchemaVersion: 1,
		Oracle: mcpCallOracle{
			Commit:        "c42b96bb",
			CommitSHA:     "c42b96bb4dd2a2d6cea1ade0770f55650045e5b3",
			SourceFiles:   mcpCallSourceFiles,
			SourceHash:    sourceHash,
			GeneratorHash: mcpCallGeneratorHash(t),
		},
		ServerName:    serverName,
		ServerVersion: serverVersion,
		Cases: []mcpCallCase{{
			Name:         "initialized_read_only_calls",
			Input:        inputs,
			Output:       outputs,
			MarkerCounts: markerCounts,
		}},
	}

	root := mcpListRepoRoot(t)
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-call-initialized.json")
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP initialized tools/call fixture is stale; run with SYMAIRA_GENERATE_MCP_CALL_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

var mcpCallMarker = regexp.MustCompile(`<!-- DATA_([0-9a-f]{16}) label=`)
var mcpCallTimestamp = regexp.MustCompile(`20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z`)

func normalizeMCPCallMarkers(input string) (string, int) {
	seen := make(map[string]string)
	for {
		loc := mcpCallMarker.FindStringSubmatchIndex(input)
		if loc == nil {
			return input, len(seen)
		}
		marker := input[loc[2]:loc[3]]
		replacement, ok := seen[marker]
		if !ok {
			replacement = fmt.Sprintf("<MARKER_%d>", len(seen)+1)
			seen[marker] = replacement
		}
		input = input[:loc[2]] + replacement + input[loc[3]:]
		input = strings.Replace(input, "<!-- /DATA_"+marker+" -->", "<!-- /DATA_"+replacement+" -->", 1)
	}
}

func normalizeMCPCallValue(value any, vaultDir string) (any, int) {
	switch typed := value.(type) {
	case string:
		text := strings.ReplaceAll(typed, vaultDir, "<fixture-vault>")
		if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
			var nested any
			if err := json.Unmarshal([]byte(text), &nested); err == nil {
				normalized, markers := normalizeMCPCallValue(nested, vaultDir)
				if encoded, marshalErr := json.Marshal(normalized); marshalErr == nil {
					return string(encoded), markers
				}
			}
		}
		text = mcpCallTimestamp.ReplaceAllString(text, "<fixture-time>")
		return normalizeMCPCallMarkers(text)
	case []any:
		markers := 0
		for i := range typed {
			var count int
			typed[i], count = normalizeMCPCallValue(typed[i], vaultDir)
			markers += count
		}
		return typed, markers
	case map[string]any:
		markers := 0
		for key, nested := range typed {
			var count int
			typed[key], count = normalizeMCPCallValue(nested, vaultDir)
			markers += count
		}
		if fields, ok := typed["fields"].([]any); ok {
			sort.SliceStable(fields, func(i, j int) bool {
				left, _ := fields[i].(map[string]any)
				right, _ := fields[j].(map[string]any)
				leftName, _ := left["name"].(string)
				rightName, _ := right["name"].(string)
				return leftName < rightName
			})
		}
		return typed, markers
	default:
		return value, 0
	}
}

func mcpCallSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(mcpListRepoRoot(t), name))
		if err != nil {
			t.Fatalf("read source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpCallGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "c42b96bb:"+name)
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

func mcpCallGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
