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
	"github.com/danieljustus/symaira-vault/internal/secureui"
	"github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

// This opt-in generator exercises the production Go tools/call dispatcher for
// value access. It writes only a synthetic encrypted vault under t.TempDir.
// The fixture keeps the sealed, redacted, scope-denied, and quarantine paths
// separate so Rust cannot pass by returning plaintext on an unavailable path.

type mcpGetValueFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        mcpGetValueOracle `json:"oracle"`
	ServerName    string            `json:"server_name"`
	ServerVersion string            `json:"server_version"`
	Cases         []mcpCallCase     `json:"cases"`
}

type mcpGetValueOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

var mcpGetValueTimestamp = regexp.MustCompile(`20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z`)

var mcpGetValueSourceFiles = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_get.go",
	"internal/mcp/server/render.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
	"internal/vault/payment.go",
	"internal/vault/taint/taint.go",
}

func TestGenerateMCPGetValueFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_GET_VALUE_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_GET_VALUE_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_GET_VALUE_FIXTURE=1 or SYMAIRA_CHECK_MCP_GET_VALUE_FIXTURE=1")
	}

	vaultDir, identity := mcpGetValueFixtureVault(t)
	originalSecure := secureInputCapabilityFn
	secureInputCapabilityFn = func() secureui.Capability { return secureui.CapTTY }
	t.Cleanup(func() { secureInputCapabilityFn = originalSecure })
	serverName := "symvault"
	serverVersion := "0.0.0-get-value-fixture"
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
			name: "default_sealed",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(false), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_entry_value","arguments":{"path":"secret"}}}`,
		},
		{
			name: "classified_redacted",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(false), ApprovalMode: config.StrPtr("none"),
				RedactFields: []string{"password"},
			},
			call: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_entry_value","arguments":{"path":"classified"}}}`,
		},
		{
			name: "explicit_allowed_redacted",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
				RedactFields: []string{"note"},
			},
			call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_entry_value","arguments":{"path":"payment"}}}`,
		},
		{
			name: "denied_scope",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"allowed/*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_entry_value","arguments":{"path":"secret"}}}`,
		},
		{
			name: "denied_quarantine",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_entry_value","arguments":{"path":"quarantine/bad"}}}`,
		},
	}

	fixtureCases := make([]mcpCallCase, 0, len(cases))
	for _, tc := range cases {
		srv := newTestServerWithVault(t, tc.profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		handler := NewProtocolHandler(serverName, serverVersion, srv)
		inputs := append(append([]string{}, base...), tc.call)
		outputs := make([]json.RawMessage, 0, len(inputs))
		markerCounts := make([]int, 0, len(inputs))
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
			value, markers := normalizeMCPCallValue(value, vaultDir)
			normalized, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal normalized %s response: %v", tc.name, err)
			}
			normalized = mcpGetValueTimestamp.ReplaceAll(normalized, []byte("<fixture-time>"))
			outputs = append(outputs, json.RawMessage(normalized))
			markerCounts = append(markerCounts, markers)
		}
		fixtureCases = append(fixtureCases, mcpCallCase{
			Name: tc.name, Input: inputs, Output: outputs, MarkerCounts: markerCounts,
		})
	}

	sourceHash := mcpCallSourceHash(t, mcpGetValueSourceFiles)
	if pinned := mcpGetValueGitSourceHash(t, mcpGetValueSourceFiles); pinned != sourceHash {
		t.Fatalf("Go get_entry_value sources differ from fca3f894: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpGetValueFixture{
		SchemaVersion: 1,
		Oracle: mcpGetValueOracle{
			Commit: "fca3f894", CommitSHA: "fca3f89401833b5e14ec4ec74ef736b0f63bca74",
			SourceFiles: mcpGetValueSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpGetValueGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	root := mcpListRepoRoot(t)
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-get-value.json")
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
			t.Fatal("MCP get_entry_value fixture is stale; run with SYMAIRA_GENERATE_MCP_GET_VALUE_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func mcpGetValueFixtureVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate fixture identity: %v", err)
	}
	secret := &vault.Entry{
		Data:           map[string]any{"password": "testpass123"},
		Classification: taint.Secret,
	}
	classified := &vault.Entry{
		Data:           map[string]any{"password": "classified-secret"},
		Classification: taint.Secret,
	}
	payment := &vault.Entry{
		Data: map[string]any{
			"card_number": "4111111111111111",
			"cvc":         "123",
			"note":        "safe-note",
		},
		SecretMetadata: vault.SecretMetadata{Type: vault.SecretTypePayment},
	}
	quarantine := &vault.Entry{Data: map[string]any{"password": "quarantined"}}
	for path, entry := range map[string]*vault.Entry{
		"secret":         secret,
		"classified":     classified,
		"payment":        payment,
		"quarantine/bad": quarantine,
	} {
		if err := vault.WriteEntry(dir, path, entry, identity); err != nil {
			t.Fatalf("write fixture entry %s: %v", path, err)
		}
	}
	return dir, identity
}

func mcpGetValueGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate get_entry_value fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read get_entry_value fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

func mcpGetValueGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "fca3f894:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned get_entry_value source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
