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
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

// This opt-in generator exercises the production Go search/fetch handlers
// against a synthetic encrypted vault. It never reads the developer's vault
// and never resolves a platform credential.

type mcpSearchFetchFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Oracle        mcpSearchFetchOracle `json:"oracle"`
	ServerName    string               `json:"server_name"`
	ServerVersion string               `json:"server_version"`
	Cases         []mcpSearchFetchCase `json:"cases"`
}

type mcpSearchFetchOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpSearchFetchCase struct {
	Name         string            `json:"name"`
	Input        []string          `json:"input"`
	Output       []json.RawMessage `json:"output"`
	MarkerCounts []int             `json:"marker_counts"`
}

var mcpSearchFetchSourceFiles = []string{
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/config_save.go",
	"internal/config/config_validate.go",
	"internal/config/dottedpath.go",
	"internal/config/migrate.go",
	"internal/config/migrate_copy_unix.go",
	"internal/config/migrate_copy_windows.go",
	"internal/config/migrate_source_unix.go",
	"internal/config/migrate_source_windows.go",
	"internal/config/paths.go",
	"internal/config/presets.go",
	"internal/config/schema.go",
	"internal/config/warn.go",
	"internal/crypto/age.go",
	"internal/crypto/argon2id.go",
	"internal/crypto/diceware.go",
	"internal/crypto/hmac.go",
	"internal/crypto/interop.go",
	"internal/crypto/keygen.go",
	"internal/crypto/keystore.go",
	"internal/crypto/password.go",
	"internal/crypto/secstring_other.go",
	"internal/crypto/secstring_unix.go",
	"internal/crypto/symmetric.go",
	"internal/crypto/totp.go",
	"internal/fsutil/createsensitiveoutput.go",
	"internal/fsutil/doc.go",
	"internal/fsutil/reexport.go",
	"internal/fsutil/safepath/doc.go",
	"internal/fsutil/safepath/manager_unix.go",
	"internal/fsutil/safepath/manager_windows.go",
	"internal/fsutil/safepath/safepath.go",
	"internal/fsutil/safewrite_windows.go",
	"internal/mcp/mcptypes.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/render.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_find.go",
	"internal/mcp/server/tools_get.go",
	"internal/mcp/server/tools_search_openai.go",
	"internal/mcp/transport/transport.go",
	"internal/template/builtins.go",
	"internal/template/engine.go",
	"internal/template/funcs.go",
	"internal/template/resolver.go",
	"internal/vault/backup_codes.go",
	"internal/vault/cache.go",
	"internal/vault/devices.go",
	"internal/vault/entry.go",
	"internal/vault/entry_canary.go",
	"internal/vault/entry_metadata.go",
	"internal/vault/entry_readwrite.go",
	"internal/vault/entry_resources.go",
	"internal/vault/entry_validate.go",
	"internal/vault/file_digest.go",
	"internal/vault/git.go",
	"internal/vault/index_resources.go",
	"internal/vault/lock_unix.go",
	"internal/vault/lock_windows.go",
	"internal/vault/manifest.go",
	"internal/vault/manifest_updater.go",
	"internal/vault/metrics.go",
	"internal/vault/payment.go",
	"internal/vault/read_admission.go",
	"internal/vault/recipients.go",
	"internal/vault/reencrypt.go",
	"internal/vault/reencrypt_journal.go",
	"internal/vault/reencrypt_journal_unix.go",
	"internal/vault/reencrypt_journal_windows.go",
	"internal/vault/reencrypt_unix.go",
	"internal/vault/reencrypt_windows.go",
	"internal/vault/retention_budget.go",
	"internal/vault/search.go",
	"internal/vault/search_index.go",
	"internal/vault/service.go",
	"internal/vault/symlink_harden.go",
	"internal/vault/symlink_harden_windows.go",
	"internal/vault/sync/sync.go",
	"internal/vault/taint/taint.go",
	"internal/vault/types.go",
	"internal/vault/url.go",
	"internal/vault/vault.go",
	"internal/vault/vault_sync_reconcile.go",
}

func TestGenerateMCPSearchFetchFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_SEARCH_FETCH_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_SEARCH_FETCH_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_SEARCH_FETCH_FIXTURE=1 or SYMAIRA_CHECK_MCP_SEARCH_FETCH_FIXTURE=1")
	}

	vaultDir, identity := mcpGetValueFixtureVault(t)
	serverName := "symvault"
	serverVersion := "0.0.0-search-fetch-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	cases := []struct {
		name    string
		profile config.AgentProfile
		call    string
		second  string
	}{
		{
			name: "search_metadata_only",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{"query":"secret"}}}`,
		},
		{
			name: "search_missing_query",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{}}}`,
		},
		{
			name: "fetch_metadata_only",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(false), ExposeValueTools: config.BoolPtr(false),
				ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_values_allowed",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_default_sealed",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(false), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_redacted_before_seal",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(false), ApprovalMode: config.StrPtr("none"),
				RedactFields: []string{"password"},
			},
			call: `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_session_limit",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
				MaxSecretsInSession: config.IntPtr(1),
			},
			call:   `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
			second: `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_expose_false_can_read_true",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(false),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_only_allowed_registry",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"}, AllowedTools: []string{"fetch"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_scope_denied",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"allowed/*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"secret"}}}`,
		},
		{
			name: "fetch_quarantine_denied",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true),
				AutoUnseal: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"quarantine/bad"}}}`,
		},
		{
			name: "fetch_missing_id",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`,
		},
		{
			name: "fetch_missing_entry",
			profile: config.AgentProfile{
				Name: "fixture", AllowedPaths: []string{"*"},
				ApprovalMode: config.StrPtr("none"),
			},
			call: `{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"missing"}}}`,
		},
	}

	fixtureCases := make([]mcpSearchFetchCase, 0, len(cases))
	for _, tc := range cases {
		srv := newTestServerWithVault(t, tc.profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		handler := NewProtocolHandler(serverName, serverVersion, srv)
		inputs := append(append([]string{}, base...), tc.call)
		if tc.second != "" {
			inputs = append(inputs, tc.second)
		}
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
			outputs = append(outputs, json.RawMessage(normalized))
			markerCounts = append(markerCounts, markers)
		}
		fixtureCases = append(fixtureCases, mcpSearchFetchCase{
			Name: tc.name, Input: inputs, Output: outputs, MarkerCounts: markerCounts,
		})
	}

	sourceHash := mcpSearchFetchSourceHash(t, mcpSearchFetchSourceFiles)
	if pinned := mcpSearchFetchGitSourceHash(t, mcpSearchFetchSourceFiles); pinned != sourceHash {
		t.Fatalf("Go search/fetch sources differ from a581df7b: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpSearchFetchFixture{
		SchemaVersion: 1,
		Oracle: mcpSearchFetchOracle{
			Commit: "a581df7b", CommitSHA: "a581df7b09630a0d8c572af727b7cf096d2557ad",
			SourceFiles: mcpSearchFetchSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpSearchFetchGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(mcpSearchFetchRepoRoot(t), "testdata", "port", "mcp", "tools-search-fetch.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP search/fetch fixture is stale; run with SYMAIRA_GENERATE_MCP_SEARCH_FETCH_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func mcpSearchFetchRepoRoot(t *testing.T) string {
	t.Helper()
	return mcpListRepoRoot(t)
}

func mcpSearchFetchSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpSearchFetchRepoRoot(t)
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

func mcpSearchFetchGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpSearchFetchRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "a581df7b:"+name)
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

func mcpSearchFetchGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate search/fetch fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read search/fetch fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}
