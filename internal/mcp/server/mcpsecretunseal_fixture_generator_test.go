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
const mcpSecretUnsealCommit = "a581df7b09630a0d8c572af727b7cf096d2557ad"

var mcpSecretUnsealSources = []string{
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
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_unseal.go",
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
			Commit: "a581df7b", CommitSHA: mcpSecretUnsealCommit, SourceFiles: mcpSecretUnsealSources,
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
