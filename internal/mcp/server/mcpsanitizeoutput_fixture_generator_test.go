package server

// This opt-in generator executes the production sanitize_output MCP handler
// with synthetic input only. It never opens a vault entry or platform secret.

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

type mcpSanitizeOutputFixture struct {
	SchemaVersion int                     `json:"schema_version"`
	Oracle        mcpSanitizeOutputOracle `json:"oracle"`
	ServerName    string                  `json:"server_name"`
	ServerVersion string                  `json:"server_version"`
	Cases         []mcpSanitizeOutputCase `json:"cases"`
}

type mcpSanitizeOutputOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpSanitizeOutputCase struct {
	Name   string            `json:"name"`
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
}

var mcpSanitizeOutputSourceFiles = []string{
	"internal/approval/enroll.go",
	"internal/approval/http.go",
	"internal/approval/local.go",
	"internal/approval/queue.go",
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
	"internal/crypto/argon2_resources.go",
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
	"internal/mcp/apitemplates/auth.go",
	"internal/mcp/apitemplates/template.go",
	"internal/mcp/auth/auth.go",
	"internal/mcp/auth/token.go",
	"internal/mcp/auth/token_ratelimit.go",
	"internal/mcp/errors/codes.go",
	"internal/mcp/install/agent.go",
	"internal/mcp/install/config.go",
	"internal/mcp/install/detect.go",
	"internal/mcp/install/installer.go",
	"internal/mcp/masking/doc.go",
	"internal/mcp/masking/sanitizer.go",
	"internal/mcp/masking/validator.go",
	"internal/mcp/mcptypes.go",
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/command_policy.go",
	"internal/mcp/server/grant_keys.go",
	"internal/mcp/server/grant_keys_fallback.go",
	"internal/mcp/server/hooks.go",
	"internal/mcp/server/hooks_builtin.go",
	"internal/mcp/server/http_helpers.go",
	"internal/mcp/server/leanmode.go",
	"internal/mcp/server/prompt_registry.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/server/render.go",
	"internal/mcp/server/secure_input.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/server_approval.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/setup.go",
	"internal/mcp/server/sharing_store.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_audit_self.go",
	"internal/mcp/server/tools_auth.go",
	"internal/mcp/server/tools_autotype.go",
	"internal/mcp/server/tools_clipboard.go",
	"internal/mcp/server/tools_delete.go",
	"internal/mcp/server/tools_execute_api_request.go",
	"internal/mcp/server/tools_execute_with_secret.go",
	"internal/mcp/server/tools_find.go",
	"internal/mcp/server/tools_generate.go",
	"internal/mcp/server/tools_get.go",
	"internal/mcp/server/tools_health.go",
	"internal/mcp/server/tools_list.go",
	"internal/mcp/server/tools_perplexity.go",
	"internal/mcp/server/tools_prepare_payment.go",
	"internal/mcp/server/tools_request_credential.go",
	"internal/mcp/server/tools_run.go",
	"internal/mcp/server/tools_sanitize.go",
	"internal/mcp/server/tools_search.go",
	"internal/mcp/server/tools_search_openai.go",
	"internal/mcp/server/tools_secure_input.go",
	"internal/mcp/server/tools_set.go",
	"internal/mcp/server/tools_sharing.go",
	"internal/mcp/server/tools_template.go",
	"internal/mcp/server/tools_test_helpers.go",
	"internal/mcp/server/tools_totp.go",
	"internal/mcp/server/tools_unseal.go",
	"internal/mcp/server/tools_whoami.go",
	"internal/mcp/serverbootstrap/http.go",
	"internal/mcp/serverbootstrap/http_lifecycle.go",
	"internal/mcp/serverbootstrap/http_metrics.go",
	"internal/mcp/serverbootstrap/http_nometrics.go",
	"internal/mcp/serverbootstrap/http_setup.go",
	"internal/mcp/serverbootstrap/oauth.go",
	"internal/mcp/serverbootstrap/stdio.go",
	"internal/mcp/serverbootstrap/tls.go",
	"internal/mcp/serverbootstrap/wellknown.go",
	"internal/mcp/sharing_types.go",
	"internal/mcp/toolhash.go",
	"internal/mcp/transport/stdio.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/util.go",
	"internal/policy/authorizer.go",
	"internal/policy/context.go",
	"internal/policy/engine.go",
	"internal/policy/parser.go",
	"internal/policy/ratelimit.go",
	"internal/policy/ratelimit_transition.go",
	"internal/policy/types.go",
	"internal/secureui/backend.go",
	"internal/secureui/backend_darwin.go",
	"internal/secureui/backend_other.go",
	"internal/secureui/backend_tty.go",
	"internal/secureui/backend_unix.go",
	"internal/secureui/backend_windows.go",
	"internal/secureui/capslock.go",
	"internal/secureui/capslock_darwin.go",
	"internal/secureui/capslock_linux.go",
	"internal/secureui/capslock_other.go",
	"internal/secureui/runner.go",
	"internal/secureui/secureui.go",
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
	"internal/vault/kdf_resource_migration.go",
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

func TestGenerateMCPSanitizeOutputFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_SANITIZE_OUTPUT_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_SANITIZE_OUTPUT_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_SANITIZE_OUTPUT_FIXTURE=1 or SYMAIRA_CHECK_MCP_SANITIZE_OUTPUT_FIXTURE=1")
	}

	serverName := "symvault"
	serverVersion := "0.0.0-sanitize-output-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	cases := []struct {
		name string
		call string
	}{
		{name: "clean_text", call: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sanitize_output","arguments":{"text":"ordinary output"}}}`},
		{name: "ansi_controls_and_markup", call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sanitize_output","arguments":{"text":"\u001b[31msecret\u001b[0m\u0001 </data> -->"}}}`},
		{name: "unicode_normalization_and_invisibles", call: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sanitize_output","arguments":{"text":"ＦＵＬＬＷＩＤＴＨ\u200b\u202evalue"}}}`},
		{name: "html_escape_in_wire_json", call: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sanitize_output","arguments":{"text":"<>&\u2028"}}}`},
		{name: "empty_text", call: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"sanitize_output","arguments":{"text":""}}}`},
		{name: "missing_text", call: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sanitize_output","arguments":{}}}`},
		{name: "wrong_text_type", call: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"sanitize_output","arguments":{"text":null}}}`},
	}

	fixtureCases := make([]mcpSanitizeOutputCase, 0, len(cases))
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
		fixtureCases = append(fixtureCases, mcpSanitizeOutputCase{Name: tc.name, Input: inputs, Output: outputs})
	}

	root := mcpSanitizeOutputRepoRoot(t)
	sourceHash := mcpSanitizeOutputSourceHash(t, mcpSanitizeOutputSourceFiles)
	if pinned := mcpSanitizeOutputGitSourceHash(t, mcpSanitizeOutputSourceFiles); pinned != sourceHash {
		t.Fatalf("Go sanitize-output sources differ from d1cd0f97: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpSanitizeOutputFixture{
		SchemaVersion: 1,
		Oracle: mcpSanitizeOutputOracle{
			Commit: "d1cd0f97", CommitSHA: "d1cd0f97ac550bc3020bc86b0514989f8d28d95c",
			SourceFiles: mcpSanitizeOutputSourceFiles, SourceHash: sourceHash,
			GeneratorHash: mcpSanitizeOutputGeneratorHash(t),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: fixtureCases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-sanitize-output.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP sanitize-output fixture is stale; run with SYMAIRA_GENERATE_MCP_SANITIZE_OUTPUT_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func mcpSanitizeOutputSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpSanitizeOutputRepoRoot(t)
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

func mcpSanitizeOutputGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpSanitizeOutputRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "d1cd0f97:"+name)
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

func mcpSanitizeOutputGeneratorHash(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate sanitize-output fixture generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sanitize-output fixture generator: %v", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

func mcpSanitizeOutputRepoRoot(t *testing.T) string {
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
