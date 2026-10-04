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
	"internal/approval/enroll.go",
	"internal/approval/http.go",
	"internal/approval/local.go",
	"internal/approval/queue.go",
	"internal/audit/audit.go",
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
	mixedCaseLog := []byte("{\"TS\":\"2026-01-02T03:04:12Z\",\"AGENT\":\"fixture\",\"ACTION\":\"mixed\",\"PATH\":\"mixed/path\",\"FIELD\":\"token\",\"TRANSPORT\":\"stdio\",\"REASON\":\"case\",\"SHARE_ID\":\"share-1\",\"FROM_AGENT\":\"from\",\"TO_AGENT\":\"to\",\"SHARE_ACTION\":\"grant\",\"DUR_MS\":7,\"TOKEN_ID\":\"token-1\",\"REQ_ID\":\"req-1\",\"SESS_ID\":\"sess-1\",\"KID\":\"kid-1\",\"HMAC\":\"hmac-1\",\"ARGV_HASH\":\"argv-1\",\"OK\":true}\n")
	invalidAgentTypeLog := []byte("{\"ts\":\"2026-01-02T03:04:13Z\",\"agent\":123,\"action\":\"invalid-agent\",\"ok\":true}\n")
	invalidDurationTypeLog := []byte("{\"ts\":\"2026-01-02T03:04:14Z\",\"action\":\"invalid-duration\",\"dur_ms\":\"slow\",\"ok\":true}\n")
	nullTypedFieldsLog := []byte("{\"ts\":null,\"agent\":null,\"action\":null,\"path\":null,\"field\":null,\"transport\":null,\"reason\":null,\"share_id\":null,\"from_agent\":null,\"to_agent\":null,\"share_action\":null,\"dur_ms\":null,\"token_id\":null,\"req_id\":null,\"sess_id\":null,\"kid\":null,\"hmac\":null,\"argv_hash\":null,\"ok\":null}\n")
	htmlEntry, err := json.Marshal(audit.LogEntry{
		Timestamp: "2026-01-02T03:04:15Z", Agent: "fixture", Action: "<>&\u2028",
		Path: "path/<>&\u2028", Reason: "reason/<>&\u2028", OK: true,
	})
	if err != nil {
		t.Fatalf("marshal HTML audit entry: %v", err)
	}
	htmlLog := append(htmlEntry, '\n')
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
		{name: "mixed_case_keys_decode", call: `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: mixedCaseLog, withLog: true},
		{name: "invalid_agent_type_skips_entry", call: `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: invalidAgentTypeLog, withLog: true},
		{name: "invalid_duration_type_skips_entry", call: `{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: invalidDurationTypeLog, withLog: true},
		{name: "null_typed_fields_default", call: `{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: nullTypedFieldsLog, withLog: true},
		{name: "html_and_line_separator_escaped", call: `{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"symaira_audit_self","arguments":{"limit":100}}}`, log: htmlLog, withLog: true},
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
		t.Fatalf("Go audit-self sources differ from d1cd0f97: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpAuditSelfFixture{
		SchemaVersion: 1,
		Oracle: mcpAuditSelfOracle{
			Commit: "d1cd0f97", CommitSHA: "d1cd0f97ac550bc3020bc86b0514989f8d28d95c",
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
		cmd := exec.Command("git", "show", "d1cd0f97:"+name)
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
