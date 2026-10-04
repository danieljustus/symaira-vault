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

const mcpRateLimitPinnedSourceHash = "0cd184bb0155c46391f31c32bb2a3e9f4c814059acaff4c7f8afddfeb64b689c"

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
		t.Fatalf("working Go MCP rate-limit sources differ from d1cd0f97: got %s, want %s", sourceHash, pinned)
	}
	fixture := mcpRateLimitFixture{
		SchemaVersion: 1,
		Oracle: mcpRateLimitOracle{
			Commit: "d1cd0f97", CommitSHA: "d1cd0f97ac550bc3020bc86b0514989f8d28d95c",
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
		data, err := exec.Command("git", "show", "d1cd0f97:"+name).Output()
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
