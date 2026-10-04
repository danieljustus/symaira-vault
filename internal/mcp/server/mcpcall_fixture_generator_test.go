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

const mcpCallPinnedSourceHash = "0cd184bb0155c46391f31c32bb2a3e9f4c814059acaff4c7f8afddfeb64b689c"

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
		t.Fatalf("working Go MCP call sources differ from d1cd0f97: got %s, want %s", sourceHash, pinnedHash)
	}

	fixture := mcpCallFixture{
		SchemaVersion: 1,
		Oracle: mcpCallOracle{
			Commit:        "d1cd0f97",
			CommitSHA:     "d1cd0f97ac550bc3020bc86b0514989f8d28d95c",
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
