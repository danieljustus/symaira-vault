package server

// This focused generator runs the production registry and list-time filters.
// It is intentionally a Go test so it can call the unexported registry seam
// without adding a public compatibility API just for fixture production.

import (
	"bytes"
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
	"github.com/danieljustus/symaira-vault/internal/secureui"
)

type mcpListFixture struct {
	SchemaVersion int              `json:"schema_version"`
	Oracle        mcpListOracle    `json:"oracle"`
	Catalog       []map[string]any `json:"catalog"`
	Cases         []mcpListCase    `json:"cases"`
}

type mcpListOracle struct {
	Commit        string   `json:"commit"`
	CommitSHA     string   `json:"commit_sha"`
	SourceFiles   []string `json:"source_files"`
	SourceHash    string   `json:"source_hash"`
	GeneratorHash string   `json:"generator_hash"`
}

type mcpListCase struct {
	Name             string           `json:"name"`
	Profile          string           `json:"profile"`
	IncludeAll       bool             `json:"include_all_tools"`
	ExposeValueTools *bool            `json:"expose_value_tools,omitempty"`
	Runtime          mcpListRuntime   `json:"runtime"`
	Tools            []map[string]any `json:"tools"`
}

type mcpListRuntime struct {
	ExecuteAPI   bool `json:"execute_api"`
	SecureInput  bool `json:"secure_input"`
	GenerateTOTP bool `json:"generate_totp"`
}

var mcpListSourceFiles = []string{
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

const mcpListPinnedSourceHash = "0cd184bb0155c46391f31c32bb2a3e9f4c814059acaff4c7f8afddfeb64b689c"

func TestGenerateMCPListFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_LIST_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_LIST_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_LIST_FIXTURE=1 or SYMAIRA_CHECK_MCP_LIST_FIXTURE=1")
	}

	// The production registry uses host capability detection for these three
	// tools. Inject deterministic capabilities so this capture never touches a
	// keychain, vault, GUI, or real command runner.
	originalSecure := secureInputCapabilityFn
	secureInputCapabilityFn = func() secureui.Capability { return secureui.CapNone }
	t.Cleanup(func() { secureInputCapabilityFn = originalSecure })

	baselineRuntime := mcpListRuntime{GenerateTOTP: true}

	cases := []mcpListCase{
		captureMCPListCase("nil_lean", "", false, baselineRuntime, nil),
		captureMCPListCase("nil_all", "", true, baselineRuntime, nil),
	}

	secureInputCapabilityFn = func() secureui.Capability { return secureui.CapTTY }
	runtime := mcpListRuntime{ExecuteAPI: true, SecureInput: true, GenerateTOTP: true}
	for _, tier := range []string{"read-only", "standard", "admin"} {
		srv := mcpListProfile(t, tier, runtime)
		cases = append(cases,
			captureMCPListCase(tier+"_all", tier, true, runtime, srv),
			captureMCPListCase(tier+"_lean", tier, false, runtime, srv),
		)
	}
	custom := mcpListProfileWithExpose(t, "custom", runtime, nil)
	cases = append(cases,
		captureMCPListCase("custom_unset_all", "custom", true, runtime, custom),
	)
	customTrue := mcpListProfileWithExpose(t, "custom", runtime, config.BoolPtr(true))
	cases = append(cases,
		captureMCPListCase("custom_true_all", "custom", true, runtime, customTrue),
	)
	customFalse := mcpListProfileWithExpose(t, "custom", runtime, config.BoolPtr(false))
	cases = append(cases,
		captureMCPListCase("custom_false_all", "custom", true, runtime, customFalse),
	)

	sourceHash := mcpListSourceHash(t, mcpListSourceFiles)
	if sourceHash != mcpListPinnedSourceHash {
		t.Fatalf("Go MCP list sources drifted from pinned oracle: got %s, want %s", sourceHash, mcpListPinnedSourceHash)
	}
	if pinnedHash := mcpListGitSourceHash(t, mcpListSourceFiles); pinnedHash != sourceHash {
		t.Fatalf("working Go MCP list sources differ from d1cd0f97: got %s, want %s", sourceHash, pinnedHash)
	}
	generatorHash := mcpListGeneratorHash(t)
	fixture := mcpListFixture{
		SchemaVersion: 1,
		Oracle: mcpListOracle{
			Commit:        "d1cd0f97",
			CommitSHA:     "d1cd0f97ac550bc3020bc86b0514989f8d28d95c",
			SourceFiles:   mcpListSourceFiles,
			SourceHash:    sourceHash,
			GeneratorHash: generatorHash,
		},
		Catalog: toolsListPayload(mcpListProfile(t, "admin", runtime)),
		Cases:   cases,
	}

	root := mcpListRepoRoot(t)
	path := filepath.Join(root, "testdata", "port", "mcp", "tool-list.json")
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
			t.Fatal("MCP list fixture is stale; run with SYMAIRA_GENERATE_MCP_LIST_FIXTURE=1")
		}
		t.Logf("checked %s (%d bytes)", path, len(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(data))
}

func captureMCPListCase(name, tier string, includeAll bool, runtime mcpListRuntime, srv *Server) mcpListCase {
	var tools []map[string]any
	if srv == nil && tier != "" {
		panic("profile required for tier case")
	}
	if srv == nil {
		tools = toolsListPayload(nil)
	} else {
		tools = toolsListPayload(srv)
	}
	if !includeAll {
		tools = filterLeanTools(tools)
	}
	var expose *bool
	if srv != nil && srv.agent != nil {
		expose = srv.agent.ExposeValueTools
	}
	return mcpListCase{Name: name, Profile: tier, IncludeAll: includeAll, ExposeValueTools: expose, Runtime: runtime, Tools: tools}
}

func mcpListProfile(t *testing.T, tier string, runtime mcpListRuntime) *Server {
	return mcpListProfileWithExpose(t, tier, runtime, config.BoolPtr(tier == "admin"))
}

func mcpListProfileWithExpose(t *testing.T, tier string, runtime mcpListRuntime, expose *bool) *Server {
	t.Helper()
	trueValue := true
	profile := config.AgentProfile{
		Name:             "fixture",
		Tier:             config.StrPtr(tier),
		CanRunCommands:   &trueValue,
		CanUseClipboard:  &trueValue,
		CanUseAutotype:   &trueValue,
		CanReadValues:    &trueValue,
		ExposeValueTools: expose,
		AllowedPaths:     []string{"*"},
		ApprovalMode:     config.StrPtr("none"),
	}
	if !runtime.ExecuteAPI {
		profile.CanRunCommands = config.BoolPtr(false)
	}
	if !runtime.GenerateTOTP {
		profile.CanUseClipboard = config.BoolPtr(false)
		profile.CanUseAutotype = config.BoolPtr(false)
		profile.CanReadValues = config.BoolPtr(false)
	}
	return newTestServerWithVault(t, profile, "stdio", "")
}

func mcpListSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(mcpListRepoRoot(t), name))
		if err != nil {
			t.Fatalf("read source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpListGitSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := mcpListRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", "d1cd0f97ac550bc3020bc86b0514989f8d28d95c:"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mcpListGeneratorHash(t *testing.T) string {
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

func mcpListRepoRoot(t *testing.T) string {
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
