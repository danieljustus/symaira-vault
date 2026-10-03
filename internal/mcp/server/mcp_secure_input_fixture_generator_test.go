package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/secureui"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

type secureInputFixture struct {
	SchemaVersion  int                      `json:"schema_version"`
	Oracle         secureInputOracle        `json:"oracle"`
	Normalizations []string                 `json:"normalizations"`
	Cases          []secureInputObservation `json:"cases"`
}

type secureInputOracle struct {
	Commit         string   `json:"commit"`
	CommitSHA      string   `json:"commit_sha"`
	SourceFiles    []string `json:"source_files"`
	SourceHash     string   `json:"source_hash"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
}

type secureInputScenario struct {
	Name          string         `json:"name"`
	Tool          string         `json:"tool"`
	Arguments     map[string]any `json:"arguments"`
	ApprovalMode  string         `json:"approval_mode"`
	ApprovalReply string         `json:"approval_reply,omitempty"`
	CanWrite      bool           `json:"can_write"`
	AllowedPaths  []string       `json:"allowed_paths"`
	Capability    string         `json:"capability"`
	InputValue    string         `json:"input_value,omitempty"`
	InputError    string         `json:"input_error,omitempty"`
}

type secureInputObservation struct {
	Name              string         `json:"name"`
	Tool              string         `json:"tool"`
	Arguments         map[string]any `json:"arguments"`
	Response          map[string]any `json:"response,omitempty"`
	RawError          string         `json:"raw_error,omitempty"`
	StoredValue       string         `json:"stored_value,omitempty"`
	PromptCalls       int            `json:"prompt_calls"`
	PromptTitle       string         `json:"prompt_title,omitempty"`
	PromptPath        string         `json:"prompt_path,omitempty"`
	PromptField       string         `json:"prompt_field,omitempty"`
	PromptDescription string         `json:"prompt_description,omitempty"`
	PromptHidden      bool           `json:"prompt_hidden"`
	InputValue        string         `json:"input_value,omitempty"`
	ApprovalReads     int            `json:"approval_reads"`
	CallOrder         []string       `json:"call_order"`
}

var secureInputSourceFiles = []string{
	"go.mod",
	"go.sum",
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
	"internal/mcp/mcptypes.go",
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/secure_input.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_request_credential.go",
	"internal/mcp/server/tools_secure_input.go",
	"internal/secureui/backend.go",
	"internal/secureui/backend_tty.go",
	"internal/secureui/secureui.go",
	"internal/template/builtins.go",
	"internal/template/engine.go",
	"internal/template/funcs.go",
	"internal/template/resolver.go",
	"internal/ui/theme/a11y.go",
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

var secureInputGeneratorFiles = []string{
	"internal/mcp/server/mcp_secure_input_fixture_generator_test.go",
	"internal/mcp/server/mcp_execute_api_request_fixture_generator_test.go",
	"internal/mcp/server/approval_test.go",
	"internal/mcp/server/tools_test_helpers.go",
	"internal/mcp/server/mcpsetentry_fixture_generator_test.go",
	"internal/secureui/pty_test.go",
	"scripts/rust-port/cmd/secure_input_unicode/main.go",
}

const secureInputOracleCommit = "55da4ca13ead39d4000cf6f866ac8671ca86d8f2"

func TestGenerateMCPSecureInputFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_SECURE_INPUT_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_SECURE_INPUT_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_SECURE_INPUT_FIXTURE=1 or SYMAIRA_CHECK_MCP_SECURE_INPUT_FIXTURE=1")
	}
	root := executeAPIRequestRepoRoot(t)
	sourceHash := executeAPIRequestGitDigest(t, root, secureInputOracleCommit, secureInputSourceFiles)
	if current := executeAPIRequestWorkingDigest(t, root, secureInputSourceFiles); current != sourceHash {
		t.Fatalf("Go production sources differ from pinned oracle %s: got %s, want %s", secureInputOracleCommit, current, sourceHash)
	}

	scenarios := []secureInputScenario{
		{Name: "secure_input_success", Tool: "secure_input", Arguments: map[string]any{"path": "allowed/service", "field": "token", "description": "synthetic fixture"}, ApprovalMode: "none", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "synthetic-secret-one"},
		{Name: "request_credential_success", Tool: "request_credential", Arguments: map[string]any{"path": "allowed/service", "field": "password", "reason": "synthetic fixture"}, ApprovalMode: "none", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "synthetic-secret-two"},
		{Name: "approval_then_secure_input", Tool: "secure_input", Arguments: map[string]any{"path": "allowed/service", "field": "approved", "description": "must approve first"}, ApprovalMode: "prompt", ApprovalReply: "y", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "approved-secret"},
		{Name: "approval_denied_before_prompt", Tool: "request_credential", Arguments: map[string]any{"path": "allowed/service", "field": "denied", "reason": "must deny first"}, ApprovalMode: "prompt", ApprovalReply: "n", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "must-not-be-read"},
		{Name: "approval_mode_deny", Tool: "secure_input", Arguments: map[string]any{"path": "allowed/service", "field": "denied"}, ApprovalMode: "deny", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "must-not-be-read"},
		{Name: "write_capability_denied", Tool: "secure_input", Arguments: map[string]any{"path": "allowed/service", "field": "denied"}, ApprovalMode: "none", CanWrite: false, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "must-not-be-read"},
		{Name: "scope_denied", Tool: "request_credential", Arguments: map[string]any{"path": "outside/service", "field": "denied"}, ApprovalMode: "none", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "must-not-be-read"},
		{Name: "missing_field", Tool: "secure_input", Arguments: map[string]any{"path": "allowed/service"}, ApprovalMode: "none", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputValue: "must-not-be-read"},
		{Name: "empty_input", Tool: "secure_input", Arguments: map[string]any{"path": "allowed/service", "field": "empty"}, ApprovalMode: "none", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty"},
		{Name: "input_timeout", Tool: "request_credential", Arguments: map[string]any{"path": "allowed/service", "field": "timeout"}, ApprovalMode: "none", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "tty", InputError: "timeout"},
		{Name: "backend_unavailable", Tool: "secure_input", Arguments: map[string]any{"path": "allowed/service", "field": "unavailable"}, ApprovalMode: "none", CanWrite: true, AllowedPaths: []string{"allowed"}, Capability: "none", InputValue: "must-not-be-read"},
	}
	cases := make([]secureInputObservation, 0, len(scenarios))
	for _, scenario := range scenarios {
		cases = append(cases, runSecureInputScenario(t, scenario))
	}

	oracle := secureInputOracle{
		Commit:         "55da4ca1",
		CommitSHA:      secureInputOracleCommit,
		SourceFiles:    secureInputSourceFiles,
		SourceHash:     sourceHash,
		GeneratorFiles: secureInputGeneratorFiles,
		GeneratorHash:  executeAPIRequestWorkingDigest(t, root, secureInputGeneratorFiles),
	}
	fixture := secureInputFixture{
		SchemaVersion: 1,
		Oracle:        oracle,
		Normalizations: []string{
			"Rust deliberately suppresses terminal echo for secure input; Go's go-tty ReadString echoes printable runes despite the hidden-input prompt.",
		},
		Cases: cases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("encode secure input fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata/port/mcp/secure-input.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read secure input fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("secure input fixture is stale; run with SYMAIRA_GENERATE_MCP_SECURE_INPUT_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write secure input fixture: %v", err)
	}
}

func runSecureInputScenario(t *testing.T, scenario secureInputScenario) secureInputObservation {
	t.Helper()
	identityRoot, identity := mcpSetEntryFixtureVault(t)
	profile := config.AgentProfile{
		Name: "secure-input-fixture", Tier: config.StrPtr("admin"),
		AllowedPaths: scenario.AllowedPaths, CanWrite: config.BoolPtr(scenario.CanWrite),
		ApprovalMode: config.StrPtr(scenario.ApprovalMode),
	}
	srv := newTestServerWithVault(t, profile, "stdio", identityRoot)
	srv.vault.Identity = identity

	observation := secureInputObservation{
		Name: scenario.Name, Tool: scenario.Tool, Arguments: scenario.Arguments,
		InputValue: scenario.InputValue,
		CallOrder:  []string{},
	}
	originalCapability := secureInputCapabilityFn
	originalPrompt := secureInputPromptFn
	originalTTY := openTTYDevice
	secureInputCapabilityFn = func() secureui.Capability {
		if scenario.Capability == "tty" {
			return secureui.CapTTY
		}
		return secureui.CapNone
	}
	secureInputPromptFn = func(request secureui.PromptRequest) (string, error) {
		observation.CallOrder = append(observation.CallOrder, "secure_input")
		observation.PromptCalls++
		observation.PromptTitle = request.Title
		observation.PromptPath = request.Path
		observation.PromptField = request.Field
		observation.PromptDescription = request.Description
		observation.PromptHidden = request.Hidden
		switch scenario.InputError {
		case "timeout":
			return "", secureui.ErrTimeout
		case "cancel":
			return "", secureui.ErrCanceled
		default:
			return scenario.InputValue, nil
		}
	}
	approvalFile, err := os.CreateTemp(t.TempDir(), "secure-input-approval-*")
	if err != nil {
		t.Fatalf("create fake approval output: %v", err)
	}
	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			output: approvalFile,
			raw:    func() (func(), error) { return func() {}, nil },
			readString: func() (string, error) {
				observation.ApprovalReads++
				observation.CallOrder = append(observation.CallOrder, "approval")
				return scenario.ApprovalReply, nil
			},
		}, nil
	}
	defer func() {
		secureInputCapabilityFn = originalCapability
		secureInputPromptFn = originalPrompt
		openTTYDevice = originalTTY
		_ = approvalFile.Close()
	}()

	arguments, err := json.Marshal(scenario.Arguments)
	if err != nil {
		t.Fatalf("marshal fixture arguments: %v", err)
	}
	response, callErr := srv.executeTool(context.Background(), scenario.Tool, arguments)
	if callErr != nil {
		observation.RawError = callErr.Error()
	} else {
		observation.Response = response
	}
	path, _ := scenario.Arguments["path"].(string)
	field, _ := scenario.Arguments["field"].(string)
	if stored, err := vault.ReadEntry(identityRoot, path, identity); err == nil {
		if value, ok := stored.Data[field]; ok {
			if text, ok := value.(string); ok {
				observation.StoredValue = text
			}
		}
	}
	return observation
}
