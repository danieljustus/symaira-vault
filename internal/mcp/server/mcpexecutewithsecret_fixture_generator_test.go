package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// This fixture executes the production Go secret-injection handler against a
// synthetic vault. It is opt-in so ordinary Go tests never rewrite artifacts.
type executeWithSecretFixture struct {
	SchemaVersion     int                                    `json:"schema_version"`
	UnicodeNameDigest string                                 `json:"unicode_name_digest"`
	Oracle            executeWithSecretOracle                `json:"oracle"`
	NameCases         map[string]string                      `json:"name_cases"`
	AuditPath         string                                 `json:"audit_path"`
	Cases             []executeWithSecretFixtureCase         `json:"cases"`
	Approval          []executeWithSecretApprovalObservation `json:"approval_observations"`
	Normalizations    []string                               `json:"normalizations,omitempty"`
}

type executeWithSecretOracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type executeWithSecretFixtureCase struct {
	Name   string                  `json:"name"`
	Phase  string                  `json:"phase"`
	Input  json.RawMessage         `json:"input"`
	Output executeWithSecretResult `json:"output"`
}

type executeWithSecretResult struct {
	Text    string `json:"text"`
	IsError bool   `json:"is_error"`
	Error   string `json:"error,omitempty"`
}

type executeWithSecretApprovalObservation struct {
	Name            string                           `json:"name"`
	AttemptOutcomes []string                         `json:"attempt_outcomes"`
	AttemptErrors   []string                         `json:"attempt_errors"`
	Remembered      bool                             `json:"remembered"`
	ApprovalCounter int64                            `json:"approval_counter"`
	PromptCount     int                              `json:"prompt_count"`
	RequestCounters []int64                          `json:"request_counters"`
	Events          []executeWithSecretApprovalEvent `json:"events"`
	VisibleDetails  []string                         `json:"visible_details,omitempty"`
}

type executeWithSecretApprovalEvent struct {
	Action string `json:"action"`
	Path   string `json:"path"`
	OK     bool   `json:"ok"`
}

const executeWithSecretOracleCommit = "12d8c616ae98b954a9b906e0984af1613ca05fde"

var executeWithSecretOracleSources = []string{
	"internal/audit/audit.go",
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/command_policy.go",
	"internal/mcp/server/render.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/tools_execute_with_secret.go",
	"internal/mcp/server/tools_sanitize.go",
	"internal/mcp/server/tools_run.go",
	"internal/mcp/masking/sanitizer.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/apitemplates/auth.go",
	"internal/redact/detectors.go",
	"internal/redact/redact.go",
	"internal/secrets/filter.go",
	"internal/secrets/runner.go",
}

func TestGenerateMCPExecuteWithSecretFixture(t *testing.T) {
	g := os.Getenv("SYMAIRA_GENERATE_MCP_EXECUTE_WITH_SECRET_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_EXECUTE_WITH_SECRET_FIXTURE") == "1"
	if !g && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_EXECUTE_WITH_SECRET_FIXTURE=1 or SYMAIRA_CHECK_MCP_EXECUTE_WITH_SECRET_FIXTURE=1")
	}
	root := executeWithSecretRepoRoot(t)
	unicodeCmd := exec.Command("go", "run", "./scripts/rust-port/cmd/execute_secret_unicode")
	unicodeCmd.Dir = root
	if output, err := unicodeCmd.CombinedOutput(); err != nil {
		t.Fatalf("verify generated Go Unicode table: %v: %s", err, output)
	}
	provenanceCmd := exec.Command("go", "run", "./scripts/rust-port/cmd/execute_secret_provenance")
	provenanceCmd.Dir = root
	provenanceOutput, err := provenanceCmd.Output()
	if err != nil {
		t.Fatalf("verify Go oracle provenance: %v", err)
	}
	var provenanceResult struct {
		CommitSHA       string `json:"commit_sha"`
		SourceDigest    string `json:"source_digest"`
		GeneratorDigest string `json:"generator_digest"`
	}
	if err := json.Unmarshal(provenanceOutput, &provenanceResult); err != nil {
		t.Fatalf("decode provenance: %v", err)
	}
	fixtureBinDir := t.TempDir()
	childBinaryName := "true"
	if runtime.GOOS == "windows" {
		childBinaryName += ".exe"
	}
	childBinary := filepath.Join(fixtureBinDir, childBinaryName)
	childSource := filepath.Join(root, "scripts", "rust-port", "cmd", "execute_secret_child", "main.go")
	buildChild := exec.Command("go", "build", "-o", childBinary, childSource)
	buildChild.Dir = root
	if output, err := buildChild.CombinedOutput(); err != nil {
		t.Fatalf("build fixture-local true child: %v: %s", err, output)
	}
	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", fixtureBinDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("prepend fixture-local child to PATH: %v", err)
	}
	defer func() { _ = os.Setenv("PATH", oldPath) }()

	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{"password": "testpass123"})
	baseProfile := config.AgentProfile{
		Name: "execute-with-secret-fixture", AllowedPaths: []string{"*"},
		CanRunCommands: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
	}
	if err := vault.WriteEntry(vaultDir, "allowed/foo", &vault.Entry{Data: map[string]any{"other": "inside"}}, identity); err != nil {
		t.Fatalf("write dotted resolver candidate: %v", err)
	}
	if err := vault.WriteEntry(vaultDir, "allowed/foo.bar", &vault.Entry{Data: map[string]any{"token": "outside"}}, identity); err != nil {
		t.Fatalf("write dotted bare entry: %v", err)
	}

	inputs := []struct {
		name    string
		phase   string
		profile config.AgentProfile
		args    map[string]any
	}{
		{name: "secret_injection_masks_output", args: map[string]any{
			"command":     []any{"go", "run", "<fixture-child-go-source>"},
			"secret_refs": []any{"op://vault/github/password"}, "env_vars": map[string]any{"PLAIN": "literal-value"}, "timeout": 30,
		}},
		{name: "missing_secret_refs", args: map[string]any{"command": []any{"true"}}},
		{name: "wrong_secret_refs_type", args: map[string]any{"command": []any{"true"}, "secret_refs": "op://vault/github/password"}},
		{name: "duplicate_generated_name", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/github/password", "op://vault/github/password"}}},
		{name: "missing_entry", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/missing/password"}}},
		{name: "missing_field", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/github/missing"}}},
		{name: "denied_environment_key", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{}, "env_vars": map[string]any{"LD_PRELOAD": "fixture"}}},
		{name: "can_run_commands_denied", phase: "authorize", profile: config.AgentProfile{Name: "fixture-readonly", AllowedPaths: []string{"*"}, CanRunCommands: config.BoolPtr(false), ApprovalMode: config.StrPtr("none")}, args: map[string]any{"command": []any{"true"}, "secret_refs": []any{}}},
		{name: "executable_allowlist_denied", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{}}},
		{name: "reference_scope_denied", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/github/password"}}},
		{name: "dotted_resolution_scope_denied", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/allowed/foo/bar"}}},
		{name: "approval_mode_denied", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{}}},
		{name: "timeout_protocol_error", args: map[string]any{"command": []any{"<fixture-timeout-child>"}, "secret_refs": []any{}, "env_vars": map[string]any{"SYMAIRA_EXECUTE_SECRET_TIMEOUT_CHILD": "1"}, "timeout": 1}},
	}

	fixture := executeWithSecretFixture{SchemaVersion: 1, UnicodeNameDigest: goUnicodeNameDigest(), Oracle: executeWithSecretOracle{
		Commit: executeWithSecretOracleCommit, CommitSHA: provenanceResult.CommitSHA,
		SourceFiles: executeWithSecretOracleSources, SourceDigest: provenanceResult.SourceDigest,
		GeneratorFiles: []string{
			"internal/mcp/server/approval_test.go",
			"internal/mcp/server/mcpexecutewithsecret_fixture_generator_test.go",
			"internal/mcp/server/tools_run_test.go",
			"internal/mcp/server/tools_test_helpers.go",
			"scripts/rust-port/cmd/execute_secret_child/main.go",
			"scripts/rust-port/cmd/execute_secret_provenance/main.go",
			"scripts/rust-port/cmd/execute_secret_unicode/main.go",
			"crates/symvault-mcp/src/go_unicode_15.rs",
		},
		GeneratorDigest: provenanceResult.GeneratorDigest,
	}, NameCases: map[string]string{
		"sharp_s":             generateEnvVarName("ß", "password"),
		"superscript_two":     generateEnvVarName("service²", "password"),
		"letter_number":       generateEnvVarName("serviceⅫ", "password"),
		"combining_uppercase": generateEnvVarName("i\u0307", "password"),
		"greek_simple_upper":  generateEnvVarName("\u1f80", "password"),
		"greek_upper":         generateEnvVarName("\u1f88", "password"),
		"kawi_letter":         generateEnvVarName("\U00011f04", "password"),
		"kawi_digit":          generateEnvVarName("service\U00011f50", ""),
		"nag_mundari_letter":  generateEnvVarName("\U0001e4d0", "password"),
		"han_ext_h_letter":    generateEnvVarName("\U00031350", "password"),
		"leading_digit":       generateEnvVarName("9service", ""),
		"empty":               generateEnvVarName("", ""),
	}, Normalizations: []string{
		"approval_observations: Go's TTY prompt may display synthetic resolved secret values embedded in command arguments; Rust redacts those values as [REDACTED] before constructing approval details.",
	}}
	redactedCommand := redactSecrets([]string{"go", "run", filepath.Join(root, "scripts", "rust-port", "cmd", "execute_secret_child", "main.go")}, map[string]string{"GITHUB_PASSWORD": "testpass123"})
	redactedCommand[2] = "<fixture-child-go-source>"
	fixture.AuditPath = fmt.Sprintf("command=[%s], refs=%v, exit=0", strings.Join(redactedCommand, " "), []string{"op://vault/github/password"})
	for _, tc := range inputs {
		profile := baseProfile
		if tc.name == "can_run_commands_denied" {
			profile = tc.profile
		}
		if tc.name == "executable_allowlist_denied" {
			profile.AllowedExecutables = []string{"echo"}
		}
		if tc.name == "reference_scope_denied" {
			profile.AllowedPaths = []string{"other"}
		}
		if tc.name == "dotted_resolution_scope_denied" {
			profile.AllowedPaths = []string{"allowed/foo"}
		}
		if tc.name == "approval_mode_denied" {
			profile.ApprovalMode = config.StrPtr("deny")
		}
		srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		encodedInput, err := json.Marshal(tc.args)
		if err != nil {
			t.Fatal(err)
		}
		actualArgs := tc.args
		if tc.name == "secret_injection_masks_output" {
			actualArgs = map[string]any{}
			for key, value := range tc.args {
				actualArgs[key] = value
			}
			actualCommand := []any{"go", "run", filepath.Join(root, "scripts", "rust-port", "cmd", "execute_secret_child", "main.go")}
			actualArgs["command"] = actualCommand
		}
		if tc.name == "timeout_protocol_error" {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			actualArgs = map[string]any{}
			for key, value := range tc.args {
				actualArgs[key] = value
			}
			actualArgs["command"] = []any{executable, "-test.run=^TestExecuteWithSecretTimeoutChild$"}
		}
		result, callErr := srv.handleExecuteWithSecret(context.Background(), mcp.CallToolRequest{Arguments: actualArgs})
		output := executeWithSecretResult{}
		if callErr != nil {
			output.Error = callErr.Error()
		}
		if result != nil {
			output.Text, output.IsError = result.Text, result.IsError
			output.Text = normalizeExecuteWithSecretOutput(t, output.Text)
		}
		fixture.Cases = append(fixture.Cases, executeWithSecretFixtureCase{Name: tc.name, Phase: tc.phase, Input: encodedInput, Output: output})
	}
	fixture.Approval = generateExecuteWithSecretApprovalObservations(t, vaultDir, identity)
	content, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "execute-with-secret.json")
	if check {
		old, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(old, content) {
			t.Fatal("execute_with_secret fixture stale; regenerate from pinned Go oracle")
		}
		t.Logf("checked %s (%d bytes)", path, len(content))
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(content))
}

func generateExecuteWithSecretApprovalObservations(t *testing.T, vaultDir string, identity *age.X25519Identity) []executeWithSecretApprovalObservation {
	// Kept as a separate source-bound execution path so the fixture records
	// actual Go TTY, cache, counter, and audit behavior rather than copied rules.
	t.Helper()
	original := openTTYDevice
	defer func() { openTTYDevice = original }()
	observations := make([]executeWithSecretApprovalObservation, 0, 5)
	for _, scenario := range []struct {
		name      string
		responses []string
		rawError  error
	}{
		{name: "granted", responses: []string{"y"}},
		{name: "granted_twice", responses: []string{"y", "y"}},
		{name: "denied", responses: []string{"n"}},
		{name: "remembered", responses: []string{"r"}},
		{name: "helper_error", responses: []string{"y"}, rawError: errors.New("fixture raw failure")},
	} {
		profile := config.AgentProfile{
			Name: "a", AllowedPaths: []string{"*"},
			AllowedExecutables: []string{"true"}, CanRunCommands: config.BoolPtr(true),
			ApprovalMode: config.StrPtr("prompt"), ApprovalTimeout: config.DurationPtr(0),
		}
		srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
		srv.vault.Identity = identity
		if err := srv.auditLog.Close(); err != nil {
			t.Fatalf("close default audit logger: %v", err)
		}
		auditDir := t.TempDir()
		logger, err := audit.New(profile.Name, auditDir, nil)
		if err != nil {
			t.Fatalf("create fixture audit logger: %v", err)
		}
		srv.auditLog = logger
		srv.auditLog.SetSyncMode(true)
		srv.approvalCache = newApprovalCache()

		promptReader, promptWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		var rawCalls, responseIndex int
		observation := executeWithSecretApprovalObservation{Name: scenario.name}
		openTTYDevice = func() (ttyDevice, error) {
			response := ""
			if responseIndex < len(scenario.responses) {
				response = scenario.responses[responseIndex]
			}
			return &mockTTYDevice{
				readString: func() (string, error) { responseIndex++; return response, nil },
				output:     promptWriter,
				raw: func() (func(), error) {
					rawCalls++
					observation.RequestCounters = append(observation.RequestCounters, srv.approvalKeyCounter.Load())
					if scenario.rawError != nil {
						return nil, scenario.rawError
					}
					return func() {}, nil
				},
			}, nil
		}
		args := map[string]any{
			"command":     []any{"true", "testpass123"},
			"secret_refs": []any{"op://vault/github/password"},
			"timeout":     5,
		}
		attempts := 1
		if scenario.name == "remembered" || scenario.name == "granted_twice" {
			attempts = 2
		}
		for index := 0; index < attempts; index++ {
			_, callErr := srv.handleExecuteWithSecret(context.Background(), mcp.CallToolRequest{Arguments: args})
			if callErr == nil {
				observation.AttemptOutcomes = append(observation.AttemptOutcomes, "granted")
				observation.AttemptErrors = append(observation.AttemptErrors, "")
			} else {
				observation.AttemptOutcomes = append(observation.AttemptOutcomes, "error")
				observation.AttemptErrors = append(observation.AttemptErrors, callErr.Error())
			}
		}
		observation.Remembered = srv.approvalCache.isRemembered(approvalCacheKey(profile.Name, "execute_with_secret", ""))
		observation.ApprovalCounter = srv.approvalKeyCounter.Load()
		observation.PromptCount = rawCalls
		if err := promptWriter.Close(); err != nil {
			t.Fatal(err)
		}
		promptBytes, err := io.ReadAll(promptReader)
		_ = promptReader.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(promptBytes), "\n") {
			if strings.Contains(line, "║ Details:") {
				observation.VisibleDetails = append(observation.VisibleDetails, strings.TrimSpace(line))
			}
		}
		if err := srv.auditLog.Close(); err != nil {
			t.Fatal(err)
		}
		auditBytes, err := os.ReadFile(filepath.Join(auditDir, "audit-"+profile.Name+".log"))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(auditBytes)), "\n") {
			if line == "" {
				continue
			}
			var event struct {
				Action string `json:"action"`
				Path   string `json:"path"`
				OK     bool   `json:"ok"`
			}
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal(err)
			}
			observation.Events = append(observation.Events, executeWithSecretApprovalEvent{Action: event.Action, Path: event.Path, OK: event.OK})
		}
		observations = append(observations, observation)
	}
	return observations
}

func goUnicodeNameDigest() string {
	h := fnv.New64a()
	var encoded [4]byte
	for code := uint32(0); code <= 0x10ffff; code++ {
		if code >= 0xd800 && code <= 0xdfff {
			continue
		}
		binary.BigEndian.PutUint32(encoded[:], code)
		_, _ = h.Write(encoded[:])
		_, _ = h.Write([]byte(generateEnvVarName(string(rune(code)), "")))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("%016x", h.Sum64())
}

func TestExecuteWithSecretTimeoutChild(t *testing.T) {
	if os.Getenv("SYMAIRA_EXECUTE_SECRET_TIMEOUT_CHILD") == "1" {
		time.Sleep(5 * time.Second)
	}
}

func normalizeExecuteWithSecretOutput(t *testing.T, text string) string {
	t.Helper()
	if strings.TrimSpace(text) == "" {
		return text
	}
	text = regexp.MustCompile(`DATA_[0-9a-f]{16}`).ReplaceAllString(text, "DATA_FIXTURE")
	var value map[string]any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		return text
	}
	if _, ok := value["duration_ms"]; ok {
		value["duration_ms"] = float64(0)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func executeWithSecretRepoRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture generator path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
