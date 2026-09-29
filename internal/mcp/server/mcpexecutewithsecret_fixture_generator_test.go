package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

// This fixture executes the production Go secret-injection handler against a
// synthetic vault. It is opt-in so ordinary Go tests never rewrite artifacts.
type executeWithSecretFixture struct {
	SchemaVersion int                            `json:"schema_version"`
	Oracle        executeWithSecretOracle        `json:"oracle"`
	NameCases     map[string]string              `json:"name_cases"`
	AuditPath     string                         `json:"audit_path"`
	Cases         []executeWithSecretFixtureCase `json:"cases"`
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
	Input  json.RawMessage         `json:"input"`
	Output executeWithSecretResult `json:"output"`
}

type executeWithSecretResult struct {
	Text    string `json:"text"`
	IsError bool   `json:"is_error"`
	Error   string `json:"error,omitempty"`
}

const executeWithSecretOracleCommit = "12d8c616ae98b954a9b906e0984af1613ca05fde"

var executeWithSecretOracleSources = []string{
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/command_policy.go",
	"internal/mcp/server/render.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tools_execute_with_secret.go",
	"internal/mcp/server/tools_sanitize.go",
	"internal/mcp/server/tools_run.go",
	"internal/mcp/transport/transport.go",
	"internal/mcp/apitemplates/auth.go",
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

	vaultDir, identity := mockVaultWithEntry(t, "github", map[string]any{"password": "testpass123"})
	profile := config.AgentProfile{
		Name: "execute-with-secret-fixture", AllowedPaths: []string{"*"},
		CanRunCommands: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
	}
	srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
	srv.vault.Identity = identity

	inputs := []struct {
		name string
		args map[string]any
	}{
		{name: "secret_injection_masks_output", args: map[string]any{
			"command":     []any{"go", "run", "<fixture-child-go-source>"},
			"secret_refs": []any{"op://vault/github/password"}, "timeout": 30,
		}},
		{name: "missing_secret_refs", args: map[string]any{"command": []any{"true"}}},
		{name: "wrong_secret_refs_type", args: map[string]any{"command": []any{"true"}, "secret_refs": "op://vault/github/password"}},
		{name: "duplicate_generated_name", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/github/password", "op://vault/github/password"}}},
		{name: "missing_entry", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/missing/password"}}},
		{name: "missing_field", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{"op://vault/github/missing"}}},
		{name: "denied_environment_key", args: map[string]any{"command": []any{"true"}, "secret_refs": []any{}, "env_vars": map[string]any{"LD_PRELOAD": "fixture"}}},
	}

	fixture := executeWithSecretFixture{SchemaVersion: 1, Oracle: executeWithSecretOracle{
		Commit: executeWithSecretOracleCommit, CommitSHA: provenanceResult.CommitSHA,
		SourceFiles: executeWithSecretOracleSources, SourceDigest: provenanceResult.SourceDigest,
		GeneratorFiles: []string{
			"internal/mcp/server/mcpexecutewithsecret_fixture_generator_test.go",
			"scripts/rust-port/cmd/execute_secret_child/main.go",
			"scripts/rust-port/cmd/execute_secret_provenance/main.go",
		},
		GeneratorDigest: provenanceResult.GeneratorDigest,
	}, NameCases: map[string]string{
		"sharp_s":             generateEnvVarName("ß", "password"),
		"superscript_two":     generateEnvVarName("service²", "password"),
		"letter_number":       generateEnvVarName("serviceⅫ", "password"),
		"combining_uppercase": generateEnvVarName("i\u0307", "password"),
		"greek_simple_upper":  generateEnvVarName("\u1f80", "password"),
		"greek_upper":         generateEnvVarName("\u1f88", "password"),
		"leading_digit":       generateEnvVarName("9service", ""),
		"empty":               generateEnvVarName("", ""),
	}}
	redactedCommand := redactSecrets([]string{"go", "run", filepath.Join(root, "scripts", "rust-port", "cmd", "execute_secret_child", "main.go")}, map[string]string{"GITHUB_PASSWORD": "testpass123"})
	redactedCommand[2] = "<fixture-child-go-source>"
	fixture.AuditPath = fmt.Sprintf("command=[%s], refs=%v, exit=0", strings.Join(redactedCommand, " "), []string{"op://vault/github/password"})
	for _, tc := range inputs {
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
		result, callErr := srv.handleExecuteWithSecret(context.Background(), mcp.CallToolRequest{Arguments: actualArgs})
		output := executeWithSecretResult{}
		if callErr != nil {
			output.Error = callErr.Error()
		}
		if result != nil {
			output.Text, output.IsError = result.Text, result.IsError
			output.Text = normalizeExecuteWithSecretOutput(t, output.Text)
		}
		fixture.Cases = append(fixture.Cases, executeWithSecretFixtureCase{Name: tc.name, Input: encodedInput, Output: output})
	}
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
