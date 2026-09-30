package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

type writeApprovalFixture struct {
	SchemaVersion  int                        `json:"schema_version"`
	Oracle         writeApprovalFixtureOracle `json:"oracle"`
	Normalizations []string                   `json:"normalizations"`
	Cases          []writeApprovalFixtureCase `json:"cases"`
}

type writeApprovalFixtureOracle struct {
	Commit         string   `json:"commit"`
	CommitSHA      string   `json:"commit_sha"`
	SourceFiles    []string `json:"source_files"`
	SourceHash     string   `json:"source_hash"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
}

type writeApprovalFixtureCase struct {
	Name             string         `json:"name"`
	Tool             string         `json:"tool"`
	Arguments        map[string]any `json:"arguments"`
	Response         string         `json:"response,omitempty"`
	ResponseError    string         `json:"response_error,omitempty"`
	RawError         string         `json:"raw_error,omitempty"`
	Text             string         `json:"text"`
	ErrorClass       string         `json:"error_class"`
	IsError          bool           `json:"is_error"`
	Exists           bool           `json:"exists"`
	Username         string         `json:"username,omitempty"`
	AuditActions     []string       `json:"audit_actions"`
	ApprovalCalls    int            `json:"approval_calls"`
	PromptDetails    []string       `json:"prompt_details"`
	SummaryDetails   []string       `json:"summary_details"`
	PromptRisks      []string       `json:"prompt_risks"`
	CanRemember      []bool         `json:"can_remember"`
	SecretsAccessed  []int          `json:"secrets_accessed"`
	PromptTimeoutSec []int64        `json:"prompt_timeout_seconds"`
	PromptText       string         `json:"prompt_text,omitempty"`
}

var writeApprovalSourceFiles = []string{
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/config/config_validate.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/tools_set.go",
	"internal/mcp/server/tools_delete.go",
	"internal/mcp/server/tool_registry.go",
	"internal/secureui/backend.go",
	"internal/secureui/secureui.go",
	"internal/mcp/mcptypes.go",
	"internal/audit/audit.go",
	"internal/audit/export.go",
	"internal/vault/service.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
}

var writeApprovalGeneratorFiles = []string{
	"internal/mcp/server/mcp_write_approval_fixture_generator_test.go",
	"internal/mcp/server/approval_test.go",
	"internal/mcp/server/tools_test_helpers.go",
	"internal/mcp/server/mcpsetentry_fixture_generator_test.go",
}

const writeApprovalOracleCommit = "cfbfd59a8a4580e8547e278ff8b9de6c7e806967"

func TestGenerateMCPWriteApprovalFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_WRITE_APPROVAL_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_WRITE_APPROVAL_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_WRITE_APPROVAL_FIXTURE=1 or SYMAIRA_CHECK_MCP_WRITE_APPROVAL_FIXTURE=1")
	}
	root := writeApprovalRepoRoot(t)
	commitSHA := writeApprovalOracleCommit
	sourceHash := writeApprovalGitSourceHash(t, writeApprovalSourceFiles, commitSHA)
	if workingHash := writeApprovalWorkingSourceHash(t, writeApprovalSourceFiles); workingHash != sourceHash {
		t.Fatalf("Go production sources differ from pinned oracle %s: got %s, want %s", commitSHA, workingHash, sourceHash)
	}

	inputs := []writeApprovalFixtureCase{
		{Name: "set_approved_twice", Tool: "set_entry_field", Arguments: map[string]any{"path": "github", "field": "username", "value": "approved-user"}, Response: "y"},
		{Name: "set_denied_unterminated_summary", Tool: "set_entry_field", Arguments: map[string]any{"path": "github\x1b[31", "field": "username", "value": "blocked-user"}, Response: "n"},
		{Name: "set_denied_unterminated_osc_summary", Tool: "set_entry_field", Arguments: map[string]any{"path": "github\x1b]open", "field": "username", "value": "blocked-user"}, Response: "n"},
		{Name: "set_denied_osc_backslash_summary", Tool: "set_entry_field", Arguments: map[string]any{"path": "github\x1b]hidden\\tail", "field": "username", "value": "blocked-user"}, Response: "n"},
		{Name: "set_denied_byte_controls_summary", Tool: "set_entry_field", Arguments: map[string]any{"path": "git\t\u0085\x7f\x1bXhub", "field": "username", "value": "blocked-user"}, Response: "n"},
		{Name: "set_denied_csi_intermediate_summary", Tool: "set_entry_field", Arguments: map[string]any{"path": "github\x1b[?25l", "field": "username", "value": "blocked-user"}, Response: "n"},
		{Name: "set_denied_csi_unicode_summary", Tool: "set_entry_field", Arguments: map[string]any{"path": "github\x1b[é", "field": "username", "value": "blocked-user"}, Response: "n"},
		{Name: "set_denied_empty_sanitized_field_summary", Tool: "set_entry_field", Arguments: map[string]any{"path": "github", "field": "\x1b[31", "value": "blocked-user"}, Response: "n"},
		{Name: "set_prompt_read_error", Tool: "set_entry_field", Arguments: map[string]any{"path": "github", "field": "username", "value": "blocked-user"}, ResponseError: "fixture read error"},
		{Name: "set_prompt_timeout", Tool: "set_entry_field", Arguments: map[string]any{"path": "github", "field": "username", "value": "blocked-user"}, ResponseError: "__timeout__"},
		{Name: "set_no_tty", Tool: "set_entry_field", Arguments: map[string]any{"path": "github", "field": "username", "value": "blocked-user"}},
		{Name: "delete_approved", Tool: "delete_entry", Arguments: map[string]any{"path": "github"}, Response: "yes"},
		{Name: "delete_denied", Tool: "delete_entry", Arguments: map[string]any{"path": "github"}, Response: "no"},
		{Name: "delete_prompt_raw_error", Tool: "delete_entry", Arguments: map[string]any{"path": "github"}, RawError: "fixture raw error"},
	}
	cases := make([]writeApprovalFixtureCase, 0, len(inputs))
	for _, input := range inputs {
		if input.Name == "set_approved_twice" {
			input = runWriteApprovalFixtureCase(t, input, []string{"y", "y"}, "")
		} else {
			input = runWriteApprovalFixtureCase(t, input, []string{input.Response}, input.ResponseError)
		}
		cases = append(cases, input)
	}

	fixture := writeApprovalFixture{
		SchemaVersion: 1,
		Normalizations: []string{
			"terminal read/raw error wording is compared by approval failure class; Go and Rust terminal backends expose different low-level messages",
			"terminal Directory/Git/Project context rows are omitted; they describe the checkout rather than approval behavior",
		},
		Oracle: writeApprovalFixtureOracle{
			Commit: commitSHA[:8], CommitSHA: commitSHA, SourceFiles: writeApprovalSourceFiles,
			SourceHash: sourceHash, GeneratorFiles: writeApprovalGeneratorFiles,
			GeneratorHash: writeApprovalGeneratorHash(t, writeApprovalGeneratorFiles),
		},
		Cases: cases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal write approval fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "write-tty-approval.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read write approval fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP write approval fixture is stale; run with SYMAIRA_GENERATE_MCP_WRITE_APPROVAL_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func runWriteApprovalFixtureCase(t *testing.T, tc writeApprovalFixtureCase, answers []string, readError string) writeApprovalFixtureCase {
	t.Helper()
	tc.AuditActions = []string{}
	tc.PromptDetails = []string{}
	tc.SummaryDetails = []string{}
	tc.PromptRisks = []string{}
	tc.CanRemember = []bool{}
	tc.SecretsAccessed = []int{}
	tc.PromptTimeoutSec = []int64{}
	vaultDir, identity := mcpSetEntryFixtureVault(t)
	profile := config.AgentProfile{Name: "fixture", AllowedPaths: []string{"*"}, CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("prompt"), ApprovalTimeout: config.DurationPtr(0)}
	srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
	srv.vault.Identity = identity
	_ = srv.auditLog.Close()
	logger, err := audit.New("fixture", vaultDir, identity)
	if err != nil {
		t.Fatalf("create fixture audit logger: %v", err)
	}
	logger.SetSyncMode(true)
	srv.auditLog = logger

	output, err := os.CreateTemp(t.TempDir(), "tty-output-*")
	if err != nil {
		t.Fatalf("create fake TTY output: %v", err)
	}
	defer output.Close()
	reads := 0
	opens := 0
	if tc.Name == "set_no_tty" {
		previous, hadPrevious := os.LookupEnv("SYMVAULT_SECUREUI")
		_ = os.Setenv("SYMVAULT_SECUREUI", "none")
		defer func() {
			if hadPrevious {
				_ = os.Setenv("SYMVAULT_SECUREUI", previous)
			} else {
				_ = os.Unsetenv("SYMVAULT_SECUREUI")
			}
		}()
	}
	original := openTTYDevice
	openTTYDevice = func() (ttyDevice, error) {
		opens++
		if tc.Name == "set_no_tty" {
			return nil, errors.New("no tty available")
		}
		return &mockTTYDevice{
			output: output,
			raw: func() (func(), error) {
				if tc.RawError != "" {
					return nil, errors.New(tc.RawError)
				}
				return func() {}, nil
			},
			readString: func() (string, error) {
				reads++
				if readError != "" {
					if readError == "__timeout__" {
						return "", os.ErrDeadlineExceeded
					}
					return "", errors.New(readError)
				}
				index := reads - 1
				if index >= len(answers) {
					return "", errors.New("missing fake answer")
				}
				return answers[index], nil
			},
		}, nil
	}
	defer func() { openTTYDevice = original }()

	request := mcp.CallToolRequest{Arguments: tc.Arguments}
	var result *mcp.CallToolResult
	switch tc.Tool {
	case "set_entry_field":
		result, err = srv.handleSet(context.Background(), request)
	case "delete_entry":
		result, err = srv.handleDelete(context.Background(), request)
	default:
		t.Fatalf("unsupported fixture tool %q", tc.Tool)
	}
	if err != nil {
		t.Fatalf("%s handler: %v", tc.Name, err)
	}
	if result == nil {
		t.Fatalf("%s returned nil result", tc.Name)
	}
	if result.Text != "" {
		tc.Text = result.Text
	}
	tc.SummaryDetails = append(tc.SummaryDetails, writeApprovalSummary(tc.Tool, tc.Arguments))
	tc.IsError = result.IsError
	if result.IsError {
		switch {
		case strings.Contains(result.Text, "approval failed"):
			tc.ErrorClass = "approval_failed"
		case strings.Contains(result.Text, "denied"):
			tc.ErrorClass = "denied"
		case strings.Contains(result.Text, "no TTY or GUI dialog available"):
			tc.ErrorClass = "no_tty"
		default:
			tc.ErrorClass = "other_error"
		}
	} else {
		tc.ErrorClass = "none"
	}
	logger.Flush()
	events, err := audit.LoadAuditLogFiles("fixture", vaultDir, 0)
	if err != nil {
		t.Fatalf("load %s audit: %v", tc.Name, err)
	}
	tc.AuditActions = make([]string, 0, len(events))
	for _, event := range events {
		tc.AuditActions = append(tc.AuditActions, event.Action)
	}
	if tc.Name == "set_approved_twice" {
		// Re-run the same real handler against the same session and store: a
		// critical write must prompt again and expose the incremented counter.
		repeated, err := srv.handleSet(context.Background(), request)
		if err != nil {
			t.Fatalf("repeat %s handler: %v", tc.Name, err)
		}
		if repeated == nil || repeated.IsError {
			t.Fatalf("repeat %s approval was not granted: %#v", tc.Name, repeated)
		}
		tc.SummaryDetails = append(tc.SummaryDetails, writeApprovalSummary(tc.Tool, tc.Arguments))
		logger.Flush()
		events, err = audit.LoadAuditLogFiles("fixture", vaultDir, 0)
		if err != nil {
			t.Fatalf("reload repeated approval audit: %v", err)
		}
		tc.AuditActions = tc.AuditActions[:0]
		for _, event := range events {
			tc.AuditActions = append(tc.AuditActions, event.Action)
		}
	}
	entry, err := vault.ReadEntry(vaultDir, "github", identity)
	if tc.Tool == "delete_entry" && tc.Name == "delete_approved" {
		tc.Exists = false
	} else if err == nil {
		tc.Exists = true
		tc.Username, _ = entry.Data["username"].(string)
	} else {
		t.Fatalf("read %s fixture state: %v", tc.Name, err)
	}
	if opens > 0 {
		tc.ApprovalCalls = opens / 3 // two TTY probes and one prompt open per approval call
		if _, err := output.Seek(0, 0); err != nil {
			t.Fatalf("seek fake TTY output: %v", err)
		}
		prompt, err := os.ReadFile(output.Name())
		if err != nil {
			t.Fatalf("read fake TTY prompt: %v", err)
		}
		// Checkout context is not part of this approval-seam contract. Keep
		// operation, details, risk, counters, answers and all other bytes.
		tc.PromptText = regexp.MustCompile(`(?m)^║ (Directory|Git|Project):[^\n]*\n`).ReplaceAllString(string(prompt), "")
		if len(prompt) > 0 {
			for _, summary := range tc.SummaryDetails {
				if !strings.Contains(string(prompt), summary) {
					t.Fatalf("%s production prompt did not contain Go summary %q: %s", tc.Name, summary, prompt)
				}
			}
			for _, token := range []string{"CRITICAL", "Operation:", "Details:"} {
				if !strings.Contains(string(prompt), token) {
					t.Fatalf("%s prompt lacks %q: %s", tc.Name, token, prompt)
				}
			}
			// Parse the actual production terminal rendering into the fields Rust's
			// fake seam exposes. This also binds control-character stripping to the
			// real RenderSummary -> buildPrompt path.
			for _, row := range regexp.MustCompile(`║ Details:\s*(.*?)\s*║`).FindAllStringSubmatch(tc.PromptText, -1) {
				tc.PromptDetails = append(tc.PromptDetails, row[1])
			}
			for range regexp.MustCompile(`║ Risk:\s*🔴\s*(CRITICAL)\s*║`).FindAllStringSubmatch(tc.PromptText, -1) {
				tc.PromptRisks = append(tc.PromptRisks, "CRITICAL")
			}
			secretsRows := regexp.MustCompile(`║ Secrets:\s*(\d+) accessed this session\s*║`).FindAllStringSubmatch(tc.PromptText, -1)
			for _, row := range secretsRows {
				var count int
				if _, err := fmt.Sscanf(row[1], "%d", &count); err != nil {
					t.Fatalf("parse secrets counter %q: %v", row[1], err)
				}
				tc.SecretsAccessed = append(tc.SecretsAccessed, count)
			}
			if strings.Contains(tc.PromptText, "(y/n/r, r=remember for session)") {
				t.Fatalf("critical write prompt unexpectedly offered remember: %s", tc.PromptText)
			}
			tc.CanRemember = make([]bool, len(tc.PromptDetails))
			tc.PromptTimeoutSec = make([]int64, len(tc.PromptDetails))
			for i := range tc.PromptDetails {
				tc.PromptTimeoutSec[i] = 30 // Go's default when the profile timeout is zero
			}
		}
	}
	return tc
}

func writeApprovalSummary(tool string, arguments map[string]any) string {
	path, _ := arguments["path"].(string)
	if tool == "set_entry_field" {
		field, _ := arguments["field"].(string)
		return RenderSummary("set field", path, field)
	}
	return RenderSummary("delete entry", path, "")
}

func writeApprovalGitSourceHash(t *testing.T, files []string, commit string) string {
	t.Helper()
	h := sha256.New()
	root := writeApprovalRepoRoot(t)
	for _, name := range files {
		cmd := exec.Command("git", "show", commit+":"+name)
		cmd.Dir = root
		data, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned production source %s at %s: %v", name, commit, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeApprovalGeneratorHash(t *testing.T, files []string) string {
	t.Helper()
	root := writeApprovalRepoRoot(t)
	h := sha256.New()
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read fixture generator input %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeApprovalWorkingSourceHash(t *testing.T, files []string) string {
	t.Helper()
	h := sha256.New()
	root := writeApprovalRepoRoot(t)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read Go production source %s: %v", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeApprovalRepoRoot(t *testing.T) string {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate write approval fixture generator")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(sourcePath), "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
