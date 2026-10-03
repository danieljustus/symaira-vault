package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/clipboard"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

const copyClipboardOracleCommit = "1add155a1ab213cbe8bb42a24254f972cda0ffc1"

type copyClipboardFixture struct {
	SchemaVersion int                        `json:"schema_version"`
	Oracle        copyClipboardOracle        `json:"oracle"`
	ServerName    string                     `json:"server_name"`
	ServerVersion string                     `json:"server_version"`
	Cases         []copyClipboardObservation `json:"cases"`
}

type copyClipboardOracle struct {
	Commit         string   `json:"commit"`
	CommitSHA      string   `json:"commit_sha"`
	SourceFiles    []string `json:"source_files"`
	SourceHash     string   `json:"source_hash"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
}

type copyClipboardScenario struct {
	Name            string
	CanUseClipboard bool
	AllowedPaths    []string
	ApprovalMode    string
	TTY             bool
	ApprovalReply   string
	Path            *string
	ClipboardError  bool
	AutoClear       int
	Repeat          int
	MissingPassword bool
	PasswordIsOther bool
}

type copyClipboardObservation struct {
	Name                   string            `json:"name"`
	CanUseClipboard        bool              `json:"can_use_clipboard"`
	AllowedPaths           []string          `json:"allowed_paths"`
	ApprovalMode           string            `json:"approval_mode"`
	TTY                    bool              `json:"tty"`
	AutoClearDuration      int               `json:"auto_clear_duration"`
	Input                  []string          `json:"input"`
	Output                 []json.RawMessage `json:"output"`
	ClipboardEvents        []string          `json:"clipboard_events"`
	ApprovalReads          int               `json:"approval_reads"`
	ApprovalCounters       []int64           `json:"approval_counters"`
	ApprovalPromptContains []string          `json:"approval_prompt_contains,omitempty"`
}

var copyClipboardSourceFiles = []string{
	"go.mod",
	"go.sum",
	"internal/mcp/server/tools_clipboard.go",
	"internal/mcp/server/tools_get.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/approval.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/protocol.go",
	"internal/mcp/mcptypes.go",
	"internal/vault/service.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
	"internal/config/schema.go",
	"internal/clipboard/interface.go",
	"internal/clipboard/provider.go",
	"internal/clipboard/clipboard.go",
	"internal/clipboard/clipboard_signal_unix.go",
	"internal/clipboard/clipboard_signal_windows.go",
	"internal/clipboard/system_clipboard.go",
	"internal/clipboard/null_clipboard.go",
}

var copyClipboardGeneratorFiles = []string{
	"internal/mcp/server/mcp_copy_clipboard_fixture_generator_test.go",
	"internal/mcp/server/tools_test_helpers.go",
	"internal/mcp/server/approval_test.go",
	"internal/mcp/server/mcpsetentry_fixture_generator_test.go",
	"internal/mcp/server/mcp_execute_api_request_fixture_generator_test.go",
}

func TestGenerateMCPCopyClipboardFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_COPY_CLIPBOARD_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_FIXTURE=1 or SYMAIRA_CHECK_MCP_COPY_CLIPBOARD_FIXTURE=1")
	}
	root := executeAPIRequestRepoRoot(t)
	sourceHash := executeAPIRequestGitDigest(t, root, copyClipboardOracleCommit, copyClipboardSourceFiles)
	if current := executeAPIRequestWorkingDigest(t, root, copyClipboardSourceFiles); current != sourceHash {
		t.Fatalf("Go production sources differ from pinned oracle %s: got %s, want %s", copyClipboardOracleCommit, current, sourceHash)
	}

	path := "github"
	scenarios := []copyClipboardScenario{
		{Name: "success_auto_clear", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: &path, AutoClear: 1},
		{Name: "success_refreshes_auto_clear", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: &path, AutoClear: 1, Repeat: 2},
		{Name: "success_without_auto_clear", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: &path},
		{Name: "approval_prompt_approved", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "prompt", TTY: true, ApprovalReply: "y", Path: &path},
		{Name: "approval_prompt_approved_twice", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "prompt", TTY: true, ApprovalReply: "y", Path: &path, Repeat: 2},
		{Name: "approval_prompt_denied", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "prompt", TTY: true, ApprovalReply: "n", Path: &path},
		{Name: "approval_remembered_cache", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "prompt", TTY: true, ApprovalReply: "r", Path: &path, Repeat: 2},
		{Name: "approval_deny_mode", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "deny", Path: &path},
		{Name: "approval_denied_before_entry_read", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "deny", Path: stringPtr("missing")},
		{Name: "clipboard_capability_denied", AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: &path},
		{Name: "scope_denied", CanUseClipboard: true, AllowedPaths: []string{"allowed/*"}, ApprovalMode: "none", Path: &path},
		{Name: "missing_path", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none"},
		{Name: "entry_not_found", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: stringPtr("missing")},
		{Name: "password_missing", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: stringPtr("missing-password"), MissingPassword: true},
		{Name: "password_wrong_type", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: stringPtr("wrong-type"), PasswordIsOther: true},
		{Name: "clipboard_write_error", CanUseClipboard: true, AllowedPaths: []string{"*"}, ApprovalMode: "none", Path: &path, ClipboardError: true},
	}
	cases := make([]copyClipboardObservation, 0, len(scenarios))
	for _, scenario := range scenarios {
		cases = append(cases, runCopyClipboardScenario(t, scenario))
	}

	fixture := copyClipboardFixture{
		SchemaVersion: 1,
		Oracle: copyClipboardOracle{
			Commit:         "1add155a",
			CommitSHA:      copyClipboardOracleCommit,
			SourceFiles:    copyClipboardSourceFiles,
			SourceHash:     sourceHash,
			GeneratorFiles: copyClipboardGeneratorFiles,
			GeneratorHash:  executeAPIRequestWorkingDigest(t, root, copyClipboardGeneratorFiles),
		},
		ServerName:    "symvault",
		ServerVersion: "0.0.0-copy-clipboard-fixture",
		Cases:         cases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("encode clipboard fixture: %v", err)
	}
	data = append(data, '\n')
	fixturePath := filepath.Join(root, "testdata/port/mcp/copy-clipboard.json")
	if check {
		got, err := os.ReadFile(fixturePath)
		if err != nil {
			t.Fatalf("read clipboard fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("copy_to_clipboard fixture is stale; run with SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(fixturePath, data, 0o644); err != nil {
		t.Fatalf("write clipboard fixture: %v", err)
	}
}

func runCopyClipboardScenario(t *testing.T, scenario copyClipboardScenario) copyClipboardObservation {
	t.Helper()
	root, identity := mcpSetEntryFixtureVault(t)
	if scenario.MissingPassword || scenario.PasswordIsOther {
		password := any(nil)
		if scenario.PasswordIsOther {
			password = 17
		}
		entry := &vault.Entry{Data: map[string]any{"username": "fixture-user"}}
		if scenario.PasswordIsOther {
			entry.Data["password"] = password
		}
		if err := vault.WriteEntry(root, filepath.Base(*scenario.Path), entry, identity); err != nil {
			t.Fatalf("write %s fixture entry: %v", scenario.Name, err)
		}
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "clipboard-fixture",
		Tier:            config.StrPtr("admin"),
		AllowedPaths:    scenario.AllowedPaths,
		CanUseClipboard: config.BoolPtr(scenario.CanUseClipboard),
		ApprovalMode:    config.StrPtr(scenario.ApprovalMode),
	}, "stdio", root)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		Clipboard: &config.ClipboardConfig{AutoClearDuration: scenario.AutoClear},
	}
	srv.approvalCache = newApprovalCache()

	clip := &copyClipboardMock{fail: scenario.ClipboardError}
	clipboard.SetClipboard(clip)
	originalTTY := openTTYDevice
	approvalFile, err := os.CreateTemp(t.TempDir(), "copy-clipboard-approval-*")
	if err != nil {
		t.Fatalf("create approval output: %v", err)
	}
	reads := 0
	approvalCounters := make([]int64, 0)
	if scenario.TTY {
		openTTYDevice = func() (ttyDevice, error) {
			return &mockTTYDevice{
				output: approvalFile,
				raw: func() (func(), error) {
					approvalCounters = append(approvalCounters, srv.approvalKeyCounter.Load())
					return func() {}, nil
				},
				readString: func() (string, error) {
					reads++
					return scenario.ApprovalReply, nil
				},
			}, nil
		}
	} else {
		openTTYDevice = func() (ttyDevice, error) { return nil, errors.New("synthetic no TTY") }
	}
	defer func() {
		clipboard.SetClipboard(nil)
		openTTYDevice = originalTTY
		_ = approvalFile.Close()
	}()

	repeat := scenario.Repeat
	if repeat == 0 {
		repeat = 1
	}
	inputs := make([]string, 0, 2+repeat)
	inputs = append(inputs,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	)
	for index := 0; index < repeat; index++ {
		arguments := map[string]any{}
		if scenario.Path != nil {
			arguments["path"] = *scenario.Path
		}
		encoded, err := json.Marshal(arguments)
		if err != nil {
			t.Fatalf("encode %s args: %v", scenario.Name, err)
		}
		inputs = append(inputs, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"copy_to_clipboard","arguments":%s}}`, index+2, encoded))
	}
	handler := NewProtocolHandler("symvault", "0.0.0-copy-clipboard-fixture", srv)
	outputs := make([]json.RawMessage, 0, len(inputs))
	for _, line := range inputs {
		var message transport.Message
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			t.Fatalf("decode %s input: %v", scenario.Name, err)
		}
		response, err := handler.HandleMessage(context.Background(), &message)
		if err != nil {
			t.Fatalf("dispatch %s: %v", scenario.Name, err)
		}
		if response == nil {
			continue
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("encode %s response: %v", scenario.Name, err)
		}
		if bytes.Contains(encoded, []byte("StrongP@ssw0rd123")) {
			t.Fatalf("%s exposed a synthetic password in protocol output", scenario.Name)
		}
		outputs = append(outputs, encoded)
	}
	if scenario.AutoClear > 0 {
		deadline := time.After(3 * time.Second)
		for {
			if clip.hasClear() {
				break
			}
			select {
			case <-clip.changed:
			case <-deadline:
				t.Fatalf("%s auto-clear did not run", scenario.Name)
			}
		}
	}
	_ = approvalFile.Sync()
	_, _ = approvalFile.Seek(0, 0)
	prompt, _ := os.ReadFile(approvalFile.Name())
	return copyClipboardObservation{
		Name: scenario.Name, CanUseClipboard: scenario.CanUseClipboard,
		AllowedPaths: scenario.AllowedPaths, ApprovalMode: scenario.ApprovalMode,
		TTY: scenario.TTY, AutoClearDuration: scenario.AutoClear,
		Input: inputs, Output: outputs,
		ClipboardEvents: clip.events(), ApprovalReads: reads,
		ApprovalCounters:       approvalCounters,
		ApprovalPromptContains: promptContains(string(prompt)),
	}
}

type copyClipboardMock struct {
	mu      sync.Mutex
	writes  []string
	changed chan struct{}
	fail    bool
}

func (c *copyClipboardMock) Copy(value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.changed == nil {
		c.changed = make(chan struct{}, 4)
	}
	if c.fail {
		return errors.New("synthetic clipboard failure")
	}
	c.writes = append(c.writes, value)
	c.changed <- struct{}{}
	return nil
}

func (c *copyClipboardMock) Read() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		return "", nil
	}
	return c.writes[len(c.writes)-1], nil
}

func (c *copyClipboardMock) events() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]string, len(c.writes))
	for index, value := range c.writes {
		if value == "" {
			result[index] = "clear"
		} else {
			result[index] = "secret"
		}
	}
	return result
}

func (c *copyClipboardMock) hasClear() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, value := range c.writes {
		if value == "" {
			return true
		}
	}
	return false
}

func promptContains(text string) []string {
	var found []string
	for _, marker := range []string{"Risk:      🟠 HIGH", "r=remember", "copy password from github to clipboard"} {
		if strings.Contains(text, marker) {
			found = append(found, marker)
		}
	}
	return found
}

func stringPtr(value string) *string { return &value }
