package server

// PLATFORM-001-FIDELITY: how the real MCP handlers treat a non-positive
// `clipboard.auto_clear_duration`.
//
// copy_to_clipboard and generate_totp (destination clipboard) read
// `s.vault.Config.Clipboard.AutoClearDuration` verbatim: a value <= 0 starts no
// auto-clear, and generate_totp reports the configured number unchanged as
// `clipboard_clears_in`, so a negative value is printed negative. (The CLI
// rejects a negative value when it opens the vault, so this is only reachable
// through a server whose config is set directly; the Rust port keeps the same
// library semantics instead of clamping to 0.) The clipboard is an in-memory
// fake; nothing touches the host.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/clipboard"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

type clipboardAutoClearFixture struct {
	SchemaVersion int                      `json:"schema_version"`
	Oracle        copyClipboardOracle      `json:"oracle"`
	ServerName    string                   `json:"server_name"`
	ServerVersion string                   `json:"server_version"`
	Cases         []clipboardAutoClearCase `json:"cases"`
}

type clipboardAutoClearCase struct {
	Name              string            `json:"name"`
	Tool              string            `json:"tool"`
	AutoClearDuration int               `json:"auto_clear_duration"`
	Input             []string          `json:"input"`
	Output            []json.RawMessage `json:"output"`
	ClipboardEvents   []string          `json:"clipboard_events"`
}

func TestGenerateMCPClipboardAutoClearFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_CLIPBOARD_AUTO_CLEAR_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_CLIPBOARD_AUTO_CLEAR_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_CLIPBOARD_AUTO_CLEAR_FIXTURE=1 or SYMAIRA_CHECK_MCP_CLIPBOARD_AUTO_CLEAR_FIXTURE=1")
	}
	const serverName = "symvault"
	const serverVersion = "0.0.0-clipboard-auto-clear-fixture"
	base := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	calls := map[string]string{
		"copy_to_clipboard": `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"copy_to_clipboard","arguments":{"path":"login"}}}`,
		"generate_totp":     `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generate_totp","arguments":{"path":"totp","destination":"clipboard"}}}`,
	}
	var cases []clipboardAutoClearCase
	for _, duration := range []int{-5, -1, 0} {
		for _, tool := range []string{"copy_to_clipboard", "generate_totp"} {
			vaultDir, identity := mcpGenerateTOTPFixtureVault(t)
			if err := vault.WriteEntry(vaultDir, "login", &vault.Entry{Data: map[string]any{"password": "fixture-password-value"}}, identity); err != nil {
				t.Fatalf("write login fixture entry: %v", err)
			}
			srv := newTestServerWithVault(t, config.AgentProfile{
				Name:            "clipboard-fixture",
				Tier:            config.StrPtr("admin"),
				AllowedPaths:    []string{"*"},
				CanUseClipboard: config.BoolPtr(true),
				CanReadValues:   config.BoolPtr(true),
				ApprovalMode:    config.StrPtr("none"),
			}, "stdio", vaultDir)
			srv.vault.Identity = identity
			srv.vault.Config = &config.Config{Clipboard: &config.ClipboardConfig{AutoClearDuration: duration}}
			clip := &copyClipboardMock{}
			clipboard.SetClipboard(clip)
			handler := NewProtocolHandler(serverName, serverVersion, srv)
			inputs := append(append([]string{}, base...), calls[tool])
			outputs := make([]json.RawMessage, 0, len(inputs))
			for _, line := range inputs {
				var message transport.Message
				if err := json.Unmarshal([]byte(line), &message); err != nil {
					t.Fatalf("decode input: %v", err)
				}
				response, err := handler.HandleMessage(context.Background(), &message)
				if err != nil {
					t.Fatalf("dispatch %s: %v", tool, err)
				}
				if response == nil {
					continue
				}
				encoded, err := json.Marshal(response)
				if err != nil {
					t.Fatalf("encode response: %v", err)
				}
				outputs = append(outputs, encoded)
			}
			// No auto-clear may start for a non-positive duration; give a wrongly
			// started timer time to show up.
			time.Sleep(1500 * time.Millisecond)
			clipboard.SetClipboard(nil)
			cases = append(cases, clipboardAutoClearCase{
				Name:              fmt.Sprintf("%s_auto_clear_%d", tool, duration),
				Tool:              tool,
				AutoClearDuration: duration,
				Input:             inputs,
				Output:            outputs,
				ClipboardEvents:   clip.events(),
			})
		}
	}

	root := executeAPIRequestRepoRoot(t)
	sourcePin := localMCPOracleSourcePin(t, root, copyClipboardOracleCommit, copyClipboardSourceFiles)
	sourceHash := executeAPIRequestWorkingDigest(t, root, copyClipboardSourceFiles)
	generatorFiles := []string{
		"internal/mcp/server/mcp_clipboard_auto_clear_fixture_generator_test.go",
		"internal/mcp/server/mcp_copy_clipboard_fixture_generator_test.go",
		"internal/mcp/server/mcpgeneratetotp_fixture_generator_test.go",
		"internal/mcp/server/mcp_local_fixture_provenance_test.go",
		"internal/mcp/server/tools_test_helpers.go",
	}
	fixture := clipboardAutoClearFixture{
		SchemaVersion: 1,
		Oracle: copyClipboardOracle{
			Commit:          "58d978bb",
			CommitSHA:       copyClipboardOracleCommit,
			SourceFiles:     copyClipboardSourceFiles,
			SourceHash:      sourceHash,
			SourcePinDigest: sourcePin,
			GoVersion:       localMCPOracleGoVersion,
			CorekitVersion:  localMCPOracleCorekitVersion,
			GeneratorFiles:  generatorFiles,
			GeneratorHash:   executeAPIRequestWorkingDigest(t, root, generatorFiles),
		},
		ServerName: serverName, ServerVersion: serverVersion, Cases: cases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "clipboard-auto-clear.json")
	if check {
		got, err := os.ReadFile(path) // #nosec G304 -- fixed fixture path under the repository root
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP clipboard auto-clear fixture is stale; run with SYMAIRA_GENERATE_MCP_CLIPBOARD_AUTO_CLEAR_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
