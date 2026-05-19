package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

func TestBuildProfile(t *testing.T) {
	profile := buildProfile("test-agent", "standard", "*", "prompt", true)
	if profile.Name != "test-agent" {
		t.Errorf("Name = %q, want %q", profile.Name, "test-agent")
	}
	if *profile.ApprovalMode != "prompt" {
		t.Errorf("ApprovalMode = %q, want %q", *profile.ApprovalMode, "prompt")
	}
	if profile.RequireApproval == nil || !*profile.RequireApproval {
		t.Error("RequireApproval should be true")
	}
}

func TestPromptApprovalMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "default (empty)", input: "\n", expected: "prompt"},
		{name: "choice 1", input: "1\n", expected: "prompt"},
		{name: "choice 2", input: "2\n", expected: "deny"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tc.input))
			result := promptApprovalMode(reader)
			if result != tc.expected {
				t.Errorf("promptApprovalMode() = %q, want %q", result, tc.expected)
			}
		})
	}
}

func TestBuildProfileDefaults(t *testing.T) {
	profile := buildProfile("readonly-agent", "read-only", "bank/*", "deny", false)
	if profile.Name != "readonly-agent" {
		t.Errorf("Name = %q", profile.Name)
	}
	if *profile.ApprovalMode != "deny" {
		t.Errorf("ApprovalMode = %q, want %q", *profile.ApprovalMode, "deny")
	}
	if profile.RequireApproval != nil && *profile.RequireApproval {
		t.Error("RequireApproval should be false")
	}
	if len(profile.AllowedPaths) != 1 || profile.AllowedPaths[0] != "bank/*" {
		t.Errorf("AllowedPaths = %v, want [bank/*]", profile.AllowedPaths)
	}
}

func TestValidateAgentName(t *testing.T) {
	tests := []struct {
		name    string
		agent   string
		wantErr bool
	}{
		{name: "valid", agent: "agent-1", wantErr: false},
		{name: "empty", agent: "   ", wantErr: true},
		{name: "traversal", agent: "../agent", wantErr: true},
		{name: "separator", agent: "group/agent", wantErr: true},
		{name: "dotdot", agent: "agent..name", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAgentName(tt.agent)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAgentName(%q) error = %v, wantErr %v", tt.agent, err, tt.wantErr)
			}
		})
	}
}

func TestSaveAgentConfigCreatesMissingConfig(t *testing.T) {
	vaultDir := t.TempDir()
	profile := buildProfile("agent", "standard", "team/*", "prompt", true)

	if err := saveAgentConfig(vaultDir, "agent", profile); err != nil {
		t.Fatalf("saveAgentConfig() error = %v", err)
	}

	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("Load(config.yaml) error = %v", err)
	}

	got, ok := cfg.Agents["agent"]
	if !ok {
		t.Fatal("saved agent profile missing from config")
	}
	if len(got.AllowedPaths) != 1 || got.AllowedPaths[0] != "team/*" {
		t.Fatalf("AllowedPaths = %v, want [team/*]", got.AllowedPaths)
	}
	if *got.ApprovalMode != "prompt" {
		t.Fatalf("ApprovalMode = %q, want prompt", *got.ApprovalMode)
	}
}

func TestSaveAgentConfigRejectsInvalidAgentName(t *testing.T) {
	err := saveAgentConfig(t.TempDir(), "../agent", buildProfile("bad", "standard", "*", "prompt", true))
	if err == nil {
		t.Fatal("saveAgentConfig() expected error for invalid agent name")
	}
}

func TestWriteAgentTokenFile(t *testing.T) {
	vaultDir := t.TempDir()

	tokenPath, err := writeAgentTokenFile(vaultDir, "agent", "secret-token")
	if err != nil {
		t.Fatalf("writeAgentTokenFile() error = %v", err)
	}

	wantPath := filepath.Join(vaultDir, "mcp-tokens", "agent.token")
	if tokenPath != wantPath {
		t.Fatalf("token path = %q, want %q", tokenPath, wantPath)
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", tokenPath, err)
	}
	if string(data) != "secret-token\n" {
		t.Fatalf("token file contents = %q, want %q", string(data), "secret-token\n")
	}

	if runtime.GOOS != "windows" {
		fileInfo, err := os.Stat(tokenPath)
		if err != nil {
			t.Fatalf("Stat(%q) error = %v", tokenPath, err)
		}
		if fileInfo.Mode().Perm() != 0o600 {
			t.Fatalf("token file mode = %o, want 600", fileInfo.Mode().Perm())
		}

		dirInfo, err := os.Stat(filepath.Dir(tokenPath))
		if err != nil {
			t.Fatalf("Stat(%q) error = %v", filepath.Dir(tokenPath), err)
		}
		if dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf("token dir mode = %o, want 700", dirInfo.Mode().Perm())
		}
	}
}

func TestWriteAgentTokenFileRejectsInvalidAgentName(t *testing.T) {
	_, err := writeAgentTokenFile(t.TempDir(), "../agent", "secret-token")
	if err == nil {
		t.Fatal("writeAgentTokenFile() expected error for invalid agent name")
	}
}

func TestOutputAgentMCPSnippet(t *testing.T) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	t.Cleanup(func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	})

	outputAgentMCPSnippet("agent", "token-value")

	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()

	var stdoutBuf bytes.Buffer
	if _, err := stdoutBuf.ReadFrom(stdoutReader); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	var stderrBuf bytes.Buffer
	if _, err := stderrBuf.ReadFrom(stderrReader); err != nil {
		t.Fatalf("read stderr: %v", err)
	}

	if !strings.Contains(stderrBuf.String(), "generic stdio") {
		t.Fatalf("stderr = %q, want generic stdio label", stderrBuf.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdoutBuf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal stdout: %v", err)
	}

	mcpServers, ok := payload["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("mcpServers missing from payload: %#v", payload)
	}
	openpass, ok := mcpServers["openpass"].(map[string]any)
	if !ok {
		t.Fatalf("openpass server missing from payload: %#v", mcpServers)
	}
	if openpass["command"] != "openpass" {
		t.Fatalf("command = %#v, want openpass", openpass["command"])
	}
}
