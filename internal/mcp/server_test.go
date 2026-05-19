package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/policy"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestNew_NilVault(t *testing.T) {
	_, err := New(nil, "test", "stdio")
	if err == nil {
		t.Fatal("New() expected error for nil vault, got nil")
	}
	if err.Error() != "nil vault" {
		t.Errorf("New() error = %q, want %q", err.Error(), "nil vault")
	}
}

func TestNew_WithConfig(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil server")
	}
	if srv.agent == nil {
		t.Fatal("srv.agent is nil")
	}
	if srv.agent.Name != "test" {
		t.Errorf("agent.Name = %q, want %q", srv.agent.Name, "test")
	}
	_ = srv.Close()
}

func TestNew_LoadConfig(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	if err = vault.Init(dir, identity, cfg); err != nil {
		t.Fatalf("vault.Init() error = %v", err)
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil server")
	}
	_ = srv.Close()
}

func TestNew_EmptyAgentName(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "default-agent",
		Agents: map[string]config.AgentProfile{
			"default-agent": {
				Name:         "default-agent",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(false),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if srv.agent.Name != "default-agent" {
		t.Errorf("agent.Name = %q, want %q", srv.agent.Name, "default-agent")
	}
	_ = srv.Close()
}

func TestNew_UnknownAgentRejected(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "default",
		Agents: map[string]config.AgentProfile{
			"default": {
				Name:         "default",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(false),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	_, err = New(v, "unknown-agent", "stdio")
	if err == nil {
		t.Fatal("New() expected error for unknown agent, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("New() error = %q, want error containing 'not found'", err.Error())
	}
}

func TestNew_UnknownAgentRejected_HTTP(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "default",
		Agents: map[string]config.AgentProfile{
			"default": {
				Name:         "default",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(false),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	_, err = New(v, "unknown-agent", "http")
	if err == nil {
		t.Fatal("New() expected error for unknown agent with http transport, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("New() error = %q, want error containing 'not found'", err.Error())
	}
}

func TestNew_UnknownAgentNoDefault(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "default",
		Agents: map[string]config.AgentProfile{
			"specific": {
				Name:         "specific",
				AllowedPaths: []string{"specific/"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	_, err = New(v, "unknown", "stdio")
	if err == nil {
		t.Fatal("New() expected error for unknown agent with no default, got nil")
	}
}

func TestBuild(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_ = srv.Close()
}

func TestCheckScope(t *testing.T) {
	srv := &Server{
		agent: &config.AgentProfile{
			Name:         "test",
			AllowedPaths: []string{"work/", "personal/"},
		},
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"work/entry", true},
		{"personal/entry", true},
		{"work/sub/path", true},
		{"other/entry", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := srv.checkScope(tt.path)
			if result != tt.expected {
				t.Errorf("checkScope(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestCheckScope_StarPath(t *testing.T) {
	srv := &Server{
		agent: &config.AgentProfile{
			Name:         "test",
			AllowedPaths: []string{"*"},
		},
	}

	if !srv.checkScope("anything/at/all") {
		t.Error("checkScope() with * should allow any path")
	}
}

func TestCheckScope_EmptyAllowedPaths(t *testing.T) {
	srv := &Server{
		agent: &config.AgentProfile{
			Name:         "test",
			AllowedPaths: []string{},
		},
	}

	if srv.checkScope("any/path") {
		t.Error("checkScope() with empty allowed paths should deny all paths")
	}
}

func TestCheckScope_PrefixPatterns(t *testing.T) {
	srv := &Server{
		agent: &config.AgentProfile{
			Name:         "test",
			AllowedPaths: []string{"work"},
		},
	}

	tests := []struct {
		name         string
		path         string
		allowedPaths []string
		expected     bool
	}{
		{
			name:         "simple prefix match",
			allowedPaths: []string{"work"},
			path:         "work/entry",
			expected:     true,
		},
		{
			name:         "no match just because string starts with prefix",
			allowedPaths: []string{"work"},
			path:         "workshop",
			expected:     false,
		},
		{
			name:         "prefix with trailing slash",
			allowedPaths: []string{"work/"},
			path:         "work/entry",
			expected:     true,
		},
		{
			name:         "prefix with slash no match workshop",
			allowedPaths: []string{"work/"},
			path:         "workshop",
			expected:     false,
		},
		{
			name:         "literal star is not glob",
			allowedPaths: []string{"work/*"},
			path:         "work/*/entry",
			expected:     true,
		},
		{
			name:         "star literal prefix no match on plain path",
			allowedPaths: []string{"work/*"},
			path:         "work/entry",
			expected:     false,
		},
		{
			name:         "deep path matches parent prefix",
			allowedPaths: []string{"work/sub"},
			path:         "work/sub/deep",
			expected:     true,
		},
		{
			name:         "exact match is allowed",
			allowedPaths: []string{"work/sub"},
			path:         "work/sub",
			expected:     true,
		},
		{
			name:         "sibling path not allowed",
			allowedPaths: []string{"work/sub"},
			path:         "work/other",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv.agent.AllowedPaths = tt.allowedPaths
			result := srv.checkScope(tt.path)
			if result != tt.expected {
				t.Errorf("checkScope(%q) with allowedPaths=%v = %v, want %v",
					tt.path, tt.allowedPaths, result, tt.expected)
			}
		})
	}
}

func TestCheckScope_NilServer(t *testing.T) {
	var srv *Server
	if srv.checkScope("any/path") {
		t.Error("checkScope() on nil server should return false")
	}
}

func TestCheckScope_NilAgent(t *testing.T) {
	srv := &Server{
		agent: nil,
	}
	if srv.checkScope("any/path") {
		t.Error("checkScope() on server with nil agent should return false")
	}
}

func TestNormalizeScopePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	tests := []struct {
		input    string
		expected string
	}{
		{"work/", "work"},
		{"work", "work"},
		{"/work/", "/work"},
		{".", ""},
		{"", ""},
		{"  work  ", "work"},
		{"work/sub/path", "work/sub/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeScopePath(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeScopePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCanWrite(t *testing.T) {
	tests := []struct {
		agent    *config.AgentProfile
		name     string
		expected bool
	}{
		{name: "nil agent", agent: nil, expected: false},
		{name: "can write", agent: &config.AgentProfile{CanWrite: config.BoolPtr(true)}, expected: true},
		{name: "cannot write", agent: &config.AgentProfile{CanWrite: config.BoolPtr(false)}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{agent: tt.agent}
			if srv.canWrite() != tt.expected {
				t.Errorf("canWrite() = %v, want %v", srv.canWrite(), tt.expected)
			}
		})
	}
}

func TestRequiresApproval(t *testing.T) {
	tests := []struct {
		agent    *config.AgentProfile
		name     string
		expected bool
	}{
		{name: "nil agent", agent: nil, expected: false},
		{name: "mode none", agent: &config.AgentProfile{ApprovalMode: config.StrPtr("none")}, expected: false},
		{name: "mode deny", agent: &config.AgentProfile{ApprovalMode: config.StrPtr("deny")}, expected: true},
		{name: "mode prompt", agent: &config.AgentProfile{ApprovalMode: config.StrPtr("prompt")}, expected: true},
		{name: "mode empty with RequireApproval true", agent: &config.AgentProfile{ApprovalMode: config.StrPtr(""), RequireApproval: config.BoolPtr(true)}, expected: true},
		{name: "mode empty with RequireApproval false", agent: &config.AgentProfile{ApprovalMode: config.StrPtr(""), RequireApproval: config.BoolPtr(false)}, expected: false},
		{name: "unknown mode", agent: &config.AgentProfile{ApprovalMode: config.StrPtr("unknown")}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{agent: tt.agent}
			if srv.requiresApproval() != tt.expected {
				t.Errorf("requiresApproval() = %v, want %v", srv.requiresApproval(), tt.expected)
			}
		})
	}
}

func TestServer_Close(t *testing.T) {
	srv := &Server{}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestServer_Close_NilAuditLog(t *testing.T) {
	srv := &Server{auditLog: nil}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestServer_LogAudit(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	srv.logAudit(context.Background(), "test", "test/path", true)
	_ = srv.Close()
}

func TestServer_LogAudit_NilServer(t *testing.T) {
	var srv *Server
	srv.logAudit(context.Background(), "test", "test/path", true)
}

func TestServer_LogAudit_NilAgent(t *testing.T) {
	srv := &Server{agent: nil}
	srv.logAudit(context.Background(), "test", "test/path", true)
}

func TestAuthorize(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"work/"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	err = srv.authorize(context.Background(), "work/entry", false, false)
	if err != nil {
		t.Errorf("authorize() unexpected error: %v", err)
	}
}

func TestAuthorize_NilServer(t *testing.T) {
	var srv *Server
	err := srv.authorize(context.Background(), "work/entry", false, false)
	if err == nil {
		t.Error("authorize() expected error for nil server")
	}
}

func TestAuthorize_EmptyPath(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", t.TempDir())
	defer func() { _ = srv.Close() }()

	err := srv.authorize(context.Background(), "", false, false)
	if err == nil {
		t.Error("authorize() expected error for empty path")
	}
}

func TestAuthorize_WriteWithoutPermission(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", t.TempDir())
	defer func() { _ = srv.Close() }()

	err := srv.authorize(context.Background(), "work/entry", true, false)
	if err == nil {
		t.Error("authorize() expected error for write without permission")
	}
}

func TestAuthorize_WriteWithApprovalDeny(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("deny"),
	}, "stdio", t.TempDir())
	defer func() { _ = srv.Close() }()

	err := srv.authorize(context.Background(), "work/entry", true, false)
	if err == nil {
		t.Error("authorize() expected error for write with approval deny")
	}
}

func TestAuthorize_WriteWithApprovalButNotApproved(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("deny"),
	}, "stdio", t.TempDir())
	defer func() { _ = srv.Close() }()

	err := srv.authorize(context.Background(), "work/entry", true, false)
	if err == nil {
		t.Error("authorize() expected error when approval required but not approved")
	}
}

func TestNew_VaultConfigUnavailable(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	v := &vault.Vault{
		Dir:      "",
		Identity: identity,
		Config:   nil,
	}

	_, err = New(v, "test", "stdio")
	if err == nil {
		t.Fatal("New() expected error for vault with nil config and empty dir, got nil")
	}
	if err.Error() != "vault config unavailable" {
		t.Errorf("New() error = %q, want %q", err.Error(), "vault config unavailable")
	}
}

func TestExecuteTool_ParseError(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	args := json.RawMessage(`{invalid json}`)
	_, err := srv.executeTool(context.Background(), "list_entries", args)
	if err == nil {
		t.Fatal("executeTool() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse arguments") {
		t.Fatalf("executeTool() error = %v, want 'parse arguments'", err)
	}
}

func TestExecuteTool_FindEntries(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"query": "test"}`)
	result, err := srv.executeTool(context.Background(), "find_entries", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
}

func TestExecuteTool_SetEntryField(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"path": "github", "field": "password", "value": "StrongP@ssw0rd123"}`)
	result, err := srv.executeTool(context.Background(), "set_entry_field", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
	if result["isError"] == true {
		t.Errorf("expected no error, got isError=true: %s", content[0]["text"])
	}
}

func TestExecuteTool_GeneratePassword_Server(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	args := json.RawMessage(`{}`)
	result, err := srv.executeTool(context.Background(), "generate_password", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
}

func TestExecuteTool_OpenpassDelete(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"path": "github"}`)
	result, err := srv.executeTool(context.Background(), "openpass_delete", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
	if result["isError"] == true {
		t.Errorf("expected no error, got isError=true: %s", content[0]["text"])
	}
}

func TestExecuteTool_DeleteEntryCanonicalName(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"path": "github"}`)
	result, err := srv.executeTool(context.Background(), "delete_entry", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
	if result["isError"] == true {
		t.Fatalf("expected no error, got result: %#v", result)
	}
}

func TestExecuteTool_Health(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	result, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
	if result["isError"] == true {
		t.Fatalf("expected no error, got result: %#v", result)
	}
}

func TestExecuteTool_HandlerError(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"path": "nonexistent"}`)
	result, err := srv.executeTool(context.Background(), "get_entry", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
	if result["isError"] != true {
		t.Fatalf("executeTool() expected tool error result, got %#v", result)
	}
}

func TestServeStdio(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_ = srv.Close()
}

func TestServer_Authorize_ReadsCorrectly(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"work/", "work/sub/"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	if !srv.checkScope("work/entry") {
		t.Error("checkScope(work/entry) = false, want true")
	}
	if !srv.checkScope("work/sub/deep/path") {
		t.Error("checkScope(work/sub/deep/path) = false, want true")
	}
	if srv.checkScope("other/path") {
		t.Error("checkScope(other/path) = true, want false")
	}
}

func TestServer_Authorization_AuditLogging(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(false),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	err = srv.authorize(context.Background(), "test", true, true)
	if err == nil {
		t.Error("authorize() should fail when agent cannot write")
	}

	auditFile := filepath.Join(dir, "audit.log")
	if _, err := os.Stat(auditFile); err == nil {
		t.Log("Audit log created")
	}
}

func TestShouldRedactField(t *testing.T) {
	tests := []struct {
		name         string
		agent        *config.AgentProfile
		field        string
		shouldRedact bool
	}{
		{
			name:         "nil agent returns false",
			agent:        nil,
			field:        "totp.secret",
			shouldRedact: false,
		},
		{
			name:         "nil redact fields returns false",
			agent:        &config.AgentProfile{RedactFields: nil},
			field:        "totp.secret",
			shouldRedact: false,
		},
		{
			name:         "empty redact fields returns false",
			agent:        &config.AgentProfile{RedactFields: []string{}},
			field:        "totp.secret",
			shouldRedact: false,
		},
		{
			name:         "exact match returns true",
			agent:        &config.AgentProfile{RedactFields: []string{"totp.secret"}},
			field:        "totp.secret",
			shouldRedact: true,
		},
		{
			name:         "non-matching field returns false",
			agent:        &config.AgentProfile{RedactFields: []string{"totp.secret"}},
			field:        "password",
			shouldRedact: false,
		},
		{
			name:         "wildcard matches all",
			agent:        &config.AgentProfile{RedactFields: []string{"*"}},
			field:        "anything",
			shouldRedact: true,
		},
		{
			name:         "prefix wildcard matches nested",
			agent:        &config.AgentProfile{RedactFields: []string{"totp.*"}},
			field:        "totp.secret",
			shouldRedact: true,
		},
		{
			name:         "prefix wildcard does not match sibling",
			agent:        &config.AgentProfile{RedactFields: []string{"totp.*"}},
			field:        "password",
			shouldRedact: false,
		},
		{
			name:         "multiple patterns",
			agent:        &config.AgentProfile{RedactFields: []string{"password", "totp.secret", "api.key"}},
			field:        "password",
			shouldRedact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{agent: tt.agent}
			result := srv.shouldRedactField(tt.field)
			if result != tt.shouldRedact {
				t.Errorf("shouldRedactField(%q) = %v, want %v", tt.field, result, tt.shouldRedact)
			}
		})
	}
}

func TestRedactEntry(t *testing.T) {
	tests := []struct {
		entry          *vault.Entry
		redactedFields map[string]bool
		name           string
		redactFields   []string
		nilResult      bool
	}{
		{
			name:         "nil entry returns nil",
			entry:        nil,
			redactFields: []string{"totp.secret"},
			nilResult:    true,
		},
		{
			name:           "nil redact fields returns original",
			entry:          &vault.Entry{Data: map[string]any{"password": "secret123"}},
			redactFields:   nil,
			redactedFields: map[string]bool{},
		},
		{
			name:           "empty redact fields returns original",
			entry:          &vault.Entry{Data: map[string]any{"password": "secret123"}},
			redactFields:   []string{},
			redactedFields: map[string]bool{},
		},
		{
			name:           "exact field redaction",
			entry:          &vault.Entry{Data: map[string]any{"password": "secret123", "username": "user"}},
			redactFields:   []string{"password"},
			redactedFields: map[string]bool{"password": true, "username": false},
		},
		{
			name:           "wildcard redaction",
			entry:          &vault.Entry{Data: map[string]any{"password": "secret123", "api_key": "key123"}},
			redactFields:   []string{"*"},
			redactedFields: map[string]bool{"password": true, "api_key": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactEntry(tt.entry, tt.redactFields)
			if tt.nilResult {
				if result != nil {
					t.Errorf("redactEntry() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("redactEntry() = nil")
			}
			for field, shouldBeRedacted := range tt.redactedFields {
				got, ok := result.Data[field]
				if !ok {
					t.Errorf("redactEntry() missing field %q", field)
					continue
				}
				if shouldBeRedacted && got != "[REDACTED]" {
					t.Errorf("redactEntry()[%q] = %v, want [REDACTED]", field, got)
				}
				if !shouldBeRedacted && got == "[REDACTED]" {
					t.Errorf("redactEntry()[%q] = [REDACTED], want original value", field)
				}
			}
		})
	}
}

func TestRedactValue(t *testing.T) {
	tests := []struct {
		name           string
		field          string
		value          any
		redactFields   []string
		expectRedacted bool
	}{
		{
			name:           "non-matching field returns original",
			field:          "username",
			value:          "user123",
			redactFields:   []string{"password"},
			expectRedacted: false,
		},
		{
			name:           "matching field returns REDACTED",
			field:          "password",
			value:          "secret",
			redactFields:   []string{"password"},
			expectRedacted: true,
		},
		{
			name:           "wildcard redaction",
			field:          "password",
			value:          "secret123",
			redactFields:   []string{"*"},
			expectRedacted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactValue(tt.field, tt.value, tt.redactFields)
			if tt.expectRedacted && result != "[REDACTED]" {
				t.Errorf("redactValue(%q, _, %v) = %v, want [REDACTED]", tt.field, tt.redactFields, result)
			}
			if !tt.expectRedacted && result == "[REDACTED]" {
				t.Errorf("redactValue(%q, _, %v) = [REDACTED], want original", tt.field, tt.redactFields)
			}
		})
	}
}

func TestRedactValue_NestedMap(t *testing.T) {
	nestedValue := map[string]any{
		"secret": "hidden",
		"public": "visible",
	}

	result := redactValue("data", nestedValue, []string{"data.secret"})
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("redactValue() returned %T, want map[string]any", result)
	}
	if resultMap["secret"] != "[REDACTED]" {
		t.Errorf("data.secret = %v, want [REDACTED]", resultMap["secret"])
	}
	if resultMap["public"] != "visible" {
		t.Errorf("data.public = %v, want visible", resultMap["public"])
	}
}

func TestRedactValue_NestedMapWildcard(t *testing.T) {
	nestedValue := map[string]any{
		"secret": "hidden",
		"public": "visible",
	}

	result := redactValue("data", nestedValue, []string{"data.*"})
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("redactValue() returned %T, want map[string]any", result)
	}
	if resultMap["secret"] != "[REDACTED]" {
		t.Errorf("data.secret = %v, want [REDACTED]", resultMap["secret"])
	}
	if resultMap["public"] != "[REDACTED]" {
		t.Errorf("data.public = %v, want [REDACTED]", resultMap["public"])
	}
}

func TestCheckPolicy_AllowsWhenNoEngine(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	err := srv.checkPolicy(context.Background(), "test/path", "read")
	if err != nil {
		t.Errorf("checkPolicy() unexpected error: %v", err)
	}
}

func TestCheckPolicy_DeniesByRule(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	p := &policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				Name:       "deny all",
				Priority:   100,
				Conditions: policy.Conditions{AgentID: "test"},
				Action:     policy.ActionDeny,
			},
		},
	}
	srv.policyEngine = policy.NewEngine([]*policy.Policy{p})

	err := srv.checkPolicy(context.Background(), "test/path", "read")
	if err == nil {
		t.Fatal("checkPolicy() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "policy denied") {
		t.Errorf("checkPolicy() error = %v, want 'policy denied'", err)
	}
}

func TestCheckPolicy_AllowsByRule(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	p := &policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				Name:       "allow test",
				Priority:   100,
				Conditions: policy.Conditions{AgentID: "test"},
				Action:     policy.ActionAllow,
			},
		},
	}
	srv.policyEngine = policy.NewEngine([]*policy.Policy{p})

	err := srv.checkPolicy(context.Background(), "test/path", "read")
	if err != nil {
		t.Errorf("checkPolicy() unexpected error: %v", err)
	}
}

func TestCheckPolicy_RequiresBiometry(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	p := &policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				Name:       "require biometry",
				Priority:   100,
				Conditions: policy.Conditions{AgentID: "test"},
				Action:     policy.ActionRequireBiometry,
			},
		},
	}
	srv.policyEngine = policy.NewEngine([]*policy.Policy{p})

	err := srv.checkPolicy(context.Background(), "test/path", "read")
	if err == nil {
		t.Fatal("checkPolicy() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "biometry") {
		t.Errorf("checkPolicy() error = %v, want 'biometry'", err)
	}
}

func TestCheckPolicy_Prompt(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	p := &policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				Name:       "prompt",
				Priority:   100,
				Conditions: policy.Conditions{AgentID: "test"},
				Action:     policy.ActionPrompt,
			},
		},
	}
	srv.policyEngine = policy.NewEngine([]*policy.Policy{p})

	err := srv.checkPolicy(context.Background(), "test/path", "read")
	if err == nil {
		t.Fatal("checkPolicy() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "approval") {
		t.Errorf("checkPolicy() error = %v, want 'approval'", err)
	}
}
