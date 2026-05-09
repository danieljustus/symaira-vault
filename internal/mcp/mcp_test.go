package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

//nolint:unparam // transport always "stdio" in current test suite
func newTestServer(t *testing.T, profile config.AgentProfile, transport string) *Server {
	t.Helper()

	auditLog, err := audit.New("test", "")
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}

	return &Server{
		vault:     &vault.Vault{},
		agent:     &profile,
		auditLog:  auditLog,
		transport: transport,
	}
}

func TestAuthorizeDeniesWritesWhenAgentCannotWrite(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "claude",
		AllowedPaths: []string{"work/"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio")

	err := srv.authorize(context.Background(), "work/entry", true, true)
	if err == nil {
		t.Fatal("authorize() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "cannot write") {
		t.Fatalf("authorize() error = %v, want cannot write", err)
	}
}

func TestAuthorizeDeniesPathsOutsideAllowedScope(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "claude",
		AllowedPaths: []string{"work/"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio")

	err := srv.authorize(context.Background(), "personal/entry", false, false)
	if err == nil {
		t.Fatal("authorize() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "outside agent scope") {
		t.Fatalf("authorize() error = %v, want outside agent scope", err)
	}
}

func TestAuthorizeRequiresApprovalForWrites(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "claude",
		AllowedPaths: []string{"work/"},
		CanWrite:     true,
		ApprovalMode: "deny",
	}, "stdio")

	err := srv.authorize(context.Background(), "work/entry", true, false)
	if err == nil {
		t.Fatal("authorize() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "approval") {
		t.Fatalf("authorize() error = %v, want approval-related error", err)
	}
}

func TestAuthorizeApprovalModeDenyRejectsWrites(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "untrusted",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "deny",
	}, "stdio")

	err := srv.authorize(context.Background(), "work/entry", true, false)
	if err == nil {
		t.Fatal("authorize() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "approval") {
		t.Fatalf("authorize() error = %v, want approval-related error", err)
	}
}

func TestAuthorizeApprovalModeNoneAllowsWrites(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "trusted",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio")

	err := srv.authorize(context.Background(), "work/entry", true, false)
	if err != nil {
		t.Fatalf("authorize() unexpected error = %v", err)
	}
}

func TestAuthorizeApprovalModePromptDegradesToDenyInStdio(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "semi-trusted",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "prompt",
	}, "stdio")

	err := srv.authorize(context.Background(), "work/entry", true, false)
	if err == nil {
		t.Fatal("authorize() expected error for prompt mode in stdio, got nil")
	}
	if !strings.Contains(err.Error(), "approval") {
		t.Fatalf("authorize() error = %v, want approval-related error", err)
	}
}

func TestNewFallsBackToDefaultProfileForUnknownAgent(t *testing.T) {
	v := &vault.Vault{
		Dir: t.TempDir(),
		Config: &config.Config{
			DefaultAgent: "default",
			Agents: map[string]config.AgentProfile{
				"default": {
					Name:         "default",
					AllowedPaths: []string{"*"},
					CanWrite:     false,
					ApprovalMode: "none",
				},
			},
		},
	}

	_, err := New(v, "unknown-agent", "stdio")
	if err == nil {
		t.Fatal("New() expected error for unknown agent, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("New() error = %q, want error containing 'not found'", err.Error())
	}
}

func TestNewErrorsWhenNoDefaultProfile(t *testing.T) {
	v := &vault.Vault{
		Dir: t.TempDir(),
		Config: &config.Config{
			DefaultAgent: "default",
			Agents: map[string]config.AgentProfile{
				"specific-agent": {
					Name:         "specific-agent",
					AllowedPaths: []string{"*"},
					CanWrite:     true,
					ApprovalMode: "none",
				},
			},
		},
	}

	_, err := New(v, "unknown-agent", "stdio")
	if err == nil {
		t.Fatal("New() error = nil, want error for unknown agent with no default profile")
	}
}

func TestToolActionType(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"set_entry_field", "set"},
		{"secure_input", "set"},
		{"delete_entry", "delete"},
		{"openpass_delete", "delete"},
		{"run_command", "run"},
		{"execute_with_secret", "run"},
		{"list_entries", "list"},
		{"get_entry", "get"},
		{"get_entry_value", "get"},
		{"get_entry_metadata", "get"},
		{"find_entries", "find"},
		{"generate_password", "generate"},
		{"generate_totp", "generate"},
		{"generate_dynamic_secret", "generate"},
		{"generate_template", "generate"},
		{"copy_to_clipboard", "read"},
		{"autotype", "read"},
		{"request_share", "share_request"},
		{"approve_share", "share_approve"},
		{"revoke_share", "share_revoke"},
		{"list_shares", "share_list"},
		{"unknown_tool", "read"},
	}
	for _, tc := range cases {
		got := toolActionType(tc.tool)
		if got != tc.want {
			t.Errorf("toolActionType(%q) = %q, want %q", tc.tool, got, tc.want)
		}
	}
}
