package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestGenerateDynamicSecret_Gates_CanRunCommands(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   false,
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"provider": "postgres",
		"role":     "readonly",
	})
	_, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for agent without CanRunCommands")
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("error = %q, want contains 'not permitted'", err.Error())
	}
}

func TestGenerateDynamicSecret_Gates_NilDynamicProviders(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanRunCommands: true,
		// DynamicProviders is nil — should deny all
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"provider": "postgres",
		"role":     "readonly",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for nil DynamicProviders")
	}
	if !strings.Contains(result.Text, "not permitted") {
		t.Errorf("result = %q, want contains 'not permitted'", result.Text)
	}
}

func TestGenerateDynamicSecret_Gates_ProviderNotAllowed(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"provider": "aws-sts",
		"role":     "readonly",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for disallowed provider")
	}
	if !strings.Contains(result.Text, "not in the agent's allowed") {
		t.Errorf("result = %q, want contains 'not in the agent's allowed'", result.Text)
	}
}

func TestGenerateDynamicSecret_Gates_RoleNotAllowed(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"provider": "postgres",
		"role":     "superuser",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for disallowed role")
	}
	if !strings.Contains(result.Text, "not allowed for provider") {
		t.Errorf("result = %q, want contains 'not allowed for provider'", result.Text)
	}
}

func TestGenerateDynamicSecret_Gates_WildcardRole(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		DynamicProviders: map[string][]string{"postgres": {"*"}},
	}, "stdio", "")

	// The wildcard "*" role should allow any role past the gate check.
	// The actual generation still fails because no engines are registered
	// (separate issue #24), but the gate should pass (error is from the engine).
	req := testShareRequest(map[string]any{
		"provider": "postgres",
		"role":     "custom-role",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected engine error (not gate error) with wildcard role")
	}
	if strings.Contains(result.Text, "not permitted") || strings.Contains(result.Text, "not in") || strings.Contains(result.Text, "not allowed") {
		t.Errorf("gate rejected wildcard role, but should have passed: %s", result.Text)
	}
}

func TestGenerateDynamicSecret_ContainsRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		role     string
		expected bool
	}{
		{"exact match", []string{"readonly", "admin"}, "readonly", true},
		{"no match", []string{"readonly", "admin"}, "superuser", false},
		{"wildcard", []string{"*"}, "anything", true},
		{"empty list", []string{}, "anything", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containsRole(tc.roles, tc.role)
			if got != tc.expected {
				t.Errorf("containsRole(%v, %q) = %v, want %v", tc.roles, tc.role, got, tc.expected)
			}
		})
	}
}

func TestGenerateDynamicSecret_MissingProvider(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"role": "readonly",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing provider")
	}
}

func TestGenerateDynamicSecret_MissingRole(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"provider": "postgres",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing role")
	}
}

func TestGenerateDynamicSecret_InvalidTTL(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"provider": "postgres",
		"role":     "readonly",
		"ttl":      "not-a-duration",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid TTL")
	}
}

func TestCheckDynamicSecretApproval_Deny(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		ApprovalMode:     "deny",
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")
	err := checkDynamicSecretApproval(srv, "postgres", "readonly", "1h")
	if err == nil {
		t.Fatal("expected error for deny mode")
	}
	if !strings.Contains(err.Error(), "denied by policy") {
		t.Errorf("error = %q, want contains 'denied by policy'", err.Error())
	}
}

func TestCheckDynamicSecretApproval_None(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		ApprovalMode:     "none",
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")
	err := checkDynamicSecretApproval(srv, "postgres", "readonly", "1h")
	if err != nil {
		t.Fatalf("unexpected error for none mode: %v", err)
	}
}

func TestCheckDynamicSecretApproval_NilServer(t *testing.T) {
	err := checkDynamicSecretApproval(nil, "postgres", "readonly", "1h")
	if err == nil {
		t.Fatal("expected error for nil server")
	}
}

func TestCheckDynamicSecretApproval_EmptyModeWithRequireApproval(t *testing.T) {
	// mode="" + RequireApproval=true should treat as "prompt" which requires a TTY.
	// Since no TTY is available, it should fail with a TTY error.
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		RequireApproval:  true,
		ApprovalMode:     "",
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")
	err := checkDynamicSecretApproval(srv, "postgres", "readonly", "1h")
	if err == nil {
		t.Fatal("expected error for empty mode with RequireApproval (no TTY)")
	}
}

func TestCheckDynamicSecretApproval_EmptyModeNoRequireApproval(t *testing.T) {
	// mode="" + RequireApproval=false → treated as "none" → should pass
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		RequireApproval:  false,
		ApprovalMode:     "",
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")
	err := checkDynamicSecretApproval(srv, "postgres", "readonly", "1h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckDynamicSecretApproval_AutoMode(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		ApprovalMode:     "auto",
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")
	err := checkDynamicSecretApproval(srv, "postgres", "readonly", "1h")
	if err != nil {
		t.Fatalf("unexpected error for auto mode: %v", err)
	}
}

func TestGenerateDynamicSecret_Gates_ApprovalDeny(t *testing.T) {
	// ApprovalMode "deny" should cause the gate to reject even though
	// the provider/role are allowed.
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		CanRunCommands:   true,
		ApprovalMode:     "deny",
		DynamicProviders: map[string][]string{"postgres": {"readonly"}},
	}, "stdio", "")

	req := testShareRequest(map[string]any{
		"provider": "postgres",
		"role":     "readonly",
	})
	result, err := srv.handleGenerateDynamicSecret(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for approval deny mode")
	}
	if !strings.Contains(result.Text, "denied") {
		t.Errorf("result = %q, want contains 'denied'", result.Text)
	}
}

// Test that generate_dynamic_secret is in the tools registry.
func TestGenerateDynamicSecret_InToolRegistry(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "http", "")

	tools := toolsListPayload(srv)
	found := false
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "generate_dynamic_secret" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("generate_dynamic_secret not found in tool registry")
	}
}
