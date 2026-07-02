package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/authguard"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

// --- NewAuthorizer + option wiring ---

func TestNewAuthorizerDefaults(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AgentName: "a", AllowedPaths: []string{"work/*"}})
	if a == nil {
		t.Fatal("nil authorizer")
	}
	if a.CanWrite() {
		t.Error("CanWrite should be false by default")
	}
	if a.RequiresApproval() {
		t.Error("RequiresApproval should be false with empty mode")
	}
}

func TestNewAuthorizerWithPolicyEngine(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "allow", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionAllow,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AgentName: "a", AllowedPaths: []string{"*"}},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	if err := a.Authorize(context.Background(), "x", false, false); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
}

func TestNewAuthorizerWithOptionsNil(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AgentName: "a", AllowedPaths: []string{"*"}},
		WithPolicyEngine(nil), WithAuditLog(nil), WithShareStore(nil))
	if a == nil {
		t.Fatal("nil authorizer")
	}
}

// --- RequiresApproval modes ---

func TestRequiresApprovalModes(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"", false}, {"none", false}, {"deny", true}, {"prompt", true}, {"unknown", false},
	}
	for _, tt := range tests {
		a := NewAuthorizer(AuthorizerConfig{ApprovalMode: tt.mode})
		if got := a.RequiresApproval(); got != tt.want {
			t.Errorf("mode=%q: RequiresApproval() = %v, want %v", tt.mode, got, tt.want)
		}
	}
}

// --- CheckScope ---

func TestCheckScope(t *testing.T) {
	tests := []struct {
		name   string
		paths  []string
		check  string
		expect bool
	}{
		{"empty returns false", []string{}, "anything", false},
		{"wildcard matches all", []string{"*"}, "anything", true},
		{"exact match", []string{"work/s"}, "work/s", true},
		{"prefix match", []string{"work"}, "work/sub", true},
		{"no match", []string{"work"}, "other/s", false},
		{"dot normalized", []string{"work"}, "./work/s", true},
		{"whitespace trimmed", []string{"work"}, "  work/s  ", true},
		{"multiple paths", []string{"work", "personal"}, "personal/s", true},
		{"prefix no match deeper", []string{"work"}, "work", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAuthorizer(AuthorizerConfig{AllowedPaths: tt.paths})
			if got := a.CheckScope(tt.check); got != tt.expect {
				t.Errorf("CheckScope(%q) = %v, want %v", tt.check, got, tt.expect)
			}
		})
	}
}

// --- normalizeScopePath ---

func TestNormalizeScopePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"work/s", "work/s"}, {"./work/s", "work/s"}, {".", ""}, {"", ""}, {"  x  ", "x"},
	}
	for _, tt := range tests {
		if got := normalizeScopePath(tt.in); got != tt.want {
			t.Errorf("normalizeScopePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// --- Authorize core paths ---

func TestAuthorizeEmptyPath(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}})
	err := a.Authorize(context.Background(), "", false, false)
	if err == nil || err.Error() != "empty path" {
		t.Errorf("expected 'empty path', got: %v", err)
	}
}

func TestAuthorizeReadAllow(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"work"}})
	if err := a.Authorize(context.Background(), "work/s", false, false); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestAuthorizeScopeDenied(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"work/*"}})
	err := a.Authorize(context.Background(), "other/s", false, false)
	if err == nil {
		t.Fatal("expected scope denied error")
	}
}

func TestAuthorizeWriteDenied(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"work/*"}, CanWrite: false})
	err := a.Authorize(context.Background(), "work/s", true, false)
	if err == nil {
		t.Fatal("expected write denied")
	}
}

func TestAuthorizeWriteApprovalRequired(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: true, ApprovalMode: "prompt"})
	err := a.Authorize(context.Background(), "work/s", true, false)
	if err == nil {
		t.Fatal("expected approval required")
	}
}

func TestAuthorizeWriteApproved(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: true, ApprovalMode: "prompt"})
	if err := a.Authorize(context.Background(), "work/s", true, true); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestAuthorizeWriteApprovalNone(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: true, ApprovalMode: "none"})
	if err := a.Authorize(context.Background(), "work/s", true, false); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestAuthorizeWriteDenyMode(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: true, ApprovalMode: "deny"})
	err := a.Authorize(context.Background(), "work/s", true, false)
	if err == nil {
		t.Fatal("expected approval required for deny mode")
	}
}

func TestAuthorizeWriteUnknownMode(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: true, ApprovalMode: "unknown"})
	if err := a.Authorize(context.Background(), "work/s", true, false); err != nil {
		t.Errorf("unknown mode should not require approval: %v", err)
	}
}

// --- Policy engine integration ---

func TestAuthorizePolicyDeny(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "deny", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionDeny,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AllowedPaths: []string{"*"}},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	err := a.Authorize(context.Background(), "x", false, false)
	if err == nil {
		t.Fatal("expected policy deny")
	}
}

func TestAuthorizePolicyPrompt(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "prompt", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionPrompt,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AllowedPaths: []string{"*"}},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	err := a.Authorize(context.Background(), "x", false, false)
	if err == nil {
		t.Fatal("expected policy prompt")
	}
}

func TestAuthorizePolicyBiometry(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "bio", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionRequireBiometry,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AllowedPaths: []string{"*"}},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	err := a.Authorize(context.Background(), "x", false, false)
	if err == nil {
		t.Fatal("expected biometry error")
	}
	if !errors.Is(err, authguard.ErrBiometryRequired) {
		t.Errorf("expected ErrBiometryRequired wrapping, got: %v", err)
	}
}

func TestAuthorizePolicyDefaultDeny(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "other-agent", Priority: 100,
		Conditions: Conditions{AgentID: "other"}, Action: ActionAllow,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AgentName: "me", AllowedPaths: []string{"*"}},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	err := a.Authorize(context.Background(), "x", false, false)
	if err == nil {
		t.Fatal("expected default deny")
	}
}

func TestAuthorizePolicyScopeDeniedAfterAllow(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "allow", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionAllow,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AllowedPaths: []string{"work/*"}},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	err := a.Authorize(context.Background(), "other/s", false, false)
	if err == nil {
		t.Fatal("expected scope denied")
	}
}

func TestAuthorizeWriteDeniedAfterPolicyAllow(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "allow", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionAllow,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: false},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	err := a.Authorize(context.Background(), "x", true, false)
	if err == nil {
		t.Fatal("expected write denied")
	}
}

func TestAuthorizeWriteApprovalRequiredAfterPolicyAllow(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "allow", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionAllow,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: true, ApprovalMode: "prompt"},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	err := a.Authorize(context.Background(), "x", true, false)
	if err == nil {
		t.Fatal("expected approval required")
	}
}

func TestAuthorizeWriteApprovedAfterPolicyAllow(t *testing.T) {
	p := &Policy{Version: "1.0", Rules: []Rule{{
		Name: "allow", Priority: 100,
		Conditions: Conditions{AgentID: "*"}, Action: ActionAllow,
	}}}
	a := NewAuthorizer(
		AuthorizerConfig{AllowedPaths: []string{"*"}, CanWrite: true, ApprovalMode: "prompt"},
		WithPolicyEngine(NewEngine([]*Policy{p})),
	)
	if err := a.Authorize(context.Background(), "x", true, true); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

// --- logAudit / logAuditShare nil logger ---

func TestLogAuditNilLogger(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}})
	impl := a.(*authorizerImpl)
	// Should not panic
	impl.logAudit(context.Background(), "read", "x", true)
	impl.logAudit(context.Background(), "read", "x", false)
}

func TestLogAuditShareNilLogger(t *testing.T) {
	a := NewAuthorizer(AuthorizerConfig{AllowedPaths: []string{"*"}})
	impl := a.(*authorizerImpl)
	// Should not panic
	impl.logAuditShare(context.Background(), "share", "x", &mcp.ShareGrant{
		ID: "g1", FromAgent: "a", ToAgent: "b",
	}, true)
}

// --- ShareStore override ---

type testShareStore struct {
	grant     bool
	expiresAt *time.Time
}

func (s *testShareStore) CheckAccess(agentName, path string) (*mcp.ShareGrant, bool) {
	if !s.grant {
		return nil, false
	}
	return &mcp.ShareGrant{
		ID:        "grant1",
		FromAgent: "other",
		ToAgent:   agentName,
		ExpiresAt: s.expiresAt,
	}, true
}

func TestCheckScopeShareStoreGrant(t *testing.T) {
	a := NewAuthorizer(
		AuthorizerConfig{AgentName: "agent1", AllowedPaths: []string{"restricted/*"}},
		WithShareStore(&testShareStore{grant: true}),
	)
	if !a.CheckScope("shared/s") {
		t.Error("expected share store override to grant access")
	}
}

func TestCheckScopeShareStoreExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	a := NewAuthorizer(
		AuthorizerConfig{AgentName: "agent1", AllowedPaths: []string{"restricted/*"}},
		WithShareStore(&testShareStore{grant: true, expiresAt: &past}),
	)
	if a.CheckScope("shared/s") {
		t.Error("expected expired share to deny access")
	}
}

func TestCheckScopeShareStoreNoGrant(t *testing.T) {
	a := NewAuthorizer(
		AuthorizerConfig{AgentName: "agent1", AllowedPaths: []string{"restricted/*"}},
		WithShareStore(&testShareStore{grant: false}),
	)
	if a.CheckScope("shared/s") {
		t.Error("expected no grant to deny access")
	}
}

func TestCheckScopeShareStoreNil(t *testing.T) {
	a := NewAuthorizer(
		AuthorizerConfig{AgentName: "agent1", AllowedPaths: []string{"restricted/*"}},
	)
	// No share store set — should not panic, just deny
	if a.CheckScope("shared/s") {
		t.Error("expected no share store to deny access")
	}
}
