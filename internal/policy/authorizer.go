package policy

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/authguard"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
)

// Authorizer defines the interface for authorization checks.
type Authorizer interface {
	// Authorize checks if the given path is authorized for the specified action.
	// Returns nil if authorized, error otherwise.
	Authorize(ctx context.Context, path string, write bool, approved bool) error

	// CheckScope checks if the path is within the allowed scope.
	CheckScope(path string) bool

	// CanWrite returns true if write operations are allowed.
	CanWrite() bool

	// RequiresApproval returns true if write operations require approval.
	RequiresApproval() bool
}

// AuthorizerConfig holds configuration for the authorizer.
type AuthorizerConfig struct {
	AgentName           string
	AllowedPaths        []string
	CanWrite            bool
	ApprovalMode        string
	PromptInjectionMode string
	RedactFields        []string
}

// AuthorizerOption is a functional option for configuring the authorizer.
type AuthorizerOption func(*authorizerImpl)

// WithPolicyEngine sets the policy engine for the authorizer.
func WithPolicyEngine(engine *Engine) AuthorizerOption {
	return func(a *authorizerImpl) {
		a.policyEngine = engine
	}
}

// WithAuditLog sets the audit log for the authorizer.
func WithAuditLog(log *audit.Logger) AuthorizerOption {
	return func(a *authorizerImpl) {
		a.auditLog = log
	}
}

// WithShareStore sets the share store for the authorizer.
func WithShareStore(store ShareStore) AuthorizerOption {
	return func(a *authorizerImpl) {
		a.shareStore = store
	}
}

// ShareStore defines the interface for share access checking.
type ShareStore interface {
	CheckAccess(agentName, path string) (*mcp.ShareGrant, bool)
}

// authorizerImpl implements the Authorizer interface.
type authorizerImpl struct {
	config       AuthorizerConfig
	policyEngine *Engine
	auditLog     *audit.Logger
	shareStore   ShareStore
}

// NewAuthorizer creates a new Authorizer with the given configuration and options.
func NewAuthorizer(config AuthorizerConfig, opts ...AuthorizerOption) Authorizer {
	a := &authorizerImpl{
		config: config,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

const (
	actionRead  = "read"
	actionWrite = "write"
)

func (a *authorizerImpl) Authorize(ctx context.Context, path string, write bool, approved bool) error {
	if path == "" {
		return errors.New("empty path")
	}

	actionType := actionRead
	if write {
		actionType = actionWrite
	}

	if err := a.checkPolicy(ctx, path, actionType); err != nil {
		return err
	}

	if !a.CheckScope(path) {
		a.logAudit(ctx, "scope_denied", path, false)
		metrics.RecordAuthDenial("scope_denied", a.config.AgentName)
		return fmt.Errorf("path %q is outside agent scope", path)
	}

	if write && !a.CanWrite() {
		a.logAudit(ctx, "write_denied", path, false)
		metrics.RecordAuthDenial("write_denied", a.config.AgentName)
		return fmt.Errorf("agent %q cannot write", a.config.AgentName)
	}

	if write && a.RequiresApproval() && !approved {
		a.logAudit(ctx, "approval_required", path, false)
		metrics.RecordAuthDenial("approval_required", a.config.AgentName)
		return fmt.Errorf("write to %q requires approval", path)
	}

	a.logAudit(ctx, actionType, path, approved)
	if write && approved {
		metrics.RecordApproval(a.config.AgentName, "granted")
	}
	return nil
}

func (a *authorizerImpl) checkPolicy(ctx context.Context, path, actionType string) error {
	if a.policyEngine == nil {
		return nil
	}

	cp := NewContextProvider()
	evalCtx := cp.BuildContext(a.config.AgentName, path, actionType, nil)

	start := time.Now()
	result := a.policyEngine.Evaluate(evalCtx)
	elapsed := time.Since(start)

	if elapsed > time.Millisecond {
		metrics.RecordPolicyEvalDuration(elapsed)
	}

	if !result.Matched {
		a.logAudit(ctx, "policy_denied", path, false)
		metrics.RecordAuthDenial("policy_denied", a.config.AgentName)
		return fmt.Errorf("policy: no matching rule (default deny)")
	}

	switch result.Action {
	case ActionAllow:
		return nil
	case ActionDeny:
		a.logAudit(ctx, "policy_denied", path, false)
		metrics.RecordAuthDenial("policy_denied", a.config.AgentName)
		return fmt.Errorf("policy denied by rule %q", result.RuleName)
	case ActionPrompt:
		a.logAudit(ctx, "policy_prompt", path, false)
		metrics.RecordAuthDenial("policy_prompt", a.config.AgentName)
		return fmt.Errorf("policy requires approval by rule %q", result.RuleName)
	case ActionRequireBiometry:
		a.logAudit(ctx, "policy_biometry", path, false)
		metrics.RecordAuthDenial("policy_biometry", a.config.AgentName)
		return fmt.Errorf("%w by rule %q", authguard.ErrBiometryRequired, result.RuleName)
	default:
		return nil
	}
}

func (a *authorizerImpl) CheckScope(path string) bool {
	if len(a.config.AllowedPaths) == 0 {
		return false
	}

	normalizedPath := normalizeScopePath(path)
	for _, allowed := range a.config.AllowedPaths {
		if allowed == "*" {
			return true
		}
		normalizedAllowed := normalizeScopePath(allowed)
		if normalizedPath == normalizedAllowed {
			return true
		}
		if strings.HasPrefix(normalizedPath, normalizedAllowed+"/") {
			return true
		}
	}

	// Share access override
	if a.shareStore != nil {
		if grant, ok := a.shareStore.CheckAccess(a.config.AgentName, path); ok {
			if grant.ExpiresAt == nil || !time.Now().After(*grant.ExpiresAt) {
				a.logAuditShare(context.Background(), "share_grant", path, grant, true)
				return true
			}
		}
	}

	return false
}

func (a *authorizerImpl) CanWrite() bool {
	return a.config.CanWrite
}

func (a *authorizerImpl) RequiresApproval() bool {
	mode := a.config.ApprovalMode
	if mode == "" {
		return false
	}
	switch mode {
	case "none":
		return false
	case "deny":
		return true
	case "prompt":
		return true
	default:
		return false
	}
}

func (a *authorizerImpl) logAudit(_ context.Context, action, path string, ok bool) {
	if a.auditLog == nil {
		return
	}
	reason := ""
	if !ok {
		reason = action
	}
	entry := audit.LogEntry{
		Agent:  a.config.AgentName,
		Action: action,
		Path:   path,
		OK:     ok,
		Reason: reason,
	}
	if err := a.auditLog.LogEntry(entry); err != nil {
		// Log error but don't fail the authorization
		_ = err
	}
}

func (a *authorizerImpl) logAuditShare(_ context.Context, action, path string, grant *mcp.ShareGrant, ok bool) {
	if a.auditLog == nil {
		return
	}
	entry := audit.LogEntry{
		Agent:       a.config.AgentName,
		Action:      action,
		Path:        path,
		OK:          ok,
		ShareID:     grant.ID,
		FromAgent:   grant.FromAgent,
		ToAgent:     grant.ToAgent,
		ShareAction: action,
	}
	if err := a.auditLog.LogEntry(entry); err != nil {
		_ = err
	}
}

func normalizeScopePath(p string) string {
	cleaned := path.Clean(strings.TrimSpace(filepath.ToSlash(p)))
	if cleaned == "." {
		return ""
	}
	return cleaned
}
