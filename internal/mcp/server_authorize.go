package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/policy"
	"github.com/danieljustus/OpenPass/internal/vault"
)

// requestIDKey is used for storing request IDs in context.
type requestIDKey struct{}

// WithRequestID stores a request ID in the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext extracts the request ID from the context, returning
// empty string if it is not set.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, ok := ctx.Value(requestIDKey{}).(string)
	if !ok {
		return ""
	}
	return id
}

func (s *Server) authorize(ctx context.Context, path string, write bool, approved bool) error {
	if s == nil || s.agent == nil {
		return errors.New("server not initialized")
	}
	if path == "" {
		return errors.New("empty path")
	}

	actionType := "read"
	if write {
		actionType = "write"
	}

	if err := s.checkPolicy(ctx, path, actionType); err != nil {
		return err
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "scope_denied", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return fmt.Errorf("path %q is outside agent scope", path)
	}

	if write && !s.canWrite() {
		s.logAudit(ctx, "write_denied", path, false)
		metrics.RecordAuthDenial("write_denied", s.agent.Name)
		return fmt.Errorf("agent %q cannot write", s.agent.Name)
	}

	if write && s.requiresApproval() && !approved {
		s.logAudit(ctx, "approval_required", path, false)
		metrics.RecordAuthDenial("approval_required", s.agent.Name)
		return fmt.Errorf("write to %q requires approval", path)
	}

	s.logAudit(ctx, actionType, path, approved)
	if write && approved {
		metrics.RecordApproval(s.agent.Name, "granted")
	}
	return nil
}

func (s *Server) checkPolicy(ctx context.Context, path, actionType string) error {
	if s == nil || s.policyEngine == nil || s.agent == nil {
		return nil
	}

	cp := policy.NewContextProvider()
	evalCtx := cp.BuildContext(s.agent.Name, path, actionType, nil)

	start := time.Now()
	result := s.policyEngine.Evaluate(evalCtx)
	elapsed := time.Since(start)

	if elapsed > time.Millisecond {
		metrics.RecordPolicyEvalDuration(elapsed)
	}

	if !result.Matched {
		s.logAudit(ctx, "policy_denied", path, false)
		metrics.RecordAuthDenial("policy_denied", s.agent.Name)
		return fmt.Errorf("policy: no matching rule (default deny)")
	}

	switch result.Action {
	case policy.ActionAllow:
		return nil
	case policy.ActionDeny:
		s.logAudit(ctx, "policy_denied", path, false)
		metrics.RecordAuthDenial("policy_denied", s.agent.Name)
		return fmt.Errorf("policy denied by rule %q", result.RuleName)
	case policy.ActionPrompt:
		s.logAudit(ctx, "policy_prompt", path, false)
		metrics.RecordAuthDenial("policy_prompt", s.agent.Name)
		return fmt.Errorf("policy requires approval by rule %q", result.RuleName)
	case policy.ActionRequireBiometry:
		s.logAudit(ctx, "policy_biometry", path, false)
		metrics.RecordAuthDenial("policy_biometry", s.agent.Name)
		return fmt.Errorf("policy requires biometry by rule %q", result.RuleName)
	default:
		return nil
	}
}

func (s *Server) logAudit(ctx context.Context, action, path string, ok bool) {
	if s == nil || s.auditLog == nil {
		return
	}
	reason := ""
	if !ok {
		reason = action // action IS the reason when denied (e.g., "scope_denied", "write_denied")
	}
	entry := audit.LogEntry{
		Agent:     s.agent.Name,
		Action:    action,
		Path:      path,
		Transport: s.transport,
		OK:        ok,
		Reason:    reason,
		SessionID: s.sessionID,
		RequestID: RequestIDFromContext(ctx),
	}
	if token, ok := TokenFromContext(ctx); ok {
		entry.TokenID = token.ID
	}
	if err := s.auditLog.LogEntry(entry); err != nil {
		slog.Default().Warn("audit log write failed", "err", err)
	}
}

// checkShareAccess checks if the current agent has an approved, non-expired
// share for the given path. Grants with invalid HMAC (tampered/forged) are
// rejected as a security measure. Returns the ShareGrant and true if access
// is granted, or nil and false otherwise.
func (s *Server) checkShareAccess(ctx context.Context, path string) (*ShareGrant, bool) {
	if s.shareStore == nil {
		return nil, false
	}
	grant, ok := s.shareStore.CheckAccess(s.agent.Name, path)
	if !ok {
		return nil, false
	}
	if grant.ExpiresAt != nil && time.Now().After(*grant.ExpiresAt) {
		s.logAuditShare(ctx, "share_expired", path, grant, false)
		return nil, false
	}
	return grant, true
}

func (s *Server) checkScope(path string) bool {
	if s == nil || s.agent == nil {
		return false
	}
	if len(s.agent.AllowedPaths) == 0 {
		return false
	}

	normalizedPath := normalizeScopePath(path)
	for _, allowed := range s.agent.AllowedPaths {
		if allowed == "*" {
			return true
		}
		normalizedAllowed := normalizeScopePath(allowed)
		if normalizedPath == normalizedAllowed {
			return true
		}
		if strings.HasPrefix(normalizedPath, normalizedAllowed+string(os.PathSeparator)) {
			return true
		}
	}

	// Share access override: allow access if there's an active share grant
	if grant, ok := s.checkShareAccess(context.Background(), path); ok {
		s.logAuditShare(context.Background(), "share_grant", path, grant, true)
		return true
	}

	return false
}

func (s *Server) logAuditShare(ctx context.Context, action, path string, grant *ShareGrant, ok bool) {
	if s == nil || s.auditLog == nil {
		return
	}
	entry := audit.LogEntry{
		Agent:       s.agent.Name,
		Action:      action,
		Path:        path,
		Transport:   s.transport,
		OK:          ok,
		ShareID:     grant.ID,
		FromAgent:   grant.FromAgent,
		ToAgent:     grant.ToAgent,
		ShareAction: action,
		SessionID:   s.sessionID,
		RequestID:   RequestIDFromContext(ctx),
	}
	if token, ok := TokenFromContext(ctx); ok {
		entry.TokenID = token.ID
	}
	if err := s.auditLog.LogEntry(entry); err != nil {
		slog.Default().Warn("audit log write failed", "err", err)
	}
}

func (s *Server) canWrite() bool {
	return s != nil && s.agent != nil && s.agent.CanWrite
}

func (s *Server) canRunCommands() bool {
	return s != nil && s.agent != nil && s.agent.CanRunCommands
}

func (s *Server) canManageConfig() bool {
	return s != nil && s.agent != nil && s.agent.CanManageConfig
}

func (s *Server) canUseClipboard() bool {
	return s != nil && s.agent != nil && s.agent.CanUseClipboard
}

func (s *Server) canUseAutotype() bool {
	return s != nil && s.agent != nil && s.agent.CanUseAutotype
}

func (s *Server) canReadValues() bool {
	return s != nil && s.agent != nil && s.agent.CanReadValues
}

func (s *Server) requiresApproval() bool {
	if s == nil || s.agent == nil {
		return false
	}
	mode := s.agent.ApprovalMode
	if mode == "" {
		if s.agent.RequireApproval {
			mode = "prompt"
		} else {
			return false
		}
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

func (s *Server) shouldRedactField(field string) bool {
	if s == nil || s.agent == nil || s.agent.RedactFields == nil {
		return false
	}
	for _, pattern := range s.agent.RedactFields {
		if pattern == field || pattern == "*" {
			return true
		}
		if strings.HasSuffix(pattern, ".*") {
			prefix := strings.TrimSuffix(pattern, ".*")
			if strings.HasPrefix(field, prefix+".") {
				return true
			}
		}
	}
	return false
}

func (s *Server) applySemanticInjectionCheck(text string) (string, error) {
	mode := s.agent.PromptInjectionMode
	if mode == "" || mode == "off" {
		return text, nil
	}
	pattern, found := detectSemanticInjection(text)
	if !found {
		return text, nil
	}
	switch mode {
	case "log-only":
		slog.Warn("semantic prompt injection detected", "pattern", pattern, "agent", s.agent.Name)
		return text, nil
	case "wrap":
		warning := fmt.Sprintf("[SECURITY WARNING: potential prompt injection detected (pattern: %q)]\n", pattern)
		return warning + text, nil
	case "deny":
		return "", fmt.Errorf("access denied: vault content contains potential prompt injection pattern %q", pattern)
	default:
		return text, nil
	}
}

func redactEntry(entry *vault.Entry, redactFields []string) *vault.Entry {
	if entry == nil || redactFields == nil || len(redactFields) == 0 {
		return entry
	}

	redacted := &vault.Entry{
		Data:     make(map[string]any),
		Metadata: entry.Metadata,
	}

	for k, v := range entry.Data {
		redacted.Data[k] = redactValue(k, v, redactFields)
	}

	return redacted
}

func redactValue(field string, value any, redactFields []string) any {
	switch v := value.(type) {
	case map[string]any:
		result := make(map[string]any)
		for k2, v2 := range v {
			nestedField := field + "." + k2
			result[k2] = redactValue(nestedField, v2, redactFields)
		}
		return result
	default:
		for _, pattern := range redactFields {
			if pattern == field || pattern == "*" {
				return "[REDACTED]"
			}
			if strings.HasSuffix(pattern, ".*") {
				prefix := strings.TrimSuffix(pattern, ".*")
				if strings.HasPrefix(field, prefix+".") {
					return "[REDACTED]"
				}
			}
		}
		return value
	}
}

func normalizeScopePath(path string) string {
	cleaned := filepath.Clean(strings.TrimSpace(filepath.FromSlash(path)))
	if cleaned == "." {
		return ""
	}
	return cleaned
}
