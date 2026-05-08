package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func shareStatusFromString(s string) *ShareStatus {
	if s == "" {
		return nil
	}
	status := ShareStatus(s)
	return &status
}

func (s *Server) handleRequestShare(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	toAgent, err := req.RequireString("to_agent")
	if err != nil {
		s.logAudit(ctx, "share_request", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	path, err := req.RequireString("secret_path")
	if err != nil {
		s.logAudit(ctx, "share_request", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	field := req.GetString("secret_field", "")
	ttlStr := req.GetString("ttl", "")

	if !s.checkScope(path) {
		s.logAudit(ctx, "share_request", path, false)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	var ttlDuration time.Duration
	if ttlStr != "" {
		ttlDuration, err = time.ParseDuration(ttlStr)
		if err != nil {
			return NewToolResultError(fmt.Sprintf("invalid ttl %q: %v", ttlStr, err)), nil
		}
		if ttlDuration < 0 {
			return NewToolResultError("ttl must be a positive duration"), nil
		}
	}

	grant, err := s.shareStore.Create(s.agent.Name, toAgent, path, field, ttlDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create share grant: %w", err)
	}

	s.logAudit(ctx, "share_request", path, true)

	result := map[string]any{
		"grant_id":   grant.ID,
		"status":     grant.Status,
		"from_agent": grant.FromAgent,
		"to_agent":   grant.ToAgent,
		"secret_path": grant.SecretPath,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(resultJSON)), nil
}

func (s *Server) handleApproveShare(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	grantID, err := req.RequireString("grant_id")
	if err != nil {
		s.logAudit(ctx, "share_approve", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	grant, ok := s.shareStore.Get(grantID)
	if !ok {
		s.logAudit(ctx, "share_approve", grantID, false)
		return NewToolResultError(fmt.Sprintf("share grant %q not found", grantID)), nil
	}

	if grant.Status != SharePending {
		return NewToolResultError(fmt.Sprintf("share grant %q is not pending (status: %s)", grantID, grant.Status)), nil
	}

	if !IsTTYPresent() {
		s.logAudit(ctx, "share_approve", grant.SecretPath, false)
		return NewToolResultError("cannot approve share: no TTY available for human confirmation"), nil
	}

	details := fmt.Sprintf("Share %s: %s → %s, path: %s", grant.ID[:8], grant.FromAgent, grant.ToAgent, grant.SecretPath)
	if grant.SecretField != "" {
		details += fmt.Sprintf(", field: %s", grant.SecretField)
	}
	if grant.TTL > 0 {
		details += fmt.Sprintf(", ttl: %s", grant.TTL)
	}

	approvalResult := RequestApproval(ApprovalRequest{
		Operation: "approve_share",
		Details:   details,
		Timeout:   60 * time.Second,
	})

	if approvalResult.Error != nil {
		s.logAudit(ctx, "share_approve", grant.SecretPath, false)
		return NewToolResultError(fmt.Sprintf("approval failed: %v", approvalResult.Error)), nil
	}

	if approvalResult.Approved {
		if err := s.shareStore.Approve(grantID, "human"); err != nil {
			return nil, fmt.Errorf("failed to approve share grant: %w", err)
		}
		s.logAudit(ctx, "share_approve", grant.SecretPath, true)
		return NewToolResultText(fmt.Sprintf("Share grant %s approved", grantID)), nil
	}

	if err := s.shareStore.Reject(grantID); err != nil {
		return nil, fmt.Errorf("failed to reject share grant: %w", err)
	}
	s.logAudit(ctx, "share_reject", grant.SecretPath, true)
	return NewToolResultText(fmt.Sprintf("Share grant %s rejected", grantID)), nil
}

func (s *Server) handleRevokeShare(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	grantID, err := req.RequireString("grant_id")
	if err != nil {
		s.logAudit(ctx, "share_revoke", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	grant, ok := s.shareStore.Get(grantID)
	if !ok {
		s.logAudit(ctx, "share_revoke", grantID, false)
		return NewToolResultError(fmt.Sprintf("share grant %q not found", grantID)), nil
	}

	if s.agent.Name != grant.FromAgent {
		return NewToolResultError(fmt.Sprintf("only the source agent %q can revoke this share", grant.FromAgent)), nil
	}

	if err := s.shareStore.Revoke(grantID); err != nil {
		return NewToolResultError(fmt.Sprintf("failed to revoke share grant: %v", err)), nil
	}

	s.logAudit(ctx, "share_revoke", grant.SecretPath, true)
	return NewToolResultText(fmt.Sprintf("Share grant %s revoked", grantID)), nil
}

func (s *Server) handleListShares(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	statusStr := req.GetString("status", "")
	fromAgent := req.GetString("from_agent", "")
	toAgent := req.GetString("to_agent", "")
	secretPath := req.GetString("secret_path", "")

	filter := ShareFilter{
		Status:     shareStatusFromString(statusStr),
		FromAgent:  fromAgent,
		ToAgent:    toAgent,
		SecretPath: secretPath,
	}

	grants := s.shareStore.List(filter)

	resultJSON, err := json.Marshal(grants)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, "share_list", "", true)
	return NewToolResultText(string(resultJSON)), nil
}
