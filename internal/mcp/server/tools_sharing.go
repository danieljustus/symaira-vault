package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

func shareStatusFromString(s string) *mcp.ShareStatus {
	if s == "" {
		return nil
	}
	status := mcp.ShareStatus(s)
	return &status
}

func (s *Server) handleRequestShare(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	toAgent, err := req.RequireString("to_agent")
	if err != nil {
		s.logAudit(ctx, "share_request", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	path, err := req.RequireString("secret_path")
	if err != nil {
		s.logAudit(ctx, "share_request", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
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
			return mcp.NewToolResultError(fmt.Sprintf("invalid ttl %q: %v", ttlStr, err)), nil
		}
		if ttlDuration < 0 {
			return mcp.NewToolResultError("ttl must be a positive duration"), nil
		}
	}

	grant, err := s.shareStore.Create(s.agent.Name, toAgent, path, field, ttlDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create share grant: %w", err)
	}

	s.logAudit(ctx, "share_request", path, true)

	result := map[string]any{
		"grant_id":    grant.ID,
		"status":      grant.Status,
		"from_agent":  grant.FromAgent,
		"to_agent":    grant.ToAgent,
		"secret_path": grant.SecretPath,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(resultJSON)), nil
}

func (s *Server) handleApproveShare(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	grantID, err := req.RequireString("grant_id")
	if err != nil {
		s.logAudit(ctx, "share_approve", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	grant, ok := s.shareStore.Get(grantID)
	if !ok {
		s.logAudit(ctx, "share_approve", grantID, false)
		return mcp.NewToolResultError(fmt.Sprintf("share grant %q not found", grantID)), nil
	}

	if grant.Status != mcp.SharePending {
		return mcp.NewToolResultError(fmt.Sprintf("share grant %q is not pending (status: %s)", grantID, grant.Status)), nil
	}

	// Reject self-approval: the agent that requested the share cannot also
	// approve it. This prevents social-engineering attacks where a malicious
	// agent uses a look-alike name to trick the human into approving (#29).
	if s.agent != nil && s.agent.Name == grant.FromAgent {
		s.logAudit(ctx, "share_approve_denied", grant.SecretPath, false)
		return mcp.NewToolResultError("the requesting agent cannot approve its own share request"), nil
	}

	if !IsTTYPresent() {
		s.logAudit(ctx, "share_approve", grant.SecretPath, false)
		return mcp.NewToolResultError("cannot approve share: no TTY available for human confirmation"), nil
	}

	details := fmt.Sprintf("Share %s: %s → %s, path: %s\nAgent requesting approval: %s", grant.ID[:8], grant.FromAgent, grant.ToAgent, grant.SecretPath, s.agent.Name)
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
		return mcp.NewToolResultError(fmt.Sprintf("approval failed: %v", approvalResult.Error)), nil
	}

	if approvalResult.Approved {
		approvedBy := "human"
		if s.agent != nil {
			approvedBy = s.agent.Name
		}
		if err := s.shareStore.Approve(grantID, approvedBy); err != nil {
			return nil, fmt.Errorf("failed to approve share grant: %w", err)
		}
		s.logAudit(ctx, "share_approve", grant.SecretPath, true)
		return mcp.NewToolResultText(fmt.Sprintf("Share grant %s approved", grantID)), nil
	}

	if err := s.shareStore.Reject(grantID); err != nil {
		return nil, fmt.Errorf("failed to reject share grant: %w", err)
	}
	s.logAudit(ctx, "share_reject", grant.SecretPath, true)
	return mcp.NewToolResultText(fmt.Sprintf("Share grant %s rejected", grantID)), nil
}

func (s *Server) handleRevokeShare(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	grantID, err := req.RequireString("grant_id")
	if err != nil {
		s.logAudit(ctx, "share_revoke", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	grant, ok := s.shareStore.Get(grantID)
	if !ok {
		s.logAudit(ctx, "share_revoke", grantID, false)
		return mcp.NewToolResultError(fmt.Sprintf("share grant %q not found", grantID)), nil
	}

	if s.agent.Name != grant.FromAgent {
		return mcp.NewToolResultError(fmt.Sprintf("only the source agent %q can revoke this share", grant.FromAgent)), nil
	}

	if err := s.shareStore.Revoke(grantID); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to revoke share grant: %v", err)), nil
	}

	s.logAudit(ctx, "share_revoke", grant.SecretPath, true)
	return mcp.NewToolResultText(fmt.Sprintf("Share grant %s revoked", grantID)), nil
}

func (s *Server) handleListShares(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	statusStr := req.GetString("status", "")
	fromAgent := req.GetString("from_agent", "")
	toAgent := req.GetString("to_agent", "")
	secretPath := req.GetString("secret_path", "")

	// Scope results to the calling agent first — an agent must only see shares
	// where it is either the source or the target. Without this, any agent can
	// enumerate all other agents and secret paths on the host (see #22).
	agentGrants := s.shareStore.ListForAgent(s.agent.Name)

	// Apply user-supplied filter on top of the agent-scoped results.
	filter := mcp.ShareFilter{
		Status:     shareStatusFromString(statusStr),
		FromAgent:  fromAgent,
		ToAgent:    toAgent,
		SecretPath: secretPath,
	}
	grants := filterShareGrants(agentGrants, filter)

	resultJSON, err := json.Marshal(grants)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, "share_list", "", true)
	return mcp.NewToolResultText(string(resultJSON)), nil
}

// filterShareGrants applies a mcp.ShareFilter to a slice of grants in place.
func filterShareGrants(grants []*mcp.ShareGrant, filter mcp.ShareFilter) []*mcp.ShareGrant {
	if filter.Status == nil && filter.FromAgent == "" && filter.ToAgent == "" && filter.SecretPath == "" {
		return grants
	}
	filtered := make([]*mcp.ShareGrant, 0, len(grants))
	for _, g := range grants {
		if filter.Status != nil && g.Status != *filter.Status {
			continue
		}
		if filter.FromAgent != "" && g.FromAgent != filter.FromAgent {
			continue
		}
		if filter.ToAgent != "" && g.ToAgent != filter.ToAgent {
			continue
		}
		if filter.SecretPath != "" && g.SecretPath != filter.SecretPath {
			continue
		}
		filtered = append(filtered, g)
	}
	return filtered
}

func init() {
	RegisterTool(toolDefinition{
		Name:        "request_share",
		Description: "Request to share a secret with another agent. Creates a pending share grant that requires human approval.",
		InputSchema: objectSchema([]string{"to_agent", "secret_path"}, map[string]schemaProperty{
			"to_agent":     {Type: "string", Description: "Name of the agent to share the secret with"},
			"secret_path":  {Type: "string", Description: "Path to the secret entry (e.g., \"api-keys/stripe\")"},
			"secret_field": {Type: "string", Description: "Specific field to share (optional, shares entire entry if omitted)"},
			"ttl":          {Type: "string", Description: "Time-to-live duration (e.g., \"1h\", \"30m\"). Share expires after this duration."},
		}),
		Handler:   (*Server).handleRequestShare,
		RiskLevel: RiskLevelMedium,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "approve_share",
		Description: "Approve a pending share request. Requires human confirmation.",
		InputSchema: objectSchema([]string{"grant_id"}, map[string]schemaProperty{
			"grant_id": {Type: "string", Description: "ID of the share grant to approve"},
		}),
		Handler:   (*Server).handleApproveShare,
		RiskLevel: RiskLevelHigh,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "revoke_share",
		Description: "Revoke an active share grant, immediately removing access.",
		InputSchema: objectSchema([]string{"grant_id"}, map[string]schemaProperty{
			"grant_id": {Type: "string", Description: "ID of the share grant to revoke"},
		}),
		Handler:   (*Server).handleRevokeShare,
		RiskLevel: RiskLevelHigh,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "list_shares",
		Description: "List share grants. Can filter by status, agent, or secret path.",
		InputSchema: objectSchema([]string{}, map[string]schemaProperty{
			"status":      {Type: "string", Description: "Filter by status: pending, approved, revoked, expired, rejected"},
			"from_agent":  {Type: "string", Description: "Filter by source agent name"},
			"to_agent":    {Type: "string", Description: "Filter by target agent name"},
			"secret_path": {Type: "string", Description: "Filter by secret path"},
		}),
		Handler:   (*Server).handleListShares,
		RiskLevel: RiskLevelLow,
		ReadOnlyHint: true,
	})
}
