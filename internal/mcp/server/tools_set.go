package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/danieljustus/symaira-vault/internal/crypto"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
)

func (s *Server) handleSet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canWrite() {
		s.logAudit(ctx, "set", "<write-denied>", false)
		metrics.RecordAuthDenial("write_denied", s.agent.Name)
		return nil, fmt.Errorf("write operations not permitted for this agent")
	}

	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "set", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}
	field, err := req.RequireString("field")
	if err != nil {
		s.logAudit(ctx, "set", path, false)
		return mcp.NewToolResultError(err.Error()), nil
	}
	value, err := req.RequireString("value")
	if err != nil {
		s.logAudit(ctx, "set", path, false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "set", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	if err := s.requireApproval(ctx, Intent{
		Action:    "set_entry_field",
		EntryPath: path,
		FieldName: field,
		Summary:   RenderSummary("set field", path, field),
	}); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	partialData := make(map[string]any)
	if field == "totp" {
		var totpData map[string]any
		if err := json.Unmarshal([]byte(value), &totpData); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid TOTP JSON: %v", err)), nil
		}
		algo, _ := totpData["algorithm"].(string)
		digits := 0
		if d, ok := totpData["digits"].(float64); ok {
			digits = int(d)
		}
		period := 0
		if p, ok := totpData["period"].(float64); ok {
			period = int(p)
		}
		if err := crypto.ValidateTOTPParams(algo, digits, period); err != nil {
			return mcp.NewToolResultError(fmt.Errorf("invalid TOTP: %w", err).Error()), nil
		}
		partialData[field] = totpData
	} else {
		partialData[field] = value
	}

	if field == "password" && !req.GetBool("force", false) {
		if err := crypto.ValidatePasswordStrength(value); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("%s — re-call with force:true if you want to store this password (the entry will be tagged as weak)", err.Error())), nil
		}
	}

	if err := s.vaultService.UpsertEntry(path, partialData, "set", nil); err != nil {
		s.logAudit(ctx, "set", path, false)
		metrics.RecordVaultOperation("write", "error")
		mapped, mappedErr := vaultServiceErrorResult(err)
		if mapped != nil {
			return mapped, nil
		}
		if mappedErr != nil {
			return nil, mappedErr
		}
		return nil, fmt.Errorf("vault operation failed: %w", err)
	}

	s.logAudit(ctx, "set", path, true)
	metrics.RecordVaultOperation("write", "success")
	return mcp.NewToolResultText(fmt.Sprintf("Set %s.%s = ***", path, field)), nil
}
