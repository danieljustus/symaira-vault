package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func (s *Server) handleSet(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	if !s.canWrite() {
		s.logAudit(ctx, "set", "<write-denied>", false)
		metrics.RecordAuthDenial("write_denied", s.agent.Name)
		return nil, fmt.Errorf("write operations not permitted for this agent")
	}

	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "set", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}
	field, err := req.RequireString("field")
	if err != nil {
		s.logAudit(ctx, "set", path, false)
		return NewToolResultError(err.Error()), nil
	}
	value, err := req.RequireString("value")
	if err != nil {
		s.logAudit(ctx, "set", path, false)
		return NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "set", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	if s.requiresApproval() {
		s.logAudit(ctx, "approval_denied", path, false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, fmt.Errorf("write to %q denied: approval required but cannot be granted", path)
	}

	// Prepare the partial data to merge
	partialData := make(map[string]any)
	if field == "totp" {
		var totpData map[string]any
		if err := json.Unmarshal([]byte(value), &totpData); err != nil {
			return NewToolResultError(fmt.Sprintf("invalid TOTP JSON: %v", err)), nil
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
			return NewToolResultError(fmt.Errorf("invalid TOTP: %w", err).Error()), nil
		}
		partialData[field] = totpData
	} else {
		partialData[field] = value
	}

	if field == "password" && !req.GetBool("force", false) {
		if err := crypto.ValidatePasswordStrength(value); err != nil {
			return NewToolResultError(fmt.Sprintf("%s — re-call with force:true if you want to store this password (the entry will be tagged as weak)", err.Error())), nil
		}
	}

	if err := s.upsertEntry(ctx, path, partialData, "set"); err != nil {
		return nil, err
	}

	s.logAudit(ctx, "set", path, true)
	metrics.RecordVaultOperation("write", "success")
	return NewToolResultText(fmt.Sprintf("Set %s.%s = ***", path, field)), nil
}

func (s *Server) upsertEntry(ctx context.Context, path string, partialData map[string]any, action string) error {
	svc := vaultsvc.New(slog.Default(), s.vault)
	_, span := metrics.StartSpan(ctx, "vault.SetEntry")
	err := svc.SetFields(path, partialData)
	span.End()
	if err != nil {
		s.logAudit(ctx, action, path, false)
		metrics.RecordVaultOperation("write", "error")
		_, mappedErr := vaultServiceErrorResult(err)
		if mappedErr != nil {
			return mappedErr
		}
		return fmt.Errorf("vault operation failed: %w", err)
	}
	return nil
}
