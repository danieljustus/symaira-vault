package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/danieljustus/symaira-vault/internal/crypto"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
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

	// Prepare the partial data to merge
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

	if err := s.upsertEntry(ctx, path, partialData, "set"); err != nil {
		return nil, err
	}

	s.logAudit(ctx, "set", path, true)
	metrics.RecordVaultOperation("write", "success")
	return mcp.NewToolResultText(fmt.Sprintf("Set %s.%s = ***", path, field)), nil
}

func (s *Server) upsertEntry(ctx context.Context, path string, partialData map[string]any, action string) error {
	_, span := metrics.StartSpan(ctx, "vault.SetEntry")
	defer span.End()

	// Infer field name from single-key data maps (typical for set_entry_field).
	field := ""
	if len(partialData) == 1 {
		for k := range partialData {
			field = k
			break
		}
	}

	existing, readErr := vaultpkg.ReadEntry(s.vault.Dir, path, s.vault.Identity)
	switch {
	case readErr == nil && existing != nil:
		// Entry exists — merge new data into it
		existing.PendingWrite = &vaultpkg.WriteRecord{Field: field, Action: action}
		if _, err := vaultpkg.MergeEntryWithRecipients(s.vault.Dir, path, partialData, s.vault.Identity); err != nil {
			s.logAudit(ctx, action, path, false)
			metrics.RecordVaultOperation("write", "error")
			_, mappedErr := vaultServiceErrorResult(err)
			if mappedErr != nil {
				return mappedErr
			}
			return fmt.Errorf("vault operation failed: %w", err)
		}
	case errors.Is(readErr, os.ErrNotExist):
		// New entry
		entry := &vaultpkg.Entry{
			Data: partialData,
			Metadata: vaultpkg.EntryMetadata{
				Created: time.Now().UTC(),
				Updated: time.Now().UTC(),
				Version: 0,
			},
			PendingWrite: &vaultpkg.WriteRecord{Field: field, Action: action},
		}
		if pwd, ok := partialData["password"]; ok {
			if pwdStr, ok := pwd.(string); ok && pwdStr != "" {
				strength := crypto.AssessPasswordStrength(pwdStr)
				if strength.Weak {
					entry.AddTag(vaultpkg.TagWeakPassword)
				}
			}
		}
		if err := vaultpkg.WriteEntryWithRecipients(s.vault.Dir, path, entry, s.vault.Identity); err != nil {
			s.logAudit(ctx, action, path, false)
			metrics.RecordVaultOperation("write", "error")
			_, mappedErr := vaultServiceErrorResult(err)
			if mappedErr != nil {
				return mappedErr
			}
			return fmt.Errorf("vault operation failed: %w", err)
		}
	default:
		s.logAudit(ctx, action, path, false)
		metrics.RecordVaultOperation("write", "error")
		_, mappedErr := vaultServiceErrorResult(readErr)
		if mappedErr != nil {
			return mappedErr
		}
		return fmt.Errorf("vault operation failed: %w", readErr)
	}

	// Auto-commit failure is a warning, not an error.
	if acErr := s.vault.AutoCommit(fmt.Sprintf("Update %s", path)); acErr != nil {
		slog.Default().Warn("auto-commit failed", "error", acErr)
	}
	vaultpkg.InvalidateListCache(s.vault.Dir)
	return nil
}

func init() {
	RegisterTool(toolDefinition{
		Name:        "set_entry_field",
		Description: "Set a field on an entry (requires write scope)",
		InputSchema: objectSchema([]string{"path", "field", "value"}, map[string]schemaProperty{
			"path":  {Type: "string", Description: "Entry path"},
			"field": {Type: "string", Description: "Field name"},
			"value": {Type: "string", Description: "Field value"},
			"force": {Type: "boolean", Description: "Skip password strength validation. Default: false."},
		}),
		Handler:   (*Server).handleSet,
		RiskLevel: RiskLevelCritical,
	})
}
