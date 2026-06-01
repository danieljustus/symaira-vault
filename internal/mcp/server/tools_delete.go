package server

import (
	"context"
	"fmt"
	"log/slog"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func (s *Server) handleDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canWrite() {
		s.logAudit(ctx, "delete", "<write-denied>", false)
		metrics.RecordAuthDenial("write_denied", s.agent.Name)
		return nil, fmt.Errorf("delete operations not permitted for this agent")
	}

	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "delete", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "delete", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	if approvalErr := s.requireApproval(ctx, Intent{
		Action:    "delete_entry",
		EntryPath: path,
		Summary:   RenderSummary("delete entry", path, ""),
	}); approvalErr != nil {
		return mcp.NewToolResultError(approvalErr.Error()), nil
	}

	_, span := metrics.StartSpan(ctx, "vault.DeleteEntry")
	err = vaultpkg.DeleteEntry(s.vault.Dir, path, s.vault.Identity)
	span.End()
	if err != nil {
		s.logAudit(ctx, "delete", path, false)
		metrics.RecordVaultOperation("delete", "error")
		return vaultServiceErrorResult(err)
	}

	// Auto-commit failure is a warning, not an error.
	if acErr := s.vault.AutoCommit(fmt.Sprintf("Delete %s", path)); acErr != nil {
		slog.Default().Warn("auto-commit failed", "error", acErr)
	}
	vaultpkg.InvalidateListCache(s.vault.Dir)

	s.logAudit(ctx, "delete", path, true)
	metrics.RecordVaultOperation("delete", "success")
	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted entry: %s", path)), nil
}

func init() {
	RegisterTool(toolDefinition{
		Name:        "delete_entry",
		Description: "Delete a password entry by path",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path": {Type: "string", Description: "Entry path to delete"},
		}),
		Handler:         (*Server).handleDelete,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})
	RegisterTool(toolDefinition{
		Name:        "symaira_delete",
		Description: "Deprecated alias for delete_entry. Use delete_entry for new clients.",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path": {Type: "string", Description: "Entry path to delete"},
		}),
		Handler:         (*Server).handleDelete,
		Deprecated:      true,
		AliasFor:        "delete_entry",
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})
}
