package mcp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func (s *Server) handleDelete(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	if !s.canWrite() {
		s.logAudit(ctx, "delete", "<write-denied>", false)
		metrics.RecordAuthDenial("write_denied", s.agent.Name)
		return nil, fmt.Errorf("delete operations not permitted for this agent")
	}

	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "delete", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "delete", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	if err := s.requireApproval(ctx, Intent{
		Action:    "delete_entry",
		EntryPath: path,
		Summary:   RenderSummary("delete entry", path, ""),
	}); err != nil {
		return NewToolResultError(err.Error()), nil
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	_, span := metrics.StartSpan(ctx, "vault.Delete")
	err = svc.Delete(path)
	span.End()
	if err != nil {
		s.logAudit(ctx, "delete", path, false)
		metrics.RecordVaultOperation("delete", "error")
		return vaultServiceErrorResult(err)
	}

	s.logAudit(ctx, "delete", path, true)
	metrics.RecordVaultOperation("delete", "success")
	return NewToolResultText(fmt.Sprintf("Successfully deleted entry: %s", path)), nil
}
