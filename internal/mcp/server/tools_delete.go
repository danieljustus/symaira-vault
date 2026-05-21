package server

import (
	"context"
	"fmt"
	"log/slog"

	mcp "github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
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
	return mcp.NewToolResultText(fmt.Sprintf("Successfully deleted entry: %s", path)), nil
}
