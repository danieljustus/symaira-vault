package mcp

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func (s *Server) handleFind(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		s.logAudit(ctx, "find", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	matches, err := s.findEntries(ctx, query)
	if err != nil {
		s.logAudit(ctx, "find", query, false)
		return nil, err
	}

	s.logAudit(ctx, "find", query, true)

	for i := range matches {
		matches[i].Path = globalChokepoint.SanitizeForMCP(matches[i].Path)
	}

	result, err := json.Marshal(matches)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(result)), nil
}

// findEntries searches vault entries matching a query.
// It delegates to vaultsvc for concurrent search with scope filtering applied
// before decryption. Worker count is read from vault config (SearchWorkers) or
// auto-scaled based on vault size and CPU cores.
func (s *Server) findEntries(ctx context.Context, query string) ([]vault.Match, error) {
	svc := vaultsvc.New(slog.Default(), s.vault)
	_, span := metrics.StartSpan(ctx, "vault.Find")
	defer span.End()

	workers := 4
	if s.vault != nil && s.vault.Config != nil && s.vault.Config.Vault != nil && s.vault.Config.Vault.SearchWorkers > 0 {
		workers = s.vault.Config.Vault.SearchWorkers
	}

	var redactPatterns []string
	if s.agent != nil {
		redactPatterns = s.agent.EffectiveRedactFields("find_entries")
	}

	return svc.Find(query, vault.FindOptions{
		MaxWorkers:          workers,
		ScopeFilter:         s.checkScope,
		RedactFieldPatterns: redactPatterns,
	})
}
