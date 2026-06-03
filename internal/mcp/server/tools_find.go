package server

import (
	"context"
	"encoding/json"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func (s *Server) handleFind(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		s.logAudit(ctx, "find", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
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
	return mcp.NewToolResultText(string(result)), nil
}

// findEntries searches vault entries matching a query.
// It delegates to vaultpkg for concurrent search with scope filtering applied
// before decryption. Worker count is read from vault config (SearchWorkers) or
// auto-scaled based on vault size and CPU cores.
func (s *Server) findEntries(ctx context.Context, query string) ([]vaultpkg.Match, error) {
	_, span := metrics.StartSpan(ctx, "vault.FindWithOptions")
	defer span.End()

	workers := vaultpkg.SearchWorkerCount(0)
	if s.vault != nil && s.vault.Config != nil && s.vault.Config.Vault != nil && s.vault.Config.Vault.SearchWorkers > 0 {
		workers = s.vault.Config.Vault.SearchWorkers
	}

	var redactPatterns []string
	if s.agent != nil {
		redactPatterns = s.agent.EffectiveRedactFields("find_entries")
	}

	return s.vault.FindWithOptions(query, vaultpkg.FindOptions{
		MaxWorkers:          workers,
		ScopeFilter:         s.checkScope,
		RedactFieldPatterns: redactPatterns,
	})
}

func init() {
	RegisterTool(toolDefinition{
		Name:        "find_entries",
		Description: "Search entries by query string",
		InputSchema: objectSchema([]string{"query"}, map[string]schemaProperty{
			"query": {Type: "string", Description: "Search query"},
		}),
		Handler:      (*Server).handleFind,
		RiskLevel:    RiskLevelLow,
		ReadOnlyHint: true,
	})
}
