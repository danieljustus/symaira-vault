package server

import (
	"context"
	"encoding/json"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

func (s *Server) handleHealth(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, _ = ctx, req
	result := map[string]any{
		"status":    "healthy",
		"server":    defaultServerName,
		"version":   defaultServerVersion,
		"transport": s.transport,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(resultJSON)), nil
}

func init() {
	RegisterTool(toolDefinition{
		Name:        "health",
		Description: "Return Symaira Vault MCP server health information",
		InputSchema: objectSchema(nil, map[string]schemaProperty{}),
		Handler:     (*Server).handleHealth,
		RiskLevel:   RiskLevelLow,
		ReadOnlyHint: true,
	})
}
