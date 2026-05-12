package mcp

import (
	"context"

	"github.com/danieljustus/OpenPass/internal/secureui"
)

// handleRequestCredential handles the `request_credential` MCP tool. It is the
// agent-facing entry point for the auto-trigger flow: when the agent realizes
// it needs a credential the vault does not contain, it calls this tool. The
// user gets a native dialog (TTY box or GUI popup), types the value, and the
// value is stored in the vault — the agent never sees it.
func (s *Server) handleRequestCredential(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	path, field, reason, result, err := s.preflightSecureInput(ctx, req, "request_credential")
	if result != nil || err != nil {
		return result, err
	}
	return s.promptAndStore(ctx, secureui.PromptRequest{
		Title:       "OpenPass: Agent requesting credential",
		Path:        path,
		Field:       field,
		Description: reason,
		Hidden:      true,
	}, "request_credential")
}
