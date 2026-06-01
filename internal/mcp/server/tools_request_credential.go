package server

import (
	"context"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/secureui"
)

// handleRequestCredential handles the `request_credential` MCP tool. It is the
// agent-facing entry point for the auto-trigger flow: when the agent realizes
// it needs a credential the vault does not contain, it calls this tool. The
// user gets a native dialog (TTY box or GUI popup), types the value, and the
// value is stored in the vault — the agent never sees it.
func (s *Server) handleRequestCredential(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, field, reason, result, err := s.preflightSecureInput(ctx, req, "request_credential")
	if result != nil || err != nil {
		return result, err
	}
	return s.promptAndStore(ctx, secureui.PromptRequest{
		Title:       "Symaira Vault: Agent requesting credential",
		Path:        path,
		Field:       field,
		Description: reason,
		Hidden:      true,
	}, "request_credential")
}

func init() {
	RegisterTool(toolDefinition{
		Name: "request_credential",
		Description: "Request the user to securely enter a credential the agent needs " +
			"but cannot find in the vault. Opens a native input dialog (TTY box or " +
			"OS-native popup). The value is stored in the vault and never exposed to " +
			"the agent. Use this after find_entries / get_entry returns nothing for an " +
			"expected path, instead of asking the user for the secret in chat.",
		InputSchema: objectSchema([]string{"path", "field", "reason"}, map[string]schemaProperty{
			"path":   {Type: "string", Description: "Vault path to store the new credential, e.g. \"github/api-token\""},
			"field":  {Type: "string", Description: "Field name, e.g. \"token\", \"password\", \"api_key\""},
			"reason": {Type: "string", Description: "Short human-readable reason shown in the dialog (why does the agent need this?)"},
		}),
		Handler:         (*Server).handleRequestCredential,
		Available:       secureInputToolAvailable,
		RiskLevel:       RiskLevelCritical,
		DestructiveHint: true,
	})
}
