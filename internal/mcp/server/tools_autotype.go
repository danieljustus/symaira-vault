package server

import (
	"context"
	"fmt"

	"github.com/danieljustus/symaira-vault/internal/autotype"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func (s *Server) handleAutotype(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canUseAutotype() {
		s.logAudit(ctx, "autotype", "<autotype-denied>", false)
		metrics.RecordAuthDenial("autotype_denied", s.agent.Name)
		return nil, fmt.Errorf("autotype operations not permitted for this agent")
	}

	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "autotype", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	field := req.GetString("field", "password")

	if !s.checkScope(path) {
		s.logAudit(ctx, "autotype", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	if s.requiresApproval() {
		s.logAudit(ctx, "autotype", path, false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, fmt.Errorf("autotype denied: approval required but cannot be granted")
	}

	entry, err := vaultpkg.ReadEntry(s.vault.Dir, path, s.vault.Identity)
	if err != nil {
		s.logAudit(ctx, "autotype", path, false)
		metrics.RecordVaultOperation("read", "error")
		return vaultServiceErrorResult(err)
	}

	value, ok := entry.Data[field]
	if !ok {
		s.logAudit(ctx, "autotype", path, false)
		return mcp.NewToolResultError(fmt.Sprintf("field %q not found in entry %s", field, path)), nil
	}

	strValue, ok := value.(string)
	if !ok {
		s.logAudit(ctx, "autotype", path, false)
		return mcp.NewToolResultError(fmt.Sprintf("field %q is not a string", field)), nil
	}

	at := autotype.DefaultAutotype()
	if at == nil {
		return mcp.NewToolResultError("autotype not available on this platform"), nil
	}

	if err := at.Type(strValue); err != nil {
		s.logAudit(ctx, "autotype", path, false)
		return mcp.NewToolResultError(fmt.Sprintf("autotype failed: %v", err)), nil
	}

	s.logAudit(ctx, "autotype", path, true)
	metrics.RecordVaultOperation("read", "success")

	return mcp.NewToolResultText(`{"success": true}`), nil
}

func init() {
	RegisterTool(toolDefinition{
		Name:        "autotype",
		Description: "Type a vault entry field value as keyboard input into the currently focused application without exposing the value to the agent",
		InputSchema: objectSchema([]string{"path"}, map[string]schemaProperty{
			"path":  {Type: "string", Description: "Entry path"},
			"field": {Type: "string", Description: "Field name to type (default: password)"},
		}),
		Handler:   (*Server).handleAutotype,
		RiskLevel: RiskLevelHigh,
	})
}
