package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/danieljustus/symaira-vault/internal/clipboard"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	"github.com/danieljustus/symaira-vault/internal/vaultsvc"
)

func (s *Server) handleCopyToClipboard(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canUseClipboard() {
		s.logAudit(ctx, "copy_to_clipboard", "<clipboard-denied>", false)
		metrics.RecordAuthDenial("clipboard_denied", s.agent.Name)
		return nil, fmt.Errorf("clipboard operations not permitted for this agent")
	}

	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "copy_to_clipboard", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "copy_to_clipboard", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	if s.requiresApproval() {
		if reqErr := s.requireApproval(ctx, Intent{
			Action:    "copy_to_clipboard",
			EntryPath: path,
			Summary:   fmt.Sprintf("copy password from %s to clipboard", path),
		}); reqErr != nil {
			return nil, reqErr
		}
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	value, err := svc.GetField(path, "password")
	if err != nil {
		s.logAudit(ctx, "copy_to_clipboard", path, false)
		metrics.RecordVaultOperation("read", "error")
		return vaultServiceErrorResult(err)
	}

	strValue, ok := value.(string)
	if !ok {
		s.logAudit(ctx, "copy_to_clipboard", path, false)
		return mcp.NewToolResultError("password field is not a string"), nil
	}

	clip := clipboard.DefaultClipboard()
	if clip == nil {
		return mcp.NewToolResultError("clipboard not available"), nil
	}

	if err := clip.Copy(strValue); err != nil {
		s.logAudit(ctx, "copy_to_clipboard", path, false)
		return mcp.NewToolResultError(fmt.Sprintf("clipboard copy failed: %v", err)), nil
	}

	autoClearDuration := 30
	if s.vault != nil && s.vault.Config != nil && s.vault.Config.Clipboard != nil {
		autoClearDuration = s.vault.Config.Clipboard.AutoClearDuration
	}

	if autoClearDuration > 0 {
		go clipboard.StartAutoClear(autoClearDuration, func() {
			_ = clip.Copy("")
		}, make(chan struct{}))
	}

	s.logAudit(ctx, "copy_to_clipboard", path, true)
	metrics.RecordVaultOperation("read", "success")

	return mcp.NewToolResultText(`{"success": true}`), nil
}
