package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/danieljustus/OpenPass/internal/autotype"
	"github.com/danieljustus/OpenPass/internal/clipboard"
	"github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

const totpToolName = "generate_totp"

func (s *Server) handleGenerateTOTP(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, totpToolName, "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, totpToolName, path, false)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	destination := req.GetString("destination", s.defaultTOTPDestination())
	returnCode := req.GetBool("return_code", false)

	svc := vaultsvc.New(slog.Default(), s.vault)
	entry, err := svc.GetEntry(path)
	if err != nil {
		s.logAudit(ctx, totpToolName, path, false)
		return vaultServiceErrorResult(err)
	}

	secret, algorithm, digits, period, hasTOTP := vault.ExtractTOTP(entry.Data)
	if !hasTOTP {
		s.logAudit(ctx, totpToolName, path, false)
		return nil, fmt.Errorf("entry %q does not have TOTP configuration", path)
	}

	totpCode, err := crypto.GenerateTOTP(secret, algorithm, digits, period)
	if err != nil {
		s.logAudit(ctx, totpToolName, path, false)
		return nil, fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	switch destination {
	case "clipboard":
		return s.totpClipboard(ctx, path, totpCode)
	case "autotype":
		return s.totpAutotype(ctx, path, totpCode)
	case "return":
		return s.totpReturn(ctx, path, totpCode, returnCode)
	default:
		return NewToolResultError(fmt.Sprintf("invalid destination %q: must be clipboard, autotype, or return", destination)), nil
	}
}

func (s *Server) totpClipboard(ctx context.Context, path string, code *crypto.TOTPCode) (*CallToolResult, error) {
	if !s.canUseClipboard() {
		s.logAudit(ctx, totpToolName, path, false)
		metrics.RecordAuthDenial("clipboard_denied", s.agent.Name)
		return nil, fmt.Errorf("clipboard operations not permitted for this agent")
	}

	if s.requiresApproval() {
		s.logAudit(ctx, totpToolName, path, false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, fmt.Errorf("generate_totp denied: approval required but clipboard mode does not support approval")
	}

	clip := clipboard.DefaultClipboard()
	if clip == nil {
		return NewToolResultError("clipboard not available"), nil
	}

	if err := clip.Copy(code.Code); err != nil {
		s.logAudit(ctx, totpToolName, path, false)
		return NewToolResultError(fmt.Sprintf("clipboard copy failed: %v", err)), nil
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

	s.logAudit(ctx, totpToolName+".clipboard", path, true)
	metrics.RecordVaultOperation("totp", "success")

	result := map[string]any{
		"success":             true,
		"destination":         "clipboard",
		"clipboard_clears_in": autoClearDuration,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal totp clipboard result: %w", err)
	}
	return NewToolResultText(string(resultJSON)), nil
}

func (s *Server) totpAutotype(ctx context.Context, path string, code *crypto.TOTPCode) (*CallToolResult, error) {
	if !s.canUseAutotype() {
		s.logAudit(ctx, totpToolName, path, false)
		metrics.RecordAuthDenial("autotype_denied", s.agent.Name)
		return nil, fmt.Errorf("autotype operations not permitted for this agent")
	}

	if s.requiresApproval() {
		s.logAudit(ctx, totpToolName, path, false)
		metrics.RecordApproval(s.agent.Name, "denied")
		return nil, fmt.Errorf("generate_totp denied: approval required but autotype mode does not support approval")
	}

	at := autotype.DefaultAutotype()
	if at == nil {
		return NewToolResultError("autotype not available on this platform"), nil
	}

	if err := at.Type(code.Code); err != nil {
		s.logAudit(ctx, totpToolName, path, false)
		return NewToolResultError(fmt.Sprintf("autotype failed: %v", err)), nil
	}

	s.logAudit(ctx, totpToolName+".autotype", path, true)
	metrics.RecordVaultOperation("totp", "success")

	return NewToolResultText(`{"success": true}`), nil
}

func (s *Server) totpReturn(ctx context.Context, path string, code *crypto.TOTPCode, returnCode bool) (*CallToolResult, error) {
	if !returnCode {
		return NewToolResultError("return_code must be true when destination is \"return\""), nil
	}

	if !s.canReadValues() {
		if approvalErr := s.requireApproval(ctx, Intent{
			Action:    "generate_totp_return",
			EntryPath: path,
			Summary:   RenderSummary("return TOTP code in response", path, ""),
		}); approvalErr != nil {
			return NewToolResultError(approvalErr.Error()), nil
		}
	}

	s.logAudit(ctx, totpToolName+".return", path, true)
	metrics.RecordVaultOperation("totp", "success")

	result := map[string]any{
		"code":       code.Code,
		"expires_at": code.ExpiresAt,
		"period":     code.Period,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal totp result: %w", err)
	}
	return NewToolResultText(string(resultJSON)), nil
}

func (s *Server) defaultTOTPDestination() string {
	if s.canUseClipboard() {
		return "clipboard"
	}
	if s.canUseAutotype() {
		return "autotype"
	}
	return "return"
}

func generateTOTPAvailable(s *Server) bool {
	if s == nil || s.agent == nil {
		return true // show when no profile context
	}
	return s.canUseClipboard() || s.canUseAutotype() || s.canReadValues()
}
