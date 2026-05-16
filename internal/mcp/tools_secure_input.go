package mcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/secureui"
)

func (s *Server) handleSecureInput(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	path, field, description, result, err := s.preflightSecureInput(ctx, req, "secure_input")
	if result != nil || err != nil {
		return result, err
	}
	return s.promptAndStore(ctx, secureui.PromptRequest{
		Title:       "OpenPass: Secure Input",
		Path:        path,
		Field:       field,
		Description: description,
		Hidden:      true,
	}, "secure_input")
}

// preflightSecureInput runs the shared write/scope/approval gates for both
// secure_input and request_credential. It returns either:
//   - non-nil result (validation error to surface to caller) and nil err
//   - nil result and non-nil err (hard authorization error)
//   - all-zero result/err (proceed with the returned path/field/description)
func (s *Server) preflightSecureInput(
	ctx context.Context, req CallToolRequest, auditTag string,
) (path, field, description string, result *CallToolResult, err error) {
	if !s.canWrite() {
		s.logAudit(ctx, auditTag, "<write-denied>", false)
		metrics.RecordAuthDenial("write_denied", s.agent.Name)
		return "", "", "", nil, fmt.Errorf("write operations not permitted for this agent")
	}

	path, vErr := req.RequireString("path")
	if vErr != nil {
		s.logAudit(ctx, auditTag, "<invalid>", false)
		return "", "", "", NewToolResultError(vErr.Error()), nil
	}
	field, vErr = req.RequireString("field")
	if vErr != nil {
		s.logAudit(ctx, auditTag, path, false)
		return "", "", "", NewToolResultError(vErr.Error()), nil
	}
	description = req.GetString("description", req.GetString("reason", ""))

	if !s.checkScope(path) {
		s.logAudit(ctx, auditTag, path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return "", "", "", nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	if s.requiresApproval() {
		verb := "secure_input"
		if auditTag == "request_credential" {
			verb = "request_credential"
		}
		if err := s.requireApproval(ctx, Intent{
			Action:    verb,
			EntryPath: path,
			Summary:   fmt.Sprintf("%s for %s", verb, path),
		}); err != nil {
			return "", "", "", nil, err
		}
	}

	return path, field, description, nil, nil
}

// promptAndStore opens a secure-input dialog (TTY or GUI), persists the value
// to the vault, and returns a non-leaking result. The value is never echoed.
func (s *Server) promptAndStore(
	ctx context.Context, req secureui.PromptRequest, auditTag string,
) (*CallToolResult, error) {
	value, inputErr := secureInputPromptFn(req)
	if inputErr != nil {
		s.logAudit(ctx, auditTag, req.Path, false)
		metrics.RecordVaultOperation(auditTag, "error")
		switch {
		case errors.Is(inputErr, secureui.ErrCanceled):
			return NewToolResultError("secure input canceled by user"), nil
		case errors.Is(inputErr, secureui.ErrTimeout):
			return NewToolResultError("secure input timed out"), nil
		case errors.Is(inputErr, secureui.ErrUnavailable):
			return nil, fmt.Errorf("secure input unavailable on this host (no TTY or GUI dialog)")
		default:
			return nil, fmt.Errorf("secure input failed: %w", inputErr)
		}
	}

	if value == "" {
		s.logAudit(ctx, auditTag, req.Path, false)
		return NewToolResultError("secure input canceled: empty value provided"), nil
	}

	partial := map[string]any{req.Field: value}
	if err := s.upsertEntry(ctx, req.Path, partial, auditTag); err != nil {
		return nil, err
	}

	s.logAudit(ctx, auditTag, req.Path, true)
	metrics.RecordVaultOperation("write", "success")
	return NewToolResultText(fmt.Sprintf("Securely stored %s.%s = *** (value hidden from agent)", req.Path, req.Field)), nil
}
