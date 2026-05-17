package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/danieljustus/OpenPass/internal/masking"
	"github.com/danieljustus/OpenPass/internal/metrics"
)

func (s *Server) handleSanitizeOutput(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		s.logAudit(ctx, "sanitize_output", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}

	s.logAudit(ctx, "sanitize_output", "<scan>", true)
	metrics.RecordVaultOperation("sanitize", "success")

	sanitized := globalChokepoint.SanitizeForMCP(text)

	result := map[string]any{
		"original_length":  len(text),
		"sanitized_length": len(sanitized),
		"sanitized":        sanitized,
		"was_modified":     sanitized != text,
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal sanitize result: %w", err)
	}

	return NewToolResultText(string(resultJSON)), nil
}

// sanitizeRunOutput applies two passes to subprocess output before it
// reaches the LLM:
//  1. Mask any known secret values from resolvedEnv with "***".
//  2. Strip prompt-injection vectors (ANSI escapes, XML closing tags,
//     bidi overrides, zero-width chars) via the MCP chokepoint.
//
// Pass (2) is defense-in-depth: the final callToolResultPayload step
// also runs the chokepoint, but applying it here means stdout and
// stderr can be embedded into structured responses (e.g. JSON fields)
// without depending on the outer pipeline's order.
func (s *Server) sanitizeRunOutput(stdout, stderr string, resolvedEnv map[string]string) (string, string) {
	stdout = s.sanitizeKnownSecretValues(stdout, resolvedEnv)
	stderr = s.sanitizeKnownSecretValues(stderr, resolvedEnv)
	stdout = globalChokepoint.SanitizeForMCP(stdout)
	stderr = globalChokepoint.SanitizeForMCP(stderr)
	return stdout, stderr
}

func (s *Server) sanitizeKnownSecretValues(text string, resolvedEnv map[string]string) string {
	if len(resolvedEnv) == 0 {
		return text
	}

	return masking.SanitizeWithKnownSecrets(text, resolvedEnv, "***")
}
