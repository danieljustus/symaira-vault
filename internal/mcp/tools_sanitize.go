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

func (s *Server) sanitizeRunOutput(stdout, stderr string, resolvedEnv map[string]string) (string, string) {
	return s.sanitizeKnownSecretValues(stdout, resolvedEnv), s.sanitizeKnownSecretValues(stderr, resolvedEnv)
}

func (s *Server) sanitizeKnownSecretValues(text string, resolvedEnv map[string]string) string {
	if len(resolvedEnv) == 0 {
		return text
	}

	return masking.SanitizeWithKnownSecrets(text, resolvedEnv, "***")
}
