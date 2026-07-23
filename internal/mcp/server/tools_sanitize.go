package server

import (
	"context"
	"encoding/json"
	"fmt"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/mcp/masking"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	"github.com/danieljustus/symaira-vault/internal/redact"
)

// outputScanner is the output-scanning redaction core (#695) applied to
// every MCP/tool response payload that carries subprocess or externally
// sourced text, as a defense-in-depth layer alongside the known-secret
// masking already performed by sanitizeKnownSecretValues. It is a package
// var (not per-call) since it is stateless and safe for concurrent use.
var outputScanner = redact.NewScanner(redact.NewPatternDetector())

func (s *Server) handleSanitizeOutput(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text, err := req.RequireString("text")
	if err != nil {
		s.logAudit(ctx, "sanitize_output", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
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

	return mcp.NewToolResultText(string(resultJSON)), nil
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
	stdout = scanOutputPatterns(stdout)
	stderr = scanOutputPatterns(stderr)
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

// scanOutputPatterns applies the output-scanning redaction core's
// credential-shaped pattern detector (#695) to text before it is embedded
// in an MCP tool response payload. It fails closed: if scanning itself
// errors, text is withheld (replaced with a fixed marker) rather than
// returned unredacted.
func scanOutputPatterns(text string) string {
	res, _ := outputScanner.Scan(text, redact.ScanOptions{})
	return res.Text
}
