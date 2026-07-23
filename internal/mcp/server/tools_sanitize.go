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

// redactAuditAction is the audit log action name used for metadata-only
// leak-detection events (#696). It is distinct from the tool-call action
// (e.g. "run_command") so audit consumers can filter on it independently.
const redactAuditAction = "leak_detection"

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

// sanitizeRunOutput applies three passes to subprocess output before it
// reaches the LLM:
//  1. Mask any known secret values from resolvedEnv with "***".
//  2. Run the output-scanning redaction core's credential-pattern detector
//     (#695), which — when strict mode is opted into (#696) — blocks the
//     affected stream instead of only redacting it, and always emits a
//     metadata-only audit event.
//  3. Strip prompt-injection vectors (ANSI escapes, XML closing tags,
//     bidi overrides, zero-width chars) via the MCP chokepoint.
//
// Pass (3) is defense-in-depth: the final callToolResultPayload step
// also runs the chokepoint, but applying it here means stdout and
// stderr can be embedded into structured responses (e.g. JSON fields)
// without depending on the outer pipeline's order.
func (s *Server) sanitizeRunOutput(ctx context.Context, stdout, stderr string, resolvedEnv map[string]string) (string, string) {
	stdout = s.sanitizeKnownSecretValues(stdout, resolvedEnv)
	stderr = s.sanitizeKnownSecretValues(stderr, resolvedEnv)

	corrID := redact.NewCorrelationID()
	stdout = s.scanOutputPatterns(ctx, "stdout", corrID, stdout)
	stderr = s.scanOutputPatterns(ctx, "stderr", corrID, stderr)

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
//
// Strict mode (#696) is an opt-in, process-wide setting (EnvStrictMode):
// when enabled, a high-confidence match causes the affected channel to be
// withheld entirely rather than redacted in place. Every detection — redacted
// or blocked — emits one audit event via s.logAudit containing detector
// name, channel, confidence, redaction count, and correlationID only;
// never the matched value or any excerpt of it.
func (s *Server) scanOutputPatterns(ctx context.Context, channel, correlationID, text string) string {
	scanner := redact.NewScanner(redact.NewPatternDetector())
	scanner.Channel = channel
	scanner.Audit = func(e redact.AuditEvent) {
		s.logAudit(ctx, redactAuditAction, redactAuditPath(e), true)
	}

	res, _ := scanner.Scan(text, redact.ScanOptions{
		Strict:        redact.StrictModeEnabled(),
		CorrelationID: correlationID,
	})
	return res.Text
}

// redactAuditPath renders an AuditEvent as the free-text "path" field
// logAudit expects, using metadata only (detector, channel, confidence,
// count, blocked, correlation ID) — never the matched value.
func redactAuditPath(e redact.AuditEvent) string {
	return fmt.Sprintf("detector=%s, channel=%s, confidence=%s, count=%d, blocked=%t, correlation_id=%s",
		e.Detector, e.Channel, e.Confidence, e.RedactedCount, e.Blocked, e.CorrelationID)
}
