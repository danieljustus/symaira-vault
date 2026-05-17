package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/danieljustus/OpenPass/internal/anomaly"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/notify"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func toolError(msg string) *CallToolResult {
	return NewToolResultError(msg)
}

func toolActionType(toolName string) string {
	switch toolName {
	case "set_entry_field", "secure_input", "request_credential":
		return "set"
	case "delete_entry", "openpass_delete":
		return "delete"
	case "run_command", "execute_with_secret", "execute_api_request":
		return "run"
	case "list_entries":
		return "list"
	case "get_entry", "get_entry_value", "get_entry_metadata", "secret_unseal":
		return "get"
	case "find_entries":
		return "find"
	case "generate_password", "generate_totp", "generate_template":
		return "generate"
	case "copy_to_clipboard", "autotype":
		return "read"
	case "request_share":
		return "share_request"
	case "approve_share":
		return "share_approve"
	case "revoke_share":
		return "share_revoke"
	case "list_shares":
		return "share_list"
	default:
		return "read"
	}
}

func (s *Server) executeTool(ctx context.Context, name string, args json.RawMessage) (map[string]any, error) {
	start := time.Now()
	agentName := ""
	if s.agent != nil {
		agentName = s.agent.Name
	}

	// Generate request ID and propagate it through context for audit logging
	reqID, err := generateRequestID()
	if err != nil {
		slog.Default().Warn("failed to generate request ID", "err", err)
	}
	ctx = WithRequestID(ctx, reqID)

	ctx, span := metrics.StartSpan(ctx, "executeTool",
		attribute.String("tool.name", name),
		attribute.String("agent.name", agentName),
		attribute.String("transport", s.transport),
	)
	defer span.End()

	req, err := decodeToolRequest(args)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		metrics.RecordMCPRequest(name, agentName, "error", time.Since(start))
		return nil, fmt.Errorf("parse arguments: %w", err)
	}

	entryPath, _ := req.RequireString("path")

	if entryPath != "" {
		span.SetAttributes(attribute.String("entry.path", metrics.HashEntryPath(entryPath)))
	}

	def, ok := findToolDefinition(name)
	if !ok {
		span.SetStatus(codes.Error, "unknown tool")
		metrics.RecordMCPRequest(name, agentName, "error", time.Since(start))
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if def.Available != nil && !def.Available(s) {
		span.SetStatus(codes.Error, "tool not available")
		metrics.RecordMCPRequest(name, agentName, "error", time.Since(start))
		return nil, fmt.Errorf("tool %q is not available in the current environment", name)
	}
	if isToolBlockedByAgent(s.agent, name) {
		span.SetStatus(codes.Error, "tool not found")
		metrics.RecordMCPRequest(name, agentName, "error", time.Since(start))
		s.logAudit(ctx, "agent_tool_denied", name, false)
		return nil, fmt.Errorf("unknown tool: %s", name)
	}

	// Check token tool scope
	if token, ok := TokenFromContext(ctx); ok {
		if !isToolAllowed(token, name) {
			span.SetStatus(codes.Error, "tool scope denied")
			metrics.RecordAuthDenial("tool_scope_denied", agentName)
			s.logAudit(ctx, "tool_scope_denied", name, false)
			return nil, fmt.Errorf("tool %q not allowed by token scope", name)
		}
		token.UpdateLastUsed()
	}

	// Registry drift check: reject if binary was updated since this token was issued.
	// Returns a user-visible tool error (not a protocol error) so the agent sees
	// a descriptive message. Pattern: return callToolResultPayload(...), nil
	// (contrast with the scope check above which returns nil, fmt.Errorf — a protocol error).
	if token, ok := TokenFromContext(ctx); ok && token != nil {
		if token.IsToolRegistryDriftDetected() {
			span.SetStatus(codes.Error, "tool registry drift")
			metrics.RecordMCPRequest(name, agentName, "error", time.Since(start))
			s.logAudit(ctx, "tool_registry_drift", name, false)
			return callToolResultPayload(toolError(
				"tool registry has changed since this token was issued — " +
					"re-issue the token with 'openpass mcp token create'",
			)), nil
		}
	}

	// Evaluate declarative policies before tool execution
	if entryPath != "" {
		if policyErr := s.checkPolicy(ctx, entryPath, toolActionType(name)); policyErr != nil {
			span.SetStatus(codes.Error, policyErr.Error())
			metrics.RecordMCPRequest(name, agentName, "error", time.Since(start))
			return nil, policyErr
		}
	}

	// Execute pre-call hooks
	if s.hookRegistry != nil {
		for _, hook := range s.hookRegistry.PreCallHooks() {
			ctx, err = hook(ctx, name, req, s)
			if err != nil {
				span.SetStatus(codes.Error, err.Error())
				metrics.RecordMCPRequest(name, agentName, "error", time.Since(start))
				return nil, err
			}
		}
	}

	result, err := def.Handler(s, ctx, req)

	// Execute post-call hooks
	// Post-call hook errors are logged but never abort execution
	// (the result has already been computed by the handler).
	if s.hookRegistry != nil {
		for _, hook := range s.hookRegistry.PostCallHooks() {
			newResult, newErr := hook(ctx, name, req, result, err)
			if newErr != nil {
				s.logAudit(ctx, "post_call_hook_error", name, false)
			} else {
				result = newResult
			}
		}
	}

	duration := time.Since(start)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.String("status", "error"))
		metrics.RecordMCPRequest(name, agentName, "error", duration)
		// Fire-and-forget anomaly detection (non-blocking)
		s.detectAnomalyAsync(ctx, name, entryPath, reqID, agentName, duration, false, 0)
		return nil, err
	}

	status := "success"
	if result != nil && result.IsError {
		status = "error"
		span.SetStatus(codes.Error, "tool returned error")
	}
	span.SetAttributes(attribute.String("status", status))
	metrics.RecordMCPRequest(name, agentName, status, duration)

	// Compute field length for anomaly detection (read tools only)
	fieldLength := 0
	if !result.IsError && (name == "get_entry" || name == "get_entry_value") {
		fieldLength = len(result.Text)
	}

	// Fire-and-forget anomaly detection (non-blocking)
	s.detectAnomalyAsync(ctx, name, entryPath, reqID, agentName, duration, true, fieldLength)

	return callToolResultPayload(result), nil
}

// detectAnomalyAsync runs anomaly detection in a separate goroutine so it
// NEVER blocks tool execution. It checks all detection patterns and handles
// any alerts that are generated (logging, notifications, cache invalidation).
func (s *Server) detectAnomalyAsync(_ context.Context, toolName, entryPath, reqID, agentName string, duration time.Duration, ok bool, fieldLength int) {
	if s == nil || s.anomalyDetector == nil {
		return
	}
	if agentName == "" {
		return
	}

	go func() {
		event := anomaly.ToolCallEvent{
			Timestamp:   time.Now(),
			Agent:       agentName,
			Tool:        toolName,
			Path:        entryPath,
			Duration:    duration,
			OK:          ok,
			IsCanary:    entryPath != "" && vault.IsCanaryPath(entryPath),
			RequestID:   reqID,
			FieldLength: fieldLength,
		}

		alert := s.anomalyDetector.Check(context.Background(), event)
		if alert == nil {
			return
		}

		slog.Default().Warn("anomaly detected",
			"type", alert.Type,
			"severity", alert.Severity.String(),
			"agent", alert.Agent,
			"path", alert.Path,
			"request_id", alert.RequestID,
			"description", alert.Description,
		)

		// Log anomaly to audit
		s.logAudit(context.Background(), "anomaly_"+string(alert.Type), alert.Path, false)

		// Desktop notification for high-severity events
		if alert.Severity >= anomaly.SeverityHigh {
			notify.AlertNotify(
				"Anomaly: "+string(alert.Type),
				alert.Description,
			)
		}

		// Invalidate approval cache for any anomaly to force re-approval
		s.invalidateApprovalCache()
	}()
}
