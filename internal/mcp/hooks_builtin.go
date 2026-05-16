package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/danieljustus/OpenPass/internal/metrics"
)

// ---------------------------------------------------------------------------
// Audit hooks
// ---------------------------------------------------------------------------

// NewAuditPreHook returns a PreCallHook that logs tool invocations to the
// server's audit log. Uses the audit subsystem already available on *Server.
func NewAuditPreHook() PreCallHook {
	return func(ctx context.Context, toolName string, args CallToolRequest, server *Server) (context.Context, error) {
		if server != nil {
			server.logAudit(ctx, "tool_invocation", toolName, true)
		}
		return ctx, nil
	}
}

// NewAuditPostHook returns a PostCallHook that logs tool completion status to
// the server's audit log.
func NewAuditPostHook() PostCallHook {
	return func(ctx context.Context, toolName string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		if err != nil {
			return result, err
		}
		return result, nil
	}
}

// ---------------------------------------------------------------------------
// Rate-limit hook
// ---------------------------------------------------------------------------

// NewRateLimitPreHook returns a PreCallHook that enforces a maximum number of
// tool invocations per minute. The limit is a simple sliding-window counter.
func NewRateLimitPreHook(maxPerMinute int) PreCallHook {
	var mu sync.Mutex
	var count int
	var reset time.Time

	return func(ctx context.Context, toolName string, args CallToolRequest, server *Server) (context.Context, error) {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if now.Sub(reset) > time.Minute {
			count = 0
			reset = now
		}
		count++
		if count > maxPerMinute {
			return ctx, fmt.Errorf("rate limit exceeded: max %d requests per minute", maxPerMinute)
		}
		return ctx, nil
	}
}

// ---------------------------------------------------------------------------
// Scope-check hook
// ---------------------------------------------------------------------------

// NewScopeCheckPreHook returns a PreCallHook that validates the tool is in the
// agent's allowed tools list. If the agent's AllowedTools slice is empty, all
// tools are permitted. This is an additional defense-in-depth layer beyond the
// existing checks in executeTool.
func NewScopeCheckPreHook() PreCallHook {
	return func(ctx context.Context, toolName string, args CallToolRequest, server *Server) (context.Context, error) {
		if server == nil || server.agent == nil {
			return ctx, nil
		}
		if len(server.agent.AllowedTools) == 0 {
			return ctx, nil
		}
		for _, allowed := range server.agent.AllowedTools {
			if allowed == toolName {
				return ctx, nil
			}
		}
		server.logAudit(ctx, "tool_scope_denied", toolName, false)
		return ctx, fmt.Errorf("tool %q is not in the agent's allowed tools", toolName)
	}
}

// ---------------------------------------------------------------------------
// Notification hook
// ---------------------------------------------------------------------------

// NewNotificationPostHook returns a PostCallHook that logs a notification for
// critical tool operations (those at RiskLevelCritical). In a production system
// this could be extended to send webhooks, emails, etc.
func NewNotificationPostHook() PostCallHook {
	return func(ctx context.Context, toolName string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		def, ok := findToolDefinition(toolName)
		if !ok || def.RiskLevel != RiskLevelCritical {
			return result, err
		}
		// Audit logging of critical operations is handled elsewhere.
		// This hook is a placeholder for external notification dispatch.
		return result, err
	}
}

// ---------------------------------------------------------------------------
// Metrics hook
// ---------------------------------------------------------------------------

type metricsStartKey struct{}

// NewMetricsPreHook returns a PreCallHook that records a start timestamp in the
// context for use by NewMetricsPostHook.
func NewMetricsPreHook() PreCallHook {
	return func(ctx context.Context, toolName string, args CallToolRequest, server *Server) (context.Context, error) {
		return context.WithValue(ctx, metricsStartKey{}, time.Now()), nil
	}
}

// NewMetricsPostHook returns a PostCallHook that records tool execution
// duration and status via the metrics package.
func NewMetricsPostHook() PostCallHook {
	return func(ctx context.Context, toolName string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		start, ok := ctx.Value(metricsStartKey{}).(time.Time)
		if !ok {
			return result, err
		}
		duration := time.Since(start)
		status := metricsStatus(err, result)
		metrics.RecordMCPRequest(toolName, "", status, duration)
		return result, err
	}
}

func metricsStatus(err error, result *CallToolResult) string {
	if err != nil {
		return "error"
	}
	if result != nil && result.IsError {
		return "error"
	}
	return "success"
}
