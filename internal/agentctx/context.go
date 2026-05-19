// Package agentctx provides the AgentContext type for OpenPass v4.0 dual-surface
// CLI agent mode (ADR-0004). It manages profile loading, tier-based tool/path
// enforcement, audit logging, and quota tracking for AI agent integration.
package agentctx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	mcpErr "github.com/danieljustus/OpenPass/internal/mcp/errors"
)

const (
	envAgent = "OPENPASS_AGENT"

	tierSafe     = "safe"
	tierStandard = "standard"
	tierAdmin    = "admin"
)

// QuotaCounter is the interface for quota management.
// Implementations are injected via SetQuotaCounter.
type QuotaCounter interface {
	Increment(toolName string) (current int, err error)
}

// blockedToolsByTier maps tier → set of blocked tool names.
// This is the single source of truth for tier-based tool enforcement.
// All enforcement logic reads from this map — do not duplicate tier checks.
var blockedToolsByTier = map[string]map[string]bool{
	tierSafe: {
		"set_entry_field":     true,
		"delete_entry":        true,
		"run_command":         true,
		"execute_with_secret": true,
		"execute_api_request": true,
		"secure_input":        true,
		"request_credential":  true,
		"copy_to_clipboard":   true,
		"autotype":            true,
	},
	tierStandard: {
		"delete_entry":        true,
		"run_command":         true,
		"execute_with_secret": true,
		"execute_api_request": true,
	},
	tierAdmin: {},
}

// AgentContext holds the loaded agent profile and runtime enforcement state.
// It is the core type for the dual-surface CLI agent mode (ADR-0004).
type AgentContext struct {
	profile   *config.AgentProfile
	auditLog  *audit.Logger
	quotas    QuotaCounter
	agentName string
	vaultDir  string
}

// Load loads an agent profile from config.yaml in vaultDir for the given agentName.
// It initializes the audit logger and returns an error if the config cannot be
// loaded or the agent is not found.
func Load(agentName, vaultDir string) (*AgentContext, error) {
	if vaultDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home dir: %w", err)
		}
		vaultDir = filepath.Join(home, ".openpass")
	}

	configPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config from %s: %w", configPath, err)
	}

	profile, ok := cfg.Agents[agentName]
	if !ok {
		return nil, fmt.Errorf("agent %q not found in config", agentName)
	}
	profile.Name = agentName

	// Normalise legacy tier name for internal use.
	if profile.Tier != nil {
		tier := normalizeTier(*profile.Tier)
		profile.Tier = &tier
	}

	// Attempt to create the audit logger; silently continue without it on
	// failure so agentctx can still function even if audit logging is down.
	var auditLog *audit.Logger
	auditLog, _ = audit.New(agentName, vaultDir)

	return &AgentContext{
		profile:   &profile,
		auditLog:  auditLog,
		agentName: agentName,
		vaultDir:  vaultDir,
	}, nil
}

// Close cleans up the agent context, releasing the audit logger resources.
func (ctx *AgentContext) Close() error {
	if ctx == nil || ctx.auditLog == nil {
		return nil
	}
	return ctx.auditLog.Close()
}

// EnforceTool checks whether toolName is blocked by the agent's tier.
// Returns an *mcpErr.MCPError with code ERR_TOOL_NOT_ALLOWED if blocked.
func (ctx *AgentContext) EnforceTool(toolName string) error {
	if ctx == nil || ctx.profile == nil {
		return nil
	}

	blocked := blockedToolsByTier[ctx.effectiveTier()]
	if blocked == nil {
		blocked = blockedToolsByTier[tierStandard]
	}

	if blocked[toolName] {
		required := nextTier(ctx.effectiveTier())
		return mcpErr.ToolNotAllowed(toolName, required, upgradeCommand(required))
	}
	return nil
}

// EnforcePath checks whether the given path/action is allowed by the agent's
// tier. Action must be one of "read", "write", or "delete".
// Returns an *mcpErr.MCPError with code ERR_PATH_FORBIDDEN if blocked.
func (ctx *AgentContext) EnforcePath(path, action string) error {
	if ctx == nil || ctx.profile == nil {
		return nil
	}

	switch ctx.effectiveTier() {
	case tierSafe:
		if action == "write" || action == "delete" {
			return mcpErr.PathForbidden(path, ctx.profile.AllowedPaths)
		}
	case tierStandard:
		if action == "delete" {
			return mcpErr.PathForbidden(path, ctx.profile.AllowedPaths)
		}
		// tierAdmin — all actions allowed
	}
	return nil
}

// RecordAudit records an audit entry for the given action and details.
// Uses the audit.Logger if available; otherwise falls back to a JSONL file
// at <vaultDir>/audit/<agent>.log.
func (ctx *AgentContext) RecordAudit(action string, details map[string]any) error {
	if ctx == nil {
		return nil
	}

	ok := true
	if v, exists := details["ok"]; exists {
		if b, isBool := v.(bool); isBool {
			ok = b
		}
	}

	path, _ := details["path"].(string)
	reason, _ := details["reason"].(string)

	// Use the structured audit logger when available.
	if ctx.auditLog != nil {
		return ctx.auditLog.LogEntry(audit.LogEntry{
			Agent:  ctx.agentName,
			Action: action,
			Path:   path,
			Reason: reason,
			OK:     ok,
		})
	}

	// Fallback: write a simple JSONL entry.
	return ctx.writeFallbackAudit(action, path, reason, ok)
}

// BumpQuota increments the quota counter for the given tool and returns the
// new count. If no QuotaCounter is configured, it returns 0 with no error.
func (ctx *AgentContext) BumpQuota(toolName string) (current int, err error) {
	if ctx == nil || ctx.quotas == nil {
		return 0, nil
	}
	return ctx.quotas.Increment(toolName)
}

// SetQuotaCounter injects a QuotaCounter implementation for quota tracking.
func (ctx *AgentContext) SetQuotaCounter(qc QuotaCounter) {
	if ctx != nil {
		ctx.quotas = qc
	}
}

// Profile returns the loaded agent profile. Returns nil for a nil context.
func (ctx *AgentContext) Profile() *config.AgentProfile {
	if ctx == nil {
		return nil
	}
	return ctx.profile
}

// IsAgentMode returns true when the OPENPASS_AGENT environment variable is set,
// indicating that the CLI is running in agent (headless) mode.
func IsAgentMode() bool {
	return os.Getenv(envAgent) != ""
}

// AgentName returns the agent name from the OPENPASS_AGENT environment variable.
// Returns an empty string when not running in agent mode.
func AgentName() string {
	return os.Getenv(envAgent)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// normalizeTier maps legacy tier names to current conventions so that existing
// configs with "read-only" continue to work alongside the new "safe" name.
func normalizeTier(tier string) string {
	switch tier {
	case "read-only", tierSafe:
		return tierSafe
	case tierStandard:
		return tierStandard
	case tierAdmin:
		return tierAdmin
	default:
		// Default to standard for unrecognized tiers — the strictest
		// common-sense default outside explicit safe/admin.
		return tierStandard
	}
}

// effectiveTier returns the tier to use for enforcement. Defaults to standard
// when the profile has no tier set (should not happen in practice).
func (ctx *AgentContext) effectiveTier() string {
	if ctx.profile == nil || ctx.profile.Tier == nil || *ctx.profile.Tier == "" {
		return tierStandard
	}
	return normalizeTier(*ctx.profile.Tier)
}

// nextTier returns the tier above the current one for upgrade hints.
func nextTier(current string) string {
	switch normalizeTier(current) {
	case tierSafe:
		return tierStandard
	case tierStandard:
		return tierAdmin
	default:
		return tierAdmin
	}
}

// upgradeCommand returns a CLI command hint for upgrading to the given tier.
func upgradeCommand(tier string) string {
	name := os.Getenv(envAgent)
	if name == "" {
		name = "<agent>"
	}
	return fmt.Sprintf("openpass config agent %s --tier %s", name, tier)
}

// sanitizeAgentName replaces path separators in agent names to prevent
// directory traversal when constructing audit log file paths.
func sanitizeAgentName(name string) string {
	return strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(name)
}

// writeFallbackAudit writes a minimal JSONL audit entry to
// <vaultDir>/audit/<agent>.log when the audit.Logger is unavailable.
func (ctx *AgentContext) writeFallbackAudit(action, path, reason string, ok bool) error {
	auditDir := filepath.Join(ctx.vaultDir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return fmt.Errorf("create audit dir: %w", err)
	}

	logPath := filepath.Join(auditDir, sanitizeAgentName(ctx.agentName)+".log")

	entry := map[string]any{
		"ts":     time.Now().UTC().Format(time.RFC3339),
		"agent":  ctx.agentName,
		"action": action,
		"ok":     ok,
	}
	if path != "" {
		entry["path"] = path
	}
	if reason != "" {
		entry["reason"] = reason
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	f, err := os.OpenFile(filepath.Clean(logPath), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer func() { _ = f.Close() }()

	_, err = f.Write(data)
	return err
}
