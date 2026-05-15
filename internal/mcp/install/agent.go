// Package install provides auto-discovery and configuration of OpenPass MCP
// server for supported AI agents.
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AgentType identifies a supported AI agent.
type AgentType string

const (
	AgentOpenClaw   AgentType = "openclaw"
	AgentClaudeCode AgentType = "claude-code"
	AgentHermes     AgentType = "hermes"
	AgentCodex      AgentType = "codex"
	AgentOpenCode   AgentType = "opencode"
)

// ConfigFormat determines the serialization format for an agent's config file.
type ConfigFormat string

const (
	FormatJSON ConfigFormat = "json"
	FormatYAML ConfigFormat = "yaml"
	FormatTOML ConfigFormat = "toml"
)

// AgentDefinition holds metadata for a supported agent.
type AgentDefinition struct {
	Type        AgentType
	DisplayName string
	// ConfigPaths are possible config file paths, ordered by preference.
	// Paths may contain ~ which is expanded to the user's home directory.
	ConfigPaths []string
	// BinaryNames are executable names to check in PATH for detection.
	BinaryNames []string
	Format      ConfigFormat
	// RootKey is the top-level config key (e.g. "mcpServers" or "mcp_servers").
	RootKey string
	// ServerKey is the key used for the OpenPass server entry inside RootKey.
	ServerKey string
	// ServerConfigExtras are extra fields merged into the server config entry.
	// Used to add agent-specific fields like "type", "enabled", etc.
	ServerConfigExtras map[string]any
}

var (
	// agentDefs maps supported agent types to their definitions.
	agentDefs = map[AgentType]AgentDefinition{
		AgentOpenClaw: {
			Type:        AgentOpenClaw,
			DisplayName: "OpenClaw",
			ConfigPaths: []string{
				"~/.config/openclaw/mcp.json",
				"~/.openclaw/mcp.json",
			},
			BinaryNames: []string{"openclaw"},
			Format:      FormatJSON,
			RootKey:     "mcpServers",
			ServerKey:   "openpass",
		},
		AgentClaudeCode: {
			Type:        AgentClaudeCode,
			DisplayName: "Claude Code",
			ConfigPaths: []string{
				"~/.claude/settings.json",
				"~/.claude/settings.local.json",
			},
			BinaryNames: []string{"claude", "claude-code"},
			Format:      FormatJSON,
			RootKey:     "mcpServers",
			ServerKey:   "openpass",
		},
		AgentHermes: {
			Type:        AgentHermes,
			DisplayName: "Hermes",
			ConfigPaths: []string{
				"~/.config/hermes/mcp.yaml",
				"~/.hermes/mcp.yaml",
				"~/.config/hermes/mcp.yml",
				"~/.hermes/mcp.yml",
			},
			BinaryNames: []string{"hermes"},
			Format:      FormatYAML,
			RootKey:     "mcp_servers",
			ServerKey:   "openpass",
		},
		AgentCodex: {
			Type:        AgentCodex,
			DisplayName: "Codex",
			ConfigPaths: []string{
				"~/.codex/config.toml",
			},
			BinaryNames: []string{"codex"},
			Format:      FormatTOML,
			RootKey:     "mcp_servers",
			ServerKey:   "openpass",
		},
		AgentOpenCode: {
			Type:        AgentOpenCode,
			DisplayName: "OpenCode",
			ConfigPaths: []string{
				"~/.config/opencode/opencode.json",
				"opencode.json",
			},
			BinaryNames: []string{"opencode"},
			Format:      FormatJSON,
			RootKey:     "mcp",
			ServerKey:   "openpass",
			ServerConfigExtras: map[string]any{
				"type":    "remote",
				"enabled": true,
			},
		},
	}

	// osStat is swappable for testing.
	osStat = os.Stat
	// osLookupEnv is swappable for testing.
	osLookupEnv = os.LookupEnv
	// osUserHomeDir is swappable for testing.
	osUserHomeDir = os.UserHomeDir
)

// IsSupportedAgent reports whether the given agent name is supported.
func IsSupportedAgent(name string) bool {
	_, ok := agentDefs[AgentType(name)]
	return ok
}

// SupportedAgents returns all supported agent types.
func SupportedAgents() []AgentType {
	result := make([]AgentType, 0, len(agentDefs))
	for _, def := range agentDefs {
		result = append(result, def.Type)
	}
	return result
}

// GetAgentDefinition returns the definition for an agent type.
func GetAgentDefinition(agentType AgentType) (AgentDefinition, error) {
	def, ok := agentDefs[agentType]
	if !ok {
		return AgentDefinition{}, fmt.Errorf("unsupported agent %q (valid: openclaw, claude-code, hermes, codex, opencode)", agentType)
	}
	return def, nil
}

// ExpandHome replaces a leading ~ with the user's home directory.
func ExpandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := osUserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:]), nil
	}
	return filepath.Join(home, path[1:]), nil
}

// normalizeAgentName maps common aliases to canonical agent names.
func normalizeAgentName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "claude", "claude-code", "claude_code", "claudedesktop":
		return string(AgentClaudeCode)
	case "openclaw":
		return string(AgentOpenClaw)
	case "hermes":
		return string(AgentHermes)
	case "codex":
		return string(AgentCodex)
	case "opencode":
		return string(AgentOpenCode)
	default:
		return lower
	}
}

// ParseAgentType normalizes and validates an agent name.
func ParseAgentType(name string) (AgentType, error) {
	canonical := normalizeAgentName(name)
	agent := AgentType(canonical)
	if _, ok := agentDefs[agent]; !ok {
		valid := make([]string, 0, len(agentDefs))
		for t := range agentDefs {
			valid = append(valid, string(t))
		}
		return "", fmt.Errorf("unsupported agent %q (valid: %s)", name, strings.Join(valid, ", "))
	}
	return agent, nil
}
