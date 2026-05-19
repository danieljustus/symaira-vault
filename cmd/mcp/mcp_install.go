package mcp

import (
	"fmt"
	"maps"
	"time"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/mcp/install"
)

var mcpInstallCmd = &cobra.Command{
	Use:   "install [agent]",
	Short: "Auto-configure an AI agent to use the OpenPass MCP server",
	Example: `  # Install MCP integration for Claude Code (auto-detected)
  openpass mcp install claude-code

  # HTTP mode with a fresh scoped token
  openpass mcp install claude-code --http

  # List installed agent integrations
  openpass mcp install --list`,
	Long: `Automatically detect and configure a supported AI agent to use the OpenPass MCP server.

Supported agents:
  - openclaw    (OpenClaw)
  - claude-code (Claude Code)
  - hermes      (Hermes)
  - codex       (OpenAI Codex CLI)
  - opencode    (OpenCode)

The command detects if the agent is installed, finds its MCP config file,
and injects the OpenPass server configuration. When using HTTP mode, a
scoped token is automatically generated for the agent.

The operation is idempotent: running it multiple times will not create
duplicate entries.

Examples:
  openpass mcp install openclaw
  openpass mcp install claude-code --http
  openpass mcp install --auto-detect
  openpass mcp install hermes --dry-run`,
	Args: func(cmd *cobra.Command, args []string) error {
		autoDetect, _ := cmd.Flags().GetBool("auto-detect")
		if autoDetect {
			if len(args) > 0 {
				return fmt.Errorf("cannot specify an agent with --auto-detect")
			}
			return nil
		}
		if len(args) != 1 {
			return fmt.Errorf("requires exactly 1 arg (agent name), or use --auto-detect")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent install [agent]", nil)
	},
}

func buildServerConfig(vDir, agentName string, httpMode, dryRun bool) (map[string]any, string, error) {
	if httpMode {
		return buildHTTPServerConfig(vDir, agentName, dryRun)
	}
	return buildStdioServerConfig(agentName), "", nil
}

func buildStdioServerConfig(agentName string) map[string]any {
	return map[string]any{
		"command": "openpass",
		"args":    stdioArgs(agentName),
		"timeout": 120,
	}
}

func buildHTTPServerConfig(vDir, agentName string, dryRun bool) (map[string]any, string, error) {
	httpCfg, err := resolveHTTPConfig(agentName, "")
	if err != nil {
		return nil, "", err
	}

	var rawToken string
	var tokenID string

	if !dryRun {
		// Create a scoped token for this agent.
		regPath := mcp.TokenRegistryFilePath(vDir)
		reg := mcp.NewTokenRegistry(regPath)
		if loadErr := reg.Load(); loadErr != nil {
			return nil, "", fmt.Errorf("load token registry: %w", loadErr)
		}

		token, rt, err := reg.Create(
			fmt.Sprintf("mcp-install-%s", agentName),
			[]string{"*"},
			agentName,
			30*24*time.Hour, // 30 days default
		)
		if err != nil {
			return nil, "", fmt.Errorf("create scoped token: %w", err)
		}
		if err := reg.Save(); err != nil {
			return nil, "", fmt.Errorf("save token registry: %w", err)
		}
		rawToken = rt
		tokenID = token.ID
	} else {
		// Use a deterministic preview token so dry-run output is stable.
		rawToken = "<dry-run-preview-token>" // #nosec G101 — placeholder for dry-run mode, not a real credential
		tokenID = "<not-generated-dry-run>"
	}

	// Use the raw token directly in the config instead of env reference
	// since this is an automated install.
	config := map[string]any{
		"url":             httpCfg.URL,
		"timeout":         120,
		"connect_timeout": 30,
		"headers": map[string]string{
			"Accept":               httpCfg.Header["Accept"],
			"Authorization":        "Bearer " + rawToken,
			"MCP-Protocol-Version": httpCfg.Header["MCP-Protocol-Version"],
			"X-OpenPass-Agent":     httpCfg.Header["X-OpenPass-Agent"],
		},
	}

	if def, err := install.GetAgentDefinition(install.AgentType(agentName)); err == nil {
		maps.Copy(config, def.ServerConfigExtras)
	}

	return config, tokenID, nil
}

func init() {
	mcpCmd.AddCommand(mcpInstallCmd)
	mcpInstallCmd.Flags().Bool("dry-run", false, "Preview changes without applying them")
	mcpInstallCmd.Flags().Bool("auto-detect", false, "Detect all installed agents and configure them")
	mcpInstallCmd.Flags().Bool("http", false, "Use HTTP transport with auto-generated bearer token")
	mcpInstallCmd.Flags().Bool("stdio", true, "Use stdio transport (default)")
}
