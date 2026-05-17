package cmd

import (
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/spf13/cobra"

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
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		autoDetect, _ := cmd.Flags().GetBool("auto-detect")
		httpMode, _ := cmd.Flags().GetBool("http")
		stdioMode, _ := cmd.Flags().GetBool("stdio")
		httpFlag := cmd.Flags().Lookup("http")
		stdioFlag := cmd.Flags().Lookup("stdio")

		// Determine transport mode: default to stdio unless --http is explicitly set.
		useHTTP := false
		if httpFlag != nil && httpFlag.Changed {
			useHTTP = httpMode
		} else if stdioFlag != nil && stdioFlag.Changed && !stdioMode {
			useHTTP = true
		}

		if httpFlag != nil && httpFlag.Changed && stdioFlag != nil && stdioFlag.Changed {
			return fmt.Errorf("--http and --stdio cannot be used together")
		}

		vDir, err := vaultPath()
		if err != nil {
			return err
		}

		if autoDetect {
			return runAutoDetect(vDir, dryRun, useHTTP)
		}

		agentName := args[0]
		agentType, err := install.ParseAgentType(agentName)
		if err != nil {
			return err
		}

		return runInstall(vDir, agentType, dryRun, useHTTP)
	},
}

func runInstall(vDir string, agentType install.AgentType, dryRun, httpMode bool) error {
	def, err := install.GetAgentDefinition(agentType)
	if err != nil {
		return err
	}

	// Detect agent.
	detectResult, err := install.DetectAgent(agentType)
	if err != nil {
		return err
	}

	if !detectResult.Detected {
		return fmt.Errorf("agent %q not detected (checked binary in PATH and config files)", def.DisplayName)
	}

	// Generate server config.
	serverConfig, tokenID, err := buildServerConfig(vDir, string(agentType), httpMode, dryRun)
	if err != nil {
		return err
	}

	// Determine config path.
	configPath := detectResult.ConfigPath
	if configPath == "" {
		configPath, err = install.ResolveConfigPath(agentType)
		if err != nil {
			return err
		}
	}

	// Backup existing config before modifying.
	var backupPath string
	if !dryRun {
		backupPath, _ = install.BackupConfig(configPath)
	}

	// Run install.
	result, err := install.Install(install.InstallOptions{
		AgentType:    agentType,
		ServerConfig: serverConfig,
		Format:       def.Format,
		ConfigPath:   configPath,
		DryRun:       dryRun,
	})
	if err != nil {
		return fmt.Errorf("install failed for %s: %w", def.DisplayName, err)
	}

	result.TokenID = tokenID

	// Print result.
	printInstallResult(result, dryRun, backupPath)
	return nil
}

func runAutoDetect(vDir string, dryRun, httpMode bool) error {
	detected := install.DetectAllAgents()
	if len(detected) == 0 {
		printlnQuietAware("No supported agents detected.")
		return nil
	}

	var errors []string
	for agentType, detectResult := range detected {
		if !detectResult.Detected {
			continue
		}
		def, _ := install.GetAgentDefinition(agentType)
		printQuietAware("Detected %s\n", def.DisplayName)

		if err := runInstall(vDir, agentType, dryRun, httpMode); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", def.DisplayName, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during auto-detect:\n  %s", strings.Join(errors, "\n  "))
	}
	return nil
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
		rawToken = "<dry-run-preview-token>"
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

func printInstallResult(result *install.Result, dryRun bool, backupPath string) {
	def, _ := install.GetAgentDefinition(result.AgentType)

	if result.WasUnchanged {
		printQuietAware("%s is already configured for OpenPass MCP (no changes needed)\n", def.DisplayName)
		return
	}

	action := "Configured"
	if dryRun {
		action = "[DRY-RUN] Would configure"
	}

	if result.WasCreated {
		printQuietAware("%s %s for OpenPass MCP (new config file)\n", action, def.DisplayName)
	} else if result.WasUpdated {
		printQuietAware("%s %s for OpenPass MCP (updated existing config)\n", action, def.DisplayName)
	}

	printQuietAware("  Config path: %s\n", result.ConfigPath)
	if backupPath != "" {
		printQuietAware("  Backup:      %s\n", backupPath)
	}
	if result.TokenID != "" {
		if result.TokenID == "<not-generated-dry-run>" {
			printQuietAware("  Token ID:    <not generated (dry-run)>\n")
		} else {
			printQuietAware("  Token ID:    %s\n", result.TokenID)
		}
	}
}

func init() {
	mcpCmd.AddCommand(mcpInstallCmd)
	mcpInstallCmd.Flags().Bool("dry-run", false, "Preview changes without applying them")
	mcpInstallCmd.Flags().Bool("auto-detect", false, "Detect all installed agents and configure them")
	mcpInstallCmd.Flags().Bool("http", false, "Use HTTP transport with auto-generated bearer token")
	mcpInstallCmd.Flags().Bool("stdio", true, "Use stdio transport (default)")
}
