package mcp

import (
	"fmt"
	"maps"
	"time"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	auth "github.com/danieljustus/symaira-vault/internal/mcp/auth"
	"github.com/danieljustus/symaira-vault/internal/mcp/install"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

var mcpInstallCmd = &cobra.Command{
	Use:   "install [agent]",
	Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent install [agent]'",
	Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

Use 'symvault agent install [agent]' instead to install and configure
AI agents with proper security profiles.`,
	Example: `  symvault agent install [agent]`,
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent install [agent]")
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: symvault agent install [agent]", nil)
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
		"command": "symvault",
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
		regPath := auth.TokenRegistryFilePath(vDir)
		reg := auth.NewTokenRegistry(regPath)
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
			"X-Symaira-Agent":      httpCfg.Header["X-Symaira-Agent"],
		},
	}

	if def, err := install.GetAgentDefinition(install.AgentType(agentName)); err == nil {
		maps.Copy(config, def.ServerConfigExtras)
	}

	return config, tokenID, nil
}

func init() {
	mcpCmd.AddCommand(mcpInstallCmd)
}
