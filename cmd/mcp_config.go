package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/mcp"
)

var mcpConfigCmd = &cobra.Command{
	Use:   "mcp-config <agent>",
	Short: "Output MCP config snippet for an AI tool",
	Long: `Generate the MCP server configuration snippet for a specific AI tool.

The default output is generic JSON that can be pasted into an MCP client
configuration. Use --format for agent-specific formats:
  - generic:  JSON stdio/HTTP (default)
  - hermes:    YAML hermes-specific (write-capable)
  - claude-code: YAML for Claude Code (write-capable)
  - codex:     YAML for Codex (read-only)
  - opencode:  YAML for OpenCode (read-only)
  - openclaw:  YAML for OpenClaw (write-capable)

By default, output uses stdio transport; use --http for HTTP transport.

HTTP config output uses a token reference (env:OPENPASS_MCP_TOKEN) by default.
Use --include-token only when you explicitly want to print the raw bearer token.

Use --token-only to output just the raw token (for use in scripts).`,
	Example: `  # Generic JSON snippet for any MCP client
  openpass mcp-config claude-code

  # YAML for Claude Code, HTTP transport with a token reference
  openpass mcp-config claude-code --format claude-code --http

  # Just the token (for use in scripts)
  openpass mcp-config claude-code --token-only`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent install <agent> --config-only", nil)
	},
}

var mcpTokenRotateCmd = &cobra.Command{
	Use:   "mcp-token-rotate",
	Short: "Rotate the MCP HTTP bearer token",
	Long: `Generate a new MCP HTTP bearer token, invalidating the previous one.

This command generates a new 32-byte random token and writes it to the
mcp-token file in your vault directory. Any MCP clients using the old token
will need to be updated with the new token.

After rotating, run 'openpass mcp-config [agent] --http' to see the new token.`,
	Example: `  # Rotate the bearer token and show the new value
  openpass mcp-token-rotate

  # Followed by re-issuing config snippets to all agents
  openpass mcp-config claude-code --http`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vDir, err := vaultPath()
		if err != nil {
			return err
		}

		tokenPath := filepath.Join(vDir, "mcp-token")
		newToken, err := mcp.RotateToken(tokenPath)
		if err != nil {
			return fmt.Errorf("rotate token: %w", err)
		}

		printQuietAware("Token rotated successfully. New token: %s\n", newToken)
		printQuietAware("Token stored at: %s\n", tokenPath)
		printlnQuietAware("\nWarning: Any MCP clients using the old token will no longer work.")
		printlnQuietAware("Update their configuration with the new token.")
		return nil
	},
}

type httpConfig struct {
	Header map[string]string
	URL    string
}

func resolveHTTPConfig(agentName string, tokenID string) (*httpConfig, error) {
	vDir, err := vaultPath()
	if err != nil {
		return nil, err
	}

	bind := "127.0.0.1" //nolint:goconst // Loopback default is self-documenting
	configuredPort := 8080

	cfgPath := filepath.Join(vDir, "config.yaml")
	if cfg, cfgErr := loadConfigSilent(cfgPath); cfgErr == nil && cfg.MCP != nil {
		if cfg.MCP.Bind != "" {
			bind = cfg.MCP.Bind
		}
		if cfg.MCP.Port > 0 {
			configuredPort = cfg.MCP.Port
		}
	}

	port, err := resolveHTTPPort(vDir, bind, configuredPort)
	if err != nil {
		return nil, err
	}

	var token string
	if tokenID != "" {
		registry, _, loadErr := mcp.LoadTokenSystem(vDir)
		if loadErr != nil {
			return nil, fmt.Errorf("load token registry: %w", loadErr)
		}
		found := false
		list := registry.List()
		for i := range list {
			if list[i].ID == tokenID {
				token = list[i].Hash
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("token %q not found in registry", tokenID)
		}
	} else {
		tokenPath := filepath.Join(vDir, "mcp-token")
		if cfg, cfgErr := loadConfigSilent(cfgPath); cfgErr == nil && cfg.MCP != nil {
			if cfg.MCP.HTTPTokenFile != "" && cfg.MCP.HTTPTokenFile != "auto" {
				tokenPath = cfg.MCP.HTTPTokenFile
			}
		}
		token, err = mcp.LoadOrCreateToken(tokenPath)
		if err != nil {
			return nil, fmt.Errorf("load token: %w", err)
		}
	}

	return &httpConfig{
		URL: fmt.Sprintf("http://%s:%d/mcp", bind, port),
		Header: map[string]string{
			"Accept":               "application/json, text/event-stream",
			"Authorization":        "Bearer " + token,
			"MCP-Protocol-Version": mcp.LatestSupportedProtocolVersion,
			"X-OpenPass-Agent":     agentName,
		},
	}, nil
}

func stdioArgs(agentName string) []string {
	args := []string{}
	vDir, err := vaultPath()
	if err == nil && shouldIncludeVaultArg(vDir) {
		args = append(args, "--vault", vDir)
	}
	args = append(args, "serve", "--stdio", "--agent", agentName)
	return args
}

func shouldIncludeVaultArg(vDir string) bool {
	defaultVault, err := expandVaultDir("~/.openpass")
	if err != nil {
		return false
	}
	return filepath.Clean(vDir) != filepath.Clean(defaultVault)
}

func resolveHTTPPort(vaultDir string, bind string, configuredPort int) (int, error) {
	if port, ok := loadRuntimePort(vaultDir); ok {
		if err := checkRuntimePortHealth(bind, port); err != nil {
			return 0, fmt.Errorf("stale runtime port %d from %s: %w; remove %s or restart 'openpass serve'", port, filepath.Join(vaultDir, runtimePortFileName), err, filepath.Join(vaultDir, runtimePortFileName))
		}
		return port, nil
	}
	if configuredPort > 0 {
		return configuredPort, nil
	}
	return 8080, nil
}

func checkRuntimePortHealth(bind string, port int) error {
	host := bind
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	url := fmt.Sprintf("http://%s:%d/health", strings.Trim(host, "[]"), port)
	client := http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(url) //nolint:gosec // #nosec G107 — local health check for configured MCP server
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func outputStdioConfig(agentName, serverName string) error {
	config := map[string]any{
		"mcpServers": map[string]any{
			serverName: map[string]any{
				"command": "openpass",
				"args":    stdioArgs(agentName),
			},
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(config)
}

func outputHermesStdioConfig(agentName, serverName string) error {
	config := map[string]any{
		"mcp_servers": map[string]any{
			serverName: map[string]any{
				"command": "openpass",
				"args":    stdioArgs(agentName),
				"timeout": 120,
			},
		},
	}

	enc := yaml.NewEncoder(os.Stdout)
	defer func() { _ = enc.Close() }()
	return enc.Encode(config)
}

func outputHTTPConfig(agentName, serverName string, redact bool, tokenID string) error {
	httpCfg, err := resolveHTTPConfig(agentName, tokenID)
	if err != nil {
		return err
	}

	authValue := httpCfg.Header["Authorization"]
	if redact {
		authValue = "env:OPENPASS_MCP_TOKEN" //nolint:goconst // Redaction placeholder string
	}

	config := map[string]any{
		"server_name": serverName,
		"url":         httpCfg.URL,
		"headers": map[string]string{
			"Accept":               httpCfg.Header["Accept"],
			"Authorization":        authValue,
			"MCP-Protocol-Version": httpCfg.Header["MCP-Protocol-Version"],
			"X-OpenPass-Agent":     httpCfg.Header["X-OpenPass-Agent"],
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(config)
}

func outputHermesHTTPConfig(agentName, serverName string, redact bool, tokenID string) error {
	httpCfg, err := resolveHTTPConfig(agentName, tokenID)
	if err != nil {
		return err
	}

	authValue := httpCfg.Header["Authorization"]
	if redact {
		authValue = "env:OPENPASS_MCP_TOKEN" //nolint:goconst // Redaction placeholder string
	}

	headers := map[string]string{
		"Accept":               httpCfg.Header["Accept"],
		"Authorization":        authValue,
		"MCP-Protocol-Version": httpCfg.Header["MCP-Protocol-Version"],
		"X-OpenPass-Agent":     httpCfg.Header["X-OpenPass-Agent"],
	}

	config := map[string]any{
		"mcp_servers": map[string]any{
			serverName: map[string]any{
				"url":             httpCfg.URL,
				"headers":         headers,
				"timeout":         120,
				"connect_timeout": 30,
			},
		},
	}

	enc := yaml.NewEncoder(os.Stdout)
	defer func() { _ = enc.Close() }()
	return enc.Encode(config)
}

// outputAgentStdioConfig outputs YAML stdio config for agent-specific formats.
// serverKey is the key name in mcp_servers (e.g., "claude_code", "codex").
// agentName is passed to openpass serve (e.g., "claude-code", "codex").
//
// Verification: openpass mcp-config claude-code --format claude-code | paste into Claude Desktop config
func outputAgentStdioConfig(agentName, serverKey string) error {
	config := map[string]any{
		"mcp_servers": map[string]any{
			serverKey: map[string]any{
				"command": "openpass",
				"args":    stdioArgs(agentName),
				"timeout": 120,
			},
		},
	}

	enc := yaml.NewEncoder(os.Stdout)
	defer func() { _ = enc.Close() }()
	return enc.Encode(config)
}

// outputAgentHTTPConfig outputs YAML HTTP config for agent-specific formats.
// serverKey is the key name in mcp_servers.
// agentName is passed to openpass serve and X-OpenPass-Agent header.
// redact outputs env:OPENPASS_MCP_TOKEN instead of the actual token.
//
// Verification: openpass mcp-config claude-code --http --format claude-code | paste into Claude Desktop config
// Then verify: curl -H "Authorization: Bearer $(cat ~/.openpass/mcp-token)" http://127.0.0.1:8080/mcp
func outputAgentHTTPConfig(agentName, serverKey, displayName string, redact bool, tokenID string) error {
	httpCfg, err := resolveHTTPConfig(agentName, tokenID)
	if err != nil {
		return err
	}

	authValue := httpCfg.Header["Authorization"]
	if redact {
		authValue = "env:OPENPASS_MCP_TOKEN" //nolint:goconst // Redaction placeholder string
	}

	headers := map[string]string{
		"Accept":               httpCfg.Header["Accept"],
		"Authorization":        authValue,
		"MCP-Protocol-Version": httpCfg.Header["MCP-Protocol-Version"],
		"X-OpenPass-Agent":     httpCfg.Header["X-OpenPass-Agent"],
	}

	config := map[string]any{
		"mcp_servers": map[string]any{
			serverKey: map[string]any{
				"url":             httpCfg.URL,
				"headers":         headers,
				"timeout":         120,
				"connect_timeout": 30,
			},
		},
	}

	_ = displayName
	enc := yaml.NewEncoder(os.Stdout)
	defer func() { _ = enc.Close() }()
	return enc.Encode(config)
}

func init() {
	rootCmd.AddCommand(mcpConfigCmd)
	rootCmd.AddCommand(mcpTokenRotateCmd)
	mcpConfigCmd.Flags().Bool("http", false, "Output HTTP-based config instead of stdio")
	mcpConfigCmd.Flags().String("format", "generic", "Output format: generic, hermes, claude-code, codex, opencode, openclaw")
	mcpConfigCmd.Flags().String("server-name", "openpass", "MCP server name for formats that wrap server config")
	mcpConfigCmd.Flags().Bool("redact", false, "Output token reference (env:OPENPASS_MCP_TOKEN); kept for explicitness because this is the default")
	mcpConfigCmd.Flags().Bool("include-token", false, "Include the raw HTTP bearer token in config output")
	mcpConfigCmd.Flags().Bool("token-only", false, "Output just the raw token (for scripts)")
	mcpConfigCmd.Flags().String("token-id", "", "Use a specific scoped token for HTTP auth")
}

func outputTokenOnly() error {
	vDir, err := vaultPath()
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(vDir, "config.yaml")
	tokenPath := filepath.Join(vDir, "mcp-token")
	if cfg, cfgErr := loadConfigSilent(cfgPath); cfgErr == nil && cfg.MCP != nil {
		if cfg.MCP.HTTPTokenFile != "" && cfg.MCP.HTTPTokenFile != "auto" {
			tokenPath = cfg.MCP.HTTPTokenFile
		}
	}

	token, err := mcp.LoadOrCreateToken(tokenPath)
	if err != nil {
		return fmt.Errorf("load token: %w", err)
	}

	fmt.Println(token)
	return nil
}

// loadConfigSilent loads config without erroring if file doesn't exist.
func loadConfigSilent(path string) (*configpkg.Config, error) {
	return configpkg.Load(path)
}
