package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	auth "github.com/danieljustus/OpenPass/internal/mcp/auth"
	server "github.com/danieljustus/OpenPass/internal/mcp/server"
)

var McpConfigCmd = &cobra.Command{
	Use:   "mcp-config <agent>",
	Short: "[Deprecated v4.0, removed in v4.1] Use 'openpass agent install <agent> --config-only'",
	Long: `This command was deprecated in OpenPass v4.0 and will be removed in v4.1.

Use 'openpass agent install <agent> --config-only' to output MCP config snippets.`,
	Example: `  openpass agent install claude-code --config-only`,
	Hidden: true,
	Args:   cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(os.Stderr, "This command is deprecated in v4.0. Use: openpass agent install <agent> --config-only\n")
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent install <agent> --config-only", nil)
	},
}

var mcpTokenRotateCmd = &cobra.Command{
	Use:   "mcp-token-rotate",
	Short: "[Deprecated v4.0, removed in v4.1] Use 'openpass agent token <name> rotate'",
	Long: `This command was deprecated in OpenPass v4.0 and will be removed in v4.1.

Token rotation is now managed per-agent via 'openpass agent token <name> rotate'.`,
	Example: `  openpass agent token my-agent rotate`,
	Hidden: true,
	Args:   cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(os.Stderr, "This command is deprecated in v4.0. Use: openpass agent token <name> rotate\n")
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent token <name> rotate", nil)
	},
}

type httpConfig struct {
	Header map[string]string
	URL    string
}

func resolveHTTPConfig(agentName string, tokenID string) (*httpConfig, error) {
	vDir, err := cli.VaultPath()
	if err != nil {
		return nil, err
	}

	bind := "127.0.0.1" //nolint:goconst // Loopback default is self-documenting
	configuredPort := 8080

	cfgPath := filepath.Join(vDir, "config.yaml")
	if cfg, cfgErr := LoadConfigSilent(cfgPath); cfgErr == nil && cfg.MCP != nil {
		if cfg.MCP.Bind != "" {
			bind = cfg.MCP.Bind
		}
		if cfg.MCP.Port > 0 {
			configuredPort = cfg.MCP.Port
		}
	}

	port, err := ResolveHTTPPort(vDir, bind, configuredPort)
	if err != nil {
		return nil, err
	}

	var token string
	if tokenID != "" {
		registry, _, loadErr := auth.LoadTokenSystem(vDir)
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
		if cfg, cfgErr := LoadConfigSilent(cfgPath); cfgErr == nil && cfg.MCP != nil {
			if cfg.MCP.HTTPTokenFile != "" && cfg.MCP.HTTPTokenFile != "auto" {
				tokenPath = cfg.MCP.HTTPTokenFile
			}
		}
		token, err = auth.LoadOrCreateToken(tokenPath)
		if err != nil {
			return nil, fmt.Errorf("load token: %w", err)
		}
	}

	return &httpConfig{
		URL: fmt.Sprintf("http://%s:%d/mcp", bind, port),
		Header: map[string]string{
			"Accept":               "application/json, text/event-stream",
			"Authorization":        "Bearer " + token,
			"MCP-Protocol-Version": server.LatestSupportedProtocolVersion,
			"X-OpenPass-Agent":     agentName,
		},
	}, nil
}

func stdioArgs(agentName string) []string {
	args := []string{}
	vDir, err := cli.VaultPath()
	if err == nil && shouldIncludeVaultArg(vDir) {
		args = append(args, "--vault", vDir)
	}
	args = append(args, "serve", "--stdio", "--agent", agentName)
	return args
}

func shouldIncludeVaultArg(vDir string) bool {
	defaultVault, err := cli.ExpandVaultDir("~/.openpass")
	if err != nil {
		return false
	}
	return filepath.Clean(vDir) != filepath.Clean(defaultVault)
}

func ResolveHTTPPort(vaultDir string, bind string, configuredPort int) (int, error) {
	if port, ok := cli.LoadRuntimePort(vaultDir); ok {
		if err := CheckRuntimePortHealth(bind, port); err != nil {
			return 0, fmt.Errorf("stale runtime port %d from %s: %w; remove %s or restart 'openpass serve'", port, filepath.Join(vaultDir, cli.RuntimePortFileName), err, filepath.Join(vaultDir, cli.RuntimePortFileName))
		}
		return port, nil
	}
	if configuredPort > 0 {
		return configuredPort, nil
	}
	return 8080, nil
}

func CheckRuntimePortHealth(bind string, port int) error {
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

func OutputStdioConfig(agentName, serverName string) error {
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

func OutputHermesStdioConfig(agentName, serverName string) error {
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

func OutputHTTPConfig(agentName, serverName string, redact bool, tokenID string) error {
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

func OutputHermesHTTPConfig(agentName, serverName string, redact bool, tokenID string) error {
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

// OutputAgentStdioConfig outputs YAML stdio config for agent-specific formats.
// serverKey is the key name in mcp_servers (e.g., "claude_code", "codex").
// agentName is passed to openpass serve (e.g., "claude-code", "codex").
//
// Verification: openpass mcp-config claude-code --format claude-code | paste into Claude Desktop config
func OutputAgentStdioConfig(agentName, serverKey string) error {
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

// OutputAgentHTTPConfig outputs YAML HTTP config for agent-specific formats.
// serverKey is the key name in mcp_servers.
// agentName is passed to openpass serve and X-OpenPass-Agent header.
// redact outputs env:OPENPASS_MCP_TOKEN instead of the actual token.
//
// Verification: openpass mcp-config claude-code --http --format claude-code | paste into Claude Desktop config
// Then verify: curl -H "Authorization: Bearer $(cat ~/.openpass/mcp-token)" http://127.0.0.1:8080/mcp
func OutputAgentHTTPConfig(agentName, serverKey, displayName string, redact bool, tokenID string) error {
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
	cli.RootCmd.AddCommand(McpConfigCmd)
	cli.RootCmd.AddCommand(mcpTokenRotateCmd)
}

func OutputTokenOnly() error {
	vDir, err := cli.VaultPath()
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(vDir, "config.yaml")
	tokenPath := filepath.Join(vDir, "mcp-token")
	if cfg, cfgErr := LoadConfigSilent(cfgPath); cfgErr == nil && cfg.MCP != nil {
		if cfg.MCP.HTTPTokenFile != "" && cfg.MCP.HTTPTokenFile != "auto" {
			tokenPath = cfg.MCP.HTTPTokenFile
		}
	}

	token, err := auth.LoadOrCreateToken(tokenPath)
	if err != nil {
		return fmt.Errorf("load token: %w", err)
	}

	fmt.Println(token)
	return nil
}

// LoadConfigSilent loads config without erroring if file doesn't exist.
func LoadConfigSilent(path string) (*configpkg.Config, error) {
	return configpkg.Load(path)
}
