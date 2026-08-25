package mcp

import (
	"fmt"
	"os/signal"
	"path/filepath"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/config"

	"github.com/spf13/cobra"
)

var ServeSignalNotify = signal.Notify
var Version = "dev"

// mcpLongDescription builds the canonical mcp help text, deriving the advertised
// config location from the same resolver the binary uses so help and behavior
// cannot drift. New installs use the XDG default; existing installs may still
// read from the legacy ~/.symvault directory.
func mcpLongDescription() string {
	return fmt.Sprintf(`Start an MCP server that exposes vault operations to AI agents.

Each agent must be configured in the agents section of the config file
(default: %s; existing installs may use the legacy
~/%s/config.yaml) with specific permissions and scope restrictions.

The server can run in stdio mode or HTTP mode.`,
		filepath.Join(config.DefaultConfigDir(), "config.yaml"),
		config.LegacyVaultSubdir)
}

// serveLongDescription builds the serve help text, deriving the advertised
// config location from the same resolver the binary uses so help and behavior
// cannot drift. New installs use the XDG default; existing installs may still
// read from the legacy ~/.symvault directory.
func serveLongDescription() string {
	return fmt.Sprintf(`Start an MCP server that exposes vault operations to AI agents.

Each agent must be configured in the agents section of the config file
(default: %s; existing installs may use the legacy
~/%s/config.yaml) with specific permissions and scope restrictions.

The server can run in HTTP mode or stdio mode.`,
		filepath.Join(config.DefaultConfigDir(), "config.yaml"),
		config.LegacyVaultSubdir)
}

// McpCmd is retained for API compatibility; NewCommands() uses
// newMcpCmd() so every call gets a fresh command.
var McpCmd = newMcpCmd()

func newMcpCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP server for agent access",
		Long:  mcpLongDescription(),
		Example: `  # stdio mode for a single agent (called by MCP clients directly, canonical)
  symvault mcp --stdio --agent claude-code

  # HTTP mode bound to localhost:8080
  symvault mcp --bind 127.0.0.1 --port 8080

  # Install as a system service (macOS launchd or systemd)
  symvault mcp install`,
		RunE: runServe,
	}
	c.GroupID = cli.GroupIDAgentsMCP
	c.Flags().String("agent", "", "Agent name (required for --stdio; HTTP mode resolves agents per-request via X-Symaira-Agent header)")
	c.Flags().Int("port", 8080, "Server port")
	c.Flags().Bool("stdio", false, "Enable stdio transport (for MCP)")
	c.Flags().String("bind", "127.0.0.1", "Bind address for HTTP server")
	c.Flags().String("tls-cert", "", "TLS certificate file path (overrides config)")
	c.Flags().String("tls-key", "", "TLS key file path (overrides config)")
	c.Flags().String("tls-ca", "", "CA certificate file path for mTLS client verification (enables mTLS)")
	c.Flags().Bool("allow-locked", false, "Allow the MCP server to start even when the vault is locked (stdio mode only)")
	c.AddCommand(newServeInstallCmd())
	c.AddCommand(newServeUninstallCmd())
	c.AddCommand(newServeStatusCmd())
	c.AddCommand(newMcpTokenCmd())
	return c
}

// ServeCmd is retained for API compatibility; NewCommands() uses
// newServeCmd() so every call gets a fresh command.
var ServeCmd = newServeCmd()

func newServeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:    "serve",
		Short:  "Start MCP server for agent access (deprecated: use 'symvault mcp')",
		Long:   serveLongDescription(),
		Hidden: true,
		Example: `  # HTTP mode bound to localhost:8080
  symvault serve --bind 127.0.0.1 --port 8080

  # stdio mode for a single agent (called by MCP clients directly)
  symvault serve --stdio --agent claude-code

  # Install as a system service (macOS launchd or systemd)
  symvault serve install`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "Warning: 'symvault serve' is deprecated, use 'symvault mcp' instead.")
			return runServe(cmd, args)
		},
	}
	c.GroupID = cli.GroupIDAgentsMCP
	c.Flags().String("agent", "", "Agent name (required for --stdio; HTTP mode resolves agents per-request via X-Symaira-Agent header)")
	c.Flags().Int("port", 8080, "Server port")
	c.Flags().Bool("stdio", false, "Enable stdio transport (for MCP)")
	c.Flags().String("bind", "127.0.0.1", "Bind address for HTTP server")
	c.Flags().String("tls-cert", "", "TLS certificate file path (overrides config)")
	c.Flags().String("tls-key", "", "TLS key file path (overrides config)")
	c.Flags().String("tls-ca", "", "CA certificate file path for mTLS client verification (enables mTLS)")
	c.Flags().Bool("allow-locked", false, "Allow the MCP server to start even when the vault is locked (stdio mode only)")
	c.AddCommand(newServeInstallCmd())
	c.AddCommand(newServeUninstallCmd())
	c.AddCommand(newServeStatusCmd())
	c.AddCommand(newMcpTokenCmd())
	return c
}
