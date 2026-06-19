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

var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start MCP server for agent access",
	Long:  serveLongDescription(),
	Example: `  # HTTP mode bound to localhost:8080
  symvault serve --bind 127.0.0.1 --port 8080

  # stdio mode for a single agent (called by MCP clients directly)
  symvault serve --stdio --agent claude-code

  # Install as a system service (macOS launchd or systemd)
  symvault serve install`,
	RunE: runServe,
}

func init() {
	cli.RootCmd.AddCommand(ServeCmd)
	ServeCmd.Flags().String("agent", "", "Agent name (required for --stdio; HTTP mode resolves agents per-request via X-Symaira-Agent header)")
	ServeCmd.Flags().Int("port", 8080, "Server port")
	ServeCmd.Flags().Bool("stdio", false, "Enable stdio transport (for MCP)")
	ServeCmd.Flags().String("bind", "127.0.0.1", "Bind address for HTTP server")
	ServeCmd.Flags().String("tls-cert", "", "TLS certificate file path (overrides config)")
	ServeCmd.Flags().String("tls-key", "", "TLS key file path (overrides config)")
	ServeCmd.Flags().String("tls-ca", "", "CA certificate file path for mTLS client verification (enables mTLS)")
	ServeCmd.Flags().Bool("allow-locked", false, "Allow the MCP server to start even when the vault is locked (stdio mode only)")
}
