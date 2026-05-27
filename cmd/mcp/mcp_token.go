package mcp

import (
	"fmt"
	"strings"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "[Deprecated v4.0] MCP server commands — use 'symvault agent' instead",
	Long: `MCP management commands have been replaced by the agent command group.

All MCP server functionality (install, configure, token management) is
now available via the 'symvault agent' command family.`,
	Example: `  symvault agent install claude-code`,
	Hidden:  true,
}

var McpTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token <name>'",
	Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

Scoped token management is now available via 'symvault agent token <name>'
with subcommands new, list, revoke, and rotate.`,
	Example: `  symvault agent token my-agent new`,
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token <name> new/list/revoke")
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: symvault agent token <name> new/list/revoke", nil)
	},
}

var TokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token <name> new'",
	Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

Create scoped tokens via 'symvault agent token <name> new'.`,
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token <name> new")
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: symvault agent token <name> new", nil)
	},
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token <name> list'",
	Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

List tokens via 'symvault agent token <name> list'.`,
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token <name> list")
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: symvault agent token <name> list", nil)
	},
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token <name> revoke'",
	Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

Revoke tokens via 'symvault agent token <name> revoke'.`,
	Hidden: true,
	Args:   cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token <name> revoke")
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: symvault agent token <name> revoke", nil)
	},
}

func ResolveTokenTTL(_ string, ttlFlag string) (time.Duration, error) {
	if ttlFlag != "" {
		d, err := ParseHumanDuration(ttlFlag)
		if err != nil {
			return 0, fmt.Errorf("invalid TTL %q: %w", ttlFlag, err)
		}
		return d, nil
	}

	return 24 * time.Hour, nil
}

// ParseHumanDuration parses a duration string supporting optional day suffix.
// e.g. "24h", "7d", "30m".
func ParseHumanDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}

	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := parseDurationNumber(daysStr)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("negative duration")
	}
	return d, nil
}

func parseDurationNumber(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative duration")
	}
	return n, nil
}

func init() {
	cli.RootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(McpTokenCmd)
	McpTokenCmd.AddCommand(TokenCreateCmd)
	McpTokenCmd.AddCommand(tokenListCmd)
	McpTokenCmd.AddCommand(tokenRevokeCmd)
}
