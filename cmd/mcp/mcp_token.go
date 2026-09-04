package mcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

// McpTokenCmd is retained for API compatibility; NewCommands() uses
// newMcpTokenCmd() so every call gets a fresh command.
var McpTokenCmd = newMcpTokenCmd()

func newMcpTokenCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "token",
		Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token <action> <name>'",
		Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

Scoped token management is now available via 'symvault agent token <action> <name>'
with subcommands new, list, revoke, and rotate.`,
		Example: `  symvault agent token new my-agent`,
		Hidden:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token <new|list|revoke|rotate> <name>")
			return errorspkg.NewCLIError(errorspkg.ExitNotFound,
				"This command is deprecated in v4.0. Use: symvault agent token <new|list|revoke|rotate> <name>", nil)
		},
	}
	c.AddCommand(newTokenCreateCmd())
	c.AddCommand(newTokenListCmd())
	c.AddCommand(newTokenRevokeCmd())
	return c
}

// TokenCreateCmd is retained for API compatibility; NewCommands() uses
// newTokenCreateCmd() so every call gets a fresh command.
var TokenCreateCmd = newTokenCreateCmd()

func newTokenCreateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "create",
		Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token new <name>'",
		Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

Create scoped tokens via 'symvault agent token new <name>'.`,
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token new <name>")
			return errorspkg.NewCLIError(errorspkg.ExitNotFound,
				"This command is deprecated in v4.0. Use: symvault agent token new <name>", nil)
		},
	}
	return c
}

func newTokenListCmd() *cobra.Command {
	tokenListCmd := &cobra.Command{
		Use:   "list",
		Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token list <name>'",
		Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

List tokens via 'symvault agent token list <name>'.`,
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token list <name>")
			return errorspkg.NewCLIError(errorspkg.ExitNotFound,
				"This command is deprecated in v4.0. Use: symvault agent token list <name>", nil)
		},
	}
	return tokenListCmd
}

func newTokenRevokeCmd() *cobra.Command {
	tokenRevokeCmd := &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "[Deprecated v4.0, removed in v4.1] Use 'symvault agent token revoke <name> <token-id>'",
		Long: `This command was deprecated in Symaira Vault v4.0 and will be removed in v4.1.

Revoke tokens via 'symvault agent token revoke <name> <token-id>'.`,
		Hidden: true,
		Args:   cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliout.Warnf("This command is deprecated in v4.0. Use: symvault agent token revoke <name> <token-id>")
			return errorspkg.NewCLIError(errorspkg.ExitNotFound,
				"This command is deprecated in v4.0. Use: symvault agent token revoke <name> <token-id>", nil)
		},
	}
	return tokenRevokeCmd
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
