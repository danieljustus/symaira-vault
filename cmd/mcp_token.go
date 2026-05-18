package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server commands",
	Long:  `Commands for managing the Model Context Protocol (MCP) server integration.`,
	Example: `  # Generate a per-tool token
  openpass mcp token create --name "ide-tools" --tools list,get

  # List configured tokens
  openpass mcp token list`,
}

var mcpTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage MCP scoped tokens",
	Long: `Create, list, and revoke per-tool scoped tokens for MCP HTTP authentication.

Scoped tokens allow fine-grained access control for MCP clients. Each token can
be restricted to specific tools and has an optional expiration time.`,
	Example: `  # Create a read-only token expiring in 24h
   openpass mcp token create --name "ci-readonly" --tools list,get --ttl 24h

   # List all tokens
   openpass mcp token list

   # Revoke by ID
   openpass mcp token revoke <token-id>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent token <name> new/list/revoke", nil)
	},
}

var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new scoped token",
	Long: `Create a new scoped MCP token with restricted tool access.

The raw token is printed exactly once — copy it immediately. It cannot be
retrieved later.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent token <name> new", nil)
	},
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scoped tokens",
	Long:  `List all scoped tokens in the registry, including their status and expiration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent token <name> list", nil)
	},
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke a scoped token",
	Long:  `Revoke a scoped token by its ID. Revoked tokens are immediately invalidated.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return errorspkg.NewCLIError(errorspkg.ExitNotFound,
			"This command is deprecated in v4.0. Use: openpass agent token <name> revoke", nil)
	},
}

func resolveTokenTTL(_ string, ttlFlag string) (time.Duration, error) {
	if ttlFlag != "" {
		d, err := parseHumanDuration(ttlFlag)
		if err != nil {
			return 0, fmt.Errorf("invalid TTL %q: %w", ttlFlag, err)
		}
		return d, nil
	}

	return 24 * time.Hour, nil
}

// parseHumanDuration parses a duration string supporting optional day suffix.
// e.g. "24h", "7d", "30m".
func parseHumanDuration(s string) (time.Duration, error) {
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
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpTokenCmd)
	mcpTokenCmd.AddCommand(tokenCreateCmd)
	mcpTokenCmd.AddCommand(tokenListCmd)
	mcpTokenCmd.AddCommand(tokenRevokeCmd)

	tokenCreateCmd.Flags().StringSlice("tools", []string{"*"}, "Comma-separated allowed tools, or '*' for all")
	tokenCreateCmd.Flags().String("ttl", "", "Token TTL (e.g. 24h, 7d); defaults to mcp.scoped_token_ttl from config")
	tokenCreateCmd.Flags().String("agent", "", "Agent profile to associate")
	tokenCreateCmd.Flags().String("label", "", "Human-readable label")
}
