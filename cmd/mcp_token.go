package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/mcp"
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
}

var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new scoped token",
	Long: `Create a new scoped MCP token with restricted tool access.

The raw token is printed exactly once — copy it immediately. It cannot be
retrieved later.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tools, _ := cmd.Flags().GetStringSlice("tools")
		ttlStr, _ := cmd.Flags().GetString("ttl")
		agent, _ := cmd.Flags().GetString("agent")
		label, _ := cmd.Flags().GetString("label")

		if len(tools) == 0 {
			return fmt.Errorf("at least one tool must be specified (use --tools '*')")
		}

		vDir, err := vaultPath()
		if err != nil {
			return err
		}

		ttl, err := resolveTokenTTL(vDir, ttlStr)
		if err != nil {
			return err
		}

		regPath := mcp.TokenRegistryFilePath(vDir)
		reg := mcp.NewTokenRegistry(regPath)
		if loadErr := reg.Load(); loadErr != nil {
			return fmt.Errorf("load token registry: %w", loadErr)
		}

		token, rawToken, err := reg.Create(label, tools, agent, ttl)
		if err != nil {
			return fmt.Errorf("create token: %w", err)
		}

		if err := reg.Save(); err != nil {
			return fmt.Errorf("save token registry: %w", err)
		}

		printlnQuietAware("Token created successfully.")
		printQuietAware("  ID:    %s\n", token.ID)
		printQuietAware("  Label: %s\n", token.Label)
		if token.AgentName != "" {
			printQuietAware("  Agent: %s\n", token.AgentName)
		}
		printQuietAware("  Tools: %s\n", strings.Join(token.AllowedTools, ", "))
		if token.ExpiresAt != nil {
			printQuietAware("  Expires: %s\n", token.ExpiresAt.Format(time.RFC3339))
		} else {
			printQuietAware("  Expires: never\n")
		}
		printlnQuietAware()
		printQuietAware("Raw token (copy now — shown once): %s\n", rawToken)
		printlnQuietAware()
		printlnQuietAware("Warning: This is the only time the raw token is displayed.")
		printlnQuietAware("         Store it securely — it cannot be retrieved later.")

		return nil
	},
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scoped tokens",
	Long:  `List all scoped tokens in the registry, including their status and expiration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vDir, err := vaultPath()
		if err != nil {
			return err
		}

		regPath := mcp.TokenRegistryFilePath(vDir)
		reg := mcp.NewTokenRegistry(regPath)
		if err := reg.Load(); err != nil {
			return fmt.Errorf("load token registry: %w", err)
		}

		tokens := reg.List()
		if len(tokens) == 0 {
			printlnQuietAware("No tokens found.")
			return nil
		}

		printQuietAware("%-22s %-16s %-14s %-28s %-20s %s\n", "ID", "LABEL", "AGENT", "TOOLS", "EXPIRES AT", "STATUS")
		for i := range tokens {
			status := "active"
			if tokens[i].Revoked {
				status = "revoked"
			} else if tokens[i].IsExpired() {
				status = "expired"
			}

			label := tokens[i].Label
			if label == "" {
				label = "-"
			}
			agent := tokens[i].AgentName
			if agent == "" {
				agent = "-"
			}
			tools := strings.Join(tokens[i].AllowedTools, ", ")
			if len(tools) > 26 {
				tools = tools[:23] + "..."
			}
			expires := "never"
			if tokens[i].ExpiresAt != nil {
				expires = tokens[i].ExpiresAt.Format("2006-01-02 15:04")
			}

			printQuietAware("%-22s %-16s %-14s %-28s %-20s %s\n", tokens[i].ID, label, agent, tools, expires, status)
		}

		return nil
	},
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke a scoped token",
	Long:  `Revoke a scoped token by its ID. Revoked tokens are immediately invalidated.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenID := args[0]

		vDir, err := vaultPath()
		if err != nil {
			return err
		}

		regPath := mcp.TokenRegistryFilePath(vDir)
		reg := mcp.NewTokenRegistry(regPath)
		if err := reg.Load(); err != nil {
			return fmt.Errorf("load token registry: %w", err)
		}

		if !reg.Revoke(tokenID) {
			return fmt.Errorf("token %q not found or already revoked", tokenID)
		}

		if err := reg.Save(); err != nil {
			return fmt.Errorf("save token registry: %w", err)
		}

		printQuietAware("Token %s revoked successfully.\n", tokenID)
		return nil
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
