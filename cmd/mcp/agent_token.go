package mcp

import (
	"fmt"
	"strings"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/mcp"
)

var agentTokenCmd = &cobra.Command{
	Use:   "token <name>",
	Short: "Manage tokens for an agent",
	Long:  `Create, list, revoke, and rotate scoped tokens for a specific agent.`,
	Args:  cobra.ExactArgs(1),
	Example: `  # Create a scoped token for an agent
  openpass agent token my-agent new

  # List tokens for an agent
  openpass agent token my-agent list

  # Revoke a token by ID
  openpass agent token my-agent revoke <token-id>

  # Rotate an agent's token (revoke + create new)
  openpass agent token my-agent rotate`,
}

var agentTokenNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new scoped token for the agent",
	Long: `Create a new scoped MCP token associated with the named agent.

The raw token is printed exactly once — copy it immediately. It cannot be
retrieved later.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := mustGetAgentName(cmd)
		tools, _ := cmd.Flags().GetStringSlice("tools")
		ttlStr, _ := cmd.Flags().GetString("ttl")
		label, _ := cmd.Flags().GetString("label")

		if len(tools) == 0 {
			return fmt.Errorf("at least one tool must be specified (use --tools '*')")
		}

		vDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		ttl, err := ResolveTokenTTL(vDir, ttlStr)
		if err != nil {
			return err
		}

		regPath := mcp.TokenRegistryFilePath(vDir)
		reg := mcp.NewTokenRegistry(regPath)
		if loadErr := reg.Load(); loadErr != nil {
			return fmt.Errorf("load token registry: %w", loadErr)
		}

		token, rawToken, err := reg.Create(label, tools, agentName, ttl)
		if err != nil {
			return fmt.Errorf("create token: %w", err)
		}

		if err := reg.Save(); err != nil {
			return fmt.Errorf("save token registry: %w", err)
		}

		cli.PrintlnQuietAware("Token created successfully.")
		cli.PrintQuietAware("  ID:    %s\n", token.ID)
		cli.PrintQuietAware("  Label: %s\n", token.Label)
		if token.AgentName != "" {
			cli.PrintQuietAware("  Agent: %s\n", token.AgentName)
		}
		cli.PrintQuietAware("  Tools: %s\n", strings.Join(token.AllowedTools, ", "))
		if token.ExpiresAt != nil {
			cli.PrintQuietAware("  Expires: %s\n", token.ExpiresAt.Format(time.RFC3339))
		} else {
			cli.PrintQuietAware("  Expires: never\n")
		}
		cli.PrintlnQuietAware()
		cli.PrintQuietAware("Raw token (copy now — shown once): %s\n", rawToken)
		cli.PrintlnQuietAware()
		cli.PrintlnQuietAware("Warning: This is the only time the raw token is displayed.")
		cli.PrintlnQuietAware("         Store it securely — it cannot be retrieved later.")

		return nil
	},
}

var agentTokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tokens for this agent",
	Long:  `List all scoped tokens associated with the given agent name.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := mustGetAgentName(cmd)

		vDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		regPath := mcp.TokenRegistryFilePath(vDir)
		reg := mcp.NewTokenRegistry(regPath)
		if err := reg.Load(); err != nil {
			return fmt.Errorf("load token registry: %w", err)
		}

		allTokens := reg.List()
		var tokens []*mcp.ScopedToken
		for i := range allTokens {
			if allTokens[i].AgentName == agentName {
				tokens = append(tokens, allTokens[i])
			}
		}

		if len(tokens) == 0 {
			cli.PrintQuietAware("No tokens found for agent %q.\n", agentName)
			return nil
		}

		cli.PrintQuietAware("%-22s %-16s %-14s %-28s %-20s %s\n", "ID", "LABEL", "AGENT", "TOOLS", "EXPIRES AT", "STATUS")
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

			cli.PrintQuietAware("%-22s %-16s %-14s %-28s %-20s %s\n", tokens[i].ID, label, agent, tools, expires, status)
		}

		return nil
	},
}

var agentTokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke a scoped token",
	Long:  `Revoke a scoped token by its ID. Revoked tokens are immediately invalidated.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenID := args[0]

		vDir, err := cli.VaultPath()
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

		cli.PrintQuietAware("Token %s revoked successfully.\n", tokenID)
		return nil
	},
}

var agentTokenRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the agent's token",
	Long: `Revoke the current token for this agent and create a new one.
The new raw token is printed exactly once.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := mustGetAgentName(cmd)
		tools, _ := cmd.Flags().GetStringSlice("tools")
		ttlStr, _ := cmd.Flags().GetString("ttl")
		label, _ := cmd.Flags().GetString("label")

		if len(tools) == 0 {
			return fmt.Errorf("at least one tool must be specified (use --tools '*')")
		}

		vDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		regPath := mcp.TokenRegistryFilePath(vDir)
		reg := mcp.NewTokenRegistry(regPath)
		if loadErr := reg.Load(); loadErr != nil {
			return fmt.Errorf("load token registry: %w", loadErr)
		}

		allTokens := reg.List()
		for i := range allTokens {
			if allTokens[i].AgentName == agentName && !allTokens[i].Revoked {
				reg.Revoke(allTokens[i].ID)
			}
		}

		ttl, err := ResolveTokenTTL(vDir, ttlStr)
		if err != nil {
			return err
		}

		token, rawToken, err := reg.Create(label, tools, agentName, ttl)
		if err != nil {
			return fmt.Errorf("create token: %w", err)
		}

		if err := reg.Save(); err != nil {
			return fmt.Errorf("save token registry: %w", err)
		}

		cli.PrintlnQuietAware("Token rotated successfully.")
		cli.PrintQuietAware("  ID:    %s\n", token.ID)
		cli.PrintQuietAware("  Label: %s\n", token.Label)
		cli.PrintQuietAware("  Agent: %s\n", token.AgentName)
		cli.PrintQuietAware("  Tools: %s\n", strings.Join(token.AllowedTools, ", "))
		if token.ExpiresAt != nil {
			cli.PrintQuietAware("  Expires: %s\n", token.ExpiresAt.Format(time.RFC3339))
		} else {
			cli.PrintQuietAware("  Expires: never\n")
		}
		cli.PrintlnQuietAware()
		cli.PrintQuietAware("Raw token (copy now — shown once): %s\n", rawToken)
		cli.PrintlnQuietAware()
		cli.PrintlnQuietAware("Warning: This is the only time the raw token is displayed.")

		return nil
	},
}

func mustGetAgentName(cmd *cobra.Command) string {
	parent := cmd.Parent()
	if parent != nil {
		parentArgs := parent.Flags().Args()
		if len(parentArgs) > 0 {
			return parentArgs[0]
		}
	}
	return "unknown"
}

func init() {
	agentTokenCmd.AddCommand(agentTokenNewCmd)
	agentTokenCmd.AddCommand(agentTokenListCmd)
	agentTokenCmd.AddCommand(agentTokenRevokeCmd)
	agentTokenCmd.AddCommand(agentTokenRotateCmd)
	agentCmd.AddCommand(agentTokenCmd)

	agentTokenNewCmd.Flags().StringSlice("tools", []string{"*"}, "Comma-separated allowed tools, or '*' for all")
	agentTokenNewCmd.Flags().String("ttl", "", "Token TTL (e.g. 24h, 7d); defaults to mcp.scoped_token_ttl from config")
	agentTokenNewCmd.Flags().String("label", "", "Human-readable label")

	agentTokenRotateCmd.Flags().StringSlice("tools", []string{"*"}, "Comma-separated allowed tools, or '*' for all")
	agentTokenRotateCmd.Flags().String("ttl", "", "Token TTL (e.g. 24h, 7d); defaults to mcp.scoped_token_ttl from config")
	agentTokenRotateCmd.Flags().String("label", "", "Human-readable label")
}
