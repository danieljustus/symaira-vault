package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/ui/render"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
)

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage secret sharing between agents",
	Long:  "List and revoke secret share grants between MCP agents.",
	Example: `  # List all pending share requests
  openpass share list --status pending

  # Revoke a grant by ID
  openpass share revoke <grant-id>

  # JSON output for tooling
  openpass share list --output json`,
}

var shareListCmd = &cobra.Command{
	Use:   "list",
	Short: "List share grants",
	Long: `List all share grants with optional filtering by status, agent, or path.

Examples:
  openpass share list
  openpass share list --status approved
  openpass share list --from agent-a
  openpass share list --to agent-b
  openpass share list --path github.password
  openpass share list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vDir, err := vaultPath()
		if err != nil {
			return err
		}

		store := mcp.NewShareStore(mcp.ShareStoreFilePath(vDir))
		if err := store.Load(); err != nil {
			return fmt.Errorf("load share store: %w", err)
		}

		statusStr, _ := cmd.Flags().GetString("status")
		from, _ := cmd.Flags().GetString("from")
		to, _ := cmd.Flags().GetString("to")
		path, _ := cmd.Flags().GetString("path")

		var filter mcp.ShareFilter
		if statusStr != "" {
			s := mcp.ShareStatus(statusStr)
			filter.Status = &s
		}
		if from != "" {
			filter.FromAgent = from
		}
		if to != "" {
			filter.ToAgent = to
		}
		if path != "" {
			filter.SecretPath = path
		}

		grants := store.List(filter)

		if outputFormat != "text" {
			if err := PrintResult(grants); err != nil {
				return err
			}
			return nil
		}

		if len(grants) == 0 {
			printlnQuietAware("No share grants found.")
			return nil
		}

		hasFilter := statusStr != "" || from != "" || to != "" || path != ""

		printQuietAware("%-22s %-18s %-18s %-28s %-8s %-10s %-16s %s\n",
			"ID", "FROM", "TO", "PATH", "FIELD", "STATUS", "CREATED", "EXPIRES")
		for _, g := range grants {
			status := string(g.Status)
			if g.IsExpired() {
				status = "expired"
			}

			field := g.SecretField
			if field == "" {
				field = "-"
			}

			expires := "never"
			if g.ExpiresAt != nil {
				expires = g.ExpiresAt.Format("2006-01-02 15:04")
			}

			printQuietAware("%-22s %-18s %-18s %-28s %-8s %-10s %-16s %s\n",
				g.ID, g.FromAgent, g.ToAgent, render.ForTerminal(taint.Wrap(g.SecretPath, taint.Provenance{Source: "cli.path"})), field, status,
				g.CreatedAt.Format("2006-01-02 15:04"), expires)
		}

		if hasFilter {
			printQuietAware("\n%d grant(s) match the current filter.\n", len(grants))
		} else {
			printQuietAware("\n%d grant(s) total.\n", len(grants))
		}

		return nil
	},
}

var shareRevokeCmd = &cobra.Command{
	Use:   "revoke <grant-id>",
	Short: "Revoke a share grant",
	Long:  "Revoke an active share grant, immediately removing the recipient's access to the shared secret.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		grantID := args[0]

		vDir, err := vaultPath()
		if err != nil {
			return err
		}

		store := mcp.NewShareStore(mcp.ShareStoreFilePath(vDir))
		if err := store.Load(); err != nil {
			return fmt.Errorf("load share store: %w", err)
		}

		if err := store.Revoke(grantID); err != nil {
			return fmt.Errorf("revoke share grant: %w", err)
		}

		printQuietAware("Share grant %s revoked successfully.\n", grantID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(shareCmd)
	shareCmd.AddCommand(shareListCmd)
	shareCmd.AddCommand(shareRevokeCmd)

	shareListCmd.Flags().String("status", "", "Filter by status (pending, approved, revoked, expired, rejected)")
	shareListCmd.Flags().String("from", "", "Filter by source agent")
	shareListCmd.Flags().String("to", "", "Filter by target agent")
	shareListCmd.Flags().String("path", "", "Filter by secret path")
}
