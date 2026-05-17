package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var (
	deleteYes bool
)

var deleteCmd = &cobra.Command{
	Use:     "delete <path>",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a password entry",
	Example: `  # Delete an entry (with confirmation)
  openpass delete github

  # Skip confirmation
  openpass delete github --yes`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: entryCompletionFunc,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		return withVault(func(svc vaultsvc.Service) error {
			if !deleteYes {
				fmt.Fprintf(os.Stderr, "Delete %s? (y/N): ", path)
				answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil && answer == "" {
					return fmt.Errorf("read confirmation: %w", err)
				}
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					if outputFormat == "text" { //nolint:goconst // output format literal
						fmt.Fprintln(os.Stderr, "Canceled")
					} else {
						if err := PrintResult(map[string]any{"deleted": false, "path": path, "canceled": true}); err != nil {
							return err
						}
					}
					return nil
				}
			}

			if err := svc.Delete(path); err != nil {
				return fmt.Errorf("cannot delete entry: %w", err)
			}
			if outputFormat == "text" {
				printQuietAware("Deleted: %s\n", path)
			} else {
				if err := PrintResult(map[string]any{"deleted": true, "path": path}); err != nil {
					return err
				}
			}
			return nil
		})
	},
}

func init() {
	deleteCmd.Flags().BoolVarP(&deleteYes, "yes", "y", false, "Skip confirmation prompt")
	rootCmd.AddCommand(deleteCmd)
}
