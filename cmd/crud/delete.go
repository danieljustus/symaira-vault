package crud

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var (
	DeleteYes bool
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
	ValidArgsFunction: cli.EntryCompletionFunc,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		return cli.WithVault(func(svc vaultsvc.Service) error {
			if !DeleteYes {
				fmt.Fprintf(os.Stderr, "Delete %s? (y/N): ", path)
				answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil && answer == "" {
					return fmt.Errorf("read confirmation: %w", err)
				}
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					if cli.OutputFormat == "text" { //nolint:goconst // output format literal
						fmt.Fprintln(os.Stderr, "Canceled")
					} else {
						if err := cli.PrintResult(map[string]any{"deleted": false, "path": path, "canceled": true}); err != nil {
							return err
						}
					}
					return nil
				}
			}

			if err := svc.Delete(path); err != nil {
				return fmt.Errorf("cannot delete entry: %w", err)
			}
			if cli.OutputFormat == "text" {
				cli.PrintQuietAware("Deleted: %s\n", path)
			} else {
				if err := cli.PrintResult(map[string]any{"deleted": true, "path": path}); err != nil {
					return err
				}
			}
			return nil
		})
	},
}

func init() {
	deleteCmd.Flags().BoolVarP(&DeleteYes, "yes", "y", false, "Skip confirmation prompt")
	cli.RootCmd.AddCommand(deleteCmd)
}
