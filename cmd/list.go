package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var listCmd = &cobra.Command{
	Use:     "list [prefix]",
	Aliases: []string{"ls"},
	Short:   "List password entries",
	Example: `  # List all entries
  openpass list

  # List entries under "work/" prefix
  openpass list work/

  # JSON output
  openpass list --output json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVault(func(svc vaultsvc.Service) error {
			maybeAutoPull(svc.GetDir(), svc.Vault().Config)
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}

			entries, err := svc.List(prefix)
			if err != nil {
				return fmt.Errorf("cannot list entries: %w", err)
			}

			if outputFormat != "text" { //nolint:goconst // output format literal
				if err := PrintResult(entries); err != nil {
					return err
				}
				return nil
			}

			for _, e := range entries {
				printlnQuietAware(e)
			}

			return nil
		})
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
