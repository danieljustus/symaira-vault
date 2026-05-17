package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/ui"
	"github.com/danieljustus/OpenPass/internal/ui/cliout"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var uiPrintKeybindings bool

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the OpenPass terminal UI",
	Long: `Launches the interactive terminal UI for browsing and managing the vault.

Inside the TUI:
  ↑/↓ or j/k   move
  /            filter by name
  t            filter by tag
  s            cycle sort (name/updated, asc/desc)
  e            edit selected entry in $EDITOR
  d            delete selected entry (with confirmation)
  g            generate password for selected entry
  ?            toggle full keybinding help
  q or Ctrl+C  quit`,
	Example: `  # Launch the TUI
  openpass ui

  # Combined with a specific profile
  openpass ui --profile work`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if uiPrintKeybindings {
			tbl := cliout.NewTable("Key", "Action")
			for _, b := range ui.Keybindings() {
				tbl.AddRow(b.Key, b.Action)
			}
			fmt.Print(tbl.Render())
			return nil
		}
		return withVault(func(svc vaultsvc.Service) error {
			if err := ui.Run(svc); err != nil {
				return fmt.Errorf("ui failed: %w", err)
			}

			return nil
		})
	},
}

func init() {
	uiCmd.Flags().BoolVar(&uiPrintKeybindings, "print-keybindings", false, "Print the TUI keybinding reference and exit")
	rootCmd.AddCommand(uiCmd)
}
