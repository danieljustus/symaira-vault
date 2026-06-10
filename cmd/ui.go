package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/ui"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var uiPrintKeybindings bool
var uiExperimental bool

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the Symaira Vault terminal UI (Experimental)",
	Long: `Launches the interactive terminal UI for browsing and managing the vault.

NOTE: The terminal UI is currently experimental and must be enabled using the --experimental flag.

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
  symvault ui --experimental

  # Combined with a specific profile
  symvault ui --profile work --experimental`,
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
		if !uiExperimental {
			return fmt.Errorf("the terminal UI is currently experimental and must be enabled with the --experimental flag: symvault ui --experimental")
		}
		return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
			if err := ui.Run(v); err != nil {
				return fmt.Errorf("ui failed: %w", err)
			}

			return nil
		})
	},
}

func init() {
	uiCmd.Flags().BoolVar(&uiPrintKeybindings, "print-keybindings", false, "Print the TUI keybinding reference and exit")
	uiCmd.Flags().BoolVar(&uiExperimental, "experimental", false, "Enable the experimental terminal UI")
	rootCmd.AddCommand(uiCmd)
}
