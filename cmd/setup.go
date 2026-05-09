package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljustus/OpenPass/internal/ui/wizard"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup wizard for OpenPass",
	Long: `Launch the interactive setup wizard to initialize or re-configure your vault.

The wizard guides you through:
  • Vault directory and passphrase
  • Authentication method (Touch ID or passphrase)
  • Sync strategy (local or git remote)
  • Multi-device setup hints
  • Additional recipients for shared access
  • AI agent (MCP) configuration
  • Backup recommendations
  • Profile name

For non-interactive environments (CI, scripts), use 'openpass init' instead.`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// WIZ-15: Non-TTY guard.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("setup needs a TTY; use `openpass init` for non-interactive vault initialization")
		}

		vaultDir := getVaultDir()
		return wizard.Run(vaultDir)
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
