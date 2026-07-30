package admin

import (
	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

// newTestRootCmd creates a cobra.Command tree containing the admin package's
// commands, suitable for use in tests that need to exercise the admin CLI.
func newTestRootCmd() *cobra.Command {
	root := cli.NewRootCmd()
	root.AddCommand(NewCommands()...)
	return root
}
