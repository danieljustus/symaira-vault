package crud

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all CRUD commands for root command assembly.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		newAddCmd(),
		newDeleteCmd(),
		newEditCmd(),
		newFindCmd(),
		newGetCmd(),
		newListCmd(),
		newSetCmd(),
	}
}
