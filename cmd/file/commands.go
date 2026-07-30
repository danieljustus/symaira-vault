package file

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all file attachment commands for root command assembly.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		fileCmd,
	}
}
