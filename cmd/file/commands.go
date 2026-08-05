package file

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all file attachment commands for root command assembly.
// Each call builds a fresh command tree so consecutive calls never share
// command objects or flag state.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		newFileCmd(),
	}
}
