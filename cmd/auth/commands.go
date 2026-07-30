package auth

import (
	"github.com/spf13/cobra"
)

// NewCommands returns all authentication commands for root command assembly.
func NewCommands() []*cobra.Command {
	return []*cobra.Command{
		AuthCmd,
		lockCmd,
		AuthUnlockCmd,
	}
}
