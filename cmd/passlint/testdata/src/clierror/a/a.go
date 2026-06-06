package a

import (
	"fmt"

	"clierror/cobra"
)

var cmdWithFmtErrorf = &cobra.Command{
	Use: "bad",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("entry already exists: %s", args[0]) // want "do not use fmt.Errorf in RunE handlers"
	},
}

var cmdWithTypedError = &cobra.Command{
	Use: "good",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}
