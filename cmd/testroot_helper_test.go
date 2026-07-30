package cmd

import (
	"github.com/spf13/cobra"
)

// testRoot creates a fresh, isolated root command tree for use in tests.
// Tests MUST use this instead of the package-level rootCmd when they modify
// command state (SetArgs, SetOut, etc.) to avoid cross-test pollution.
func testRoot() *cobra.Command {
	// Recreate the full root command tree
	root := NewRootCmd()
	return root
}
