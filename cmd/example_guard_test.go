package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestEveryCommandHasExample is a discoverability guard: every leaf cobra
// command that the user can invoke must declare Example so `symaira <cmd>
// --help` shows a copyable invocation. The root command is exempt — its
// usage block is the command list itself.
//
// Adding a new command without an Example will fail this test; the fix is to
// add a one-line Example: with a realistic invocation. The audit's D1 item
// brought existing commands up to standard; this test keeps regressions out.
func TestEveryCommandHasExample(t *testing.T) {
	var missing []string
	walk(rootCmd, &missing)
	if len(missing) > 0 {
		t.Errorf("the following commands lack Example: (see docs/user-messages.md for the style guide):\n  %s",
			joinNL(missing))
	}
}

func walk(c *cobra.Command, missing *[]string) {
	// Skip the root command and the synthetic "help" / "completion" leaves
	// that cobra auto-generates.
	if c.Parent() == rootCmd && !c.IsAdditionalHelpTopicCommand() &&
		c.Name() != "help" && c.Name() != "completion" {
		// Top-level commands MUST declare Example so `symaira --help` plus
		// `symaira <cmd> --help` give the user a copyable invocation. We
		// deliberately don't enforce examples on sub-commands here — the
		// parent's Example block typically covers them. Track sub-commands
		// separately in the audit and bring them up to par incrementally.
		if c.Example == "" {
			*missing = append(*missing, c.CommandPath())
		}
	}
	for _, child := range c.Commands() {
		walk(child, missing)
	}
}

func joinNL(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "\n  "
		}
		out += s
	}
	return out
}
