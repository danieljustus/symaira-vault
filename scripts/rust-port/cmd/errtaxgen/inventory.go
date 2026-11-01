package main

import (
	"sort"

	"github.com/spf13/cobra"

	vaultcmd "github.com/danieljustus/symaira-vault/cmd"
)

// nilArgsEntry is one command of the pinned tree whose cobra Args validator is
// nil. Cobra then accepts every positional (ValidateArgs falls back to
// ArbitraryArgs, legacyArgs for commands with subcommands), so a native port
// that declares a strict arity rejects calls the Go CLI accepts.
type nilArgsEntry struct {
	Path           string `json:"path"`
	Runnable       bool   `json:"runnable"`
	HasSubcommands bool   `json:"has_subcommands"`
	Hidden         bool   `json:"hidden"`
	// Origin is "tree" for commands the product constructs and "cobra" for the
	// default commands cobra adds when the root executes.
	Origin string `json:"origin"`
}

// nilArgsInventory is replaced only by tests that run main against a fake
// repository.
var nilArgsInventory = compiledNilArgsInventory

// compiledNilArgsInventory walks the command tree the pinned sources build
// (cmd.NewRootCmd, the constructor `symvault` itself executes) after cobra has
// added its default help and completion commands, and returns every command
// except the root whose Args is nil. The sources are digest-bound by
// provenance.Verify (cmd/**/*.go, internal/cli/cli.go), so the compiled tree is
// the tree of the pinned oracle. Deriving it from the compiled tree instead of
// pattern-matching `Args:` keys also covers assignments after construction and
// constructors shared by several parents.
func compiledNilArgsInventory() ([]nilArgsEntry, error) {
	root := vaultcmd.NewRootCmd()
	known := map[*cobra.Command]bool{}
	var mark func(*cobra.Command)
	mark = func(c *cobra.Command) {
		known[c] = true
		for _, child := range c.Commands() {
			mark(child)
		}
	}
	mark(root)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	var out []nilArgsEntry
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root && c.Args == nil {
			origin := "tree"
			if !known[c] {
				origin = "cobra"
			}
			out = append(out, nilArgsEntry{
				Path:           c.CommandPath(),
				Runnable:       c.Runnable(),
				HasSubcommands: c.HasSubCommands(),
				Hidden:         c.Hidden,
				Origin:         origin,
			})
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
