package auth

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestNewCommands_FreshTrees guards the constructor migration (#744): every
// NewCommands() call must return a freshly built tree, so consecutive calls
// never share command objects, parent/child pointers, or flag state.
func TestNewCommands_FreshTrees(t *testing.T) {
	first := NewCommands()
	second := NewCommands()

	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("NewCommands() returned %d and %d commands, want 3 (auth, lock, unlock)", len(first), len(second))
	}

	seen := map[string]*cobra.Command{}
	for i, secondCmd := range second {
		firstCmd := first[i]
		if firstCmd == secondCmd {
			t.Fatalf("command %q is shared between NewCommands() calls", secondCmd.Name())
		}
		if prev, ok := seen[secondCmd.Name()]; ok && prev == secondCmd {
			t.Fatalf("duplicate command %q in NewCommands() result", secondCmd.Name())
		}
		seen[secondCmd.Name()] = secondCmd
	}

	// The auth parent must expose all three children on every fresh tree.
	authCmd := second[0]
	if authCmd.Name() != "auth" {
		t.Fatalf("first command = %q, want %q", authCmd.Name(), "auth")
	}
	children := authCmd.Commands()
	if len(children) != 3 {
		t.Fatalf("auth command has %d children, want 3 (status, set, rotate-passphrase)", len(children))
	}
	childNames := map[string]bool{}
	for _, c := range children {
		if c.Parent() != authCmd {
			t.Fatalf("child %q is not parented to the fresh auth command", c.Name())
		}
		childNames[c.Name()] = true
	}
	for _, want := range []string{"status", "set", "rotate-passphrase"} {
		if !childNames[want] {
			t.Errorf("auth command missing child %q", want)
		}
	}
}
