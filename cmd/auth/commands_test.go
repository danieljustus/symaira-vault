package auth

import (
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

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

// TestNewCommands_Assembly guards the wiring contract of the assembled tree:
// group IDs, child wiring, and per-command flags must survive constructor
// refactors.
func TestNewCommands_Assembly(t *testing.T) {
	cmds := NewCommands()
	byName := map[string]*cobra.Command{}
	for _, c := range cmds {
		byName[c.Name()] = c
	}

	for _, name := range []string{"auth", "lock", "unlock"} {
		if byName[name] == nil {
			t.Fatalf("NewCommands() missing %q", name)
		}
	}

	if got := byName["auth"].GroupID; got != cli.GroupIDAuthAccess {
		t.Errorf("auth GroupID = %q, want %q", got, cli.GroupIDAuthAccess)
	}
	if got := byName["lock"].GroupID; got != cli.GroupIDAuthAccess {
		t.Errorf("lock GroupID = %q, want %q", got, cli.GroupIDAuthAccess)
	}
	if got := byName["unlock"].GroupID; got != cli.GroupIDAuthAccess {
		t.Errorf("unlock GroupID = %q, want %q", got, cli.GroupIDAuthAccess)
	}

	status := byName["auth"].Commands()
	if len(status) != 3 {
		t.Fatalf("auth has %d children, want 3", len(status))
	}
	var statusCmd *cobra.Command
	for _, c := range status {
		if c.Name() == "status" {
			statusCmd = c
		}
	}
	if statusCmd == nil {
		t.Fatal("auth missing status child")
	}
	if statusCmd.Flags().Lookup("json") == nil {
		t.Error("status command missing --json flag")
	}

	unlock := byName["unlock"]
	if unlock.Flags().Lookup("ttl") == nil {
		t.Error("unlock command missing --ttl flag")
	}
	if unlock.Flags().Lookup("check") == nil {
		t.Error("unlock command missing --check flag")
	}

	rotate := byName["auth"].Commands()
	var rotateCmd *cobra.Command
	for _, c := range rotate {
		if c.Name() == "rotate-passphrase" {
			rotateCmd = c
		}
	}
	if rotateCmd == nil {
		t.Fatal("auth missing rotate-passphrase child")
	}
	if rotateCmd.Flags().Lookup("reencrypt") == nil {
		t.Error("rotate command missing --reencrypt flag")
	}
	if rotateCmd.Flags().Lookup("yes") == nil {
		t.Error("rotate command missing --yes flag")
	}
}
