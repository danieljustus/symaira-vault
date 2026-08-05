package file

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

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("NewCommands() returned %d and %d commands, want 1 each", len(first), len(second))
	}

	fileA, fileB := first[0], second[0]
	if fileA == fileB {
		t.Fatal("two NewCommands() calls returned the same file command object")
	}

	childrenA := fileA.Commands()
	childrenB := fileB.Commands()
	if len(childrenA) != 3 || len(childrenB) != 3 {
		t.Fatalf("file command has %d and %d children, want 3 (add, get, use)", len(childrenA), len(childrenB))
	}

	seen := map[string]*cobra.Command{}
	for i, childB := range childrenB {
		childA := childrenA[i]
		if childA == childB {
			t.Fatalf("child %q is shared between NewCommands() calls", childB.Name())
		}
		if childB.Parent() != fileB {
			t.Fatalf("child %q is not parented to the fresh file command", childB.Name())
		}
		if prev, ok := seen[childB.Name()]; ok && prev == childB {
			t.Fatalf("duplicate child %q in tree", childB.Name())
		}
		seen[childB.Name()] = childB
	}
}
