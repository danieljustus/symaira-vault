package cmd

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewRootCmd_IndependentTrees(t *testing.T) {
	root1 := NewRootCmd()
	root2 := NewRootCmd()

	if root1 == root2 {
		t.Fatal("NewRootCmd() returned the same pointer instance twice")
	}

	root1.SetArgs([]string{"version"})
	root2.SetArgs([]string{"help"})

	if strings.Join(root1.Flags().Args(), " ") == strings.Join(root2.Flags().Args(), " ") {
		t.Errorf("Modifying root1 args mutated root2 args")
	}
}

func collectCommandPaths(cmd *cobra.Command, currentPath string, paths *[]string, seen map[string]int) {
	fullPath := currentPath
	if fullPath != "" {
		fullPath += " " + cmd.Name()
	} else {
		fullPath = cmd.Name()
	}

	seen[fullPath]++
	*paths = append(*paths, fullPath)

	for _, sub := range cmd.Commands() {
		collectCommandPaths(sub, fullPath, paths, seen)
	}
}

func TestNewRootCmd_NoDuplicatePaths(t *testing.T) {
	root := NewRootCmd()
	var paths []string
	seen := make(map[string]int)

	collectCommandPaths(root, "", &paths, seen)

	var duplicates []string
	for path, count := range seen {
		if count > 1 {
			duplicates = append(duplicates, path)
		}
	}

	if len(duplicates) > 0 {
		t.Fatalf("Found duplicate command registrations: %v", duplicates)
	}
}

func TestNewRootCmd_GoldenCommandTree(t *testing.T) {
	root := NewRootCmd()
	var paths []string
	seen := make(map[string]int)

	collectCommandPaths(root, "", &paths, seen)
	sort.Strings(paths)

	if len(paths) == 0 {
		t.Fatal("NewRootCmd() has no registered commands")
	}

	// Verify expected core subcommands exist
	expectedSubcommands := []string{
		"symvault add",
		"symvault delete",
		"symvault get",
		"symvault list",
		"symvault set",
		"symvault find",
		"symvault edit",
		"symvault admin",
		"symvault auth",
		"symvault file",
		"symvault agent",
		"symvault version",
	}

	allPaths := strings.Join(paths, "\n")
	for _, expected := range expectedSubcommands {
		if !strings.Contains(allPaths, expected) {
			t.Errorf("Command tree missing expected subcommand %q", expected)
		}
	}
}
