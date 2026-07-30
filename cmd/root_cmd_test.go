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

	// Verify both trees have commands
	if len(root1.Commands()) == 0 {
		t.Fatal("NewRootCmd() has no commands")
	}
	if len(root1.Commands()) != len(root2.Commands()) {
		t.Errorf("two roots have different command counts: %d vs %d", len(root1.Commands()), len(root2.Commands()))
	}

	// Verify version works on a fresh, untouched root
	versionFound := false
	for _, c := range root1.Commands() {
		if c.Name() == "version" {
			versionFound = true
			break
		}
	}
	if !versionFound {
		t.Error("NewRootCmd() does not include version command")
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
		"symvault audit",
		"symvault auth",
		"symvault unlock",
		"symvault file",
		"symvault agent",
		"symvault version",
		"symvault dynamic",
		"symvault git",
		"symvault profile",
		"symvault run",
		"symvault sync",
	}

	allPaths := strings.Join(paths, "\n")
	for _, expected := range expectedSubcommands {
		if !strings.Contains(allPaths, expected) {
			t.Errorf("Command tree missing expected subcommand %q", expected)
		}
	}
}
