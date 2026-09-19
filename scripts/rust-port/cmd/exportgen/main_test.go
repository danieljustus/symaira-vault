package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Exercise the production generator against its committed fixture, including
// source provenance and exact output. Synthetic inputs never open a vault.
func TestCommittedFixtureFreshness(t *testing.T) {
	t.Chdir(filepath.Join("..", "..", "..", ".."))
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	flag.CommandLine = flag.NewFlagSet("fixture-check", flag.ExitOnError)
	os.Args = []string{"fixture-check", "-check"}
	main()
}
