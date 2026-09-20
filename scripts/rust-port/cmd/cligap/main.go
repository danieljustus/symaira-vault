// Command cligap measures the Rust CLI's command surface against the pinned Go
// oracle command tree.
//
// It deliberately needs no Go oracle binary: testdata/port/cli/command-tree.json
// already freezes the oracle's command paths, aliases and local flags, so the
// comparison runs against a committed artifact and stays deterministic and
// cheap enough for CI. What it measures is surface reachability and flag
// presence - never behavioral parity. A reachable command with a byte-identical
// help text is not evidence that the command behaves like Go.
//
// Deliberate non-claims:
//   - Argument-count probes from the oracle tree are not replayed. Clap and
//     Cobra report argument errors with different exit codes and text, so an
//     accepted/rejected comparison would measure the parser's error style
//     rather than the contract.
//   - Clap prints inherited global flags in every subcommand's Options section,
//     while the oracle tree records only each node's own flags. The report
//     therefore lists oracle flags missing from Rust and never calls the
//     additional Rust entries a divergence.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type treeFlag struct {
	Name string `json:"name"`
}

type treeCommand struct {
	Path         string     `json:"path"`
	Name         string     `json:"name"`
	Aliases      []string   `json:"aliases"`
	LocalFlags   []treeFlag `json:"local_flags"`
	HasSubcmds   bool       `json:"has_subcommands"`
	RunnableFlag bool       `json:"runnable"`
}

type tree struct {
	SchemaVersion int           `json:"schema_version"`
	Oracle        treeOracle    `json:"oracle"`
	Commands      []treeCommand `json:"commands"`
}

type treeOracle struct {
	Commit  string `json:"commit"`
	Release string `json:"release"`
}

type report struct {
	SchemaVersion int      `json:"schema_version"`
	Tool          string   `json:"tool"`
	GeneratedAt   string   `json:"generated_at"`
	RustBinary    string   `json:"rust_binary"`
	Tree          string   `json:"oracle_tree"`
	OracleCommit  string   `json:"oracle_commit"`
	OracleRelease string   `json:"oracle_release"`
	Depth         int      `json:"depth"`
	OraclePaths   int      `json:"oracle_paths"`
	RustPaths     int      `json:"rust_paths"`
	MissingPaths  []gap    `json:"missing_paths"`
	FlagGaps      []gap    `json:"flag_gaps"`
	AliasGaps     []gap    `json:"alias_gaps"`
	RustOnlyPaths []string `json:"rust_only_paths"`
}

type gap struct {
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("cligap", flag.ContinueOnError)
	binary := fs.String("binary", filepath.Join("target", "debug", "symvault"), "Rust CLI binary to probe")
	treePath := fs.String("tree", filepath.Join("testdata", "port", "cli", "command-tree.json"), "frozen oracle command tree")
	output := fs.String("output", filepath.Join("target", "resume-evidence", "cli-gap-inventory.json"), "report path")
	depth := fs.Int("depth", 3, "maximum command depth to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*binary); err != nil {
		return fmt.Errorf("rust binary %s: %w (build it first: cargo build -p symvault-cli)", *binary, err)
	}
	content, err := os.ReadFile(*treePath)
	if err != nil {
		return fmt.Errorf("read oracle tree: %w", err)
	}
	var oracle tree
	if unmarshalErr := json.Unmarshal(content, &oracle); unmarshalErr != nil {
		return fmt.Errorf("parse oracle tree: %w", unmarshalErr)
	}

	repr := report{
		SchemaVersion: 1,
		Tool:          "scripts/rust-port/cmd/cligap",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		RustBinary:    *binary,
		Tree:          *treePath,
		OracleCommit:  oracle.Oracle.Commit,
		OracleRelease: oracle.Oracle.Release,
		Depth:         *depth,
	}
	absolute, err := filepath.Abs(*binary)
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}
	repr.RustBinary = absolute

	scoped := make([]treeCommand, 0, len(oracle.Commands))
	for _, command := range oracle.Commands {
		if command.Path == "symvault" {
			continue
		}
		if strings.Count(command.Path, " ") > *depth {
			continue
		}
		scoped = append(scoped, command)
	}
	repr.OraclePaths = len(scoped)

	oraclePaths := map[string]bool{}
	for _, command := range scoped {
		oraclePaths[command.Path] = true
		help, reachable := probe(absolute, command.Path)
		if !reachable {
			repr.MissingPaths = append(repr.MissingPaths, gap{Path: command.Path, Detail: help})
			continue
		}
		for _, alias := range command.Aliases {
			aliasPath := aliasPathFor(command.Path, alias)
			if _, ok := probe(absolute, aliasPath); !ok {
				repr.AliasGaps = append(repr.AliasGaps, gap{Path: command.Path, Detail: alias})
			}
		}
		present := flagNames(help)
		var missing []string
		for _, declared := range command.LocalFlags {
			if declared.Name == "help" {
				continue
			}
			if !present[declared.Name] {
				missing = append(missing, declared.Name)
			}
		}
		sort.Strings(missing)
		for _, name := range missing {
			repr.FlagGaps = append(repr.FlagGaps, gap{Path: command.Path, Detail: "--" + name})
		}
	}
	for _, path := range rustWalk(absolute, *depth) {
		if !oraclePaths[path] {
			repr.RustOnlyPaths = append(repr.RustOnlyPaths, path)
		}
	}
	sort.Strings(repr.RustOnlyPaths)
	repr.RustPaths = len(rustWalkAll(absolute, *depth))

	encoded, err := json.MarshalIndent(repr, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	encoded = append(encoded, '\n')
	if dir := filepath.Dir(*output); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create report directory: %w", err)
		}
	}
	if err := os.WriteFile(*output, encoded, 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("WROTE %s\n", *output)
	fmt.Printf("oracle paths %d, rust paths %d, missing %d, flag gaps %d, alias gaps %d, rust-only %d\n",
		repr.OraclePaths, repr.RustPaths, len(repr.MissingPaths), len(repr.FlagGaps), len(repr.AliasGaps), len(repr.RustOnlyPaths))
	return nil
}

func aliasPathFor(path, alias string) string {
	parts := strings.Split(path, " ")
	if len(parts) == 0 {
		return alias
	}
	parts[len(parts)-1] = alias
	return strings.Join(parts, " ")
}

// probe runs `<binary> <path without the root name> --help` and reports the
// first diagnostic line when the binary rejects the command path.
func probe(binary, path string) (string, bool) {
	parts := strings.Split(path, " ")
	if len(parts) > 0 {
		parts = parts[1:]
	}
	args := append(append([]string{}, parts...), "--help")
	// #nosec G204 -- the probed binary is an explicit operator argument of this
	// measurement tool (--binary), never untrusted input.
	cmd := exec.Command(binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		line, _, _ := strings.Cut(strings.TrimSpace(stderr.String()), "\n")
		if line == "" {
			line = err.Error()
		}
		return line, false
	}
	return stdout.String(), true
}

var longFlag = regexp.MustCompile(`--([a-zA-Z0-9][a-zA-Z0-9-]*)`)

// flagNames extracts the long option names from a clap help page's option
// section only; names mentioned in prose are not flags.
func flagNames(help string) map[string]bool {
	names := map[string]bool{}
	inOptions := false
	for _, line := range strings.Split(help, "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "Options:", "Flags:":
			inOptions = true
			continue
		case "Commands:", "Available Commands:", "Arguments:":
			inOptions = false
			continue
		}
		if !inOptions || !strings.HasPrefix(line, " ") {
			continue
		}
		for _, match := range longFlag.FindAllStringSubmatch(line, -1) {
			names[match[1]] = true
		}
	}
	return names
}

func rustWalk(binary string, depth int) []string {
	all := rustWalkAll(binary, depth)
	var only []string
	for path := range all {
		if path != "symvault" {
			only = append(only, path)
		}
	}
	return only
}

// rustWalkAll walks the Rust binary's own command tree from its help pages.
func rustWalkAll(binary string, depth int) map[string]bool {
	seen := map[string]bool{}
	var walk func(args []string)
	walk = func(args []string) {
		path := strings.Join(append([]string{"symvault"}, args...), " ")
		if seen[path] {
			return
		}
		seen[path] = true
		if len(args) > depth {
			return
		}
		help, ok := probe(binary, path)
		if !ok {
			return
		}
		for _, command := range subcommands(help) {
			walk(append(append([]string{}, args...), command))
		}
	}
	walk(nil)
	return seen
}

// subcommands extracts child command names from a help page's command section,
// skipping the generated help and completion helpers.
func subcommands(help string) []string {
	var names []string
	inCommands := false
	for _, line := range strings.Split(help, "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "Commands:", "Available Commands:":
			inCommands = true
			continue
		case "Options:", "Flags:":
			inCommands = false
			continue
		}
		if !inCommands || !strings.HasPrefix(line, "  ") || trimmed == "" {
			continue
		}
		name := strings.Fields(trimmed)[0]
		if name == "help" || name == "completion" {
			continue
		}
		names = append(names, name)
	}
	return names
}
