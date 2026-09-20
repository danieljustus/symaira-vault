package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeCLI is a POSIX shell script that answers the same help queries a clap
// binary would, so the walker and the probe can be exercised without a Rust
// build. The test is skipped on Windows, where the script cannot execute.
const fakeCLI = `#!/bin/sh
case "$*" in
"--help")
cat <<'EOF'
Fake CLI

Usage: fake [OPTIONS] [COMMAND]

Commands:
  get   Read an entry
  list  List all entries

Options:
      --json       machine readable output
  -h, --help       Print help
EOF
;;
"get --help")
cat <<'EOF'
Read an entry

Usage: fake get [OPTIONS] [NAME]

Arguments:
  [NAME]  entry name

Options:
      --field <FIELD>  field to print
      --json           machine readable output
  -h, --help           Print help
EOF
;;
"list --help")
cat <<'EOF'
List all entries

Usage: fake list [OPTIONS]

Options:
      --json  machine readable output
  -h, --help  Print help
EOF
;;
*)
echo "error: unrecognized subcommand" >&2
exit 2
;;
esac
`

func fakeBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake CLI is a POSIX shell script; the Rust binary is probed on Unix instead")
	}
	path := filepath.Join(t.TempDir(), "fake-cli")
	if err := os.WriteFile(path, []byte(fakeCLI), 0o700); err != nil {
		t.Fatalf("write fake cli: %v", err)
	}
	return path
}

// oracleTree mirrors the shape of testdata/port/cli/command-tree.json but is
// small enough to assert every branch: a reachable command with a missing flag
// and a missing alias, one clean command, one missing command, and one path
// deeper than the probe depth.
func oracleTree(t *testing.T) string {
	t.Helper()
	document := map[string]any{
		"schema_version": 1,
		"oracle":         map[string]string{"commit": "deadbeef", "release": "test"},
		"commands": []map[string]any{
			{"path": "symvault"},
			{"path": "symvault get", "name": "get", "aliases": []string{"show"},
				"local_flags": []map[string]string{{"name": "field"}, {"name": "help"}, {"name": "renamed-in-rust"}}},
			{"path": "symvault list", "name": "list", "local_flags": []map[string]string{{"name": "json"}}},
			{"path": "symvault gone", "name": "gone"},
			{"path": "symvault a b c d", "name": "d"},
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "command-tree.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func readReport(t *testing.T, path string) report {
	t.Helper()
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var decoded report
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	return decoded
}

func TestRunReportsSurfaceGaps(t *testing.T) {
	binary := fakeBinary(t)
	out := filepath.Join(t.TempDir(), "nested", "cli-gap-inventory.json")

	if err := run([]string{"--binary", binary, "--tree", oracleTree(t), "--output", out, "--depth", "3"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := readReport(t, out)
	if got.OraclePaths != 3 {
		t.Errorf("oracle paths = %d, want 3 (root and the depth-4 path are out of scope)", got.OraclePaths)
	}
	if got.Depth != 3 || got.OracleCommit != "deadbeef" || got.Tool == "" {
		t.Errorf("metadata not carried over: %+v", got)
	}
	if len(got.RustBinaryID) != 64 || got.RustBuiltAt == "" {
		t.Errorf("report does not pin the probed binary: sha=%q modified=%q", got.RustBinaryID, got.RustBuiltAt)
	}
	if len(got.MissingPaths) != 1 || got.MissingPaths[0].Path != "symvault gone" {
		t.Errorf("missing paths = %+v, want only symvault gone", got.MissingPaths)
	}
	if len(got.FlagGaps) != 1 || got.FlagGaps[0] != (gap{Path: "symvault get", Detail: "--renamed-in-rust"}) {
		t.Errorf("flag gaps = %+v, want --renamed-in-rust on symvault get only", got.FlagGaps)
	}
	if len(got.AliasGaps) != 1 || got.AliasGaps[0] != (gap{Path: "symvault get", Detail: "show"}) {
		t.Errorf("alias gaps = %+v, want the missing show alias", got.AliasGaps)
	}
	if got.RustPaths != 3 {
		t.Errorf("rust paths = %d, want 3 (symvault, get, list)", got.RustPaths)
	}
	for _, path := range got.RustOnlyPaths {
		if path != "symvault" && path != "symvault get" && path != "symvault list" {
			t.Errorf("unexpected rust-only path %q", path)
		}
	}
}

// TestRunRustOnlyPathNeedsNoOracleEntry pins the direction of the comparison:
// a command the Rust binary answers that the frozen tree does not list is
// reported, never treated as parity.
func TestRunRustOnlyPathNeedsNoOracleEntry(t *testing.T) {
	binary := fakeBinary(t)
	out := filepath.Join(t.TempDir(), "report.json")
	tree := filepath.Join(t.TempDir(), "command-tree.json")
	content := `{"schema_version":1,"oracle":{"commit":"c","release":"r"},"commands":[{"path":"symvault"}]}`
	if err := os.WriteFile(tree, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if err := run([]string{"--binary", binary, "--tree", tree, "--output", out}); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := readReport(t, out)
	if len(got.MissingPaths) != 0 {
		t.Errorf("missing paths = %+v, want none: an empty oracle scope probes nothing", got.MissingPaths)
	}
	if strings.Join(got.RustOnlyPaths, ",") != "symvault get,symvault list" {
		t.Errorf("rust-only paths = %v, want the fake CLI's own commands", got.RustOnlyPaths)
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	binary := fakeBinary(t)
	out := filepath.Join(t.TempDir(), "report.json")

	if err := run([]string{"--binary", filepath.Join(t.TempDir(), "absent"), "--tree", oracleTree(t), "--output", out}); err == nil {
		t.Error("want an error for a missing binary")
	}
	if err := run([]string{"--binary", binary, "--tree", filepath.Join(t.TempDir(), "absent.json"), "--output", out}); err == nil {
		t.Error("want an error for a missing oracle tree")
	}
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := run([]string{"--binary", binary, "--tree", broken, "--output", out}); err == nil {
		t.Error("want an error for an unparsable oracle tree")
	}
	if err := run([]string{"--nope"}); err == nil {
		t.Error("want an error for an unknown flag")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("no report must be written on failure, stat err = %v", err)
	}
}

func TestFlagNamesReadsOnlyTheOptionSection(t *testing.T) {
	help := "Usage: fake [OPTIONS]\n\nArguments:\n  --json  not a flag here\n\nOptions:\n      --field <FIELD>  field\n  -h, --help           Print help\n"
	names := flagNames(help)
	if !names["field"] || !names["help"] {
		t.Errorf("flagNames = %v, want field and help", names)
	}
	if names["json"] {
		t.Errorf("flagNames picked up a name outside the option section: %v", names)
	}
	if len(names) != 2 {
		t.Errorf("flagNames = %v, want exactly the two options", names)
	}
}

func TestSubcommandsSkipsGeneratedHelpers(t *testing.T) {
	help := "Commands:\n  get   Read an entry\n  help  Print this message\n  completion  Generate a shell completion\n\nOptions:\n  -h, --help\n"
	got := subcommands(help)
	if len(got) != 1 || got[0] != "get" {
		t.Errorf("subcommands = %v, want only get", got)
	}
}

func TestAliasPathForReplacesTheLeaf(t *testing.T) {
	if got := aliasPathFor("symvault agent skill export", "exp"); got != "symvault agent skill exp" {
		t.Errorf("aliasPathFor = %q", got)
	}
	if got := aliasPathFor("get", "show"); got != "show" {
		t.Errorf("aliasPathFor = %q", got)
	}
}

func TestProbeReportsTheFirstDiagnosticLine(t *testing.T) {
	binary := fakeBinary(t)
	if _, ok := probe(binary, "symvault get"); !ok {
		t.Error("want symvault get to be reachable")
	}
	detail, ok := probe(binary, "symvault gone")
	if ok {
		t.Fatal("want symvault gone to be unreachable")
	}
	if detail == "" {
		t.Error("want a diagnostic line for an unreachable command")
	}
}

// edgeCLI answers with a self-referential tree: root lists get, list and a
// broken command, and get lists list again — so the walker meets an already
// visited path, a command whose help fails, and a depth cut-off.
const edgeCLI = `#!/bin/sh
case "$*" in
"--help")
cat <<'EOF'
Edge CLI

Usage: edge [OPTIONS] [COMMAND]

Commands:
  get     Read an entry
  list    List entries
  broken  Advertised but unusable
  get     Duplicate line, as a defensive parser case
EOF
;;
"get --help")
cat <<'EOF'
Read an entry

Commands:
  list  List entries
EOF
;;
"list --help")
cat <<'EOF'
List entries

Options:
  -h, --help  Print help
EOF
;;
*)
exit 3
;;
esac
`

func edgeBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the edge CLI is a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "edge-cli")
	if err := os.WriteFile(path, []byte(edgeCLI), 0o700); err != nil {
		t.Fatalf("write edge cli: %v", err)
	}
	return path
}

func TestWalkHandlesCyclesBrokenCommandsAndDepth(t *testing.T) {
	binary := edgeBinary(t)
	if _, ok := probe(binary, "symvault broken"); ok {
		t.Fatal("want the advertised but unusable command to be unreachable")
	}
	// A command that fails silently still yields a diagnostic.
	detail, ok := probe(binary, "symvault broken")
	if ok || detail == "" {
		t.Errorf("silent failure must still carry a diagnostic, got %q", detail)
	}

	out := filepath.Join(t.TempDir(), "report.json")
	if err := run([]string{"--binary", binary, "--tree", oracleTree(t), "--output", out, "--depth", "1"}); err != nil {
		t.Fatalf("run with depth 1: %v", err)
	}
	got := readReport(t, out)
	// symvault, get, list, broken, and the back edge symvault get list: the
	// walker records a path before it applies the depth cut-off, and the
	// duplicated root entry must not walk get twice.
	if got.RustPaths != 5 {
		t.Errorf("rust paths at depth 1 = %d, want 5", got.RustPaths)
	}
}

func TestIdentifyRejectsUnreadableTargets(t *testing.T) {
	if _, _, err := identify(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("want an error for a missing binary")
	}
	if _, _, err := identify(t.TempDir()); err == nil {
		t.Error("want an error when the binary path is a directory")
	}
}

func TestRunFailsOnUnwritableReportPaths(t *testing.T) {
	binary := fakeBinary(t)
	tree := oracleTree(t)

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := run([]string{"--binary", binary, "--tree", tree, "--output", filepath.Join(blocker, "sub", "report.json")}); err == nil {
		t.Error("want an error when the report directory cannot be created")
	}
	if err := run([]string{"--binary", binary, "--tree", tree, "--output", t.TempDir()}); err == nil {
		t.Error("want an error when the report path is a directory")
	}
	if err := run([]string{"--binary", t.TempDir(), "--tree", tree, "--output", filepath.Join(t.TempDir(), "report.json")}); err == nil {
		t.Error("want an error when the probed binary is a directory")
	}
}
