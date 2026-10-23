package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The tests in this file drive the generator against fake oracles: tiny POSIX
// shell scripts that print canned diagnostics. They never touch the network or
// the real Go CLI, so every branch of the observation pipeline can be reached
// without building the pinned oracle.

const (
	notInitLine = "Error: vault not initialized. Run 'symvault init' first\n"
	notInitHint = "Run 'symvault init' for a quick start, or 'symvault setup' for the guided wizard.\n"
)

func skipWithoutPOSIXShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake oracles are POSIX shell scripts")
	}
}

// fakeOracle writes an executable shell script and returns its path.
func fakeOracle(t *testing.T, body string) string {
	t.Helper()
	skipWithoutPOSIXShell(t)
	path := filepath.Join(t.TempDir(), "oracle.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil { // #nosec G306 -- test script must be executable
		t.Fatal(err)
	}
	return path
}

// treeRoot writes a minimal command-tree fixture under a fresh repository root.
func treeRoot(t *testing.T, paths ...string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(filepath.Dir(commandTreePath)))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	type command struct {
		Path          string `json:"path"`
		Runnable      bool   `json:"runnable"`
		HasSubcommand bool   `json:"has_subcommands"`
	}
	var tree struct {
		Commands []command `json:"commands"`
	}
	for _, p := range paths {
		runnable := !strings.HasPrefix(p, "!")
		tree.Commands = append(tree.Commands, command{Path: strings.TrimPrefix(p, "!"), Runnable: runnable})
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(commandTreePath)), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRunRecordsExitCodeAndStreams(t *testing.T) {
	script := fakeOracle(t, "echo out; echo err >&2; exit 7\n")
	res, err := run(script, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.timedOut || res.obs.ExitCode != 7 || res.obs.Stdout != "out\n" || res.obs.Stderr != "err\n" {
		t.Fatalf("result = %+v", res)
	}
	if strings.Join(res.obs.Args, " ") != "a b" {
		t.Fatalf("args = %v", res.obs.Args)
	}
}

func TestRunNormalizesTheSandboxRoot(t *testing.T) {
	// $TMPDIR is the raw sandbox root; `pwd -P` is its symlink-resolved form
	// (/var -> /private/var on macOS). Both must collapse to the marker.
	script := fakeOracle(t, "echo \"$TMPDIR\"; pwd -P; echo \"$HOME\"\n")
	res, err := run(script, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(res.obs.Stdout, "\n"), "\n")
	if len(lines) != 3 || lines[0] != rootMarker || lines[1] != rootMarker || lines[2] != rootMarker+"/home" {
		t.Fatalf("stdout = %q", res.obs.Stdout)
	}
}

func TestRunErrorPaths(t *testing.T) {
	t.Run("missing binary", func(t *testing.T) {
		if _, err := run(filepath.Join(t.TempDir(), "absent"), nil, nil); err == nil {
			t.Fatal("a missing oracle binary was accepted")
		}
	})
	t.Run("unwritable fixture file", func(t *testing.T) {
		script := fakeOracle(t, "exit 0\n")
		if _, err := run(script, nil, map[string]string{"missing-dir/note.txt": "x"}); err == nil {
			t.Fatal("a file in a nonexistent sandbox directory was written")
		}
	})
	t.Run("invalid UTF-8 stdout", func(t *testing.T) {
		script := fakeOracle(t, "printf '\\377\\376'\n")
		if _, err := run(script, []string{"bad"}, nil); err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid UTF-8 stderr", func(t *testing.T) {
		script := fakeOracle(t, "printf '\\377' >&2\n")
		if _, err := run(script, nil, nil); err == nil {
			t.Fatal("invalid UTF-8 stderr was accepted")
		}
	})
}

func TestRunTimeoutKeepsPartialStderr(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the oracle command timeout")
	}
	t.Parallel()
	script := fakeOracle(t, "echo partial >&2; exec sleep 60\n")
	res, err := run(script, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.timedOut || res.obs.ExitCode != -1 || res.obs.Stderr != "partial\n" {
		t.Fatalf("result = %+v", res)
	}
}

func TestIsUTF8(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want bool
	}{{[]byte("héllo"), true}, {nil, true}, {[]byte{0xff}, false}} {
		if got := isUTF8(tc.in); got != tc.want {
			t.Errorf("isUTF8(%q) = %v", tc.in, got)
		}
	}
}

func TestClassifiersRejectNearMisses(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  observation
	}{
		{"arity prefix without arg(s)", observation{ExitCode: 1, Stderr: "Error: accepts 1 thing\n"}},
		{"arity prefix unknown", observation{ExitCode: 1, Stderr: "Error: needs 1 arg(s)\n"}},
		{"arity empty stderr", observation{ExitCode: 1}},
	} {
		if isArityRejection(tc.obs) {
			t.Errorf("%s: classified as an arity rejection", tc.name)
		}
	}
	line := notInitLine
	for _, tc := range []struct {
		name string
		obs  observation
		want bool
	}{
		{"exit 1", observation{ExitCode: 1, Stderr: line + notInitHint}, false},
		{"stdout present", observation{ExitCode: 3, Stdout: "x", Stderr: line + notInitHint}, false},
		{"wrong prefix", observation{ExitCode: 3, Stderr: "Error: other\n" + notInitHint}, false},
		{"wrong suffix", observation{ExitCode: 3, Stderr: line + "tail\n"}, false},
		{"ok", observation{ExitCode: 3, Stderr: line + line + notInitHint}, true},
	} {
		if got := isNotInitialized(tc.obs); got != tc.want {
			t.Errorf("isNotInitialized(%s) = %v", tc.name, got)
		}
	}
	if isGateRefusal(result{obs: observation{ExitCode: 9, Stderr: "Error: something else\n"}}) {
		t.Error("exit 9 without the gate wording is not a refusal")
	}
}

func TestPathArgsCopiesAndConcatHandlesEmpty(t *testing.T) {
	if got := pathArgs(""); got != nil {
		t.Fatalf("pathArgs(\"\") = %v", got)
	}
	if got := dummyArgs(0); len(got) != 0 {
		t.Fatalf("dummyArgs(0) = %v", got)
	}
	if got := concat(); got != nil {
		t.Fatalf("concat() = %v", got)
	}
	if got := concat(nil, []string{"a"}, nil); len(got) != 1 || got[0] != "a" {
		t.Fatalf("concat = %v", got)
	}
}

func TestSandboxEnvironmentIsHermetic(t *testing.T) {
	box, err := newSandbox()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(box.root) }()
	info, err := os.Stat(filepath.Join(box.root, "home"))
	if err != nil || !info.IsDir() {
		t.Fatalf("sandbox home: %v", err)
	}
	joined := strings.Join(box.env, "\n")
	for _, want := range []string{"HOME=" + filepath.Join(box.root, "home"), "TMPDIR=" + box.root, "CI=1", "NO_COLOR=1", "XDG_CONFIG_HOME=", "XDG_DATA_HOME=", "XDG_CACHE_HOME=", "USERPROFILE="} {
		if !strings.Contains(joined, want) {
			t.Errorf("sandbox env lacks %q", want)
		}
	}
	if got := box.normalize("a " + box.root + "/x b"); got != "a "+rootMarker+"/x b" {
		t.Fatalf("normalize = %q", got)
	}
}

func TestBuildUsage(t *testing.T) {
	script := fakeOracle(t, "echo \"Error: unknown $1\" >&2; exit 1\n")
	cases, err := buildUsage(script)
	if err != nil {
		t.Fatal(err)
	}
	inputs := usageInputs()
	if len(cases) != len(inputs) {
		t.Fatalf("%d cases for %d inputs", len(cases), len(inputs))
	}
	for i, c := range cases {
		if c.Name != inputs[i].name || c.Description != inputs[i].description || c.Observation.ExitCode != 1 {
			t.Fatalf("case %d = %+v", i, c)
		}
	}
	if cases[0].Observation.Stderr != "Error: unknown bogus\n" {
		t.Fatalf("first stderr = %q", cases[0].Observation.Stderr)
	}
}

func TestBuildUsageAndShapesPropagateRunErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := buildUsage(missing); err == nil || !strings.Contains(err.Error(), "usage case unknown_root_command") {
		t.Fatalf("buildUsage err = %v", err)
	}
	if _, err := buildShapes(missing); err == nil || !strings.Contains(err.Error(), "shape join_pairing_file_equals_token") {
		t.Fatalf("buildShapes err = %v", err)
	}
}

func TestBuildUsageAndShapesRejectTimeouts(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the oracle command timeout")
	}
	t.Run("usage", func(t *testing.T) {
		t.Parallel()
		script := fakeOracle(t, "exec sleep 60\n")
		if _, err := buildUsage(script); err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("shapes", func(t *testing.T) {
		t.Parallel()
		script := fakeOracle(t, "exec sleep 60\n")
		if _, err := buildShapes(script); err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestBuildShapes(t *testing.T) {
	// The fake prints a bare diagnostic and echoes the invitation file it was
	// given, proving the shape's files reach the sandbox working directory.
	script := fakeOracle(t, "[ \"$2\" != join ] || [ -f invite-mismatch.json ] || { echo 'Error: sandbox lost the invitation' >&2; exit 1; }\necho 'Error: shape' >&2; exit 1\n")
	shapes, err := buildShapes(script)
	if err != nil {
		t.Fatal(err)
	}
	inputs := shapeInputs()
	if len(shapes) != len(inputs) {
		t.Fatalf("%d shapes for %d inputs", len(shapes), len(inputs))
	}
	for i, s := range shapes {
		if s.Name != inputs[i].name || s.Observation.Stderr != "Error: shape\n" {
			t.Fatalf("shape %d = %+v", i, s)
		}
	}
	if len(shapes[0].Files) != len(joinFiles) {
		t.Fatalf("files = %v", shapes[0].Files)
	}
}

func TestBuildShapesRejectsNonDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"exit 0 with stderr", "echo noise >&2; exit 0\n", "exit 0 with stderr"},
		{"stdout on failure", "echo out; echo 'Error: x' >&2; exit 1\n", "is not a bare diagnostic"},
		{"failure without Error prefix", "echo 'oops' >&2; exit 2\n", "is not a bare diagnostic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildShapes(fakeOracle(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// A clean exit 0 with no stderr (a help page) is a valid row.
	shapes, err := buildShapes(fakeOracle(t, "echo help\n"))
	if err != nil || len(shapes) != len(shapeInputs()) || shapes[0].Observation.Stdout != "help\n" {
		t.Fatalf("help rows: %v", err)
	}
}

// pathOracle emulates an oracle for the single-word commands of treeRoot:
//
//	get      needs one positional; refuses every format; otherwise not initialized
//	list     takes none; refuses --json only
//	version  takes none; accepts everything
//	shadow   takes none; refuses --output yaml but not xml
//	strict   always fails the arity check
const pathOracleBody = `cmd="$1"; shift
n=0; json=""; out=""
prev=""
for a in "$@"; do
  case "$a" in
    x) n=$((n+1));;
    --json) json=1;;
    yaml|xml) [ "$prev" = "--output" ] && out="$a";;
  esac
  prev="$a"
done
refuse() { echo "Error: output format \"$1\" is not supported by 'symvault $cmd'" >&2; exit 9; }
arity() { echo "Error: accepts $1 arg(s), received $n" >&2; echo "Error: accepts $1 arg(s), received $n" >&2; exit 1; }
case "$cmd" in
  get)
    [ "$n" -eq 1 ] || arity 1
    [ -n "$json$out" ] && refuse fmt
    printf '%b%b%b' "$NIL" "$NIL" "$NIH" >&2; exit 3;;
  list)
    [ "$n" -eq 0 ] || arity 0
    [ -n "$json" ] && refuse json
    exit 0;;
  version)
    [ "$n" -eq 0 ] || arity 0
    exit 0;;
  shadow)
    [ "$n" -eq 0 ] || arity 0
    [ "$out" = "yaml" ] && refuse yaml
    exit 0;;
  strict) arity 9;;
esac
exit 0
`

func pathOracle(t *testing.T) string {
	t.Helper()
	body := "NIL=\"" + strings.ReplaceAll(notInitLine, "\n", "\\n") + "\"\nNIH=\"" + strings.ReplaceAll(notInitHint, "\n", "\\n") + "\"\n" + pathOracleBody
	return fakeOracle(t, body)
}

func TestBuildPaths(t *testing.T) {
	root := treeRoot(t, "symvault", "!symvault group", "symvault get", "symvault list", "symvault version", "symvault get")
	arity, gate, notInit, err := buildPaths(pathOracle(t), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(arity) != 4 || len(gate) != 4 {
		t.Fatalf("arity rows %d, gate rows %d", len(arity), len(gate))
	}
	byPath := map[string]gateRow{}
	for _, g := range gate {
		byPath[g.Path] = g
	}
	get := byPath["symvault get"]
	if get.ValidArgs != 1 || !get.JSONRefused || !get.OutputRefused || len(get.Refusals) != 3 {
		t.Fatalf("get gate = %+v", get)
	}
	if list := byPath["symvault list"]; list.ValidArgs != 0 || !list.JSONRefused || list.OutputRefused || len(list.Refusals) != 1 {
		t.Fatalf("list gate = %+v", list)
	}
	if version := byPath["symvault version"]; version.JSONRefused || version.OutputRefused || len(version.Refusals) != 0 {
		t.Fatalf("version gate = %+v", version)
	}
	// get is probed with 0..4 dummies: 0, 2, 3 and 4 are rejected, 1 accepted.
	if row := arity[0]; row.Path != "symvault get" || len(row.Probes) != maxDummyArgs+1 {
		t.Fatalf("get arity = %+v", row)
	} else {
		for _, p := range row.Probes {
			if p.Rejected != (p.Count != 1) || (p.Rejected && p.Observation == nil) || (!p.Rejected && p.Observation != nil) {
				t.Fatalf("probe %+v", p)
			}
		}
	}
	// The duplicated `get` entry yields a single not-initialized observation.
	if len(notInit) != 1 || strings.Join(notInit[0].Args, " ") != "get x" || notInit[0].ExitCode != 3 {
		t.Fatalf("notInitialized = %+v", notInit)
	}
}

func TestBuildPathsErrors(t *testing.T) {
	oracle := pathOracle(t)
	t.Run("missing command tree", func(t *testing.T) {
		if _, _, _, err := buildPaths(oracle, t.TempDir()); err == nil {
			t.Fatal("a missing command tree was accepted")
		}
	})
	t.Run("invalid command tree", func(t *testing.T) {
		root := treeRoot(t)
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(commandTreePath)), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := buildPaths(oracle, root); err == nil {
			t.Fatal("an invalid command tree was accepted")
		}
	})
	t.Run("oracle cannot run", func(t *testing.T) {
		root := treeRoot(t, "symvault get")
		_, _, _, err := buildPaths(filepath.Join(t.TempDir(), "absent"), root)
		if err == nil || !strings.Contains(err.Error(), "arity symvault get/0") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no dummy count passes the validator", func(t *testing.T) {
		root := treeRoot(t, "symvault strict")
		_, _, _, err := buildPaths(oracle, root)
		if err == nil || !strings.Contains(err.Error(), "no dummy-argument count passes the validator") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("gate refuses only some output formats", func(t *testing.T) {
		root := treeRoot(t, "symvault shadow")
		_, _, _, err := buildPaths(oracle, root)
		if err == nil || !strings.Contains(err.Error(), "refuses only some --output formats") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oracle fails during the gate probe", func(t *testing.T) {
		// Succeeds for four arity probes, deletes itself on the fifth, so the first gate probe cannot start.
		dir := t.TempDir()
		counter := filepath.Join(dir, "count")
		script := fakeOracle(t, "echo x >> '"+counter+"'\n[ \"$(wc -l < '"+counter+"')\" -le 4 ] && exit 0\nrm -f \"$0\"; exit 0\n")
		root := treeRoot(t, "symvault version")
		if _, _, _, err := buildPaths(script, root); err != nil {
			// run() resolves the binary per call, so a deleted script surfaces here.
			if !strings.Contains(err.Error(), "gate symvault version") {
				t.Fatalf("err = %v", err)
			}
			return
		}
		t.Fatal("a vanished oracle was accepted")
	})
	t.Run("oracle fails during the plain probe", func(t *testing.T) {
		// Five arity + three gate probes run; the eighth call deletes the script so the plain probe cannot start.
		dir := t.TempDir()
		counter := filepath.Join(dir, "count")
		script := fakeOracle(t, "echo x >> '"+counter+"'\n[ \"$(wc -l < '"+counter+"')\" -le 7 ] && exit 0\nrm -f \"$0\"; exit 0\n")
		root := treeRoot(t, "symvault version")
		_, _, _, err := buildPaths(script, root)
		if err == nil || !strings.Contains(err.Error(), "plain symvault version") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSourceFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		// #nosec G204 -- fixed git arguments in a temporary repository
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	for _, name := range []string{"cmd/a.go", "cmd/a_test.go", "cmd/sub/b.go", "cmd/sub/deep/c.go", "cmd/sub/b_test.go", "other/d.go"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "-A")
	got, err := sourceFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cmd/a.go", "cmd/sub/b.go", "cmd/sub/deep/c.go", "go.mod", "go.sum", "internal/cli/cli.go", "internal/errors/errors.go"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sourceFiles = %v, want %v", got, want)
	}
	if _, err := sourceFiles(filepath.Join(root, "absent")); err == nil {
		t.Fatal("a missing repository root was accepted")
	}
}

func TestResolveOracleBranches(t *testing.T) {
	for _, tc := range []struct {
		name            string
		check           bool
		commit, release string
		wantErr         string
		wantCommit      string
		wantRelease     string
	}{
		{"unpinned release", false, pinnedOracleCommit, "v9", "oracle release", "", ""},
		{"unpinned release in check mode", true, "", "v9", "oracle release", "", ""},
		{"missing release", false, pinnedOracleCommit, "", "required", "", ""},
		{"missing commit", false, "", pinnedOracleRelease, "required", "", ""},
		{"new fixture", false, pinnedOracleCommit, pinnedOracleRelease, "", pinnedOracleCommit, pinnedOracleRelease},
		{"check ignores explicit pins", true, pinnedOracleCommit, pinnedOracleRelease, "", pinnedOracleCommit, pinnedOracleRelease},
	} {
		commit, release, err := resolveOracle(tc.check, tc.commit, tc.release)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v", tc.name, err)
			}
			continue
		}
		if err != nil || commit != tc.wantCommit || release != tc.wantRelease {
			t.Errorf("%s: %q %q %v", tc.name, commit, release, err)
		}
	}
}

func TestMarshalJSON(t *testing.T) {
	got, err := marshalJSON(map[string]any{"b": "<&>", "a": []int{1}})
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\n  \"a\": [\n    1\n  ],\n  \"b\": \"<&>\"\n}\n"
	if string(got) != want {
		t.Fatalf("marshalJSON = %q, want %q", got, want)
	}
	if _, err := marshalJSON(make(chan int)); err == nil {
		t.Fatal("an unencodable value was accepted")
	}
}

func TestRepositoryRootHoldsTheModule(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- path derived from this source file
	if err != nil || !strings.HasPrefix(string(raw), "module github.com/danieljustus/symaira-vault") {
		t.Fatalf("go.mod at %s: %v", root, err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(commandTreePath))); err != nil {
		t.Fatalf("committed command tree: %v", err)
	}
}

func TestValidateGoBinaryRejects(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		err := validateGoBinary(filepath.Join(t.TempDir(), "absent"))
		if err == nil || !strings.Contains(err.Error(), "read build metadata") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not a Go binary", func(t *testing.T) {
		if err := validateGoBinary(fakeOracle(t, "exit 0\n")); err == nil {
			t.Fatal("a shell script was accepted as the oracle")
		}
	})
	t.Run("foreign main module", func(t *testing.T) {
		// This test binary's main module is the package under test, not the
		// vault CLI, so the identity check must refuse it.
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		err = validateGoBinary(self)
		if err == nil || !strings.Contains(err.Error(), "main module") {
			t.Fatalf("err = %v", err)
		}
	})
}

// buildTinyOracle compiles a one-line program in a temporary module that has
// the vault module path, so validateGoBinary's identity check passes and the
// toolchain/VCS stamps decide the outcome. It is a sub-second build of a
// dependency-free file, not the real CLI.
func buildTinyOracle(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a tiny Go program")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain is required")
	}
	src := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module github.com/danieljustus/symaira-vault\n\ngo 1.21\n",
		"main.go": "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "tiny")
	// #nosec G204 -- go tool resolved from PATH, fixed arguments, temporary module
	cmd := exec.Command(goTool, "build", "-buildvcs=false", "-o", out, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the stand-in oracle: %v\n%s", err, output)
	}
	return out
}

func TestValidateGoBinaryChecksToolchainAndVCSStamps(t *testing.T) {
	err := validateGoBinary(buildTinyOracle(t))
	if err == nil {
		t.Fatal("a binary without the pinned VCS revision was accepted")
	}
	// Either stamp may be the first to fail depending on the local toolchain;
	// both are rejections of an unpinned oracle.
	if !strings.Contains(err.Error(), "GoVersion") && !strings.Contains(err.Error(), "build setting vcs.") {
		t.Fatalf("err = %v", err)
	}
}
