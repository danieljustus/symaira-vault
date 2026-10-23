package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests run main in-process against a disposable git repository and a
// fake oracle. The package-level seams (exit, validateOracle, locateRoot,
// pinnedOracleCommit) redirect process exit, the Go-binary identity check, the
// repository root and the pinned revision; nothing else is replaced, so flag
// parsing, provenance hashing, fixture assembly, -check and the write path all
// run for real.

type exitSignal struct{ code int }

type mainRun struct {
	stdout, stderr string
	code           int
	exited         bool
}

// runMain invokes main with args and reports what it printed and how it exited.
// It restores every global it touches.
func runMain(t *testing.T, args ...string) mainRun {
	t.Helper()
	origArgs, origFlags := os.Args, flag.CommandLine
	origStdout, origStderr, origExit := os.Stdout, os.Stderr, exit
	t.Cleanup(func() {
		os.Args, flag.CommandLine = origArgs, origFlags
		os.Stdout, os.Stderr, exit = origStdout, origStderr, origExit
	})

	dir := t.TempDir()
	outFile, err := os.Create(filepath.Join(dir, "stdout")) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	errFile, err := os.Create(filepath.Join(dir, "stderr")) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = outFile, errFile
	os.Args = append([]string{"errtaxgen"}, args...)
	// ContinueOnError: the flag package would otherwise call os.Exit(2) itself.
	flag.CommandLine = flag.NewFlagSet("errtaxgen", flag.ContinueOnError)
	flag.CommandLine.SetOutput(errFile)
	exit = func(code int) { panic(exitSignal{code}) }

	var res mainRun
	func() {
		defer func() {
			if r := recover(); r != nil {
				sig, ok := r.(exitSignal)
				if !ok {
					panic(r)
				}
				res.exited, res.code = true, sig.code
			}
		}()
		main()
	}()
	_ = outFile.Close()
	_ = errFile.Close()
	for _, item := range []struct {
		name string
		dest *string
	}{{"stdout", &res.stdout}, {"stderr", &res.stderr}} {
		raw, err := os.ReadFile(filepath.Join(dir, item.name)) // #nosec G304 -- test temp path
		if err != nil {
			t.Fatal(err)
		}
		*item.dest = string(raw)
	}
	return res
}

// mainEnv is a disposable repository holding the files main hashes, a pinned
// commit that is its HEAD and a fake oracle.
type mainEnv struct {
	root, oracle, commit string
}

func gitIn(t *testing.T, root string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", root, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "-c", "commit.gpgsign=false"}, args...)
	// #nosec G204 -- fixed git arguments in a temporary repository
	out, err := exec.Command("git", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newMainEnv(t *testing.T) mainEnv {
	t.Helper()
	skipWithoutPOSIXShell(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	root := treeRoot(t, "symvault", "!symvault group", "symvault get", "symvault list", "symvault version")
	files := map[string]string{
		"go.mod":                    "module example.invalid/x\n",
		"go.sum":                    "",
		"internal/cli/cli.go":       "package cli\n",
		"internal/errors/errors.go": "package errors\n",
		"cmd/root.go":               "package cmd\n",
		"cmd/sub/leaf.go":           "package sub\n",
		"cmd/sub/leaf_test.go":      "package sub\n",
		"scripts/rust-port/cmd/errtaxgen/main.go": "package main\n",
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "commit", "-q", "-m", "oracle")
	commit := gitIn(t, root, "rev-parse", "HEAD")

	origCommit, origValidate, origLocate := pinnedOracleCommit, validateOracle, locateRoot
	t.Cleanup(func() { pinnedOracleCommit, validateOracle, locateRoot = origCommit, origValidate, origLocate })
	pinnedOracleCommit = commit
	validateOracle = func(string) error { return nil }
	locateRoot = func() (string, error) { return root, nil }
	return mainEnv{root: root, oracle: pathOracle(t), commit: commit}
}

func (e mainEnv) writeArgs(output string) []string {
	return []string{"--go-binary", e.oracle, "--oracle-commit", e.commit, "--oracle-release", pinnedOracleRelease, "--output", output}
}

func TestMainWritesThenChecksTheFixture(t *testing.T) {
	env := newMainEnv(t)
	output := filepath.Join(t.TempDir(), "nested", "error-taxonomy.json")

	wrote := runMain(t, env.writeArgs(output)...)
	if wrote.exited {
		t.Fatalf("write failed: %+v", wrote)
	}
	// 3 runnable non-root commands -> 3 arity rows, 3 gate rows; get is not initialized.
	if !strings.HasPrefix(wrote.stdout, "WROTE "+output+" (") || !strings.Contains(wrote.stdout, "3 arity rows, 3 gate rows, 1 not-initialized cases") {
		t.Fatalf("stdout = %q", wrote.stdout)
	}

	raw, err := os.ReadFile(output) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema_version": 1`, `"commit_sha": "` + env.commit + `"`, `"release": "unreleased"`, `"go.mod"`, `"cmd/root.go"`, `"cmd/sub/leaf.go"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("fixture lacks %s", want)
		}
	}
	if strings.Contains(string(raw), "leaf_test.go") {
		t.Error("test files must not be recorded as production sources")
	}
	if !regexp.MustCompile(`"generator_digest": "[0-9a-f]{64}"`).Match(raw) || !regexp.MustCompile(`"source_digest": "[0-9a-f]{64}"`).Match(raw) {
		t.Error("digests are missing")
	}
	var parsed fixture
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Usage) != len(usageInputs()) || len(parsed.ArgvShapes) != len(shapeInputs()) {
		t.Fatalf("usage %d shapes %d", len(parsed.Usage), len(parsed.ArgvShapes))
	}

	// -check ignores the commit/release flags and compares bytes.
	checked := runMain(t, "--check", "--go-binary", env.oracle, "--output", output)
	if checked.exited || !strings.HasPrefix(checked.stdout, "PASS error taxonomy fixture (") {
		t.Fatalf("check = %+v", checked)
	}
	after, err := os.ReadFile(output) // #nosec G304 -- test temp path
	if err != nil || string(after) != string(raw) {
		t.Fatal("-check must not rewrite the fixture")
	}

	// Drift: a changed byte makes -check fail without touching the file.
	if err := os.WriteFile(output, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := runMain(t, "--check", "--go-binary", env.oracle, "--output", output)
	if !stale.exited || stale.code != 1 || !strings.Contains(stale.stderr, "FAIL fixture is stale; regenerate deliberately") {
		t.Fatalf("stale = %+v", stale)
	}
}

func TestMainCheckFailsWithoutAFixture(t *testing.T) {
	env := newMainEnv(t)
	res := runMain(t, "--check", "--go-binary", env.oracle, "--output", filepath.Join(t.TempDir(), "absent.json"))
	if !res.exited || res.code != 1 || !strings.Contains(res.stderr, "FAIL read fixture: ") {
		t.Fatalf("res = %+v", res)
	}
}

func TestMainWriteFailsOnUnusableOutput(t *testing.T) {
	env := newMainEnv(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runMain(t, env.writeArgs(filepath.Join(blocker, "sub", "out.json"))...)
	if !res.exited || res.code != 1 || !strings.Contains(res.stderr, "FAIL create fixture directory: ") {
		t.Fatalf("mkdir res = %+v", res)
	}
	// The output path is an existing directory: the directory exists, the write fails.
	res = runMain(t, env.writeArgs(t.TempDir())...)
	if !res.exited || res.code != 1 || !strings.Contains(res.stderr, "FAIL write fixture: ") {
		t.Fatalf("write res = %+v", res)
	}
}

func TestMainFailureModes(t *testing.T) {
	env := newMainEnv(t)
	out := filepath.Join(t.TempDir(), "out.json")
	valid := env.writeArgs(out)

	t.Run("no go binary", func(t *testing.T) {
		res := runMain(t, "--check")
		if !res.exited || res.code != 1 || !strings.Contains(res.stderr, "FAIL --go-binary is required") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("unknown flag leaves the binary unset", func(t *testing.T) {
		res := runMain(t, "--bogus")
		if !res.exited || !strings.Contains(res.stderr, "--go-binary is required") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("oracle validation fails", func(t *testing.T) {
		validateOracle = func(string) error { return errors.New("stamp mismatch") }
		defer func() { validateOracle = func(string) error { return nil } }()
		res := runMain(t, valid...)
		if !res.exited || !strings.Contains(res.stderr, "FAIL validate Go oracle: stamp mismatch") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("unpinned commit", func(t *testing.T) {
		res := runMain(t, "--go-binary", env.oracle, "--oracle-commit", "deadbeef", "--oracle-release", pinnedOracleRelease, "--output", out)
		if !res.exited || !strings.Contains(res.stderr, "FAIL resolve oracle metadata: oracle commit") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("new fixture without pins", func(t *testing.T) {
		res := runMain(t, "--go-binary", env.oracle, "--output", out)
		if !res.exited || !strings.Contains(res.stderr, "--oracle-commit and --oracle-release are required") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("repository cannot be located", func(t *testing.T) {
		orig := locateRoot
		locateRoot = func() (string, error) { return "", errors.New("no root") }
		defer func() { locateRoot = orig }()
		res := runMain(t, valid...)
		if !res.exited || !strings.Contains(res.stderr, "FAIL locate repository: no root") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("sources cannot be listed", func(t *testing.T) {
		orig := locateRoot
		locateRoot = func() (string, error) { return filepath.Join(t.TempDir(), "absent"), nil }
		defer func() { locateRoot = orig }()
		res := runMain(t, valid...)
		if !res.exited || !strings.Contains(res.stderr, "FAIL list production sources: ") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("sources cannot be hashed", func(t *testing.T) {
		// A real git repository without the fixed sources: ls-files works, hashing fails.
		bare := t.TempDir()
		gitIn(t, bare, "init", "-q")
		orig := locateRoot
		locateRoot = func() (string, error) { return bare, nil }
		defer func() { locateRoot = orig }()
		res := runMain(t, valid...)
		if !res.exited || !strings.Contains(res.stderr, "FAIL hash production sources: ") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("oracle commit does not match the sources", func(t *testing.T) {
		orig := pinnedOracleCommit
		pinnedOracleCommit = "0000000000000000000000000000000000000000"
		defer func() { pinnedOracleCommit = orig }()
		res := runMain(t, "--check", "--go-binary", env.oracle, "--output", out)
		if !res.exited || !strings.Contains(res.stderr, "FAIL verify oracle: ") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("generator source missing", func(t *testing.T) {
		clone := t.TempDir()
		gitIn(t, clone, "clone", "-q", "--no-hardlinks", env.root, ".")
		if err := os.Remove(filepath.Join(clone, "scripts", "rust-port", "cmd", "errtaxgen", "main.go")); err != nil {
			t.Fatal(err)
		}
		orig := locateRoot
		locateRoot = func() (string, error) { return clone, nil }
		defer func() { locateRoot = orig }()
		res := runMain(t, "--check", "--go-binary", env.oracle, "--output", out)
		if !res.exited || !strings.Contains(res.stderr, "FAIL hash generator: ") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("oracle cannot run usage cases", func(t *testing.T) {
		args := append([]string{}, valid...)
		args[1] = filepath.Join(t.TempDir(), "absent")
		res := runMain(t, args...)
		if !res.exited || !strings.Contains(res.stderr, "FAIL build usage cases: ") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("command tree missing", func(t *testing.T) {
		clone := t.TempDir()
		gitIn(t, clone, "clone", "-q", "--no-hardlinks", env.root, ".")
		if err := os.Remove(filepath.Join(clone, filepath.FromSlash(commandTreePath))); err != nil {
			t.Fatal(err)
		}
		orig := locateRoot
		locateRoot = func() (string, error) { return clone, nil }
		defer func() { locateRoot = orig }()
		res := runMain(t, valid...)
		if !res.exited || !strings.Contains(res.stderr, "FAIL build path cases: ") {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("argument shapes are not diagnostics", func(t *testing.T) {
		noisy := fakeOracle(t, "[ \"$1\" = device ] && { echo noise >&2; exit 0; }\nexit 0\n")
		args := append([]string{}, valid...)
		args[1] = noisy
		res := runMain(t, args...)
		if !res.exited || !strings.Contains(res.stderr, "FAIL build argument shapes: ") {
			t.Fatalf("res = %+v", res)
		}
	})
}
