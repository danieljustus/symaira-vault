package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	generatorSource = "scripts/rust-port/cmd/biometricgen/main.go"
	fixtureRelPath  = "testdata/port/session/biometric.json"
)

func parseSource(t *testing.T, src string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fake.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse fake source: %v", err)
	}
	return file
}

func TestStringConst(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		lookup  string
		want    string
		wantErr string
	}{
		{"plain string", "package p\nconst a = \"x\"\n", "a", "x", ""},
		{"raw string unquoted", "package p\nconst a = `a\\b`\n", "a", `a\b`, ""},
		{"escaped string unquoted", "package p\nconst a = \"a\\tb\"\n", "a", "a\tb", ""},
		{"grouped block", "package p\nconst (\n\tx = \"1\"\n\ty = \"2\"\n)\n", "y", "2", ""},
		{"second name of a multi-name spec", "package p\nconst a, b = \"1\", \"2\"\n", "b", "2", ""},
		{"integer literal", "package p\nconst a = 1\n", "a", "", "a is not a string literal"},
		{"concatenation is not a literal", "package p\nconst a = \"x\" + \"y\"\n", "a", "", "a is not a string literal"},
		{"identifier value", "package p\nconst b = \"z\"\nconst a = b\n", "a", "", "a is not a string literal"},
		{"missing", "package p\nconst a = \"x\"\n", "b", "", "const b not found"},
		{"var is not a const", "package p\nvar a = \"x\"\n", "a", "", "const a not found"},
		{"implicit repetition has no value", "package p\nconst (\n\ta = \"x\"\n\tb\n)\n", "b", "", "const b not found"},
		{"only functions and imports", "package p\nimport \"os\"\nfunc a() {}\n", "a", "", "const a not found"},
		{"empty file", "package p\n", "a", "", "const a not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stringConst(parseSource(t, tc.src), tc.lookup)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestStringConstSkipsNonValueSpecs(t *testing.T) {
	// The parser never puts a non-ValueSpec under a const GenDecl, so build the
	// tree by hand to pin that the scan skips it instead of panicking.
	file := &ast.File{Decls: []ast.Decl{&ast.GenDecl{Tok: token.CONST, Specs: []ast.Spec{&ast.ImportSpec{}}}}}
	if _, err := stringConst(file, "a"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestServiceNameShape(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{"exact production shape", "package p\nfunc biometricServiceName(vaultDir string) string { return currentBiometricServicePrefix + vaultDir }\n", ""},
		{"function missing", "package p\nfunc other() {}\n", "biometricServiceName not found"},
		{"only a type declaration", "package p\ntype biometricServiceName int\n", "biometricServiceName not found"},
		{"two statements", "package p\nfunc biometricServiceName(vaultDir string) string { _ = 1; return currentBiometricServicePrefix + vaultDir }\n", "has 2 statements"},
		{"empty body", "package p\nfunc biometricServiceName(vaultDir string) string { }\n", "has 0 statements"},
		{"not a return", "package p\nfunc biometricServiceName(vaultDir string) { println(vaultDir) }\n", "does not return one value"},
		{"two results", "package p\nfunc biometricServiceName(vaultDir string) (string, string) { return vaultDir, vaultDir }\n", "does not return one value"},
		{"not a binary expression", "package p\nfunc biometricServiceName(vaultDir string) string { return vaultDir }\n", "is not a concatenation"},
		{"wrong operator", "package p\nfunc biometricServiceName(vaultDir string) int { return currentBiometricServicePrefix - vaultDir }\n", "is not a concatenation"},
		{"swapped operands", "package p\nfunc biometricServiceName(vaultDir string) string { return vaultDir + currentBiometricServicePrefix }\n", "is not prefix+vaultDir"},
		{"literal operand", "package p\nfunc biometricServiceName(vaultDir string) string { return \"x:\" + vaultDir }\n", "is not prefix+vaultDir"},
		{"call operand", "package p\nfunc biometricServiceName(vaultDir string) string { return currentBiometricServicePrefix + f(vaultDir) }\n", "is not prefix+vaultDir"},
		{"wrong second identifier", "package p\nfunc biometricServiceName(vaultDir string) string { return currentBiometricServicePrefix + other }\n", "is not prefix+vaultDir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := serviceNameShape(parseSource(t, tc.src))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestBetween(t *testing.T) {
	cases := []struct {
		name         string
		source       string
		from, to     string
		want         string
		fromIncluded bool
	}{
		{"both markers", "aa[FROM]bb[TO]cc", "[FROM]", "[TO]", "[FROM]bb", true},
		{"start missing yields empty", "aabbcc", "[FROM]", "[TO]", "", false},
		{"end missing yields the tail", "aa[FROM]bbcc", "[FROM]", "[TO]", "[FROM]bbcc", true},
		{"end before start is ignored", "[TO]aa[FROM]bb", "[FROM]", "[TO]", "[FROM]bb", true},
		{"first start wins", "[FROM]1[TO][FROM]2[TO]", "[FROM]", "[TO]", "[FROM]1", true},
		{"empty source", "", "[FROM]", "[TO]", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := between(tc.source, tc.from, tc.to)
			if got != tc.want {
				t.Fatalf("between = %q, want %q", got, tc.want)
			}
			if tc.fromIncluded && !strings.HasPrefix(got, tc.from) {
				t.Fatalf("result %q does not start at the from marker", got)
			}
		})
	}
}

func TestBuildLayoutFailurePaths(t *testing.T) {
	good := "package p\nconst biometricAccount = \"passphrase\"\nconst currentBiometricServicePrefix = \"symvault-biometric:\"\n" +
		"func biometricServiceName(vaultDir string) string { return currentBiometricServicePrefix + vaultDir }\n"
	cases := []struct {
		name    string
		source  *string // nil: do not create the file
		wantErr string
	}{
		{"source file missing", nil, "no such file"},
		{"unparsable source", ptr("this is not go"), "expected 'package'"},
		{"account const missing", ptr("package p\nconst currentBiometricServicePrefix = \"x\"\n"), "const biometricAccount not found"},
		{"account const not a string", ptr("package p\nconst biometricAccount = 1\n"), "biometricAccount is not a string literal"},
		{"prefix const missing", ptr("package p\nconst biometricAccount = \"a\"\n"), "const currentBiometricServicePrefix not found"},
		{"service name shape drifted", ptr("package p\nconst biometricAccount = \"a\"\nconst currentBiometricServicePrefix = \"x\"\nfunc biometricServiceName(vaultDir string) string { return vaultDir }\n"), "is not a concatenation"},
		{"preamble assertions unmet", &good, "pinned source no longer satisfies layout assertion item_class_generic_password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.source != nil {
				writeFile(t, filepath.Join(root, layoutSource), *tc.source)
			}
			if _, err := buildLayout(root); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildLayoutRecordsServiceNamesAndLoadReason(t *testing.T) {
	scratch := writeLayoutSource(t, func(s string) string { return s })
	got, err := buildLayout(scratch)
	if err != nil {
		t.Fatal(err)
	}
	wantVaults := []string{"/fixture/vault", "/Users/u/.symvault", "", `C:\Users\u\.symvault`, "/home/ü/vält", "a|b"}
	if len(got.ServiceNames) != len(wantVaults) {
		t.Fatalf("service names = %d, want %d", len(got.ServiceNames), len(wantVaults))
	}
	for i, vault := range wantVaults {
		if got.ServiceNames[i].Vault != vault || got.ServiceNames[i].Service != got.ServicePrefix+vault {
			t.Fatalf("service name %d = %+v", i, got.ServiceNames[i])
		}
	}
	if got.LoadReason == "" {
		t.Fatal("load reason not recovered from the Objective-C bridge call")
	}
	if len(got.Assertions) != 15 {
		t.Fatalf("assertions = %d, want 15", len(got.Assertions))
	}
	seen := map[string]bool{}
	for _, a := range got.Assertions {
		if a.Name == "" || a.Meaning == "" || seen[a.Name] {
			t.Fatalf("assertion needs a unique name and meaning: %+v", a)
		}
		seen[a.Name] = true
	}
}

func TestBuildLayoutLoadReasonIsEmptyWithoutAReasonCall(t *testing.T) {
	scratch := writeLayoutSource(t, func(s string) string {
		return regexp.MustCompile(`C\.CString\("[^"]*"\)`).ReplaceAllString(s, `C.CString(reasonVar)`)
	})
	got, err := buildLayout(scratch)
	if err != nil {
		// Replacing every C.CString literal may also break an assertion; the
		// reason scan must in that case still not be reached with a stale value.
		if !strings.Contains(err.Error(), "layout assertion") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if got.LoadReason != "" {
		t.Fatalf("load reason = %q", got.LoadReason)
	}
}

func TestBuildLayoutRejectsEachAssertionWhenItsEvidenceIsRemoved(t *testing.T) {
	cases := []struct {
		assertion string
		mutate    func(string) string
	}{
		{"item_class_generic_password", func(s string) string {
			return strings.ReplaceAll(s, "kSecClass, kSecClassGenericPassword", "kSecClass, kSecClassInternetPassword")
		}},
		{"item_attributes_service_account_only", func(s string) string {
			return strings.ReplaceAll(s, "kSecAttrAccount, account", "kSecAttrAccount, other")
		}},
		{"store_deletes_before_add", func(s string) string {
			return strings.ReplaceAll(s, "SecItemAdd(query, NULL)", "SecItemAddX(query, NULL)")
		}},
		{"load_prompt_timeout_30s", func(s string) string {
			return strings.ReplaceAll(s, "30 * NSEC_PER_SEC", "5 * NSEC_PER_SEC")
		}},
		{"load_prompt_failure_is_auth_failed", func(s string) string {
			return strings.ReplaceAll(s, "return errSecAuthFailed;", "return errSecInternalError;")
		}},
		{"passphrase_is_c_string", func(s string) string {
			return strings.ReplaceAll(s, "C.GoString(out)", "C.GoStringX(out)")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.assertion, func(t *testing.T) {
			scratch := writeLayoutSource(t, tc.mutate)
			_, err := buildLayout(scratch)
			if err == nil || !strings.Contains(err.Error(), tc.assertion) {
				t.Fatalf("err = %v, want assertion %s", err, tc.assertion)
			}
		})
	}
}

// ---- provenance-bound tests: they need the pinned oracle commit in the object
// database (CI checks out full history), and skip otherwise.

func requirePinnedCommit(t *testing.T) (realRoot string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	realRoot = repositoryRoot()
	cmd := exec.Command("git", "cat-file", "-e", pinnedOracleCommit+"^{commit}") // #nosec G204 -- constant pinned commit
	cmd.Dir = realRoot
	if err := cmd.Run(); err != nil {
		t.Skipf("pinned oracle commit %s is not in this checkout: %v", pinnedOracleCommit, err)
	}
	return realRoot
}

// provenanceRoot builds a throwaway repository root: an empty git repo that
// borrows the real object database (via alternates, no writes to it) so the
// pinned commit resolves, plus byte-identical copies of the sources the
// generator hashes. Nothing here touches the real repository or a keychain.
func provenanceRoot(t *testing.T, realRoot string, files ...string) string {
	t.Helper()
	objects, err := exec.Command("git", "-C", realRoot, "rev-parse", "--path-format=absolute", "--git-path", "objects").Output() // #nosec G204 G702 -- fixed arguments
	if err != nil {
		t.Skipf("cannot locate the object database: %v", err)
	}
	root := t.TempDir()
	init := exec.Command("git", "init", "--quiet", "--template=", root) // #nosec G204 G702 -- throwaway temp dir
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", strings.TrimSpace(string(objects)))
	writeFile(t, filepath.Join(root, "go.mod"), "module fakeroot\n\ngo 1.26\n")
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(realRoot, rel)) // #nosec G304 -- fixed production inputs
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, rel), string(raw))
	}
	return root
}

func allGeneratorInputs() []string {
	return append(append([]string{}, scratchSources...), layoutSource, generatorSource)
}

func TestBuildOracleBindsSourcesToThePinnedCommit(t *testing.T) {
	realRoot := requirePinnedCommit(t)
	root := provenanceRoot(t, realRoot, allGeneratorInputs()...)
	got, err := buildOracle(root)
	if err != nil {
		t.Fatalf("buildOracle: %v", err)
	}
	if got.Commit != pinnedOracleCommit || got.Release != pinnedOracleRelease {
		t.Fatalf("pin = %q %q", got.Commit, got.Release)
	}
	if !strings.HasPrefix(got.CommitSHA, pinnedOracleCommit) || len(got.CommitSHA) != 40 {
		t.Fatalf("commit sha = %q", got.CommitSHA)
	}
	if !sort.StringsAreSorted(got.SourceFiles) || len(got.SourceFiles) != len(scratchSources)+1 {
		t.Fatalf("source files = %v", got.SourceFiles)
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !hex64.MatchString(got.SourceDigest) || !hex64.MatchString(got.GeneratorDigest) || got.SourceDigest == got.GeneratorDigest {
		t.Fatalf("digests = %q %q", got.SourceDigest, got.GeneratorDigest)
	}
	// scratchSources must not be reordered by the call.
	if scratchSources[0] != "internal/session/keychain_status.go" {
		t.Fatalf("scratchSources mutated: %v", scratchSources)
	}
}

func TestBuildOracleErrors(t *testing.T) {
	realRoot := requirePinnedCommit(t)
	t.Run("sources missing", func(t *testing.T) {
		_, err := buildOracle(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "hash production sources") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("working tree drifted from the pinned commit", func(t *testing.T) {
		root := provenanceRoot(t, realRoot, allGeneratorInputs()...)
		path := filepath.Join(root, scratchSources[0])
		raw, err := os.ReadFile(path) // #nosec G304 -- temp copy
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, string(raw)+"\n// drift\n")
		if _, err := buildOracle(root); err == nil || !strings.Contains(err.Error(), "provenance mismatch") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not a git repository", func(t *testing.T) {
		root := t.TempDir()
		for _, rel := range append(append([]string{}, scratchSources...), layoutSource) {
			writeFile(t, filepath.Join(root, rel), "package p\n")
		}
		t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(root))
		if _, err := buildOracle(root); err == nil {
			t.Fatal("provenance accepted a tree without git history")
		}
	})
	t.Run("generator source missing", func(t *testing.T) {
		root := provenanceRoot(t, realRoot, append(append([]string{}, scratchSources...), layoutSource)...)
		if _, err := buildOracle(root); err == nil || !strings.Contains(err.Error(), "hash generator") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRunDriverRecordsTheProductionBehavior(t *testing.T) {
	realRoot := requirePinnedCommit(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	raw, err := runDriver(realRoot)
	if err != nil {
		t.Fatalf("runDriver: %v", err)
	}
	if bytes.ContainsRune(raw, '\n') || bytes.Contains(raw, []byte(`": `)) || bytes.Contains(raw, []byte(`, "`)) {
		t.Fatalf("driver output is not compact: %q", raw)
	}
	var got struct {
		Sentinels []struct{ Name, Message string }
		Statuses  []struct {
			Status    int
			Ok        bool
			Message   string
			Sentinels []string
		}
		Noop []struct {
			Op        string
			Ok        bool
			Sentinels []string
		} `json:"noop_manager"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("driver output is not JSON: %v", err)
	}
	if len(got.Sentinels) != 13 || len(got.Statuses) != 22 || len(got.Noop) != 8 {
		t.Fatalf("shape = %d sentinels, %d statuses, %d noop ops", len(got.Sentinels), len(got.Statuses), len(got.Noop))
	}
	if got.Statuses[0].Status != 0 || !got.Statuses[0].Ok {
		t.Fatalf("status 0 must map to success: %+v", got.Statuses[0])
	}
	if got.Statuses[1].Status != -4 || got.Statuses[1].Ok {
		t.Fatalf("status -4 must map to an error: %+v", got.Statuses[1])
	}
}

func TestRunDriverErrors(t *testing.T) {
	realRoot := requirePinnedCommit(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	t.Run("first production source missing", func(t *testing.T) {
		if _, err := runDriver(t.TempDir()); err == nil || !os.IsNotExist(unwrapPathError(err)) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("second production source missing", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, scratchSources[0]), "package session\n")
		if _, err := runDriver(root); err == nil || !os.IsNotExist(unwrapPathError(err)) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("sources that do not compile", func(t *testing.T) {
		root := t.TempDir()
		for _, rel := range scratchSources {
			writeFile(t, filepath.Join(root, rel), "package session\n")
		}
		if _, err := runDriver(root); err == nil || !strings.Contains(err.Error(), "scratch driver") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("scratch directory cannot be created", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		// os.TempDir reads TMPDIR on Unix and TMP/TEMP/USERPROFILE on Windows.
		for _, name := range []string{"TMPDIR", "TMP", "TEMP", "USERPROFILE"} {
			t.Setenv(name, missing)
		}
		if _, err := runDriver(realRoot); err == nil {
			t.Fatal("expected a scratch-directory error")
		}
	})
}

func unwrapPathError(err error) error {
	for err != nil {
		if pe, ok := err.(*os.PathError); ok {
			return pe
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
	return err
}

func TestRepositoryRootWalksUpToGoMod(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module x\n")
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(nested)
	got, err := filepath.EvalSymlinks(repositoryRoot())
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("root = %q, want %q", got, want)
	}
}

// ---- main(): flag parsing, check mode and write mode.

// runMain runs main() in-process with the given arguments and returns stdout.
// Only paths that return are usable here; fatal() exits and is covered through
// runHelper below.
func runMain(t *testing.T, args ...string) string {
	t.Helper()
	oldArgs, oldFlags, oldStdout := os.Args, flag.CommandLine, os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"biometricgen"}, args...)
	flag.CommandLine = flag.NewFlagSet("biometricgen", flag.ContinueOnError)
	os.Stdout = writer
	defer func() { os.Args, flag.CommandLine, os.Stdout = oldArgs, oldFlags, oldStdout }()
	main()
	_ = writer.Close()
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestHelperProcess re-executes the test binary so fatal()'s os.Exit can be
// observed from a parent. It is a no-op unless BIOMETRICGEN_HELPER is set.
func TestHelperProcess(_ *testing.T) {
	if os.Getenv("BIOMETRICGEN_HELPER") != "1" {
		return
	}
	os.Args = append([]string{"biometricgen"}, flag.Args()...)
	flag.CommandLine = flag.NewFlagSet("biometricgen", flag.ExitOnError)
	main()
	os.Exit(0)
}

type helperResult struct {
	stdout, stderr string
	exit           int
}

// runHelper runs main() in a child process with cwd=dir.
func runHelper(t *testing.T, dir string, env []string, args ...string) helperResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestHelperProcess$", "--"}, args...)...) // #nosec G204 G702 -- re-executes this test binary
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "BIOMETRICGEN_HELPER=1"), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := helperResult{stdout: stdout.String(), stderr: stderr.String()}
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("helper did not start: %v", err)
		}
		res.exit = ee.ExitCode()
	}
	return res
}

func TestMainWritesChecksAndDetectsDrift(t *testing.T) {
	realRoot := requirePinnedCommit(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	root := provenanceRoot(t, realRoot, allGeneratorInputs()...)
	t.Chdir(root)
	fixturePath := filepath.Join(root, filepath.FromSlash(fixtureRelPath))

	// Default output path, created relative to the repository root.
	if got := runMain(t); got != "WROTE "+fixtureRelPath+"\n" {
		t.Fatalf("write mode stdout = %q", got)
	}
	generated, err := os.ReadFile(fixturePath) // #nosec G304 -- temp file
	if err != nil {
		t.Fatalf("fixture not written: %v", err)
	}

	// Byte-identical to the committed fixture: the generator is deterministic and
	// the committed file is not stale.
	committed, err := os.ReadFile(filepath.Join(realRoot, filepath.FromSlash(fixtureRelPath))) // #nosec G304 -- repository fixture
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, committed) {
		t.Fatal("generated fixture differs from the committed fixture")
	}
	var parsed fixture
	if err := json.Unmarshal(generated, &parsed); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	if parsed.SchemaVersion != 1 || parsed.Oracle.Commit != pinnedOracleCommit || len(parsed.Layout.Assertions) == 0 {
		t.Fatalf("fixture content = %+v", parsed.Oracle)
	}
	if !bytes.HasSuffix(generated, []byte("}\n")) || bytes.Contains(generated, []byte(`\u003c`)) {
		t.Fatal("fixture must be indented JSON with HTML escaping off")
	}

	// -check passes against the file just written, and a matching pin is accepted.
	got := runMain(t, "-check", "-oracle-commit", pinnedOracleCommit, "-oracle-release", pinnedOracleRelease)
	if got != "PASS biometric fixture\n" {
		t.Fatalf("check mode stdout = %q", got)
	}
	// Absolute -output paths are used as given, not joined to the root.
	abs := filepath.Join(t.TempDir(), "nested", "dir", "out.json")
	if got := runMain(t, "-output", abs); got != "WROTE "+abs+"\n" {
		t.Fatalf("absolute output stdout = %q", got)
	}
	if again, err := os.ReadFile(abs); err != nil || !bytes.Equal(again, generated) { // #nosec G304 -- temp file
		t.Fatalf("absolute output differs: %v", err)
	}
	if got := runMain(t, "-check", "-output", abs); got != "PASS biometric fixture\n" {
		t.Fatalf("check on absolute path = %q", got)
	}

	// Drift: -check must fail, name the remedy and leave the file untouched.
	drifted := append(append([]byte{}, generated...), ' ')
	writeFile(t, fixturePath, string(drifted))
	res := runHelper(t, root, nil, "-check")
	if res.exit != 1 || !strings.Contains(res.stderr, "FAIL biometric fixture is stale; run make biometric-fixtures-generate") || res.stdout != "" {
		t.Fatalf("drift: exit=%d stdout=%q stderr=%q", res.exit, res.stdout, res.stderr)
	}
	after, err := os.ReadFile(fixturePath) // #nosec G304 -- temp file
	if err != nil || !bytes.Equal(after, drifted) {
		t.Fatalf("-check modified the fixture: %v", err)
	}
	// Check mode against a missing fixture is a read error.
	res = runHelper(t, root, nil, "-check", "-output", filepath.Join(t.TempDir(), "missing.json"))
	if res.exit != 1 || !strings.Contains(res.stderr, "FAIL read fixture:") {
		t.Fatalf("missing fixture: exit=%d stderr=%q", res.exit, res.stderr)
	}
}

func TestMainFatalPaths(t *testing.T) {
	realRoot := requirePinnedCommit(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	root := provenanceRoot(t, realRoot, allGeneratorInputs()...)

	t.Run("flag parsing rejects an unknown flag", func(t *testing.T) {
		res := runHelper(t, root, nil, "-bogus")
		if res.exit != 2 || !strings.Contains(res.stderr, "flag provided but not defined: -bogus") {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
	t.Run("oracle commit other than the pin", func(t *testing.T) {
		res := runHelper(t, root, nil, "-oracle-commit", "deadbeef")
		if res.exit != 1 || !strings.Contains(res.stderr, `FAIL oracle commit "deadbeef" is not the pinned commit "`+pinnedOracleCommit+`"`) {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
	t.Run("oracle release other than the pin", func(t *testing.T) {
		res := runHelper(t, root, nil, "-oracle-release", "v9.9.9")
		if res.exit != 1 || !strings.Contains(res.stderr, `FAIL oracle release "v9.9.9" is not the pinned release "`+pinnedOracleRelease+`"`) {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
	t.Run("no repository root", func(t *testing.T) {
		dir := t.TempDir()
		res := runHelper(t, dir, nil)
		if res.exit != 1 || !strings.Contains(res.stderr, "FAIL repository root not found") {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
	t.Run("provenance failure", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "go.mod"), "module x\n")
		res := runHelper(t, dir, nil)
		if res.exit != 1 || !strings.Contains(res.stderr, "FAIL provenance:") {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
	t.Run("driver cannot run without the go tool", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			// An extensionless git link is not resolved through PATHEXT, and
			// Git for Windows does not run outside its install directory.
			t.Skip("PATH-only git link is not portable to Windows")
		}
		gitPath, err := exec.LookPath("git")
		if err != nil {
			t.Skip("git not available")
		}
		bin := t.TempDir()
		if err := os.Symlink(gitPath, filepath.Join(bin, "git")); err != nil {
			t.Skipf("cannot link git: %v", err)
		}
		res := runHelper(t, root, []string{"PATH=" + bin}, "-output", filepath.Join(t.TempDir(), "x.json"))
		if res.exit != 1 || !strings.Contains(res.stderr, "FAIL scratch driver:") {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
	t.Run("fixture directory cannot be created", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		writeFile(t, blocker, "x")
		res := runHelper(t, root, nil, "-output", filepath.Join(blocker, "sub", "out.json"))
		if res.exit != 1 || !strings.Contains(res.stderr, "FAIL create fixture directory:") {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
	t.Run("fixture file cannot be written", func(t *testing.T) {
		res := runHelper(t, root, nil, "-output", t.TempDir())
		if res.exit != 1 || !strings.Contains(res.stderr, "FAIL write fixture:") {
			t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
		}
	})
}

func TestFatalWritesFailPrefixToStderrAndExitsOne(t *testing.T) {
	if os.Getenv("BIOMETRICGEN_FATAL") == "1" {
		fatal("boom %d", 7)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFatalWritesFailPrefixToStderrAndExitsOne$") // #nosec G204 G702 -- re-executes this test binary
	cmd.Env = append(os.Environ(), "BIOMETRICGEN_FATAL=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 || stderr.String() != "FAIL boom 7\n" {
		t.Fatalf("err=%v stderr=%q", err, stderr.String())
	}
}

func ptr[T any](v T) *T { return &v }

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
