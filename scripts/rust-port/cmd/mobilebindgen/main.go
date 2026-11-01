// Command mobilebindgen freezes the Go gomobile bridge (FFI-001): every
// exported function of pkg/mobilebind, which re-exports internal/mobilebind.
//
// Every expectation is produced by calling the real Go functions in this
// process; nothing is derived from the Rust side. A case is data: an optional
// frozen vault written by Go, file mutations, and an ordered list of calls with
// the exact result or error text Go returned.
//
// Randomness. Fresh identities, ciphertexts and vault files are random by
// construction, so their bytes cannot be pinned. Two mechanisms replace byte
// equality, and neither is silent:
//
//  1. Seed material. Ciphertexts and the vault tree that Go produced once are
//     stored in the fixture ("seed") and fed back verbatim. Decrypting or
//     opening them is deterministic, so those results are pinned exactly.
//  2. Shapes. A call whose output is random records prefix, charset and length
//     (all deterministic for age) plus a round trip through the inverse
//     function, whose result is pinned. The generator verifies both before it
//     records the case; Rust and Swift verify them again.
//
// --check re-runs every case against the real Go functions from the seed that
// is stored in the fixture and fails on any byte of difference (including the
// provenance header), so a stale or hand-edited fixture cannot pass.
//
// Normalization applied identically by every consumer: the per-case temporary
// root is "$ROOT" in arguments and in every captured string (both the plain and
// the macOS "/private" spelling); meta.created/updated of an entry written in
// the same case become "<TIMESTAMP>" when, and only when, they have the shipped
// RFC 3339 UTC spelling.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommitDefault = "22c51834ef58d131640362b79fd7377240567279"
	pinnedOracleRelease       = "unreleased"
	defaultOutput             = "testdata/port/ffi/mobilebind.json"
	requiredGoVersion         = "go1.26.6"
)

// pinnedOracleCommit is only reassigned by tests.
var pinnedOracleCommit = pinnedOracleCommitDefault

// sourceDirs are every package directory pkg/mobilebind links (go list -deps),
// listed by directory so the digest is identical on every platform.
var sourceDirs = []string{
	"internal/config", "internal/crypto", "internal/errors", "internal/fsutil",
	"internal/mobilebind", "internal/vault", "pkg/mobilebind",
}

// dependencyModules are third-party modules whose error texts are part of the
// contract (age, bech32, scrypt and YAML diagnostics reach the caller).
var dependencyModules = []string{"filippo.io/age", "golang.org/x/crypto", "gopkg.in/yaml.v3", "github.com/danieljustus/symaira-corekit"}

var generatorFiles = []string{
	"scripts/rust-port/cmd/mobilebindgen/cases.go",
	"scripts/rust-port/cmd/mobilebindgen/exec.go",
	"scripts/rust-port/cmd/mobilebindgen/main.go",
}

type oracle struct {
	Commit          string            `json:"commit"`
	CommitSHA       string            `json:"commit_sha"`
	Release         string            `json:"release"`
	GoVersion       string            `json:"go_version"`
	SourceFiles     []string          `json:"source_files"`
	SourceDigest    string            `json:"source_digest"`
	Dependencies    map[string]string `json:"dependencies"`
	GeneratorFiles  []string          `json:"generator_files"`
	GeneratorDigest string            `json:"generator_digest"`
}

type fixture struct {
	SchemaVersion int            `json:"schema_version"`
	Oracle        oracle         `json:"oracle"`
	Functions     []string       `json:"functions"`
	StepCounts    map[string]int `json:"step_counts"`
	Seed          seedData       `json:"seed"`
	Cases         []caseSpec     `json:"cases"`
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func git(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed subcommands over the repository root
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v: %w: %s", args, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// productionSources lists non-test Go files of the linked packages at the
// pinned commit, plus the dependency manifests (recorded, never enforced).
func productionSources(root string) ([]string, error) {
	args := append([]string{"ls-tree", "-r", "--name-only", pinnedOracleCommit, "--"}, sourceDirs...)
	out, err := git(root, args...)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, name := range strings.Fields(string(out)) {
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	// A file added below the linked directories since the pin is an unreviewed
	// change of behavior-bearing source.
	diffArgs := append([]string{"diff", "--no-renames", "--name-only", "--diff-filter=AD", "-z", pinnedOracleCommit, "--"}, sourceDirs...)
	changed, err := git(root, diffArgs...)
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(string(changed), "\x00") {
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			return nil, fmt.Errorf("production Go source inventory differs from %s: %s; advance the oracle pin deliberately", pinnedOracleCommit, name)
		}
	}
	return append(names, "go.mod", "go.sum"), nil
}

func moduleVersions(root string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- fixed repository file
	if err != nil {
		return nil, err
	}
	versions := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), "// indirect"))
		if len(fields) >= 2 {
			for _, module := range dependencyModules {
				if fields[0] == module {
					versions[module] = fields[1]
				}
			}
		}
	}
	for _, module := range dependencyModules {
		if versions[module] == "" {
			return nil, fmt.Errorf("go.mod does not pin %s", module)
		}
	}
	return versions, nil
}

func buildOracle(root string) (oracle, error) {
	o := oracle{Commit: pinnedOracleCommit, Release: pinnedOracleRelease, GoVersion: runtime.Version(), GeneratorFiles: generatorFiles}
	if o.GoVersion != requiredGoVersion {
		return o, fmt.Errorf("requires %s, got %s", requiredGoVersion, o.GoVersion)
	}
	sources, err := productionSources(root)
	if err != nil {
		return o, err
	}
	o.SourceFiles = sources
	enforced := provenance.EnforcedSources(sources)
	if o.SourceDigest, err = provenance.Digest(root, enforced); err != nil {
		return o, err
	}
	if o.CommitSHA, err = provenance.Verify(root, pinnedOracleCommit, sources); err != nil {
		return o, err
	}
	if o.GeneratorDigest, err = provenance.Digest(root, generatorFiles); err != nil {
		return o, err
	}
	o.Dependencies, err = moduleVersions(root)
	return o, err
}

// ---- verification of random outputs -------------------------------------------

func verifyShape(o observation, sh *shape) error {
	if o.err != nil {
		return fmt.Errorf("unexpected error: %v", o.err)
	}
	switch o.kind {
	case "string":
		if !strings.HasPrefix(o.str, sh.StringPrefix) {
			return fmt.Errorf("string %q lacks prefix %q", o.str, sh.StringPrefix)
		}
		if len(o.str) != sh.Length {
			return fmt.Errorf("string length %d, want %d", len(o.str), sh.Length)
		}
		body := strings.TrimPrefix(o.str, sh.StringPrefix)
		switch sh.StringCharset {
		case "bech32-upper":
			if !bech32U.MatchString(body) {
				return fmt.Errorf("charset mismatch in %q", o.str)
			}
		case "bech32-lower":
			if !bech32L.MatchString(body) {
				return fmt.Errorf("charset mismatch in %q", o.str)
			}
		}
	case "bytes":
		if !bytes.HasPrefix(o.data, decodeB64(sh.BytesPrefixB64)) {
			return fmt.Errorf("bytes lack the expected header prefix")
		}
		if len(o.data) != sh.Length {
			return fmt.Errorf("byte length %d, want %d", len(o.data), sh.Length)
		}
		if sh.ScryptWorkFactor > 0 {
			lines := strings.SplitN(string(o.data), "\n", 3)
			if len(lines) < 3 || lines[1] == "" || !strings.HasSuffix(lines[1], fmt.Sprintf(" %d", sh.ScryptWorkFactor)) {
				return fmt.Errorf("scrypt stanza %q does not carry work factor %d", lines[1], sh.ScryptWorkFactor)
			}
		}
	default:
		return fmt.Errorf("no shape for kind %s", o.kind)
	}
	return nil
}

func substituteOut(a callArgs, o observation) callArgs {
	sub := func(s string) string {
		if s == outToken {
			return o.str
		}
		return s
	}
	a.Identity, a.Recipient, a.Pubkey = sub(a.Identity), sub(a.Recipient), sub(a.Pubkey)
	if a.CiphertextB64 == outToken {
		a.CiphertextB64 = b64(o.data)
	}
	return a
}

func sameWant(a, b want) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// runRandomized verifies one shape-recorded step and returns its want.
func runRandomized(st stepSpec, a callArgs, sh *shape) (want, error) {
	o := invoke(st.Function, a)
	if err := verifyShape(o, sh); err != nil {
		return want{}, fmt.Errorf("%s: %w", st.Function, err)
	}
	if sh.Distinct {
		again := invoke(st.Function, a)
		if again.err != nil || again.str != o.str || !bytes.Equal(again.data, o.data) {
			// distinct, as expected
		} else {
			return want{}, fmt.Errorf("%s: two calls produced identical output", st.Function)
		}
	}
	if sh.Roundtrip != nil {
		rt := invoke(sh.Roundtrip.Function, substituteOut(sh.Roundtrip.Args, o))
		if sh.Roundtrip.Want.Shape != nil {
			if err := verifyShape(rt, sh.Roundtrip.Want.Shape); err != nil {
				return want{}, fmt.Errorf("roundtrip %s: %w", sh.Roundtrip.Function, err)
			}
		} else if got := record(rt, "", nil); !sameWant(got, sh.Roundtrip.Want) {
			return want{}, fmt.Errorf("roundtrip %s: got %+v", sh.Roundtrip.Function, got)
		}
	}
	return want{OK: true, Shape: sh}, nil
}

// runCase executes one case against the real Go functions and fills its wants.
func runCase(c caseSpec, sd *seedData) (caseSpec, error) {
	root, err := os.MkdirTemp("", "mobilebindgen-")
	if err != nil {
		return c, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	if c.Vault {
		if err := materialize(sd.Vault.Files, filepath.Join(root, "vault"), root); err != nil {
			return c, err
		}
	}
	for _, m := range c.Mutations {
		if err := applyMutation(filepath.Join(root, "vault"), m); err != nil {
			return c, fmt.Errorf("%s: mutation %+v: %w", c.ID, m, err)
		}
	}
	steps := make([]stepSpec, len(c.Steps))
	copy(steps, c.Steps)
	for i, st := range steps {
		a := expandArgs(st.Args, root)
		if sh, ok := c.randomized[i]; ok {
			w, err := runRandomized(st, a, sh)
			if err != nil {
				return c, fmt.Errorf("%s step %d: %w", c.ID, i, err)
			}
			steps[i].Want = w
			continue
		}
		steps[i].Want = record(invoke(st.Function, a), root, st.Normalize)
	}
	c.Steps = steps
	if c.afterPaths != nil || c.afterTree {
		base := expandArgs(c.Steps[0].Args, root).VaultDir
		after, err := snapshotAfter(base, root, c.afterPaths, c.afterTree, c.afterText)
		if err != nil {
			return c, fmt.Errorf("%s: snapshot: %w", c.ID, err)
		}
		c.After = &after
	}
	return c, nil
}

func build(root string, sd *seedData) (fixture, error) {
	f := fixture{SchemaVersion: 1, Functions: functions, StepCounts: map[string]int{}}
	var err error
	if f.Oracle, err = buildOracle(root); err != nil {
		return f, err
	}
	curSeed = sd
	f.Seed = *sd
	seen := map[string]bool{}
	for _, c := range buildCases(*sd) {
		if seen[c.ID] {
			return f, fmt.Errorf("duplicate case id %s", c.ID)
		}
		seen[c.ID] = true
		done, err := runCase(c, sd)
		if err != nil {
			return f, err
		}
		for _, st := range done.Steps {
			f.StepCounts[st.Function]++
		}
		f.Cases = append(f.Cases, done)
	}
	for _, fn := range functions {
		if f.StepCounts[fn] == 0 {
			return f, fmt.Errorf("function %s has no case", fn)
		}
	}
	return f, nil
}

func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- driver ----------------------------------------------------------------

type driveRequest struct {
	Function string   `json:"function"`
	Args     callArgs `json:"args"`
}

type driveResponse struct {
	OK       bool    `json:"ok"`
	String   *string `json:"string,omitempty"`
	BytesB64 *string `json:"bytes_b64,omitempty"`
	Bool     *bool   `json:"bool,omitempty"`
	Error    string  `json:"error,omitempty"`
}

// drive answers one JSON request per line with the raw (unnormalized) result of
// the real Go function. The Rust interoperability tests use it so that every
// cross-direction check runs against Go itself, never against a recording.
func drive(in *os.File, out *os.File) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	writer := bufio.NewWriter(out)
	for scanner.Scan() {
		var req driveRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return err
		}
		o := invoke(req.Function, req.Args)
		var resp driveResponse
		if o.err != nil {
			resp.Error = o.err.Error()
		} else {
			resp.OK = true
			switch o.kind {
			case "string":
				resp.String = &o.str
			case "bytes":
				s := b64(o.data)
				resp.BytesB64 = &s
			case "bool":
				resp.Bool = &o.flag
			}
		}
		line, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func run() error {
	output := flag.String("output", defaultOutput, "fixture path")
	check := flag.Bool("check", false, "re-run Go against the recorded seed and compare without writing")
	keepSeed := flag.Bool("keep-seed", false, "generate from the seed already stored in the output fixture (adding only missing derived seed material) instead of drawing a new one; existing cases stay byte-identical")
	driveMode := flag.Bool("drive", false, "answer JSON-line calls on stdin with the real Go functions")
	flag.Parse()
	if *driveMode {
		return drive(os.Stdin, os.Stdout)
	}
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	path := *output
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	var sd seedData
	var existing []byte
	if *check {
		if existing, err = os.ReadFile(path); err != nil { // #nosec G304 -- operator-chosen fixture path
			return err
		}
		var old fixture
		if err := json.Unmarshal(existing, &old); err != nil {
			return fmt.Errorf("recorded fixture is not valid JSON: %w", err)
		}
		sd = old.Seed
	} else if *keepSeed {
		if existing, err = os.ReadFile(path); err != nil { // #nosec G304 -- operator-chosen fixture path
			return err
		}
		var old fixture
		if err := json.Unmarshal(existing, &old); err != nil {
			return fmt.Errorf("recorded fixture is not valid JSON: %w", err)
		}
		sd = old.Seed
		if err := addDerivedSeed(&sd); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
		existing = nil
	} else {
		tmp, err := os.MkdirTemp("", "mobilebindgen-seed-")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		if sd, err = makeSeed(tmp); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
	}
	curSeed = &sd
	f, err := build(root, &sd)
	if err != nil {
		return err
	}
	data, err := marshalJSON(f)
	if err != nil {
		return err
	}
	if *check {
		if !bytes.Equal(data, existing) {
			if scratch, werr := os.CreateTemp("", "mobilebind-actual-*.json"); werr == nil {
				_, _ = scratch.Write(data)
				_ = scratch.Close()
				fmt.Fprintf(os.Stderr, "regenerated oracle output written to %s for diffing\n", scratch.Name())
			}
			return fmt.Errorf("mobilebind fixture %s differs from the production oracle (stale or edited); regenerate deliberately with `make ffi-fixtures-generate`", *output)
		}
		fmt.Printf("OK mobilebind fixture matches Go oracle (%d cases, %d steps)\n", len(f.Cases), totalSteps(f))
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644) // #nosec G306 -- generated fixture is non-sensitive repository data
}

func totalSteps(f fixture) int {
	n := 0
	for _, c := range counts(f) {
		n += c
	}
	return n
}

func counts(f fixture) map[string]int { return f.StepCounts }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		os.Exit(1)
	}
}
