// Command exportcligen freezes the pinned Go CLI's complete `symvault export`,
// `symvault backup ARCHIVE` and `symvault restore ARCHIVE` command behaviour
// (IO-002 "complete CLI" residual) as a Go-derived byte corpus.
//
// Every observation comes from the pinned Go binary run in a disposable
// per-scenario sandbox (HOME/XDG roots, cwd, vault) with a fixed umask and a
// fixed test passphrase; nothing is derived from the Rust side. A scenario is a
// list of CLI steps (argv + stdin) over a frozen vault seed and pre-existing
// files. The recorded observation is, per step, the exit status and the exact
// stdout/stderr bytes, and for the scenario the complete resulting file tree
// (kind, mode, size, sha256) plus the member list of every archive found in it.
//
// Vault seeds (a Go-initialised vault with encrypted entries) are inputs, not
// outputs: they are created once with --new-seeds and read back from the
// fixture on every later generation and --check, so the corpus is stable even
// though `init` generates a random identity.
//
// Nondeterminism is handled by four narrow rules, all documented in the
// fixture's "normalization" block and re-implemented by the Rust replay:
//   - sandbox root paths are replaced by $ROOT in stdout/stderr/symlink targets;
//   - the audit log (audit-symvault.log) is compared after replacing the
//     per-write values ts/kid/hmac with placeholders (every other field is kept);
//   - a gzip archive written by the command under test is compared by its tar
//     member list, not by its compressed bytes (size -1, sha256 placeholder);
//   - a seed vault's manifest.age that a command created or rewrote (age
//     encryption is randomised) is recorded as "rewritten" rather than by its
//     bytes.
//
// Each scenario runs twice; any difference between the two runs fails the
// generation, so no unreviewed nondeterminism can enter the corpus.
package main

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "bf7f687bb8f57316e8333965635e733b8f567c72"
	pinnedOracleRelease = "unreleased"
	pinnedGoVersion     = "go1.26.6"
	defaultOutput       = "testdata/port/cli/export-backup-restore.json"
	generatorDir        = "scripts/rust-port/cmd/exportcligen"
)

// Seams for tests of main; production always uses the defaults.
var (
	exit           = os.Exit
	validateOracle = validateGoBinary
	locateRoot     = repositoryRoot
)

// fixedSources are the production sources whose behaviour the corpus captures.
var fixedSources = []string{
	"cmd/admin/backup.go",
	"cmd/admin/export.go",
	"internal/cli/cli.go",
	"internal/cli/input.go",
	"internal/cli/input/input.go",
	"internal/errors/errors.go",
	"internal/exporter/csv.go",
	"internal/exporter/exporter.go",
	"internal/exporter/json.go",
	"internal/importer/importer.go",
	"internal/ui/cliout/cliout.go",
}

// globbedSources are extra directories whose non-test Go files are pinned.
var globbedSources = []string{"internal/fsutil"}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	GoVersion       string   `json:"go_version"`
	GOOS            string   `json:"goos"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type normalization struct {
	Root         string `json:"root"`
	Umask        string `json:"umask"`
	Passphrase   string `json:"passphrase"`
	Stdin        string `json:"stdin"`
	AuditLog     string `json:"audit_log"`
	Archive      string `json:"generated_archive"`
	Manifest     string `json:"manifest"`
	TarMember    string `json:"tar_member"`
	Environment  string `json:"environment"`
	TwoRunCheck  string `json:"two_run_check"`
	FixtureScope string `json:"scope"`
	Tree         string `json:"tree"`
	StderrTail   string `json:"stderr_tail"`
}

type fixture struct {
	SchemaVersion int                   `json:"schema_version"`
	Oracle        oracle                `json:"oracle"`
	Normalization normalization         `json:"normalization"`
	Seeds         map[string][]FileSpec `json:"seeds"`
	Cases         []Case                `json:"cases"`
}

func documentedNormalization() normalization {
	return normalization{
		Root:         "stdout, stderr and symlink targets: the sandbox root (and its symlink-resolved form) is replaced by " + rootMarker,
		Umask:        "every step runs through /bin/sh -c 'umask " + umaskValue + "; exec ...' so the oracle and the replay create files under the same umask",
		Passphrase:   "SYMVAULT_PASSPHRASE is the fixed test passphrase and SYMVAULT_ALLOW_ENV_PASSPHRASE=1; the frozen seed identities are encrypted with it",
		Stdin:        "a null stdin is the null device (closed); otherwise the recorded bytes are piped and then EOF",
		AuditLog:     "file " + auditLogName + ": each line is parsed as a JSON object, ts/kid/hmac/argv_hash values (argv_hash digests the argv, which contains the sandbox path) are replaced by " + placeholderTS + "/" + placeholderKID + "/" + placeholderHMAC + "/" + placeholderArgv + " (keys kept), keys are sorted, size and sha256 are taken from that normalized text",
		Archive:      "a *.tar.gz/*.tgz file created or changed by the command under test (its bytes differ from the pre-run state) is recorded with size -1 and sha256 " + placeholderArchive + "; its member list is compared instead",
		Manifest:     "file " + manifestName + " of the frozen vault seed: age encryption is randomised, so when a command created or rewrote it (digest differs from the seed's, or the seed has none) it is recorded with size -1 and sha256 " + placeholderRewrite + "; an untouched manifest keeps its exact digest, and the replay requires the same changed-or-untouched state",
		TarMember:    "tar members record name, type, header mode, content size and sha256; mtime, uid, gid, uname, gname and the tar flavour are host- or implementation-dependent and are not compared",
		Environment:  "PATH=/usr/bin:/bin, HOME/USERPROFILE/XDG_* and TMPDIR inside the sandbox, NO_COLOR=1, LC_ALL=C, TZ=UTC; per-case env/unset overrides are explicit in the case",
		TwoRunCheck:  "the generator runs every case twice against the oracle and fails when any observation differs",
		Tree:         "per case, tree lists the nodes (path, kind, perm bits, size, sha256, symlink target) of the whole sandbox root that are new or differ from the pre-run state (seed vault, pre files, empty home/work/tmp), removed lists pre-run paths that no longer exist, archives lists the tar members of the archives in tree",
		StderrTail:   "a case with stderr_tail_from compares stderr only up to the first occurrence of that marker (third-party age decryption wording); the marker must occur in both, and every other observation of the case stays exact",
		FixtureScope: "unix recording (goos is recorded); modes, errno wording and symlink pre-state are Unix semantics",
	}
}

func main() {
	output := flag.String("output", defaultOutput, "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	goBinary := flag.String("go-binary", "", "validated Go symvault binary used as the oracle")
	newSeeds := flag.Bool("new-seeds", false, "create fresh vault seeds with the oracle instead of reading them from the fixture")
	flag.Parse()
	if *goBinary == "" {
		fatal("--go-binary is required")
	}
	if err := validateOracle(*goBinary); err != nil {
		fatal("validate Go oracle: %v", err)
	}
	commitLabel, releaseLabel, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	root, err := locateRoot()
	if err != nil {
		fatal("locate repository: %v", err)
	}
	sources, err := sourceFiles(root)
	if err != nil {
		fatal("list production sources: %v", err)
	}
	sourceDigest, err := provenance.Digest(root, provenance.EnforcedSources(sources))
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("verify oracle: %v", err)
	}
	generatorFiles, err := generatorSources(root)
	if err != nil {
		fatal("list generator sources: %v", err)
	}
	generatorDigest, err := provenance.Digest(root, generatorFiles)
	if err != nil {
		fatal("hash generator: %v", err)
	}

	var seeds map[string][]FileSpec
	if *newSeeds {
		seeds, err = buildSeeds(*goBinary)
		if err != nil {
			fatal("build seeds: %v", err)
		}
	} else {
		seeds, err = readSeeds(*output)
		if err != nil {
			fatal("read seeds from %s (use --new-seeds for a first generation): %v", *output, err)
		}
	}

	inputs, err := buildCases(seeds)
	if err != nil {
		fatal("build cases: %v", err)
	}
	cases := make([]Case, 0, len(inputs))
	for _, input := range inputs {
		first, err := runCase(*goBinary, seeds, input)
		if err != nil {
			fatal("%v", err)
		}
		second, err := runCase(*goBinary, seeds, input)
		if err != nil {
			fatal("%v", err)
		}
		if !reflect.DeepEqual(first, second) {
			a, _ := json.MarshalIndent(first, "", " ")
			b, _ := json.MarshalIndent(second, "", " ")
			fatal("case %s is not deterministic across two oracle runs:\nfirst:\n%s\nsecond:\n%s", input.ID, a, b)
		}
		cases = append(cases, first)
	}

	// The observations are compared across platforms: they are identical on
	// darwin and linux. `goos` records where the fixture was generated, so a
	// check keeps the recorded value and reports the verifying platform.
	recordedGOOS := runtime.GOOS
	if *check {
		if recordedGOOS, err = readRecordedGOOS(*output); err != nil {
			fatal("read fixture platform: %v", err)
		}
	}
	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: commitLabel, CommitSHA: resolved, Release: releaseLabel,
			GoVersion: pinnedGoVersion, GOOS: recordedGOOS,
			SourceFiles: sources, SourceDigest: sourceDigest,
			GeneratorFiles: generatorFiles, GeneratorDigest: generatorDigest,
		},
		Normalization: documentedNormalization(),
		Seeds:         seeds,
		Cases:         cases,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	summary := fmt.Sprintf("%d cases, %d seeds", len(cases), len(seeds))
	if *check {
		existing, err := os.ReadFile(*output) // #nosec G304 -- repository fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS export/backup/restore CLI fixture (%s; recorded on %s, verified on %s)\n", summary, recordedGOOS, runtime.GOOS)
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%s)\n", *output, summary)
}

func readRecordedGOOS(path string) (string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- repository fixture path
	if err != nil {
		return "", err
	}
	var existing struct {
		Oracle struct {
			GOOS string `json:"goos"`
		} `json:"oracle"`
	}
	if err := json.Unmarshal(raw, &existing); err != nil {
		return "", err
	}
	if existing.Oracle.GOOS == "" {
		return "", fmt.Errorf("fixture records no goos")
	}
	return existing.Oracle.GOOS, nil
}

func readSeeds(path string) (map[string][]FileSpec, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- repository fixture path
	if err != nil {
		return nil, err
	}
	var existing struct {
		Seeds map[string][]FileSpec `json:"seeds"`
	}
	if err := json.Unmarshal(raw, &existing); err != nil {
		return nil, err
	}
	if len(existing.Seeds) == 0 {
		return nil, fmt.Errorf("fixture has no seeds")
	}
	return existing.Seeds, nil
}

func sourceFiles(root string) ([]string, error) {
	files := append([]string(nil), fixedSources...)
	for _, dir := range globbedSources {
		// #nosec G204 -- fixed arguments
		out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--", dir).Output()
		if err != nil {
			return nil, err
		}
		for _, name := range strings.Split(string(out), "\x00") {
			if name == "" || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

// generatorSources lists the generator's own non-test Go files so a harness
// change forces a deliberate regeneration without relabelling the oracle.
func generatorSources(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(generatorDir)))
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, generatorDir+"/"+name)
	}
	sort.Strings(files)
	return files, nil
}

func resolveOracle(check bool, commit, release string) (string, string, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return "", "", fmt.Errorf("oracle commit %q is not pinned", commit)
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release %q is not pinned", release)
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("--oracle-commit and --oracle-release are required")
	}
	return commit, release, nil
}

func validateGoBinary(path string) error {
	const modulePath = "github.com/danieljustus/symaira-vault"
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read build metadata: %w", err)
	}
	if info.Path != modulePath || info.Main.Path != modulePath {
		return fmt.Errorf("main module %q/%q, want %q", info.Path, info.Main.Path, modulePath)
	}
	if info.GoVersion != pinnedGoVersion {
		return fmt.Errorf("GoVersion %q, want %s", info.GoVersion, pinnedGoVersion)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	for key, want := range map[string]string{
		"vcs.revision": pinnedOracleCommit,
		"vcs.modified": "false",
	} {
		if got := settings[key]; got != want {
			return fmt.Errorf("build setting %s=%q, want %q", key, got, want)
		}
	}
	return nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

// marshalJSON renders the fixture compactly, then expands only the outer
// containers (depth <= expandDepth) so a case's tree and archive members stay
// one entry per line: reviewable diffs without a multi-megabyte file.
func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return expandOuter(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), expandDepth), nil
}

const expandDepth = 3

// expandOuter inserts newlines and two-space indentation after the opening
// bracket, between elements and before the closing bracket of every container
// nested at most maxDepth levels deep; deeper containers stay on one line.
func expandOuter(compact []byte, maxDepth int) []byte {
	var out bytes.Buffer
	var stack []bool // true when the open container is expanded
	inString, escaped := false, false
	indent := func(level int) {
		out.WriteByte('\n')
		out.WriteString(strings.Repeat("  ", level))
	}
	for i := 0; i < len(compact); i++ {
		ch := compact[i]
		if inString {
			out.WriteByte(ch)
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
			out.WriteByte(ch)
		case '{', '[':
			closing := byte('}')
			if ch == '[' {
				closing = ']'
			}
			out.WriteByte(ch)
			expanded := len(stack) <= maxDepth && i+1 < len(compact) && compact[i+1] != closing
			stack = append(stack, expanded)
			if expanded {
				indent(len(stack))
			}
		case '}', ']':
			expanded := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if expanded {
				indent(len(stack))
			}
			out.WriteByte(ch)
		case ',':
			out.WriteByte(ch)
			if stack[len(stack)-1] {
				indent(len(stack))
			}
		case ':':
			out.WriteString(": ")
		default:
			out.WriteByte(ch)
		}
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	exit(1)
}
