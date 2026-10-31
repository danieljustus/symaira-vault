// Command importcligen freezes the pinned Go CLI's complete `symvault import
// <source>` command (IO-001): argv handling, format resolution, every flag and
// their interactions, per-format sources, existing-entry collisions, prefix
// joining, error paths, and the resulting vault state.
//
// Every observation comes from the pinned Go binary run in a disposable
// HOME/XDG/vault sandbox; nothing is derived from the Rust side. A case is
// data: source files materialised in the sandbox working directory, seed
// commands that build the starting vault state, the import argv, and post
// commands (`list --json`, `export --format json --yes`) that pin the
// resulting entries, field values and secret metadata.
//
// Documented normalization rules (applied identically by the Rust replay in
// crates/symvault-cli/tests/import_command_contract.rs):
//
//  1. Sandbox paths. The sandbox working directory and root are replaced by
//     "@WORK" and "@ROOT" in every captured stream, and the token "@WORK" in
//     an argv/seed element is replaced by the working directory. This keeps
//     absolute-path error text comparable without dropping it.
//  2. Quarantine import IDs. `--quarantine` mints `import-YYYYMMDD-<8 hex>`
//     from the wall clock and a random source. Exactly that shape (a valid
//     calendar date and 8 lowercase hex digits) is rewritten to
//     "import-<DATE>-<RAND>" in stdout, stderr and post stdout. Nothing else
//     is rewritten and an ID of any other shape stays visible as a diff.
//
// Streams are compared as raw bytes; post commands compare stdout and exit
// status only, because `export` stderr carries a wall-clock log line.
package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleRelease = "unreleased"
	defaultOutput       = "crates/symvault-cli/tests/fixtures/import-command/cases.json"
	commandTimeout      = 60 * time.Second
	passphrase          = "correct horse battery staple"
	workMarker          = "@WORK"
	rootMarker          = "@ROOT"
)

// pinnedOracleCommit is only reassigned by tests that run main against a
// disposable repository.
var pinnedOracleCommit = "bf7f687bb8f57316e8333965635e733b8f567c72"

var (
	exit           = os.Exit
	validateOracle = validateGoBinary
	locateRoot     = repositoryRoot
)

// generatorFiles are digested separately from the production sources so a
// harness change forces a deliberate regeneration without relabeling the
// oracle.
var generatorFiles = []string{
	"scripts/rust-port/check_import_cli.sh",
	"scripts/rust-port/cmd/importcligen/cases.go",
	"scripts/rust-port/cmd/importcligen/main.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	GoVersion       string   `json:"go_version"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

// fileSpec is one source artifact in the sandbox working directory.
type fileSpec struct {
	Name       string `json:"name"`
	Text       string `json:"text,omitempty"`
	Base64     string `json:"base64,omitempty"`
	SparseSize int64  `json:"sparse_size,omitempty"`
	Mode       string `json:"mode,omitempty"`
	Dir        bool   `json:"dir,omitempty"`
}

type step struct {
	Argv   []string `json:"argv"`
	Exit   int      `json:"exit"`
	Stdout string   `json:"stdout"`
}

type caseResult struct {
	ID       string     `json:"id"`
	Desc     string     `json:"desc"`
	Platform string     `json:"platform"`
	Files    []fileSpec `json:"files,omitempty"`
	Seed     [][]string `json:"seed"`
	Argv     []string   `json:"argv"`
	Exit     int        `json:"exit"`
	Stdout   string     `json:"stdout"`
	Stderr   string     `json:"stderr"`
	Post     []step     `json:"post,omitempty"`
}

type fixture struct {
	SchemaVersion int          `json:"schema_version"`
	Oracle        oracle       `json:"oracle"`
	Notes         []string     `json:"notes"`
	Cases         []caseResult `json:"cases"`
}

// caseInput is a case before the oracle ran it.
type caseInput struct {
	id, desc string
	platform string
	files    []fileSpec
	seed     [][]string
	argv     []string
	// noPost suppresses the vault-state post commands.
	noPost bool
	// extraPost adds commands (for example `find`) after the default ones.
	extraPost [][]string
}

type sandbox struct {
	root, home, work, vault string
	env                     []string
}

func newSandbox() (*sandbox, error) {
	root, err := os.MkdirTemp("", "importcligen-")
	if err != nil {
		return nil, err
	}
	box := &sandbox{
		root:  root,
		home:  filepath.Join(root, "home"),
		work:  filepath.Join(root, "work"),
		vault: filepath.Join(root, "home", "vault"),
	}
	for _, dir := range []string{box.home, box.work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			_ = os.RemoveAll(root)
			return nil, err
		}
	}
	box.env = []string{
		"PATH=" + filepath.Join(box.work, "bin") + ":/usr/bin:/bin",
		"HOME=" + box.home,
		"USERPROFILE=" + box.home,
		"XDG_CONFIG_HOME=" + filepath.Join(root, "xdg-config"),
		"XDG_DATA_HOME=" + filepath.Join(root, "xdg-data"),
		"XDG_CACHE_HOME=" + filepath.Join(root, "xdg-cache"),
		"TMPDIR=" + root,
		"SYMVAULT_VAULT=" + box.vault,
		"SYMVAULT_PASSPHRASE=" + passphrase,
		"SYMVAULT_ALLOW_ENV_PASSPHRASE=1",
		"CI=1",
		"NO_COLOR=1",
	}
	return box, nil
}

func (s *sandbox) materialize(files []fileSpec) error {
	for _, file := range files {
		target := filepath.Join(s.work, filepath.FromSlash(file.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if file.Dir {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		mode := os.FileMode(0o600)
		if file.Mode != "" {
			var parsed uint32
			if _, err := fmt.Sscanf(file.Mode, "%o", &parsed); err != nil {
				return fmt.Errorf("file %s: bad mode %q", file.Name, file.Mode)
			}
			mode = os.FileMode(parsed)
		}
		switch {
		case file.SparseSize > 0:
			handle, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- sandbox path
			if err != nil {
				return err
			}
			if err := handle.Truncate(file.SparseSize); err != nil {
				_ = handle.Close()
				return err
			}
			if err := handle.Close(); err != nil {
				return err
			}
		default:
			content := []byte(file.Text)
			if file.Base64 != "" {
				decoded, err := base64.StdEncoding.DecodeString(file.Base64)
				if err != nil {
					return fmt.Errorf("file %s: %w", file.Name, err)
				}
				content = decoded
			}
			if err := os.WriteFile(target, content, 0o600); err != nil {
				return err
			}
		}
		// Mode is applied last so a 0000 source is still written first.
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
	}
	return nil
}

// expand applies normalization rule 1 to an argv element.
func (s *sandbox) expand(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = strings.ReplaceAll(arg, workMarker, s.work)
	}
	return out
}

// wallClockLine matches the timestamped lines of Go's log package and slog.
var wallClockLine = regexp.MustCompile(`[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}|time=[0-9]{4}-[0-9]{2}-[0-9]{2}T`)

var quarantineID = regexp.MustCompile(`import-([0-9]{8})-[0-9a-f]{8}`)

// normalize applies both documented rules to a captured stream.
func (s *sandbox) normalize(text string) string {
	for _, pair := range []struct{ dir, marker string }{{s.work, workMarker}, {s.root, rootMarker}} {
		dirs := []string{pair.dir}
		if resolved, err := filepath.EvalSymlinks(pair.dir); err == nil && resolved != pair.dir {
			dirs = append([]string{resolved}, dirs...)
		}
		for _, dir := range dirs {
			text = strings.ReplaceAll(text, dir, pair.marker)
		}
	}
	return quarantineID.ReplaceAllStringFunc(text, func(id string) string {
		match := quarantineID.FindStringSubmatch(id)
		if _, err := time.Parse("20060102", match[1]); err != nil {
			return id
		}
		return "import-<DATE>-<RAND>"
	})
}

type observed struct {
	exit           int
	stdout, stderr string
}

func (s *sandbox) run(goBinary string, args []string) (observed, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	// #nosec G204 -- validateGoBinary checked the pinned, clean oracle before this command.
	cmd := exec.CommandContext(ctx, goBinary, s.expand(args)...)
	cmd.Dir = s.work
	cmd.Env = s.env
	cmd.WaitDelay = time.Second
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	out := observed{}
	if ctx.Err() != nil {
		return out, fmt.Errorf("%v timed out", args)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return out, runErr
		}
		out.exit = exitErr.ExitCode()
	}
	for _, text := range []struct {
		raw  []byte
		dest *string
	}{{stdout.Bytes(), &out.stdout}, {stderr.Bytes(), &out.stderr}} {
		if strings.ToValidUTF8(string(text.raw), "\x00?") != string(text.raw) {
			return out, fmt.Errorf("oracle output of %v is not valid UTF-8", args)
		}
		*text.dest = s.normalize(string(text.raw))
	}
	return out, nil
}

// postCommands are the vault-state probes: `list --json` carries the path set,
// the secret type and usage hint; `export` carries every field value.
func postCommands(extra [][]string) [][]string {
	post := [][]string{
		{"list", "--json"},
		{"export", "--format", "json", "--yes"},
	}
	return append(post, extra...)
}

func runCase(goBinary string, in caseInput) (caseResult, error) {
	box, err := newSandbox()
	if err != nil {
		return caseResult{}, err
	}
	defer func() {
		// Restore access so a 0000 source does not block cleanup.
		_ = filepath.WalkDir(box.root, func(path string, entry os.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		_ = os.RemoveAll(box.root)
	}()
	if err := box.materialize(in.files); err != nil {
		return caseResult{}, fmt.Errorf("case %s: %w", in.id, err)
	}
	for _, seed := range in.seed {
		got, err := box.run(goBinary, seed)
		if err != nil {
			return caseResult{}, fmt.Errorf("case %s seed %v: %w", in.id, seed, err)
		}
		if got.exit != 0 {
			return caseResult{}, fmt.Errorf("case %s: seed %v exited %d: %s", in.id, seed, got.exit, got.stderr)
		}
	}
	main, err := box.run(goBinary, in.argv)
	if err != nil {
		return caseResult{}, fmt.Errorf("case %s: %w", in.id, err)
	}
	for _, text := range []string{main.stdout, main.stderr} {
		// Wall-clock log lines would make the corpus unstable; fail loudly
		// instead of silently normalizing them.
		if strings.Contains(text, "level=WARN") || strings.Contains(text, "level=ERROR") || wallClockLine.MatchString(text) {
			return caseResult{}, fmt.Errorf("case %s: oracle emitted a wall-clock log line: %q", in.id, text)
		}
	}
	platform := in.platform
	if platform == "" {
		platform = "any"
	}
	result := caseResult{
		ID: in.id, Desc: in.desc, Platform: platform, Files: in.files,
		Seed: in.seed, Argv: in.argv,
		Exit: main.exit, Stdout: main.stdout, Stderr: main.stderr,
	}
	if result.Seed == nil {
		result.Seed = [][]string{}
	}
	initialized := len(in.seed) > 0 && len(in.seed[0]) == 1 && in.seed[0][0] == "init"
	if initialized && !in.noPost {
		for _, post := range postCommands(in.extraPost) {
			got, err := box.run(goBinary, post)
			if err != nil {
				return caseResult{}, fmt.Errorf("case %s post %v: %w", in.id, post, err)
			}
			result.Post = append(result.Post, step{Argv: post, Exit: got.exit, Stdout: got.stdout})
		}
	}
	return result, nil
}

func sourceFiles(root string) ([]string, error) {
	// #nosec G204 -- fixed arguments
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--",
		"cmd/admin/import.go", "internal/importer/*.go", "internal/cli/*.go").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// Only direct children: testdata and subpackages are not behavior of
		// this command.
		if strings.Count(name, "/") > 2 {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, errors.New("no production sources found")
	}
	return files, nil
}

func main() {
	output := flag.String("output", defaultOutput, "fixture path (relative to the repository root)")
	check := flag.Bool("check", false, "fail if the fixture differs")
	goBinary := flag.String("go-binary", "", "validated Go symvault binary used as the oracle")
	flag.Parse()
	if *goBinary == "" {
		fatal("--go-binary is required")
	}
	if err := validateOracle(*goBinary); err != nil {
		fatal("validate Go oracle: %v", err)
	}
	root, err := locateRoot()
	if err != nil {
		fatal("locate repository: %v", err)
	}
	sources, err := sourceFiles(root)
	if err != nil {
		fatal("list production sources: %v", err)
	}
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, pinnedOracleCommit, sources)
	if err != nil {
		fatal("verify oracle: %v", err)
	}
	generatorDigest, err := provenance.Digest(root, generatorFiles)
	if err != nil {
		fatal("hash generator: %v", err)
	}
	inputs := allCases()
	seen := map[string]bool{}
	var results []caseResult
	for _, in := range inputs {
		if seen[in.id] {
			fatal("duplicate case id %s", in.id)
		}
		seen[in.id] = true
		got, err := runCase(*goBinary, in)
		if err != nil {
			fatal("%v", err)
		}
		results = append(results, got)
	}
	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: pinnedOracleCommit, CommitSHA: resolved, Release: pinnedOracleRelease,
			GoVersion: "go1.26.6", SourceFiles: sources, SourceDigest: sourceDigest,
			GeneratorFiles: generatorFiles, GeneratorDigest: generatorDigest,
		},
		Notes: []string{
			"Every case ran the pinned Go oracle in its own disposable HOME/XDG/vault sandbox with the source files in the working directory.",
			"seed commands build the starting vault; post commands pin the resulting entries (list --json: paths, secret type, usage hint; export: every field value).",
			"Post commands compare stdout and exit only: export stderr carries a wall-clock log line.",
			"The 'SYMVAULT_PASSPHRASE is active' stderr line is part of the oracle bytes on purpose.",
			"Normalization (documented in cmd/importcligen/main.go): sandbox paths become @WORK/@ROOT; quarantine IDs import-YYYYMMDD-<8 hex> become import-<DATE>-<RAND>.",
		},
		Cases: results,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	summary := fmt.Sprintf("%d cases", len(results))
	target := filepath.Join(root, filepath.FromSlash(*output))
	if *check {
		existing, err := os.ReadFile(target) // #nosec G304 -- repository fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS import command fixture (%s)\n", summary)
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%s)\n", *output, summary)
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
	if info.GoVersion != "go1.26.6" {
		return fmt.Errorf("GoVersion %q, want go1.26.6", info.GoVersion)
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

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	exit(1)
}
