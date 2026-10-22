// Command errtaxgen freezes the pinned Go CLI's command-line error taxonomy
// (CLI-005) and its output-format gate (CLI-006).
//
// Every observation comes from the pinned Go binary run in a disposable
// HOME/XDG sandbox with stdin closed; nothing is derived from the Rust side.
//
//   - usage: cobra's own diagnostics (unknown command with suggestions, unknown
//     flag, flag needs an argument, invalid flag value, non-root group commands
//     given arguments) with the doubled "Error:" line the root executor adds.
//   - arity: for every runnable command path of the pinned tree, the result of
//     running it with zero to four dummy positional arguments. A row records the
//     full bytes when cobra's argument validator rejected the call and "ok"
//     when the validator accepted it.
//   - gate: for every runnable path, the first dummy-argument count the
//     validator accepts and whether `--json` / `--output yaml|xml` are refused
//     by the output-format gate (exit 9) before the command body runs.
//   - not_initialized: the commands that fail with "vault not initialized" in an
//     empty sandbox (exit 3, doubled line, init hint).
package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
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
	"time"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "0cc780626d3275afad14eb64c44abf8adb23d2ce"
	pinnedOracleRelease = "unreleased"
	rootMarker          = "__ROOT__"
	defaultOutput       = "testdata/port/cli/error-taxonomy.json"
	commandTreePath     = "testdata/port/cli/command-tree.json"
	maxDummyArgs        = 4
	commandTimeout      = 8 * time.Second
)

var fixedSources = []string{"go.mod", "go.sum", "internal/cli/cli.go", "internal/errors/errors.go"}

// gateFormats are the output-format selections the gate is probed with.
var gateFormats = [][]string{{"--json"}, {"--output", "yaml"}, {"--output", "xml"}}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type observation struct {
	Args     []string `json:"args"`
	ExitCode int      `json:"exit_code"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
}

type usageCase struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Observation observation `json:"observation"`
}

type arityProbe struct {
	Count int `json:"count"`
	// Rejected is true when cobra's argument validator refused the call;
	// Observation then holds the complete bytes.
	Rejected    bool         `json:"rejected"`
	Observation *observation `json:"observation,omitempty"`
}

type arityRow struct {
	Path   string       `json:"path"`
	Probes []arityProbe `json:"probes"`
}

type gateRow struct {
	Path      string `json:"path"`
	ValidArgs int    `json:"valid_args"`
	// JSONRefused is true when `--json` is refused by the gate. OutputRefused
	// is true when `--output yaml` and `--output xml` are both refused; a
	// command with its own --output flag shadows the persistent one, so the two
	// can differ.
	JSONRefused   bool          `json:"json_refused"`
	OutputRefused bool          `json:"output_refused"`
	Refusals      []observation `json:"refusals,omitempty"`
}

type fixture struct {
	SchemaVersion  int           `json:"schema_version"`
	Oracle         oracle        `json:"oracle"`
	Usage          []usageCase   `json:"usage"`
	Arity          []arityRow    `json:"arity"`
	Gate           []gateRow     `json:"gate"`
	NotInitialized []observation `json:"not_initialized"`
}

type treeFile struct {
	Commands []struct {
		Path          string `json:"path"`
		Runnable      bool   `json:"runnable"`
		HasSubcommand bool   `json:"has_subcommands"`
		Hidden        bool   `json:"hidden"`
	} `json:"commands"`
}

type usageInput struct {
	name, description string
	args              []string
}

func usageInputs() []usageInput {
	return []usageInput{
		{"unknown_root_command", "an unknown top-level command", []string{"bogus"}},
		{"unknown_root_command_suggestion", "a typo of a command name, which cobra answers with suggestions", []string{"lst"}},
		{"unknown_root_command_prefix", "a prefix of several command names", []string{"conf"}},
		{"unknown_root_command_after_flag", "an unknown command after a persistent flag with a value", []string{"--output", "json", "bogus"}},
		{"unknown_root_command_with_args", "an unknown command with trailing arguments", []string{"bogus", "a", "b"}},
		{"unknown_root_command_levenshtein", "a one-letter typo of a command name", []string{"gett"}},
		{"unknown_root_command_prefix_s", "a one-letter prefix that matches commands of several groups", []string{"s"}},
		{"unknown_root_command_prefix_e", "a prefix across the Essentials and Sharing groups", []string{"e"}},
		{"unknown_root_command_prefix_re", "a prefix across the Vault and Sharing groups", []string{"re"}},
		{"unknown_root_command_prefix_a", "a prefix across the Essentials, Agents and Administration groups", []string{"a"}},
		{"unknown_root_command_mixed_case", "suggestions compare case-insensitively", []string{"LIST"}},
		{"unknown_root_command_alias_typo", "a typo of an alias, which cobra does not suggest", []string{"lss"}},
		{"unknown_flag_root", "an unknown long flag on the root command", []string{"--bogus"}},
		{"unknown_flag_root_equals", "an unknown long flag with =value", []string{"--bogus=1"}},
		{"unknown_shorthand_root", "an unknown shorthand flag on the root command", []string{"-Z"}},
		{"unknown_shorthand_group", "an unknown shorthand cluster after a valid one", []string{"-hZ"}},
		{"unknown_flag_get", "an unknown long flag on get", []string{"get", "--bogus"}},
		{"unknown_flag_get_after_arg", "an unknown long flag after the positional argument", []string{"get", "x", "--bogus"}},
		{"unknown_flag_list", "an unknown long flag on list", []string{"list", "--bogus"}},
		{"unknown_flag_config_get", "an unknown long flag on a nested command", []string{"config", "get", "--bogus"}},
		{"unknown_shorthand_get", "an unknown shorthand flag on get", []string{"get", "-Z"}},
		{"unknown_flag_group", "an unknown long flag on a non-runnable group", []string{"config", "--bogus"}},
		{"unknown_flag_before_command", "an unknown long flag before a known command", []string{"--bogus", "list"}},
		{"flag_needs_argument_output", "--output without its value", []string{"--output"}},
		{"flag_needs_argument_vault", "--vault without its value", []string{"--vault"}},
		{"flag_needs_argument_profile", "--profile without its value", []string{"--profile"}},
		{"flag_needs_argument_after_command", "a persistent flag without its value after a command", []string{"get", "x", "--output"}},
		{"flag_needs_argument_shorthand", "a shorthand flag that needs a value", []string{"generate", "-l"}},
		{"flag_needs_argument_local", "a command-local value flag without its value", []string{"generate", "--length"}},
		{"invalid_bool_value", "an invalid boolean value", []string{"--quiet=maybe", "version"}},
		{"invalid_int_value", "an invalid integer value", []string{"generate", "--length", "abc"}},
		{"invalid_int_value_equals", "an invalid integer value with =", []string{"generate", "--length=abc"}},
		{"group_with_unknown_subcommand", "a non-root group given an unknown subcommand", []string{"config", "bogus"}},
		{"nested_group_with_unknown_subcommand", "a nested group given an unknown subcommand", []string{"agent", "token", "bogus"}},
		{"group_with_extra_args", "a non-root group given trailing arguments", []string{"config", "a", "b"}},
		{"gate_before_vault", "the output gate refuses before the vault is touched", []string{"doctor", "--output", "xml"}},
		{"gate_equals_form", "the gate with --output=yaml", []string{"--output=yaml", "startup-profile"}},
		{"output_text_explicit", "an explicit --output text on a refusing command is accepted", []string{"--output", "text", "version"}},
		{"output_empty_value", "an empty --output value", []string{"--output", "", "doctor"}},
		{"output_case_sensitive", "--output JSON is not json", []string{"--output", "JSON", "doctor"}},
	}
}

type sandbox struct {
	root string
	env  []string
}

func newSandbox() (*sandbox, error) {
	root, err := os.MkdirTemp("", "errtaxgen-")
	if err != nil {
		return nil, err
	}
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(root, "xdg-config"),
		"XDG_DATA_HOME=" + filepath.Join(root, "xdg-data"),
		"XDG_CACHE_HOME=" + filepath.Join(root, "xdg-cache"),
		"TMPDIR=" + root,
		"CI=1",
		"NO_COLOR=1",
	}
	return &sandbox{root: root, env: env}, nil
}

func (s *sandbox) normalize(text string) string {
	roots := []string{s.root}
	if resolved, err := filepath.EvalSymlinks(s.root); err == nil && resolved != s.root {
		roots = append([]string{resolved}, roots...)
	}
	for _, root := range roots {
		text = strings.ReplaceAll(text, root, rootMarker)
	}
	return text
}

type result struct {
	obs      observation
	timedOut bool
}

// run executes the oracle in a fresh sandbox. A timed-out command keeps the
// partial stderr so a gate refusal (which is immediate) can still be told apart.
func run(goBinary string, args []string) (result, error) {
	box, err := newSandbox()
	if err != nil {
		return result{}, err
	}
	defer func() { _ = os.RemoveAll(box.root) }()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	// #nosec G204 -- validateGoBinary checked the pinned, clean oracle before this command.
	cmd := exec.CommandContext(ctx, goBinary, args...)
	cmd.Dir = box.root
	cmd.Env = box.env
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	out := result{obs: observation{Args: args}}
	if ctx.Err() != nil {
		out.timedOut = true
		out.obs.ExitCode = -1
	} else if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return result{}, runErr
		}
		out.obs.ExitCode = exitErr.ExitCode()
	}
	for _, text := range []struct {
		raw  []byte
		dest *string
	}{{stdout.Bytes(), &out.obs.Stdout}, {stderr.Bytes(), &out.obs.Stderr}} {
		if !isUTF8(text.raw) {
			return result{}, fmt.Errorf("oracle output of %v is not valid UTF-8", args)
		}
		*text.dest = box.normalize(string(text.raw))
	}
	return out, nil
}

func isUTF8(raw []byte) bool { return strings.ToValidUTF8(string(raw), "\x00?") == string(raw) }

// isArityRejection reports whether stderr starts with one of cobra's argument
// validator messages as printed by the root executor.
func isArityRejection(obs observation) bool {
	if obs.ExitCode != 1 || obs.Stdout != "" {
		return false
	}
	first, _, _ := strings.Cut(obs.Stderr, "\n")
	for _, prefix := range []string{"Error: accepts ", "Error: requires at least ", "Error: requires at most "} {
		if strings.HasPrefix(first, prefix) && strings.Contains(first, " arg(s)") {
			return true
		}
	}
	return false
}

func isGateRefusal(res result) bool {
	return res.obs.ExitCode == 9 && strings.Contains(res.obs.Stderr, "is not supported by '")
}

func isNotInitialized(obs observation) bool {
	return obs.ExitCode == 3 && obs.Stdout == "" &&
		strings.HasPrefix(obs.Stderr, "Error: vault not initialized. Run 'symvault init' first\n") &&
		strings.HasSuffix(obs.Stderr, "Run 'symvault init' for a quick start, or 'symvault setup' for the guided wizard.\n")
}

func dummyArgs(count int) []string {
	args := make([]string, count)
	for i := range args {
		args[i] = "x"
	}
	return args
}

func pathArgs(path string) []string {
	fields := strings.Fields(path)
	if len(fields) <= 1 {
		return nil
	}
	return append([]string(nil), fields[1:]...)
}

func concat(parts ...[]string) []string {
	var out []string
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func buildUsage(goBinary string) ([]usageCase, error) {
	var out []usageCase
	for _, in := range usageInputs() {
		res, err := run(goBinary, in.args)
		if err != nil {
			return nil, fmt.Errorf("usage case %s: %w", in.name, err)
		}
		if res.timedOut {
			return nil, fmt.Errorf("usage case %s timed out", in.name)
		}
		out = append(out, usageCase{Name: in.name, Description: in.description, Observation: res.obs})
	}
	return out, nil
}

func buildPaths(goBinary, root string) ([]arityRow, []gateRow, []observation, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(commandTreePath))) // #nosec G304 -- repository fixture path
	if err != nil {
		return nil, nil, nil, err
	}
	var tree treeFile
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, nil, nil, err
	}
	var arity []arityRow
	var gate []gateRow
	var notInitialized []observation
	seenInit := map[string]bool{}
	for _, command := range tree.Commands {
		if !command.Runnable || command.Path == "symvault" {
			continue
		}
		base := pathArgs(command.Path)
		row := arityRow{Path: command.Path}
		valid := -1
		for count := 0; count <= maxDummyArgs; count++ {
			res, err := run(goBinary, concat(base, dummyArgs(count)))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("arity %s/%d: %w", command.Path, count, err)
			}
			probe := arityProbe{Count: count}
			if !res.timedOut && isArityRejection(res.obs) {
				probe.Rejected = true
				observed := res.obs
				probe.Observation = &observed
			} else if valid < 0 {
				valid = count
			}
			row.Probes = append(row.Probes, probe)
		}
		arity = append(arity, row)
		if valid < 0 {
			return nil, nil, nil, fmt.Errorf("%s: no dummy-argument count passes the validator", command.Path)
		}
		entry := gateRow{Path: command.Path, ValidArgs: valid}
		var outputRefusals int
		for _, format := range gateFormats {
			res, err := run(goBinary, concat(base, dummyArgs(valid), format))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("gate %s %v: %w", command.Path, format, err)
			}
			if !isGateRefusal(res) {
				continue
			}
			entry.Refusals = append(entry.Refusals, res.obs)
			if format[0] == "--json" {
				entry.JSONRefused = true
			} else {
				outputRefusals++
			}
		}
		switch outputRefusals {
		case 0:
		case len(gateFormats) - 1:
			entry.OutputRefused = true
		default:
			return nil, nil, nil, fmt.Errorf("%s: the gate refuses only some --output formats", command.Path)
		}
		gate = append(gate, entry)
		plain, err := run(goBinary, concat(base, dummyArgs(valid)))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("plain %s: %w", command.Path, err)
		}
		if !plain.timedOut && isNotInitialized(plain.obs) {
			key := strings.Join(plain.obs.Args, "\x00")
			if !seenInit[key] {
				seenInit[key] = true
				notInitialized = append(notInitialized, plain.obs)
			}
		}
	}
	return arity, gate, notInitialized, nil
}

func sourceFiles(root string) ([]string, error) {
	// #nosec G204 -- fixed arguments
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--", "cmd/*.go", "cmd/**/*.go").Output()
	if err != nil {
		return nil, err
	}
	files := append([]string(nil), fixedSources...)
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	return files, nil
}

func main() {
	output := flag.String("output", defaultOutput, "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	goBinary := flag.String("go-binary", "", "validated Go symvault binary used as the oracle")
	flag.Parse()
	if *goBinary == "" {
		fatal("--go-binary is required")
	}
	if err := validateGoBinary(*goBinary); err != nil {
		fatal("validate Go oracle: %v", err)
	}
	commitLabel, releaseLabel, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	root, err := repositoryRoot()
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
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("verify oracle: %v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/errtaxgen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}
	usage, err := buildUsage(*goBinary)
	if err != nil {
		fatal("build usage cases: %v", err)
	}
	arity, gate, notInitialized, err := buildPaths(*goBinary, root)
	if err != nil {
		fatal("build path cases: %v", err)
	}
	content, err := marshalJSON(fixture{
		SchemaVersion:  1,
		Oracle:         oracle{commitLabel, resolved, releaseLabel, sources, sourceDigest, generatorDigest},
		Usage:          usage,
		Arity:          arity,
		Gate:           gate,
		NotInitialized: notInitialized,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	summary := fmt.Sprintf("%d usage cases, %d arity rows, %d gate rows, %d not-initialized cases", len(usage), len(arity), len(gate), len(notInitialized))
	if *check {
		existing, err := os.ReadFile(*output) // #nosec G304 -- repository fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS error taxonomy fixture (%s)\n", summary)
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
	os.Exit(1)
}
