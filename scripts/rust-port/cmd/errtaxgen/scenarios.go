package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	stateUninitialized = "uninitialized"
	stateInitialized   = "initialized"

	// seedPassphrase unlocks the frozen vault through the environment. It is a
	// disposable value that protects nothing.
	seedPassphrase = "correct horse battery staple"

	// normalizePassword20 replaces a stdout that is exactly one random
	// 20-character alphanumeric password (`generate` without flags).
	normalizePassword20 = "password20"
	passwordPlaceholder = "__PASSWORD__\n"

	// normalizeKeyBytes replaces the random first four bytes `audit rotate-key`
	// reports for the key it just drew.
	normalizeKeyBytes = "key_bytes"
	keyBytesLine      = "New key: __KEY__ (first 4 bytes)"
)

var (
	password20 = regexp.MustCompile(`^[A-Za-z0-9]{20}\n$`)
	keyBytes   = regexp.MustCompile(`New key: [0-9a-f]{8} \(first 4 bytes\)`)
)

// seedFile is one entry of the frozen vault tree, relative to the sandbox root.
// Text carries the sandbox root as rootMarker.
type seedFile struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Data   string `json:"data,omitempty"`
	Base64 string `json:"base64,omitempty"`
}

// scenarioCase is one recorded run: State picks the starting sandbox (an empty
// one, or one holding the vault_seed tree plus the passphrase environment) and
// Normalize names the narrow, documented rewrites applied to both sides.
type scenarioCase struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	State       string      `json:"state"`
	Normalize   []string    `json:"normalize,omitempty"`
	Observation observation `json:"observation"`
}

type scenarioInput struct {
	name, description, state string
	args                     []string
	normalize                []string
}

type extraSections struct {
	nilArgs          []nilArgsEntry
	seed             []seedFile
	extraPositionals []scenarioCase
	exclusions       []exclusion
	runFileUse       []scenarioCase
}

// Seams for tests of main; production always uses the defaults.
var seedBuilder = buildVaultSeed

// exclusion is a nil-Args command that is not replayed in some states, with the
// reason. The fixture records every exclusion, and a stale key (a command that
// is no longer in the inventory) is an error, so the list cannot rot silently.
// The in-crate parse test still covers an excluded command's positional
// acceptance.
type exclusion struct {
	Path   string   `json:"path"`
	States []string `json:"states"`
	Reason string   `json:"reason"`
}

var bothStates = []string{stateUninitialized, stateInitialized}

var scenarioExclusions = []exclusion{
	{"symvault broker", []string{stateInitialized}, "starts the long-running credential broker; the run times out"},
	{"symvault mcp", []string{stateInitialized}, "starts the MCP server on stdio; the run times out"},
	{"symvault serve", []string{stateInitialized}, "deprecated alias of mcp: starts the MCP server; the run times out"},
	{"symvault device pair", []string{stateInitialized}, "prints a random pairing token"},
	{"symvault migrate v4", []string{stateInitialized}, "lists the agent profiles in Go map-iteration order"},
	{"symvault doctor", bothStates, "host-dependent report with a random temporary file name and a random migrated token id"},
	{"symvault startup-profile", bothStates, "prints measured timings"},
}

func (e exclusion) excludes(state string) bool {
	for _, s := range e.States {
		if s == state {
			return true
		}
	}
	return false
}

// scenarioNormalizers names the commands whose stdout carries a volatile value.
var scenarioNormalizers = map[string][]string{
	"symvault generate":         {normalizePassword20},
	"symvault audit rotate-key": {normalizeKeyBytes},
}

func initializedEnv() []string {
	return []string{
		"TZ=UTC",
		"SYMVAULT_PASSPHRASE=" + seedPassphrase,
		"SYMVAULT_ALLOW_ENV_PASSPHRASE=1",
	}
}

func applyNormalizers(names []string, obs observation) (observation, error) {
	for _, name := range names {
		switch name {
		case normalizePassword20:
			if password20.MatchString(obs.Stdout) {
				obs.Stdout = passwordPlaceholder
			}
		case normalizeKeyBytes:
			obs.Stderr = keyBytes.ReplaceAllString(obs.Stderr, keyBytesLine)
		default:
			return obs, fmt.Errorf("unknown normalizer %q", name)
		}
	}
	return obs, nil
}

func (s *sandbox) writeSeed(seed []seedFile) error {
	for _, entry := range seed {
		path := filepath.Join(s.root, filepath.FromSlash(entry.Path))
		switch entry.Kind {
		case "dir":
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
		case "file":
			raw, err := entry.bytes()
			if err != nil {
				return err
			}
			raw = []byte(strings.ReplaceAll(string(raw), rootMarker, s.root))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				return err
			}
		default:
			return fmt.Errorf("seed entry %s has unknown kind %q", entry.Path, entry.Kind)
		}
		if err := os.Chmod(path, fs.FileMode(entry.Mode)); err != nil {
			return err
		}
	}
	return nil
}

func (f seedFile) bytes() ([]byte, error) {
	if f.Base64 != "" {
		return base64.StdEncoding.DecodeString(f.Base64)
	}
	return []byte(f.Data), nil
}

// collectSeed records everything the vault wrote below XDG_DATA_HOME (the
// sandbox's xdg-data directory), parents before their contents.
func (s *sandbox) collectSeed() ([]seedFile, error) {
	base := filepath.Join(s.root, "xdg-data")
	var out []seedFile
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		item := seedFile{Path: filepath.ToSlash(rel), Mode: uint32(info.Mode().Perm())}
		switch {
		case info.IsDir():
			item.Kind = "dir"
		case info.Mode().IsRegular():
			item.Kind = "file"
			raw, err := os.ReadFile(path) // #nosec G304 -- path inside the disposable sandbox
			if err != nil {
				return err
			}
			if utf8.Valid(raw) && !strings.ContainsRune(string(raw), 0) {
				item.Data = s.normalize(string(raw))
			} else {
				item.Base64 = base64.StdEncoding.EncodeToString(raw)
			}
		default:
			return fmt.Errorf("seed contains unsupported entry %s (%v)", path, info.Mode())
		}
		out = append(out, item)
		return nil
	})
	return out, err
}

// buildVaultSeed initializes a vault with the oracle and settles it with one
// read: a fresh vault's first open rewrites config.yaml and creates .lock and
// manifest.age, which is vault-open behavior shared by every command.
func buildVaultSeed(goBinary string) ([]seedFile, error) {
	box, err := newSandbox()
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(box.root) }()
	box.env = append(box.env, initializedEnv()...)
	for _, args := range [][]string{{"init"}, {"list"}} {
		res, err := runInSandbox(goBinary, box, args)
		if err != nil {
			return nil, err
		}
		if res.timedOut || res.obs.ExitCode != 0 {
			return nil, fmt.Errorf("seed step %v: exit %d (timed out %v): %s", args, res.obs.ExitCode, res.timedOut, res.obs.Stderr)
		}
	}
	return box.collectSeed()
}

// existingSeed reads the vault_seed of an earlier fixture; a missing or
// unreadable file means there is none.
func existingSeed(path string) []seedFile {
	raw, err := os.ReadFile(path) // #nosec G304 -- repository fixture path
	if err != nil {
		return nil
	}
	var previous struct {
		VaultSeed []seedFile `json:"vault_seed"`
	}
	if json.Unmarshal(raw, &previous) != nil {
		return nil
	}
	return previous.VaultSeed
}

// extraPositionalInputs is the matrix for every runnable nil-Args command: one
// and two dummy positionals and a positional after `--`, in an empty sandbox
// and (for the commands not excluded) in the frozen initialized vault.
func extraPositionalInputs(inventory []nilArgsEntry) ([]scenarioInput, error) {
	paths := map[string]bool{}
	for _, entry := range inventory {
		paths[entry.Path] = true
	}
	excluded := map[string]exclusion{}
	for _, item := range scenarioExclusions {
		if !paths[item.Path] {
			return nil, fmt.Errorf("scenarioExclusions names %q, which is not a nil-Args command", item.Path)
		}
		excluded[item.Path] = item
	}
	for path := range scenarioNormalizers {
		if !paths[path] {
			return nil, fmt.Errorf("scenarioNormalizers names %q, which is not a nil-Args command", path)
		}
	}
	variants := []struct {
		name, description string
		extra             []string
		states            []string
	}{
		{"x1", "one extra positional", []string{"x"}, []string{stateUninitialized, stateInitialized}},
		{"x2", "two extra positionals", []string{"x", "y"}, []string{stateUninitialized, stateInitialized}},
		{"dd1", "one positional after --", []string{"--", "x"}, []string{stateUninitialized}},
	}
	var out []scenarioInput
	for _, entry := range inventory {
		if !entry.Runnable {
			continue
		}
		base := pathArgs(entry.Path)
		slug := strings.ReplaceAll(strings.TrimPrefix(entry.Path, "symvault "), " ", "_")
		for _, variant := range variants {
			for _, state := range variant.states {
				if item, skip := excluded[entry.Path]; skip && item.excludes(state) {
					continue
				}
				out = append(out, scenarioInput{
					name:        fmt.Sprintf("extra_%s_%s_%s", state, slug, variant.name),
					description: fmt.Sprintf("%s: %s of a nil-Args command (%s)", entry.Path, variant.description, state),
					state:       state,
					args:        concat(base, variant.extra),
					normalize:   scenarioNormalizers[entry.Path],
				})
			}
		}
	}
	return out, nil
}

// runFileUseInputs permutes the argv of the commands that forward a trailing
// command line. `run` demands at least one positional and `file use` two; both
// take the command after `--`, and the permutations pin where a flag may stand
// among the forwarded words and what an extra `--` does.
func runFileUseInputs() []scenarioInput {
	type permutation struct {
		name, description string
		args              []string
	}
	perms := []permutation{
		{"run_none", "run without a command", []string{"run"}},
		{"run_one_word", "run with a bare word", []string{"run", "x"}},
		{"run_dd_one_word", "run with the command after --", []string{"run", "--", "x"}},
		{"run_two_words", "run with two bare words", []string{"run", "x", "y"}},
		{"run_dd_two_words", "run with a command and an argument after --", []string{"run", "--", "x", "y"}},
		{"run_word_dd_word", "run with a word before -- and one after", []string{"run", "x", "--", "y"}},
		{"run_env_then_dd", "run with an --env flag before --", []string{"run", "--env", "A=b", "--", "x"}},
		{"run_env_then_word", "run with an --env flag before a bare word", []string{"run", "--env", "A=b", "x"}},
		{"run_word_then_env", "run with a flag after the bare word", []string{"run", "x", "--env", "A=b"}},
		{"run_dd_flag_like", "run with a flag-looking word after --", []string{"run", "--", "--env", "A=b"}},
		{"run_dd_dd", "run with a second -- after the first", []string{"run", "--", "--", "x"}},
		{"run_echo", "run executes a command given as bare words", []string{"run", "echo", "hi"}},
		{"run_dd_echo", "run executes a command given after --", []string{"run", "--", "echo", "hi"}},
		{"run_echo_dd_word", "run forwards a second -- to the command", []string{"run", "echo", "--", "hi"}},
		{"run_dd_echo_dd_word", "run forwards a -- after the command", []string{"run", "--", "echo", "--", "hi"}},
		{"run_passthrough_echo", "run with a value flag before the command", []string{"run", "--passthrough", "PATH", "--", "echo", "hi"}},
		{"run_working_dir_echo", "run with --working-dir before the command", []string{"run", "--working-dir", ".", "--", "echo", "hi"}},
		{"run_short_working_dir_echo", "run with the -C shorthand before the command", []string{"run", "-C", ".", "echo", "hi"}},
		{"run_timeout_echo", "run with a duration flag before the command", []string{"run", "--timeout", "5s", "--", "echo", "hi"}},
		{"run_short_env_dd", "run with the -e shorthand before --", []string{"run", "-e", "A=b", "--", "x"}},
		{"file_use_none", "file use without arguments", []string{"file", "use"}},
		{"file_use_path_only", "file use with only the entry path", []string{"file", "use", "p"}},
		{"file_use_path_word", "file use with the path and a bare word", []string{"file", "use", "p", "x"}},
		{"file_use_path_dd_word", "file use with the command after --", []string{"file", "use", "p", "--", "x"}},
		{"file_use_dd_path_word", "file use with the path after --", []string{"file", "use", "--", "p", "x"}},
		{"file_use_path_two_words", "file use with three positionals", []string{"file", "use", "p", "x", "y"}},
		{"file_use_path_dd_two_words", "file use with a command and an argument after --", []string{"file", "use", "p", "--", "x", "y"}},
		{"file_use_path_dd_word_dd_word", "file use with a second --", []string{"file", "use", "p", "--", "x", "--", "y"}},
		{"file_use_field_then_dd", "file use with --field before --", []string{"file", "use", "p", "--field", "f", "--", "x"}},
		{"file_use_field_before_path", "file use with --field before the path", []string{"file", "use", "--field", "f", "p", "x"}},
		{"file_use_word_then_field", "file use with --field after the words", []string{"file", "use", "p", "x", "--field", "f"}},
		{"file_use_dd_field_like", "file use with a flag-looking word after --", []string{"file", "use", "p", "--", "--field", "f"}},
	}
	var out []scenarioInput
	for _, perm := range perms {
		for _, state := range []string{stateUninitialized, stateInitialized} {
			out = append(out, scenarioInput{
				name:        fmt.Sprintf("%s_%s", perm.name, state),
				description: fmt.Sprintf("%s (%s)", perm.description, state),
				state:       state,
				args:        perm.args,
			})
		}
	}
	return out
}

// recordScenarios runs every input twice in fresh sandboxes. The two
// observations must match after normalization: anything else is a volatile
// value that needs a documented normalizer or an exclusion, not a flaky case.
func recordScenarios(goBinary string, seed []seedFile, inputs []scenarioInput) ([]scenarioCase, error) {
	var out []scenarioCase
	var problems []string
	for _, in := range inputs {
		spec := runSpec{initialized: in.state == stateInitialized}
		if spec.initialized {
			spec.seed = seed
		}
		var recorded []observation
		for attempt := 0; attempt < 2; attempt++ {
			res, err := runSpecified(goBinary, in.args, spec)
			if err != nil {
				return nil, fmt.Errorf("scenario %s: %w", in.name, err)
			}
			if res.timedOut {
				problems = append(problems, fmt.Sprintf("scenario %s timed out", in.name))
				break
			}
			obs, err := applyNormalizers(in.normalize, res.obs)
			if err != nil {
				return nil, fmt.Errorf("scenario %s: %w", in.name, err)
			}
			recorded = append(recorded, obs)
		}
		if len(recorded) < 2 {
			continue
		}
		if recorded[0].ExitCode != recorded[1].ExitCode || recorded[0].Stdout != recorded[1].Stdout || recorded[0].Stderr != recorded[1].Stderr {
			problems = append(problems, fmt.Sprintf("scenario %s is not deterministic: %s", in.name, firstDifference(recorded[0], recorded[1])))
			continue
		}
		out = append(out, scenarioCase{Name: in.name, Description: in.description, State: in.state, Normalize: in.normalize, Observation: recorded[0]})
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%d scenario(s) cannot be recorded:\n%s", len(problems), strings.Join(problems, "\n"))
	}
	return out, nil
}

func buildExtraSections(goBinary, output string, newSeed bool) (extraSections, error) {
	inventory, err := nilArgsInventory()
	if err != nil {
		return extraSections{}, fmt.Errorf("derive nil-Args inventory: %w", err)
	}
	if len(inventory) == 0 {
		return extraSections{}, errors.New("the command tree has no nil-Args command")
	}
	seed := []seedFile(nil)
	if !newSeed {
		seed = existingSeed(output)
	}
	if len(seed) == 0 {
		// Without a recorded seed -check builds a fresh one; the byte comparison
		// then reports the fixture as stale (or unreadable).
		if seed, err = seedBuilder(goBinary); err != nil {
			return extraSections{}, fmt.Errorf("record vault seed: %w", err)
		}
	}
	inputs, err := extraPositionalInputs(inventory)
	if err != nil {
		return extraSections{}, err
	}
	extra, err := recordScenarios(goBinary, seed, inputs)
	if err != nil {
		return extraSections{}, err
	}
	forwarded, err := recordScenarios(goBinary, seed, runFileUseInputs())
	if err != nil {
		return extraSections{}, err
	}
	sort.SliceStable(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })
	return extraSections{nilArgs: inventory, seed: seed, extraPositionals: extra, exclusions: scenarioExclusions, runFileUse: forwarded}, nil
}

// firstDifference names the first line that differs between two observations.
func firstDifference(a, b observation) string {
	if a.ExitCode != b.ExitCode {
		return fmt.Sprintf("exit %d vs %d", a.ExitCode, b.ExitCode)
	}
	for _, stream := range []struct{ name, a, b string }{{"stdout", a.Stdout, b.Stdout}, {"stderr", a.Stderr, b.Stderr}} {
		left, right := strings.Split(stream.a, "\n"), strings.Split(stream.b, "\n")
		for i := 0; i < len(left) || i < len(right); i++ {
			var l, r string
			if i < len(left) {
				l = left[i]
			}
			if i < len(right) {
				r = right[i]
			}
			if l != r {
				return fmt.Sprintf("%s line %d: %q vs %q", stream.name, i+1, l, r)
			}
		}
	}
	return "identical"
}
