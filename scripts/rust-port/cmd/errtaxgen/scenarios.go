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

	// normalizeTouchID replaces the Touch ID availability `auth status` reports:
	// it is a probe of the machine's biometric hardware (true on the recording
	// MacBook, false on a Mac without Touch ID and on Linux), not of the CLI.
	normalizeTouchID = "touch_id_available"
	touchIDLine      = "Touch ID available: __BOOL__\n"
)

var (
	password20 = regexp.MustCompile(`^[A-Za-z0-9]{20}\n$`)
	keyBytes   = regexp.MustCompile(`New key: [0-9a-f]{8} \(first 4 bytes\)`)
	touchID    = regexp.MustCompile(`Touch ID available: (true|false)\n`)
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
	Name        string   `json:"name"`
	Description string   `json:"description"`
	State       string   `json:"state"`
	Normalize   []string `json:"normalize,omitempty"`
	// Platforms lists the GOOS values the observation can be compared on; empty
	// means every platform. A scenario of a host-dependent command carries the
	// platform it was recorded on.
	Platforms   []string    `json:"platforms,omitempty"`
	Observation observation `json:"observation"`
	// serviceManager marks a scenario of a service-manager command
	// (serviceManagerCommands); it is not recorded, the --check projection reads
	// it from the fresh run.
	serviceManager bool
	// HostToolCalls are the service-manager calls the run made to the sandbox
	// stand-ins (`launchctl unload <plist>`), recorded on the fixture's
	// generated_on platform; a replay compares them only there.
	HostToolCalls []string `json:"host_tool_calls,omitempty"`
}

type scenarioInput struct {
	name, description, state string
	args                     []string
	normalize                []string
	platforms                []string
	// serviceManager allows the run to call launchctl/systemctl; any other
	// scenario that does fails the recording.
	serviceManager bool
}

type extraSections struct {
	nilArgs          []nilArgsEntry
	seed             []seedFile
	extraPositionals []scenarioCase
	exclusions       []exclusion
	hostDependent    []hostDependence
	serviceManager   []string
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

// hostDependence is a nil-Args command whose output names the service manager
// of the platform it ran on, so its scenarios are only comparable there. The
// fixture records the list, and a stale key (a command that is no longer in the
// inventory) is an error.
type hostDependence struct {
	Path      string   `json:"path"`
	Platforms []string `json:"platforms"`
	Reason    string   `json:"reason"`
}

var darwinOnly = []string{"darwin"}

// scenarioHostDependence lists the commands the Linux replay skips (with a
// visible count) and replays against stand-in tools only. `mcp|serve uninstall`
// print the same text on both platforms and are not listed: their stdout and
// stderr compare everywhere, only their recorded launchctl calls are darwin's.
var scenarioHostDependence = []hostDependence{
	{"symvault mcp install", darwinOnly, "prints the launchd plist path (<home>/LaunchAgents/com.symvault.mcp.plist); Linux installs a systemd user unit"},
	{"symvault mcp status", darwinOnly, "prints the launchd plist path; Linux reports the systemd unit"},
	{"symvault serve install", darwinOnly, "deprecated alias of mcp install: prints the launchd plist path; Linux installs a systemd user unit"},
	{"symvault serve status", darwinOnly, "deprecated alias of mcp status: prints the launchd plist path; Linux reports the systemd unit"},
}

// serviceManagerCommands are the only commands allowed to call launchctl or
// systemctl: they register, remove or query the user service. `uninstall` and
// `status` print the same text on both platforms (or are host-dependent), but
// their service-manager calls are the recording platform's. Every other
// scenario of the corpus must make zero host-tool calls on every platform.
var serviceManagerCommands = []string{
	"symvault mcp install", "symvault mcp status", "symvault mcp uninstall",
	"symvault serve install", "symvault serve status", "symvault serve uninstall",
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
	"symvault auth status":      {normalizeTouchID},
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
		case normalizeTouchID:
			obs.Stdout = touchID.ReplaceAllString(obs.Stdout, touchIDLine)
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

const (
	// seedAttachment is the synthetic file `file add` stores in the frozen vault.
	seedAttachmentName    = "attachment.bin"
	seedAttachmentContent = "synthetic attachment content, not a secret"
	// seedFileEntry/seedFileField name the attachment `file use` materializes.
	seedFileEntry = "seed/cert"
	seedFileField = "cert_p12"
	// seedTokenRef is a real text field `run --env` resolves; the value is a
	// disposable placeholder and no scenario prints the child's environment.
	seedTokenEntry = "seed/api"
	seedTokenPath  = seedTokenEntry + ".token"
	seedTokenValue = "synthetic-api-token-0001"
	seedTokenRef   = seedTokenPath
)

// buildVaultSeed initializes a vault with the oracle, settles it with one read
// (a fresh vault's first open rewrites config.yaml and creates .lock and
// manifest.age, which is vault-open behavior shared by every command) and
// stores two synthetic entries: a file attachment (`file use` target) and a
// text field (`run --env` target).
func buildVaultSeed(goBinary string) ([]seedFile, error) {
	box, err := newSandbox()
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(box.root) }()
	box.env = append(box.env, initializedEnv()...)
	if err := os.WriteFile(filepath.Join(box.root, seedAttachmentName), []byte(seedAttachmentContent), 0o600); err != nil {
		return nil, err
	}
	steps := [][]string{
		{"init"},
		{"list"},
		{"file", "add", seedFileEntry, "--field", seedFileField, "--from", seedAttachmentName},
		{"set", seedTokenPath, "--value", seedTokenValue, "--force"},
	}
	for _, args := range steps {
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
	serviceManager := map[string]bool{}
	for _, path := range serviceManagerCommands {
		if !paths[path] {
			return nil, fmt.Errorf("serviceManagerCommands names %q, which is not a nil-Args command", path)
		}
		serviceManager[path] = true
	}
	dependent := map[string]hostDependence{}
	for _, item := range scenarioHostDependence {
		if !paths[item.Path] {
			return nil, fmt.Errorf("scenarioHostDependence names %q, which is not a nil-Args command", item.Path)
		}
		if !serviceManager[item.Path] {
			return nil, fmt.Errorf("scenarioHostDependence names %q, which is not in serviceManagerCommands", item.Path)
		}
		dependent[item.Path] = item
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
					platforms:   dependent[entry.Path].Platforms,

					serviceManager: serviceManager[entry.Path],
				})
			}
		}
	}
	return out, nil
}

// argvChild is a child that reports its own argv, one word per line, and
// nothing else: it never prints the environment or the materialized file path.
// Both programs are at the same absolute path on macOS and Linux.
var argvChild = []string{"/bin/sh", "-c", `printf "%s\n" "$@"`, "argv"}

// printfChild reports its operands without any flag-looking word of its own, so
// it can follow the symvault positionals without `--`.
var printfChild = []string{"/usr/bin/printf", "%s\n"}

// childFlags are words that look like symvault flags (and like `ls -la`) but
// belong to the child when they stand after `--`.
var childFlags = []string{"-la", "--timeout", "5", "--json", "--"}

// runFileUseInputs permutes the argv of the commands that forward a trailing
// command line. `run` demands at least one positional and `file use` two; both
// take the command after `--`, and the permutations pin where a flag may stand
// among the forwarded words and what an extra `--` does. The initialized state
// holds a real attachment entry (seedFileEntry) and a text field
// (seedTokenRef), so the argv-reporting child really runs and prints the words
// it was given.
func runFileUseInputs() []scenarioInput {
	type permutation struct {
		name, description string
		args              []string
	}
	run := func(parts ...[]string) []string { return concat(append([][]string{{"run"}}, parts...)...) }
	use := func(parts ...[]string) []string { return concat(append([][]string{{"file", "use"}}, parts...)...) }
	dd := []string{"--"}
	entry := []string{seedFileEntry}
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
		{"run_argv_flag_words_after_dd", "run forwards flag-looking words after -- verbatim", run(dd, argvChild, childFlags)},
		{"run_argv_timeout_before_dd", "run with its own --timeout before --, flag-looking child words after", run([]string{"--timeout", "5s"}, dd, argvChild, childFlags)},
		{"run_argv_timeout_zero", "run --timeout 0 is the unitless zero Go accepts: no timeout", run([]string{"--timeout", "0"}, dd, argvChild, childFlags)},
		{"run_argv_timeout_without_unit", "run --timeout 5 without a unit is a flag error, not a child word", run([]string{"--timeout", "5"}, dd, argvChild)},
		{"run_argv_env_before_dd", "run resolves a real --env reference before --", run([]string{"--env", "TOKEN=" + seedTokenRef}, dd, argvChild, childFlags)},
		{"run_argv_env_missing_ref", "run with an --env reference to a missing entry", run([]string{"--env", "TOKEN=seed/absent.token"}, dd, argvChild)},
		{"run_argv_passthrough_before_dd", "run with --passthrough before --", run([]string{"--passthrough", "PATH"}, dd, argvChild, childFlags)},
		{"run_argv_second_dd", "run forwards a second -- verbatim", run(dd, argvChild, dd, dd, []string{"x"})},
		{"run_argv_json_before_dd", "run with the persistent --json flag before --", run([]string{"--json"}, dd, argvChild, childFlags)},
		{"run_argv_quiet_before_dd", "run with the persistent --quiet flag before --", run([]string{"--quiet"}, dd, argvChild, childFlags)},
		{"run_argv_output_before_dd", "run with --output text before --", run([]string{"--output", "text"}, dd, argvChild, childFlags)},
		{"run_argv_output_yaml_before_dd", "run with --output yaml before --", run([]string{"--output", "yaml"}, dd, argvChild)},
		{"run_argv_flags_before_and_after_dd", "run with symvault flags before -- and flag-looking child words after", run([]string{"--timeout", "5s", "-C", ".", "--env", "TOKEN=" + seedTokenRef}, dd, argvChild, childFlags)},
		{"run_bare_words_timeout_after", "run with its own --timeout after the bare command words", run(printfChild, []string{"a", "--timeout", "5s", "b"})},
		{"run_bare_words_env_after", "run with a real --env after the bare command words", run(printfChild, []string{"a", "--env", "TOKEN=" + seedTokenRef, "b"})},
		{"run_bare_words_workdir_after", "run with -C after the bare command words", run(printfChild, []string{"a", "-C", ".", "b"})},
		{"run_bare_words_json_after", "run with the persistent --json flag after the bare command words", run(printfChild, []string{"a", "--json"})},
		{"run_bare_words_quiet_after", "run with --quiet after the bare command words", run(printfChild, []string{"a", "--quiet", "b"})},
		{"run_bare_words_short_flag_like", "run with a -la word after the bare command words is a flag error", run(printfChild, []string{"a", "-la"})},
		{"run_bare_words_unknown_long_flag", "run with an unknown long flag after the bare command words", run(printfChild, []string{"a", "--bogus"})},
		{"run_bare_sh_c", "run with the child's own -c before any --: -c is symvault's unknown shorthand", run([]string{"/bin/sh", "-c", "exit 0"})},
		{"run_bare_dd_after_words", "run with -- after the bare command words", run(printfChild, []string{"a"}, dd, []string{"--timeout", "5s"})},
		{"run_child_exit_code", "run reports a child's exit code", run(dd, []string{"/bin/sh", "-c", "exit 3"})},
		{"run_timeout_expires", "run stops a child that outlives --timeout", run([]string{"--timeout", "1s"}, dd, []string{"/bin/sh", "-c", "exec sleep 5"})},
		{"run_child_stderr", "run forwards a child's stderr", run(dd, []string{"/bin/sh", "-c", `printf "%s\n" "$1" >&2`, "argv", "-la"})},
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
		{"file_use_argv_flag_words_after_dd", "file use forwards flag-looking words after -- verbatim", use(entry, dd, argvChild, childFlags)},
		{"file_use_argv_timeout_before_path", "file use with its own --timeout before the entry", use([]string{"--timeout", "5s"}, entry, dd, argvChild, childFlags)},
		{"file_use_argv_timeout_between", "file use with its own --timeout between the entry and --", use(entry, []string{"--timeout", "5s"}, dd, argvChild, childFlags)},
		{"file_use_argv_timeout_zero", "file use --timeout 0 is the unitless zero Go accepts: no timeout", use(entry, []string{"--timeout", "0"}, dd, argvChild, childFlags)},
		{"file_use_argv_timeout_without_unit", "file use --timeout 5 without a unit is a flag error", use(entry, []string{"--timeout", "5"}, dd, argvChild)},
		{"file_use_argv_field_before_path", "file use with --field before the entry", use([]string{"--field", seedFileField}, entry, dd, argvChild, childFlags)},
		{"file_use_argv_field_after_path", "file use with --field after the entry", use(entry, []string{"--field", seedFileField}, dd, argvChild, childFlags)},
		{"file_use_argv_hash_field", "file use with the path#field form", use([]string{seedFileEntry + "#" + seedFileField}, dd, argvChild, childFlags)},
		{"file_use_argv_bad_field", "file use with a field the entry lacks", use(entry, []string{"--field", "absent"}, dd, argvChild)},
		{"file_use_argv_missing_entry", "file use with an entry that does not exist", use([]string{"seed/absent"}, dd, argvChild)},
		{"file_use_argv_as_name", "file use with --as before --", use(entry, []string{"--as", "CERT"}, dd, argvChild, childFlags)},
		{"file_use_argv_flags_before_and_after_dd", "file use with symvault flags around the entry and flag-looking child words after --", use([]string{"--timeout", "5s", "--as", "CERT"}, entry, []string{"--field", seedFileField}, dd, argvChild, childFlags)},
		{"file_use_argv_json_before_path", "file use with the persistent --json flag before the entry", use([]string{"--json"}, entry, dd, argvChild)},
		{"file_use_argv_quiet_after_path", "file use with --quiet after the entry", use(entry, []string{"--quiet"}, dd, argvChild, childFlags)},
		{"file_use_argv_dd_before_path", "file use with the entry and the command all after --", use(dd, entry, argvChild, childFlags)},
		{"file_use_argv_second_dd", "file use forwards a second -- verbatim", use(entry, dd, argvChild, dd, dd, []string{"x"})},
		{"file_use_bare_words_timeout_after", "file use with its own --timeout after the bare command words", use(entry, printfChild, []string{"a", "--timeout", "5s", "b"})},
		{"file_use_bare_words_field_after", "file use with --field after the bare command words", use(entry, printfChild, []string{"a", "--field", seedFileField, "b"})},
		{"file_use_bare_words_json_after", "file use with the persistent --json flag after the bare command words", use(entry, printfChild, []string{"a", "--json"})},
		{"file_use_bare_words_short_flag_like", "file use with a -la word after the bare command words is a flag error", use(entry, printfChild, []string{"a", "-la"})},
		{"file_use_bare_words_unknown_long_flag", "file use with an unknown long flag after the bare command words", use(entry, printfChild, []string{"a", "--bogus"})},
		{"file_use_bare_sh_c", "file use with the child's own -c before any --: -c is symvault's unknown shorthand", use(entry, []string{"/bin/sh", "-c", "exit 0"})},
		{"file_use_child_exit_code", "file use reports a child's exit code", use(entry, dd, []string{"/bin/sh", "-c", "exit 3"})},
		{"file_use_argv_entry_without_attachment", "file use on an entry that records no attachment", use([]string{seedTokenEntry}, dd, argvChild)},
		{"file_use_timeout_expires", "file use stops a child that outlives --timeout", use([]string{"--timeout", "1s"}, entry, dd, []string{"/bin/sh", "-c", "exec sleep 5"})},
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
		var calls [][]string
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
			calls = append(calls, res.hostCalls)
		}
		if len(recorded) < 2 {
			continue
		}
		if recorded[0].ExitCode != recorded[1].ExitCode || recorded[0].Stdout != recorded[1].Stdout || recorded[0].Stderr != recorded[1].Stderr {
			problems = append(problems, fmt.Sprintf("scenario %s is not deterministic: %s", in.name, firstDifference(recorded[0], recorded[1])))
			continue
		}
		if !in.serviceManager && len(calls[0]) > 0 {
			problems = append(problems, fmt.Sprintf("scenario %s is not a service-manager command but called host tools: %q", in.name, calls[0]))
			continue
		}
		if strings.Join(calls[0], "\n") != strings.Join(calls[1], "\n") {
			problems = append(problems, fmt.Sprintf("scenario %s makes different host-tool calls per run: %q vs %q", in.name, calls[0], calls[1]))
			continue
		}
		out = append(out, scenarioCase{Name: in.name, Description: in.description, State: in.state, Normalize: in.normalize, Platforms: in.platforms, Observation: recorded[0], HostToolCalls: calls[0], serviceManager: in.serviceManager})
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
	return extraSections{nilArgs: inventory, seed: seed, extraPositionals: extra, exclusions: scenarioExclusions, hostDependent: scenarioHostDependence, serviceManager: serviceManagerCommands, runFileUse: forwarded}, nil
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
