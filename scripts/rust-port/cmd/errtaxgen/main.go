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
//   - argv_shapes: argument shapes whose outcome depends on a flag's *type*
//     (`device join --pairing-file` is a string flag, so the token after it is
//     a value, not a positional), run against disposable files in the sandbox
//     working directory, plus group help pages. Every row ends before the
//     command touches a vault or the network.
//   - nil_args / extra_positionals: every cobra command of the pinned tree whose
//     Args validator is nil (cobra then accepts any positionals), derived from
//     the compiled command tree, and what the binary does when such a command is
//     given extra positionals, in an empty sandbox and in a frozen initialized
//     vault (vault_seed).
//   - run_file_use_argv: argv permutations of the commands that forward a
//     trailing command line (`run`, `file use`).
//
// The oracle never touches the host's service manager, keychain, clipboard or
// notifications: every sandbox puts stand-in executables first on PATH (see
// hosttools.go). Service-manager calls are recorded with the scenario that made
// them; a call of any other stand-in fails the generator.
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
	pinnedOracleRelease = "unreleased"
	rootMarker          = "__ROOT__"
	defaultOutput       = "testdata/port/cli/error-taxonomy.json"
	commandTreePath     = "testdata/port/cli/command-tree.json"
	maxDummyArgs        = 4
	commandTimeout      = 8 * time.Second
)

// pinnedOracleCommit is only reassigned by tests that run main against a
// disposable repository.
var pinnedOracleCommit = "0cc780626d3275afad14eb64c44abf8adb23d2ce"

// Seams for tests of main; production always uses the defaults.
var (
	exit           = os.Exit
	validateOracle = validateGoBinary
	locateRoot     = repositoryRoot
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

// shapeCase is one argument shape. Files are written into the sandbox working
// directory before the oracle runs, so a relative path in Args resolves there.
type shapeCase struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Files       map[string]string `json:"files,omitempty"`
	Observation observation       `json:"observation"`
}

type fixture struct {
	SchemaVersion int `json:"schema_version"`
	// GeneratedOn is the GOOS the oracle ran on. Host-dependent output (the
	// service-manager commands) and the recorded host-tool calls belong to it.
	GeneratedOn string `json:"generated_on"`
	// HostTools names the stand-in executables every sandbox puts first on PATH.
	HostTools      hostToolSet   `json:"host_tools"`
	Oracle         oracle        `json:"oracle"`
	Usage          []usageCase   `json:"usage"`
	Arity          []arityRow    `json:"arity"`
	Gate           []gateRow     `json:"gate"`
	NotInitialized []observation `json:"not_initialized"`
	ArgvShapes     []shapeCase   `json:"argv_shapes"`
	// NilArgs lists the commands whose cobra Args validator is nil.
	NilArgs []nilArgsEntry `json:"nil_args"`
	// VaultSeed is the frozen initialized vault the initialized scenarios start from.
	VaultSeed        []seedFile     `json:"vault_seed"`
	ExtraPositionals []scenarioCase `json:"extra_positionals"`
	// ExtraPositionalExclusions are the nil-Args commands left out of a state, with the reason.
	ExtraPositionalExclusions []exclusion `json:"extra_positional_exclusions"`
	// HostDependentCommands are the nil-Args commands whose scenarios are only
	// byte-comparable on the platforms named (their scenarios carry the same list).
	HostDependentCommands []hostDependence `json:"host_dependent_commands"`
	// ServiceManagerCommands are the only commands whose scenarios may call
	// launchctl or systemctl.
	ServiceManagerCommands []string       `json:"service_manager_commands"`
	RunFileUseArgv         []scenarioCase `json:"run_file_use_argv"`
	// UnlockStates are the commands that unlock the vault, run against the vault
	// shapes the other sections never reach (see unlockStateInputs).
	UnlockStates []scenarioCase `json:"unlock_states"`
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
		{"bare_dash_before_command", "cobra stripFlags skips a lone dash during command resolution; pflag later counts it", []string{"-", "get", "x"}},
		{"bare_dash_after_group", "a lone dash does not prevent nested command resolution", []string{"config", "-", "get", "x"}},
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
		{"int_flag_hex", "pflag parses ints with ParseInt(s, 0, 64): hex is accepted, so the next flag is the first error", []string{"generate", "--length", "0x10", "--bogus"}},
		{"int_flag_octal_prefix", "0o octal is accepted", []string{"generate", "--length", "0o17", "--bogus"}},
		{"int_flag_binary", "0b binary is accepted", []string{"generate", "--length=0b101", "--bogus"}},
		{"int_flag_underscore", "underscores between digits are accepted with base 0", []string{"generate", "--length", "1_0", "--bogus"}},
		{"int_flag_legacy_octal", "a leading zero means octal", []string{"generate", "--length", "010", "--bogus"}},
		{"int_flag_signed_hex", "a sign may precede the base prefix", []string{"generate", "--length", "-0x10", "--bogus"}},
		{"int_flag_plus_sign", "a plus sign is accepted", []string{"generate", "--length", "+5", "--bogus"}},
		{"int_flag_min_int64", "the minimum int64 is accepted", []string{"generate", "--length", "-9223372036854775808", "--bogus"}},
		{"int_flag_shorthand_hex", "shorthand with an attached hex value", []string{"generate", "-l0x10", "--bogus"}},
		{"int_flag_shorthand_separate_hex", "shorthand with a separate hex value", []string{"generate", "-l", "0o17", "--bogus"}},
		{"int_flag_prefix_without_digits", "a base prefix needs digits", []string{"generate", "--length", "0x"}},
		{"int_flag_bad_hex_digit", "a digit past the base is a syntax error", []string{"generate", "--length", "0x1G"}},
		{"int_flag_bad_octal_digit", "8 is not an octal digit", []string{"generate", "--length", "08"}},
		{"int_flag_double_underscore", "doubled underscores are a syntax error", []string{"generate", "--length", "1__0"}},
		{"int_flag_leading_underscore", "a leading underscore is a syntax error", []string{"generate", "--length", "_10"}},
		{"int_flag_trailing_underscore", "a trailing underscore is a syntax error", []string{"generate", "--length", "10_"}},
		{"int_flag_empty", "an empty value", []string{"generate", "--length="}},
		{"int_flag_float", "a float is not an integer", []string{"generate", "--length", "1e3"}},
		{"int_flag_space", "surrounding space is not trimmed", []string{"generate", "--length", " 5"}},
		{"int_flag_out_of_range", "a decimal past int64 is a range error", []string{"generate", "--length", "99999999999999999999"}},
		{"int_flag_hex_out_of_range", "a hex value past int64 is a range error", []string{"generate", "--length", "0x8000000000000000"}},
		{"int_flag_negative_out_of_range", "a negative value below int64 is a range error", []string{"generate", "--length", "-9223372036854775809"}},
		{"int_flag_range_before_syntax", "an overflow is reported before a later invalid digit is seen", []string{"generate", "--length", "99999999999999999999x"}},
		{"typed_int_add_length", "add --length is an int flag: pflag rejects the value before the vault is opened", []string{"add", "x", "--length", "abc"}},
		{"typed_int_agent_audit_limit", "agent audit --limit is an int flag", []string{"agent", "audit", "--limit", "abc"}},
		{"typed_int_audit_tail", "audit --tail is an int flag; the diagnostic names the shorthand too", []string{"audit", "--tail", "x"}},
		{"typed_int_audit_tail_shorthand", "audit -n attached value", []string{"audit", "-nx"}},
		{"typed_int_audit_tail_shorthand_separate", "audit -n with a separate value", []string{"audit", "-n", "x"}},
		{"typed_int_file_add_max_size", "file add --max-size is an int64 flag", []string{"file", "add", "--max-size", "x", "f"}},
		{"typed_int_file_add_max_size_range", "an int64 flag reports a value past int64 as out of range", []string{"file", "add", "--max-size", "99999999999999999999", "f"}},
		{"typed_int_intake_max_files", "intake --max-files is an int flag", []string{"intake", "--max-files", "x"}},
		{"typed_int_intake_max_files_equals", "intake --max-files=<value>", []string{"intake", "--max-files=0x"}},
		{"typed_int_intake_batch_limit", "intake --batch-limit is an int64 flag", []string{"intake", "--batch-limit", "x"}},
		{"typed_int_intake_batch_limit_range", "intake --batch-limit past int64", []string{"intake", "--batch-limit=-9223372036854775809"}},
		{"typed_int_mcp_port", "mcp --port is an int flag", []string{"mcp", "--port", "x"}},
		{"typed_int_mcp_port_equals", "mcp --port=<value>", []string{"mcp", "--port=1.5"}},
		{"typed_int_serve_port", "serve --port is an int flag (deprecated alias of mcp)", []string{"serve", "--port", "x"}},
		{"typed_int_startup_profile_count", "startup-profile --count is an int flag", []string{"startup-profile", "--count", "x"}},
		{"typed_int_startup_profile_count_shorthand", "startup-profile -n is the shorthand of --count", []string{"startup-profile", "-n", "x"}},
		{"typed_int_startup_profile_top", "startup-profile --top is an int flag", []string{"startup-profile", "--top", "x"}},
		{"typed_int_hex_accepted_gate_decides", "a hex value is a valid int for every int flag: the output gate decides next", []string{"startup-profile", "--top", "0x10", "--output", "xml"}},
		{"typed_int_first_error_wins", "pflag stops at the first failing flag in argument order", []string{"startup-profile", "--count", "x", "--top", "y"}},
		{"typed_int_error_before_unknown_flag", "an invalid value is reported before a later unknown flag", []string{"startup-profile", "--top", "x", "--bogus"}},
		{"typed_int_unknown_flag_before_error", "an unknown flag is reported before a later invalid value", []string{"startup-profile", "--bogus", "--top", "x"}},
		{"typed_int_error_before_gate", "the flag value is parsed before the output-format gate", []string{"startup-profile", "--top", "x", "--output", "xml"}},
		{"typed_int_error_before_vault", "the flag value is parsed before the vault is opened", []string{"audit", "--tail", "x"}},
		{"typed_duration_unlock_ttl", "unlock --ttl is a duration flag", []string{"unlock", "--ttl", "x"}},
		{"typed_duration_unlock_ttl_missing_unit", "a bare number has no unit", []string{"unlock", "--ttl", "15"}},
		{"typed_duration_unlock_ttl_unknown_unit", "an unknown unit is named in the error", []string{"unlock", "--ttl=5x"}},
		{"typed_duration_unlock_ttl_empty", "an empty duration is invalid", []string{"unlock", "--ttl="}},
		{"typed_duration_intake_watch_debounce", "intake watch --debounce is a duration flag", []string{"intake", "watch", "--debounce", "x"}},
		{"typed_duration_intake_watch_interval", "intake watch --interval is a duration flag", []string{"intake", "watch", "--interval", "10"}},
		{"typed_duration_intake_watch_interval_range", "a duration past int64 nanoseconds is invalid", []string{"intake", "watch", "--interval", "9223372036854775808ns"}},
		{"typed_duration_file_use_timeout_shorthand", "file use -t is the shorthand of --timeout", []string{"file", "use", "-t", "x"}},
		{"typed_duration_valid_gate_decides", "compound durations are valid: the output gate decides next", []string{"unlock", "--ttl", "1h30m", "--output", "xml"}},
		{"typed_duration_error_before_gate", "the duration is parsed before the output-format gate", []string{"unlock", "--ttl", "x", "--output", "xml"}},
		{"typed_duration_error_before_vault", "the duration is parsed before the vault is opened", []string{"intake", "watch", "--debounce", "1x"}},
		{"typed_slice_agent_token_new_tools", "agent token new --tools is a stringSlice flag: a stray quote is a CSV error", []string{"agent", "token", "new", "bot", "--tools", "\"a"}},
		{"typed_slice_agent_token_rotate_tools", "agent token rotate --tools is a stringSlice flag", []string{"agent", "token", "rotate", "bot", "--tools=a\"b"}},
		{"typed_slice_broker_passthrough", "broker --passthrough is a stringSlice flag", []string{"broker", "--passthrough", "a,b\""}},
		{"typed_slice_doctor_only", "doctor --only is a stringSlice flag", []string{"doctor", "--only", "\"a\"b"}},
		{"typed_slice_doctor_exclude", "doctor --exclude is a stringSlice flag", []string{"doctor", "--exclude", "a,\"b\"c"}},
		{"typed_slice_run_broker_passthrough", "run --broker-passthrough is a stringSlice flag", []string{"run", "--broker-passthrough", "\"a", "--", "true"}},
		{"typed_slice_blank_lines_are_eof", "a value of blank lines has no record: encoding/csv reports EOF", []string{"doctor", "--only", "\n"}},
		{"typed_slice_multiline_quote", "a quoted field cut off on a later line reports the record and the error line", []string{"doctor", "--only", "\"a\nb"}},
		{"typed_slice_multiline_valid", "a quoted field may span lines: no flag error", []string{"doctor", "--only", "\"a\nb\"", "--output", "xml"}},
		{"typed_slice_valid_quoted_comma", "a quoted comma is valid: the output gate decides next", []string{"doctor", "--only", "\"a,b\"", "--output", "xml"}},
		{"typed_slice_crlf", "CRLF is folded to LF before the column is counted", []string{"doctor", "--only", "\"a\r\nb"}},
		{"typed_slice_lone_quote", "a lone opening quote", []string{"doctor", "--only", "\""}},
		{"typed_slice_error_before_gate", "the slice is parsed before the output-format gate", []string{"doctor", "--only", "a\"", "--output", "xml"}},
		{"typed_slice_array_flags_take_any_value", "stringArray flags (run --env) are not parsed: a quote is a plain value and the arity check decides", []string{"run", "--env", "\"a"}},
		{"required_flag_profile_add", "profile add marks --vault required: cobra reports it after the argument check", []string{"profile", "add", "work"}},
		{"required_flag_profile_add_gate_first", "the output gate runs before the required-flag check", []string{"profile", "add", "work", "--output", "xml"}},
		{"required_flag_profile_add_arity_first", "the argument validator runs before the required-flag check", []string{"profile", "add"}},
		{"required_flag_dynamic_generate_one_of_two", "dynamic generate lists only the unset required flags", []string{"dynamic", "generate", "--engine", "e"}},
		{"required_flag_template_generate", "template generate marks --type required", []string{"template", "generate"}},
		{"required_flag_export", "export marks --format required", []string{"export"}},
		{"group_with_unknown_subcommand", "a non-root group given an unknown subcommand", []string{"config", "bogus"}},
		{"nested_group_with_unknown_subcommand", "a nested group given an unknown subcommand", []string{"agent", "token", "bogus"}},
		{"group_with_extra_args", "a non-root group given trailing arguments", []string{"config", "a", "b"}},
		{"gate_before_vault", "the output gate refuses before the vault is touched", []string{"doctor", "--output", "xml"}},
		{"gate_equals_form", "the gate with --output=yaml", []string{"--output=yaml", "startup-profile"}},
		{"output_text_explicit", "an explicit --output text on a refusing command is accepted", []string{"--output", "text", "version"}},
		{"output_empty_value", "an empty --output value", []string{"--output", "", "doctor"}},
		{"output_case_sensitive", "--output JSON is not json", []string{"--output", "JSON", "doctor"}},
		{"bool_flag_reset_output_gate", "a repeated --json is last-value-wins: the reset leaves the --output xml gate to decide", []string{"--json", "--json=false", "--output", "xml", "startup-profile"}},
		{"bool_flag_reset_accepts_command", "--json --json=false no longer refuses `lock`, which rejects --json: the vault check then fails", []string{"--json", "--json=false", "lock"}},
		{"bool_flag_set_after_reset", "--json=false --json: the last occurrence turns the flag on again", []string{"--json=false", "--json", "lock"}},
		{"bool_flag_noncanonical_false", "ParseBool accepts F as false", []string{"--json=F", "lock"}},
		{"bool_flag_noncanonical_false_output_gate", "--json=F leaves the --output xml gate to decide", []string{"--json=F", "--output", "xml", "lock"}},
		{"bool_flag_reset_after_command", "the reset also applies after the command word", []string{"lock", "--json", "--json=false"}},
		{"bool_flag_set_after_command", "--json=false before the command, --json after it", []string{"--json=false", "lock", "--json"}},
		{"bool_flag_invalid_value", "an invalid boolean value on --json", []string{"--json=maybe", "lock"}},
		{"bool_flag_quiet_reset", "--quiet --quiet=false is a valid repeated boolean", []string{"--quiet", "--quiet=false", "version"}},
		{"bool_flag_quiet_set_after_reset", "--quiet=false --quiet is a valid repeated boolean", []string{"--quiet=false", "--quiet", "version"}},
		{"bool_flag_local_false", "a command-local bool flag accepts --flag=false: the vault check then fails", []string{"verify", "--rebuild=false"}},
		{"bool_flag_local_true", "a command-local bool flag accepts --flag=true", []string{"verify", "--rebuild=true"}},
		{"bool_flag_local_reset", "a repeated local bool flag is last-value-wins: --rebuild --rebuild=false", []string{"verify", "--rebuild", "--rebuild=false"}},
		{"bool_flag_local_set_after_reset", "--rebuild=false --rebuild turns the local flag on again", []string{"verify", "--rebuild=false", "--rebuild"}},
		{"bool_flag_local_reset_after_arg", "the reset also applies after a positional argument", []string{"get", "x", "--print", "--print=0"}},
		{"bool_flag_local_noncanonical_false", "ParseBool accepts F as false on a local flag", []string{"verify", "--rebuild=F"}},
		{"bool_flag_local_noncanonical_true", "ParseBool accepts t as true on a local flag", []string{"verify", "--rebuild=t"}},
		{"bool_flag_local_invalid_value", "an invalid boolean value on a local flag", []string{"verify", "--rebuild=maybe"}},
		{"bool_flag_local_empty_value", "an empty boolean value on a local flag is a ParseBool syntax error", []string{"verify", "--rebuild="}},
		{"bool_flag_local_rebuild_only_false", "verify --rebuild-only=false is accepted too", []string{"verify", "--rebuild-only=false"}},
		{"bool_flag_local_shorthand_false", "a shorthand bool flag accepts -f=false", []string{"sync", "-f=false"}},
		{"bool_flag_local_shorthand_reset", "a shorthand bool flag is last-value-wins: -p -p=false", []string{"get", "-p", "-p=false", "x"}},
		{"bool_flag_local_shorthand_invalid_value", "an invalid boolean value on a shorthand bool flag", []string{"sync", "-f=maybe"}},
		{"bool_flag_local_shorthand_bare_equals", "-f= leaves = as the next shorthand, which is unknown", []string{"sync", "-f="}},
		{"bool_flag_local_sync_force_false", "sync --force=false reaches the vault check", []string{"sync", "--force=false"}},
		{"bool_flag_local_unlock_check_false", "unlock --check=false reaches the vault check", []string{"unlock", "--check=false"}},
		{"bool_flag_local_get_metadata_false", "get --metadata=false reaches the vault check", []string{"get", "--metadata=false", "x"}},
		{"bool_flag_local_recipients_remove_false", "recipients remove --yes=false --no-reencrypt=false reaches the vault check", []string{"recipients", "remove", "--yes=false", "--no-reencrypt=false", "x"}},
		{"bool_flag_local_doctor_fix_false_help", "doctor --fix=false: the report of the command itself depends on the host, so the case ends at --help (decided before clap parses the value; the structural guard and the parse test cover doctor)", []string{"doctor", "--fix=false", "--help"}},
		{"bool_flag_local_agent_install_global_quiet", "agent install has no local --quiet: --quiet=false is the persistent flag and is accepted", []string{"agent", "install", "--quiet=false", "--help"}},
		{"bool_flag_update_check_force_false", "the hand-parsed update check accepts --force=false (non-release build: no network)", []string{"update", "check", "--force=false"}},
		{"bool_flag_update_check_force_reset", "update check --force --force=false is last-value-wins", []string{"update", "check", "--force", "--force=false"}},
		{"bool_flag_update_check_json_true", "update check --json=true prints JSON", []string{"update", "check", "--json=true"}},
		{"bool_flag_update_check_json_reset", "update check --json --json=false prints text", []string{"update", "check", "--json", "--json=false"}},
		{"bool_flag_update_check_quiet_false", "update check --quiet=F keeps the normal output", []string{"update", "check", "--quiet=F"}},
		{"bool_flag_update_check_invalid_value", "an invalid value on a hand-parsed update flag", []string{"update", "check", "--force=maybe"}},
		{"bool_flag_update_check_invalid_after_word", "pflag rejects the flag value before cobra sees the extra positional", []string{"update", "check", "extra", "--force=maybe"}},
		{"bool_flag_update_apply_dry_run_true", "update apply --dry-run=true --force=false previews", []string{"update", "apply", "--dry-run=true", "--force=false"}},
		{"bool_flag_update_apply_dry_run_invalid", "an invalid value on update apply --dry-run", []string{"update", "apply", "--dry-run=maybe"}},
		{"bool_flag_update_info_json_empty", "an empty value on update info --json", []string{"update", "info", "--json="}},
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
	box := &sandbox{root: root}
	if err := box.installHostTools(); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	// The sandbox PATH starts with the host-tool stand-ins and holds only the
	// system directories after them: nothing of the developer's PATH is visible.
	env := []string{
		"PATH=" + box.hostToolsDir() + string(os.PathListSeparator) + sandboxPathSystem,
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(root, "xdg-config"),
		"XDG_DATA_HOME=" + filepath.Join(root, "xdg-data"),
		"XDG_CACHE_HOME=" + filepath.Join(root, "xdg-cache"),
		"TMPDIR=" + root,
		"CI=1",
		"NO_COLOR=1",
	}
	box.env = env
	return box, nil
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
	// hostCalls are the calls the run made to the host-tool stand-ins (service
	// managers only: a call of any other stand-in is an error), in call order.
	hostCalls []string
}

// runSpec is what a run needs besides argv: disposable working-directory files,
// a frozen vault tree and whether the initialized-vault environment applies.
type runSpec struct {
	files map[string]string
	seed  []seedFile
	// initialized adds the passphrase environment (SYMVAULT_PASSPHRASE with its
	// opt-in); the locked states leave it out and only pin the time zone.
	initialized bool
	tzOnly      bool
	// omit names vault files (by base name) left out of the seed.
	omit []string
	// configSuffix is appended to the seeded config.yaml.
	configSuffix string
}

// run executes the oracle in a fresh sandbox whose working directory holds files. A timed-out command keeps the
// partial stderr so a gate refusal (which is immediate) can still be told apart.
func run(goBinary string, args []string, files map[string]string) (result, error) {
	return runSpecified(goBinary, args, runSpec{files: files})
}

func runSpecified(goBinary string, args []string, spec runSpec) (result, error) {
	box, err := newSandbox()
	if err != nil {
		return result{}, err
	}
	defer func() { _ = os.RemoveAll(box.root) }()
	if spec.initialized {
		box.env = append(box.env, initializedEnv()...)
	} else if spec.tzOnly {
		box.env = append(box.env, "TZ=UTC")
	}
	if err := box.writeSeed(withConfigSuffix(withoutFiles(spec.seed, spec.omit), spec.configSuffix)); err != nil {
		return result{}, err
	}
	for name, content := range spec.files {
		if err := os.WriteFile(filepath.Join(box.root, name), []byte(content), 0o600); err != nil {
			return result{}, err
		}
	}
	return runInSandbox(goBinary, box, args)
}

// runInSandbox executes the oracle in box, which the caller prepared and removes.
func runInSandbox(goBinary string, box *sandbox, args []string) (result, error) {
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
	calls, err := box.hostToolCalls()
	if err != nil {
		return result{}, fmt.Errorf("read host-tool log of %v: %w", args, err)
	}
	if err := guardHostCalls(args, calls); err != nil {
		return result{}, err
	}
	out.hostCalls = calls
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
	// NoArgs and legacyArgs use this family rather than an arg-count message.
	return strings.HasPrefix(first, "Error: unknown command ") && strings.Contains(first, " for ")
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
		res, err := run(goBinary, in.args, nil)
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

type shapeInput struct {
	name, description string
	files             map[string]string
	args              []string
}

const (
	joinToken = "ABCD1234"
	// joinInviteMismatch is a well-formed invitation for a different token: the
	// command reads it, finds the mismatch and stops before any vault work.
	joinInviteMismatch = `{"token":"ZZZZ","public_key":"age1qqqq"}`
	joinInviteNoKey    = `{"token":"ABCD1234"}`
)

// joinFiles are the disposable invitation artifacts of the device join shapes.
var joinFiles = map[string]string{
	"invite-mismatch.json": joinInviteMismatch,
	"invite-nokey.json":    joinInviteNoKey,
}

// shapeInputs covers the argument shapes whose outcome depends on a flag's type.
// `device join --pairing-file` is a string flag: the token after it is its
// value, and with it set the command wants exactly one positional (the token),
// without it exactly two. A dummy-positional sweep never passes the flag, so
// these shapes are not reachable from the arity corpus.
func shapeInputs() []shapeInput {
	join := func(name, description string, args ...string) shapeInput {
		return shapeInput{name, description, joinFiles, concat([]string{"device", "join"}, args)}
	}
	return []shapeInput{
		join("join_pairing_file_equals_token", "--pairing-file=<path> <token>: one positional", "--pairing-file=invite-mismatch.json", joinToken),
		join("join_pairing_file_separate_token", "--pairing-file <path> <token>: the path is the flag's value", "--pairing-file", "invite-mismatch.json", joinToken),
		join("join_pairing_file_path_only", "--pairing-file <path> without a token: no positional is left", "--pairing-file", "invite-mismatch.json"),
		join("join_pairing_file_equals_double_dash_token", "the token after -- is positional", "--pairing-file=invite-mismatch.json", "--", joinToken),
		join("join_pairing_file_separate_double_dash_token", "the path is consumed before --, the token follows it", "--pairing-file", "invite-mismatch.json", "--", joinToken),
		join("join_pairing_file_two_positionals", "with --pairing-file a second positional is refused", "--pairing-file=invite-mismatch.json", joinToken, "extra"),
		join("join_pairing_file_name_flag_first", "another value flag before --pairing-file", "--name", "laptop", "--pairing-file", "invite-mismatch.json", joinToken),
		join("join_pairing_file_name_flag_last", "another value flag after the token", "--pairing-file", "invite-mismatch.json", joinToken, "--name", "laptop"),
		join("join_pairing_file_value_is_token_shaped", "a token-shaped path is still the flag's value", "--pairing-file", joinToken),
		join("join_pairing_file_missing_file", "the invitation file does not exist", "--pairing-file=missing.json", joinToken),
		// A file that is not JSON is deliberately absent: the diagnostic carries the
		// decoder's wording ("invalid character 'o' in literal null ..."), which the
		// Rust serde parser words differently by design.
		join("join_pairing_file_without_public_key", "the invitation carries no public key", "--pairing-file=invite-nokey.json", joinToken),
		join("join_pairing_file_invalid_token", "the token is validated before the file is read", "--pairing-file=missing.json", "ab-cd"),
		join("join_pairing_file_empty_value_one_positional", "an empty path leaves the flag unset: two positionals are required", "--pairing-file=", joinToken),
		join("join_pairing_file_empty_value_no_positional", "an empty path and no positional", "--pairing-file="),
		join("join_pairing_file_last_value_wins", "the last occurrence decides whether the flag is set", "--pairing-file=invite-mismatch.json", "--pairing-file=", joinToken),
		join("join_pairing_file_needs_argument", "--pairing-file without its value", "--pairing-file"),
		join("join_no_flag_zero_positionals", "no flag, no positional"),
		join("join_no_flag_one_positional", "no flag, one positional", joinToken),
		join("join_no_flag_two_positionals_invalid_token", "no flag, two positionals: the token is validated before the clone", "remote", "ab-cd"),
		join("join_no_flag_three_positionals", "no flag, three positionals", "remote", joinToken, "extra"),
		join("join_no_flag_four_positionals", "no flag, four positionals", "remote", joinToken, "extra", "more"),
		{"group_help_agent_skill", "a non-runnable group prints its help and exits 0", nil, []string{"agent", "skill"}},
		{"group_help_device", "a top-level group prints its help and exits 0", nil, []string{"device"}},
		{"profile_add_empty_vault", "profile add --vault= is set, so cobra does not call it missing: the command body rejects the empty path", nil, []string{"profile", "add", "work", "--vault="}},
	}
}

func buildShapes(goBinary string) ([]shapeCase, error) {
	var out []shapeCase
	for _, in := range shapeInputs() {
		res, err := run(goBinary, in.args, in.files)
		if err != nil {
			return nil, fmt.Errorf("shape %s: %w", in.name, err)
		}
		if res.timedOut {
			return nil, fmt.Errorf("shape %s timed out", in.name)
		}
		// The replay never reaches a vault, a clone or a prompt: a row that
		// the oracle accepted would be a different command, not a diagnostic.
		if res.obs.ExitCode == 0 && res.obs.Stderr != "" {
			return nil, fmt.Errorf("shape %s: exit 0 with stderr %q", in.name, res.obs.Stderr)
		}
		if res.obs.ExitCode != 0 && (res.obs.Stdout != "" || !strings.HasPrefix(res.obs.Stderr, "Error: ")) {
			return nil, fmt.Errorf("shape %s: exit %d is not a bare diagnostic: stdout %q stderr %q", in.name, res.obs.ExitCode, res.obs.Stdout, res.obs.Stderr)
		}
		out = append(out, shapeCase{Name: in.name, Description: in.description, Files: in.files, Observation: res.obs})
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
			res, err := run(goBinary, concat(base, dummyArgs(count)), nil)
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
			res, err := run(goBinary, concat(base, dummyArgs(valid), format), nil)
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
		plain, err := run(goBinary, concat(base, dummyArgs(valid)), nil)
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

// generatorDir holds this command; every non-test Go file in it decides what the
// fixture records (inventory, exclusions, normalizers, seed handling, scenario
// permutations), so every one of them is bound into generator_digest.
const generatorDir = "scripts/rust-port/cmd/errtaxgen"

// generatorSources lists the production Go files of the generator, sorted, as
// slash-separated paths relative to root. main.go must be among them.
func generatorSources(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(generatorDir)))
	if err != nil {
		return nil, err
	}
	var files []string
	hasMain := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		hasMain = hasMain || name == "main.go"
		files = append(files, generatorDir+"/"+name)
	}
	if !hasMain {
		return nil, fmt.Errorf("%s/main.go is missing", generatorDir)
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
	newSeed := flag.Bool("new-seed", false, "record a fresh initialized-vault seed instead of reusing the existing fixture's")
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
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("verify oracle: %v", err)
	}
	generators, err := generatorSources(root)
	if err != nil {
		fatal("list generator sources: %v", err)
	}
	generatorDigest, err := provenance.Digest(root, generators)
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
	shapes, err := buildShapes(*goBinary)
	if err != nil {
		fatal("build argument shapes: %v", err)
	}
	extras, err := buildExtraSections(*goBinary, *output, *newSeed)
	if err != nil {
		fatal("build extra-positional scenarios: %v", err)
	}
	fresh := fixture{
		SchemaVersion:  1,
		GeneratedOn:    runtime.GOOS,
		HostTools:      standInTools(),
		Oracle:         oracle{commitLabel, resolved, releaseLabel, sources, sourceDigest, generatorDigest},
		Usage:          usage,
		Arity:          arity,
		Gate:           gate,
		NotInitialized: notInitialized,
		ArgvShapes:     shapes,

		NilArgs:                   extras.nilArgs,
		VaultSeed:                 extras.seed,
		ExtraPositionals:          extras.extraPositionals,
		ExtraPositionalExclusions: extras.exclusions,
		HostDependentCommands:     extras.hostDependent,
		ServiceManagerCommands:    extras.serviceManager,
		RunFileUseArgv:            extras.runFileUse,
		UnlockStates:              extras.unlockStates,
	}
	content, err := marshalJSON(fresh)
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	summary := fmt.Sprintf("%d usage cases, %d arity rows, %d gate rows, %d not-initialized cases, %d argv shapes, %d nil-Args commands, %d extra-positional scenarios, %d run/file-use argv scenarios, %d unlock-state scenarios",
		len(usage), len(arity), len(gate), len(notInitialized), len(shapes), len(extras.nilArgs), len(extras.extraPositionals), len(extras.runFileUse), len(extras.unlockStates))
	if *check {
		existing, err := os.ReadFile(*output) // #nosec G304 -- repository fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		note := ""
		if !bytes.Equal(existing, content) {
			// The corpus is recorded on one platform. On another host only the
			// parts that platform cannot observe are taken from the recording;
			// everything else must still match this host's fresh oracle run.
			projected, taken, err := projectOnForeignHost(existing, fresh, runtime.GOOS)
			if err != nil {
				fatal("fixture is stale; regenerate deliberately (%v)", err)
			}
			again, err := marshalJSON(projected)
			if err != nil {
				fatal("marshal fixture: %v", err)
			}
			if !bytes.Equal(existing, again) {
				fatal("fixture is stale; regenerate deliberately")
			}
			note = fmt.Sprintf("; recorded on %s, so the service-file line of %d host-dependent scenario observations and %d service-manager call lists are taken from that recording and verified only there; every other byte, including the arguments, exit codes and stderr of those scenarios, matched this host's oracle run", projected.GeneratedOn, taken.observations, taken.calls)
		}
		fmt.Printf("PASS error taxonomy fixture (%s%s)\n", summary, note)
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
	exit(1)
}
