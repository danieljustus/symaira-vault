package main

import (
	"fmt"
	"strings"
)

// The typed-flag section (CLI-003). The usage section records what pflag
// rejects while it parses a typed flag; this one records what happens to a value
// pflag ACCEPTS, which only a command run shows:
//
//   - `file add --max-size` is an int64 (`ParseInt(s, 0, 64)`): hex, octal,
//     binary and `_` forms are sizes, a negative limit rejects every file, and
//     the command checks `--field`, `--from`, the stat, the size and the read
//     before it opens the vault.
//   - a `stringSlice` flag reads each value as one `encoding/csv` record: quotes,
//     doubled quotes, empty elements, only the first line, an empty value is an
//     empty slice (not the default), repeated flags append. The slices are
//     observed through `doctor --only|--exclude` (which checks run) and `agent
//     token new|rotate --tools` (which tools the token lists). `broker
//     --passthrough` and `run --broker-passthrough` hand their slice to the
//     egress proxy and print it only after the broker listens, so no terminating
//     run shows it.
//   - a `time.Duration` flag is parsed by pflag; the commands then use the
//     value: `run|file use --timeout` (zero and negative mean no timeout, a
//     timeout shorter than the start-up is an expired context, the text of the
//     timeout is Duration.String), `unlock --ttl`, `intake watch
//     --interval|--debounce` and `dynamic generate --ttl`.
//
// Names are slugs, descriptions say what the case pins.

// typedFlagCase is one command line. states lists the sandboxes it runs in (the
// initialized vault when empty).
type typedFlagCase struct {
	name, description string
	args              []string
	files             map[string]string
	states            []string
	normalize         []string
}

const (
	// typedSourceName is a 100-byte source file for `file add`.
	typedSourceName = "a.bin"
	typedSourceSize = 100
	// typedEntry is a new entry: `file add` creates it.
	typedEntry = "seed/new"
)

var typedSourceFiles = map[string]string{
	typedSourceName: strings.Repeat("x", typedSourceSize),
	"dir/inner.txt": "inner",
	"inbox/.keep":   "",
}

// onlyConfig keeps the host-independent checks: `vault.initialized` and the two
// `vault.config.*` checks only read files of the sandbox's vault.
const onlyConfig = "vault.initialized,vault.config.*"

func fileAddArgs(extra ...string) []string {
	return concat([]string{"file", "add", typedEntry, "--field", "f", "--from", typedSourceName}, extra)
}

func doctorArgs(extra ...string) []string {
	return concat([]string{"doctor", "--no-network", "--json"}, extra)
}

func tokenNewArgs(extra ...string) []string {
	return concat([]string{"agent", "token", "new", "bot"}, extra)
}

func typedFlagCases() []typedFlagCase {
	var cases []typedFlagCase
	add := func(name, description string, args []string, states ...string) {
		cases = append(cases, typedFlagCase{name: name, description: description, args: args, files: typedSourceFiles, states: states})
	}
	both := []string{stateUninitialized, stateInitialized}

	// --- file add --max-size: int64 ---
	add("max_size_hex_below_size", "0x10 is 16: the 100-byte source exceeds it (exit 9, printed twice)", fileAddArgs("--max-size", "0x10"))
	add("max_size_hex_above_size", "0x100 is 256: the source fits", fileAddArgs("--max-size", "0x100"))
	add("max_size_hex_upper_prefix", "0X64 is 100: the source fits exactly", fileAddArgs("--max-size", "0X64"))
	add("max_size_octal_prefix", "0o144 is 100", fileAddArgs("--max-size", "0o144"))
	add("max_size_binary_prefix", "0b1100100 is 100", fileAddArgs("--max-size", "0b1100100"))
	add("max_size_legacy_octal", "0144 is 100 (a leading 0 means octal with base 0)", fileAddArgs("--max-size", "0144"))
	add("max_size_underscores", "1_000 is 1000 (underscores are digit separators with base 0)", fileAddArgs("--max-size", "1_000"))
	add("max_size_plus_sign", "+100 is 100", fileAddArgs("--max-size", "+100"))
	add("max_size_decimal_equal", "100 allows a 100-byte source", fileAddArgs("--max-size", "100"))
	add("max_size_decimal_one_below", "99 rejects a 100-byte source", fileAddArgs("--max-size", "99"))
	add("max_size_zero", "0 rejects every non-empty source", fileAddArgs("--max-size", "0"))
	add("max_size_negative", "-1 as a separate word is a value: every file exceeds a negative limit", fileAddArgs("--max-size", "-1"))
	add("max_size_negative_equals", "--max-size=-0x1 is minus one", fileAddArgs("--max-size=-0x1"))
	add("max_size_negative_octal", "-0o2 is minus two", fileAddArgs("--max-size", "-0o2"))
	add("max_size_min_int64", "-9223372036854775808 is the smallest int64: accepted, then every file exceeds it", fileAddArgs("--max-size", "-9223372036854775808"))
	add("max_size_min_int64_hex", "-0x8000000000000000 is the smallest int64", fileAddArgs("--max-size", "-0x8000000000000000"))
	add("max_size_max_int64", "9223372036854775807 is the largest int64: the source fits", fileAddArgs("--max-size", "9223372036854775807"))
	add("max_size_max_int64_hex", "0x7fffffffffffffff is the largest int64", fileAddArgs("--max-size", "0x7fffffffffffffff"))
	add("max_size_hex_overflow", "0x8000000000000000 is past int64: a range error before the command runs", fileAddArgs("--max-size", "0x8000000000000000"))
	add("max_size_decimal_overflow", "a decimal past int64 is a range error", fileAddArgs("--max-size", "99999999999999999999"))
	add("max_size_negative_overflow", "a negative decimal below int64 is a range error", fileAddArgs("--max-size=-99999999999999999999"))
	add("max_size_repeated_last_wins", "pflag keeps the last --max-size (1 then 100: fits)", fileAddArgs("--max-size", "1", "--max-size", "100"))
	add("max_size_repeated_last_rejects", "pflag keeps the last --max-size (100 then 1: rejected)", fileAddArgs("--max-size", "100", "--max-size", "1"))
	add("max_size_negative_before_vault", "the size check runs before the vault is resolved: no vault, the size error", fileAddArgs("--max-size", "-1"), both...)
	add("max_size_fits_vault_check", "a source that fits reaches the vault check", fileAddArgs("--max-size", "0x100"), both...)
	add("max_size_negative_missing_source", "the stat precedes the size check", concat([]string{"file", "add", typedEntry, "--field", "f", "--from", "absent.bin", "--max-size", "-1"}))
	add("max_size_negative_gate_first", "the output-format gate runs before the command body", fileAddArgs("--max-size", "-1", "--output", "xml"))
	add("max_size_field_before_size", "--field is checked before the size", []string{"file", "add", typedEntry, "--from", typedSourceName, "--max-size", "-1"})
	add("file_add_no_flags", "neither --field nor --from: the command body reports --field (exit 9)", []string{"file", "add", typedEntry}, both...)
	add("file_add_field_only", "no --from (exit 9)", []string{"file", "add", typedEntry, "--field", "f"}, both...)
	add("file_add_from_only", "no --field (exit 9)", []string{"file", "add", typedEntry, "--from", typedSourceName})
	add("file_add_empty_field", "--field= is set but empty: the body rejects it", []string{"file", "add", typedEntry, "--field=", "--from", typedSourceName})
	add("file_add_empty_from", "--from \"\" is set but empty: the body rejects it", []string{"file", "add", typedEntry, "--field", "f", "--from", ""})
	add("file_add_missing_source", "a source that does not exist: the stat error with Go's errno text", []string{"file", "add", typedEntry, "--field", "f", "--from", "absent.bin"})
	add("file_add_directory_source", "a directory is stat-able and fails on the read", []string{"file", "add", typedEntry, "--field", "f", "--from", "dir"})
	add("file_add_hyphen_values", "pflag takes the next word as the value even when it starts with a dash", []string{"file", "add", typedEntry, "--field", "-x", "--from", typedSourceName, "--type", "-y"})
	add("file_add_repeated_field", "a repeated --field keeps the last", []string{"file", "add", typedEntry, "--field", "one", "--field", "two", "--from", typedSourceName})

	// --- stringSlice: doctor --only / --exclude ---
	slice := func(name, description string, args []string) {
		cases = append(cases, typedFlagCase{name: name, description: description, args: args, files: typedSourceFiles, normalize: []string{normalizeTokenValues}})
	}
	slice("slice_doctor_only_plain", "--only takes comma-separated patterns", doctorArgs("--only", onlyConfig))
	slice("slice_doctor_only_quoted_element", "a quoted element is one element without its quotes", doctorArgs("--only", `"vault.config.*",vault.initialized`))
	slice("slice_doctor_only_quoted_comma", "a quoted comma stays inside one pattern, which matches no check", doctorArgs("--only", `"vault.config.*,vault.initialized"`))
	slice("slice_doctor_only_empty_elements", "empty elements are kept and match no check", doctorArgs("--only", "vault.config.*,,"))
	slice("slice_doctor_only_empty_value", "an empty value is an empty slice: no filter, so every check runs (narrowed by --exclude)", doctorArgs("--only", "", "--exclude", `[^v]*,vault.[^ci]*`))
	slice("slice_doctor_only_comma_only", "a lone comma is two empty elements: a filter that matches nothing", doctorArgs("--only", ","))
	slice("slice_doctor_only_repeated", "repeated flags append", doctorArgs("--only", "vault.initialized", "--only", "vault.config.*"))
	slice("slice_doctor_only_repeated_empty", "a repeated flag with an empty value appends nothing", doctorArgs("--only", onlyConfig, "--only", ""))
	slice("slice_doctor_only_empty_then_value", "an empty value first, then a value", doctorArgs("--only", "", "--only", "vault.initialized"))
	slice("slice_doctor_only_second_line_ignored", "only the first CSV record is read: the second line is dropped", doctorArgs("--only", "vault.initialized\nvault.config.*"))
	slice("slice_doctor_only_leading_blank_lines", "blank lines before the record are skipped", doctorArgs("--only", "\n\nvault.initialized"))
	slice("slice_doctor_only_crlf", "a CRLF ends the record", doctorArgs("--only", "vault.initialized\r\nvault.config.*"))
	slice("slice_doctor_only_leading_space", "a leading space is part of the pattern, which then matches nothing", doctorArgs("--only", " vault.initialized"))
	slice("slice_doctor_only_hyphen_value", "pflag takes the next word as the value even when it starts with a dash", doctorArgs("--only", "-x"))
	slice("slice_doctor_only_doubled_quote", "a doubled quote inside quotes is one quote character", doctorArgs("--only", `"vault.""initialized"`))
	slice("slice_doctor_only_backslash", "a backslash is no escape in CSV: the comma still splits", doctorArgs("--only", `vault.initialized\,vault.config.parses`))
	slice("slice_doctor_only_multiline_quoted", "a quoted field may hold a line break", doctorArgs("--only", "\"vault.initialized\nx\",vault.config.parses"))
	slice("slice_doctor_exclude_plain", "--exclude takes comma-separated patterns", doctorArgs("--only", onlyConfig, "--exclude", "vault.config.parses,vault.initialized"))
	slice("slice_doctor_exclude_quoted", "a quoted exclude element", doctorArgs("--only", onlyConfig, "--exclude", `"vault.config.parses",vault.initialized`))
	slice("slice_doctor_exclude_empty_value", "an empty --exclude excludes nothing", doctorArgs("--only", onlyConfig, "--exclude", ""))
	slice("slice_doctor_exclude_repeated", "repeated --exclude append", doctorArgs("--only", onlyConfig, "--exclude", "vault.config.parses", "--exclude", "vault.initialized"))

	// --- stringSlice: agent token --tools ---
	slice("slice_token_new_default", "without --tools the default is *", tokenNewArgs())
	slice("slice_token_new_empty_value", "--tools \"\" is an empty slice, not the default: at least one tool is required", tokenNewArgs("--tools", ""))
	slice("slice_token_new_empty_elements", "empty elements are listed", tokenNewArgs("--tools", "a,,b"))
	slice("slice_token_new_quoted_comma", "a quoted comma is one tool", tokenNewArgs("--tools", `"a,b",c`))
	slice("slice_token_new_quoted_newline", "a quoted line break stays in the tool name", tokenNewArgs("--tools", "\"a\nb\",c"))
	slice("slice_token_new_second_line_ignored", "only the first CSV record is read", tokenNewArgs("--tools", "a,b\nc"))
	slice("slice_token_new_spaces_kept", "spaces around elements are kept", tokenNewArgs("--tools", " a , b"))
	slice("slice_token_new_repeated", "repeated flags append", tokenNewArgs("--tools", "a", "--tools", "b"))
	slice("slice_token_new_repeated_empty", "an empty repeat after a value appends nothing", tokenNewArgs("--tools", "x,y", "--tools", ""))
	slice("slice_token_new_empty_then_value", "an empty value first, then a value", tokenNewArgs("--tools", "", "--tools", "x"))
	slice("slice_token_new_doubled_quote", "a doubled quote inside quotes", tokenNewArgs("--tools", `"a""b"`))
	slice("slice_token_new_backslash", "a backslash is no escape", tokenNewArgs("--tools", `a\,b`))
	slice("slice_token_new_hyphen_value", "a value starting with a dash", tokenNewArgs("--tools", "-x"))
	slice("slice_token_new_trailing_comma", "a trailing comma lists an empty tool", tokenNewArgs("--tools", "a,"))
	slice("slice_token_rotate_default", "rotate without --tools: *", []string{"agent", "token", "rotate", "bot"})
	slice("slice_token_rotate_empty_value", "rotate --tools \"\" requires a tool", []string{"agent", "token", "rotate", "bot", "--tools", ""})
	slice("slice_token_rotate_quoted", "rotate with a quoted element", []string{"agent", "token", "rotate", "bot", "--tools", `"a,b",c`})
	slice("slice_token_rotate_repeated", "rotate with repeated flags", []string{"agent", "token", "rotate", "bot", "--tools", "a", "--tools", "b,c"})

	// --- time.Duration flags the commands use ---
	timedOut := []string{"/bin/sh", "-c", "exec sleep 5"}
	clean := []string{"/bin/sh", "-c", "exit 0"}
	run := func(name, description string, flag []string, child []string, states ...string) {
		cases = append(cases, typedFlagCase{name: name, description: description, args: concat([]string{"run"}, flag, []string{"--"}, child), files: typedSourceFiles, states: states})
	}
	run("duration_run_ms", "100ms: the child outlives it; the error names Duration.String", []string{"--timeout", "100ms"}, timedOut)
	run("duration_run_fraction", "250.5ms keeps its fraction", []string{"--timeout", "250.5ms"}, timedOut)
	run("duration_run_plus_sign", "+0.1s: a signed duration is 100ms", []string{"-t", "+0.1s"}, timedOut)
	run("duration_run_leading_dot", ".1s is 100ms", []string{"--timeout", ".1s"}, timedOut)
	run("duration_run_micro_sign", "100000µs (U+00B5) is 100ms", []string{"--timeout", "100000µs"}, timedOut)
	run("duration_run_greek_mu", "100000μs (U+03BC) is 100ms", []string{"--timeout", "100000μs"}, timedOut)
	run("duration_run_compound", "1ms100us: units add up", []string{"--timeout", "100ms100us"}, timedOut)
	run("duration_run_repeated_last_wins", "pflag keeps the last --timeout", []string{"--timeout", "5s", "--timeout", "100ms"}, timedOut)
	run("duration_run_repeated_last_wins_clean", "the last --timeout wins: 5s after 100ms leaves a clean child alone", []string{"--timeout", "100ms", "--timeout", "5s"}, clean)
	run("duration_run_expired_before_start_ns", "1ns has expired before the process starts: Go does not start it (1µs is a race between the start and the deadline, so it is not recorded)", []string{"--timeout", "1ns"}, timedOut)
	run("duration_run_zero", "0 is no timeout", []string{"--timeout", "0"}, clean)
	run("duration_run_negative_zero", "-0s is no timeout", []string{"--timeout", "-0s"}, clean)
	run("duration_run_negative", "a negative duration is no timeout", []string{"--timeout", "-5s"}, clean)
	run("duration_run_negative_short", "-t -1ns: the shorthand takes a dash-leading value", []string{"-t", "-1ns"}, clean)
	run("duration_run_huge", "the largest duration is a timeout that never fires", []string{"--timeout", "9223372036854775807ns"}, clean)
	run("duration_run_huge_hours", "2562047h47m16.854775807s is the same largest duration", []string{"--timeout", "2562047h47m16.854775807s"}, clean)
	run("duration_run_negative_vault_check", "a negative timeout is accepted before the vault check", []string{"--timeout", "-5s"}, clean, both...)
	use := func(name, description string, flag []string, child []string, states ...string) {
		cases = append(cases, typedFlagCase{name: name, description: description, args: concat([]string{"file", "use", seedFileEntry}, flag, []string{"--"}, child), files: typedSourceFiles, states: states})
	}
	use("duration_file_use_ms", "file use -t 100ms", []string{"-t", "100ms"}, timedOut)
	use("duration_file_use_fraction", "file use --timeout 250.5ms", []string{"--timeout", "250.5ms"}, timedOut)
	use("duration_file_use_expired_before_start", "file use --timeout 1ns", []string{"--timeout", "1ns"}, timedOut)
	use("duration_file_use_negative", "file use -t -5s is no timeout", []string{"-t", "-5s"}, clean)
	use("duration_file_use_zero", "file use --timeout 0 is no timeout", []string{"--timeout", "0"}, clean)
	use("duration_file_use_repeated", "file use keeps the last --timeout", []string{"-t", "5s", "-t", "100ms"}, timedOut)

	ttl := func(name, description string, value string, states ...string) {
		cases = append(cases, typedFlagCase{name: name, description: description, args: []string{"unlock", "--ttl", value}, files: typedSourceFiles, states: states})
	}
	for _, c := range []struct{ slug, value string }{
		{"compound", "1h30m"}, {"fraction", "1.5h"}, {"plus_sign", "+5s"}, {"leading_dot", ".5s"}, {"trailing_dot", "1.s"},
		{"micro", "1µs"}, {"zero", "0"}, {"negative", "-5s"}, {"max", "9223372036854775807ns"}, {"max_compound", "2562047h47m16.854775807s"},
	} {
		ttl("duration_unlock_ttl_"+c.slug, "unlock --ttl "+c.value+": pflag accepts it and the command runs", c.value)
	}
	ttl("duration_unlock_ttl_vault_check", "a valid --ttl reaches the vault check", "1h30m", both...)
	ttl("duration_unlock_ttl_negative_vault_check", "a negative --ttl reaches the vault check", "-5s", stateUninitialized)
	cases = append(cases, typedFlagCase{name: "duration_unlock_ttl_repeated", description: "unlock keeps the last --ttl", args: []string{"unlock", "--ttl", "bogus", "--ttl", "1h"}, files: typedSourceFiles})

	watch := func(name, description string, flags ...string) {
		cases = append(cases, typedFlagCase{name: name, description: description, args: concat([]string{"intake", "watch", "inbox", "--once"}, flags), files: typedSourceFiles})
	}
	for _, c := range []struct{ slug, value string }{
		{"negative", "-5s"}, {"zero", "0"}, {"plus_sign", "+1s"}, {"leading_dot", ".5s"}, {"micro", "1µs"}, {"max", "9223372036854775807ns"}, {"compound", "1h30m"},
	} {
		watch("duration_watch_interval_"+c.slug, "intake watch --once --interval "+c.value, "--interval", c.value)
		watch("duration_watch_debounce_"+c.slug, "intake watch --once --debounce "+c.value, "--debounce", c.value)
	}
	watch("duration_watch_repeated", "intake watch keeps the last --interval", "--interval", "bogus", "--interval", "1s")
	watch("duration_watch_json", "intake watch --once --json with a negative interval", "--interval", "-1s", "--json")

	dyn := func(name, description, value string, states ...string) {
		cases = append(cases, typedFlagCase{name: name, description: description, args: []string{"dynamic", "generate", "--engine", "e", "--role", "r", "--ttl", value}, files: typedSourceFiles, states: states})
	}
	dyn("duration_dynamic_ttl_fraction", "dynamic generate --ttl 1.5h", "1.5h")
	dyn("duration_dynamic_ttl_negative", "dynamic generate --ttl -1s", "-1s")
	dyn("duration_dynamic_ttl_zero", "dynamic generate --ttl 0", "0")
	dyn("duration_dynamic_ttl_micro", "dynamic generate --ttl 1µs", "1µs")
	dyn("duration_dynamic_ttl_vault_check", "dynamic generate --ttl reaches the vault check", "1h", both...)
	return cases
}

// typedFlagInputs expands typedFlagCases to scenario inputs, one per state.
func typedFlagInputs() []scenarioInput {
	var out []scenarioInput
	for _, c := range typedFlagCases() {
		states := c.states
		if len(states) == 0 {
			states = []string{stateInitialized}
		}
		for _, state := range states {
			out = append(out, scenarioInput{
				name:        fmt.Sprintf("typed_%s_%s", c.name, state),
				description: fmt.Sprintf("%s (%s)", c.description, state),
				state:       state,
				args:        c.args,
				files:       c.files,
				normalize:   c.normalize,
			})
		}
	}
	return out
}
