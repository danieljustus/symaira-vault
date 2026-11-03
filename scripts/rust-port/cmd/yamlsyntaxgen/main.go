// Command yamlsyntaxgen freezes the pinned Go CLI's rendering of config.yaml
// syntax failures (CLI-005: the go-yaml scanner/parser/reader error dialect).
//
// Every case is a config.yaml whose bytes the go-yaml (gopkg.in/yaml.v3)
// scanner, parser or reader rejects. The pinned Go binary is run over the same
// five commands that surface the failure — `config validate`, `config validate
// --json`, `config get`, `config set` and the five `doctor` checks that load the
// config, plus `agent list` for a few failures — and its exit status, stdout and
// stderr are recorded byte for byte.
// The Rust integration test replays the identical cases against the native CLI.
//
// The corpus also freezes what `config.Load` and `Config.Validate` accept and
// reject once the bytes parse (the `load_*` cases): the typed-decode failures
// of sections the port does not model, the merge guards, the session-duration
// rule, `authMethod` normalization and the agent-profile enums. Those cases
// pin the wording of the loader's errors too, which Go returns bare: no
// `parse config:` / `invalid config:` prefix reaches any command.
//
// Expected output always comes from the pinned Go binary; nothing is derived
// from the Rust side. The `open_divergences` list records inputs on which the
// native CLI is known to differ from Go, together with the Go bytes of every
// command the difference shows on (validate, get, set with its side effect on
// the file, doctor), so the gap stays explicit instead of being dropped from the
// corpus. Each entry says whether only the wording differs (same exit status and
// same effect on the file) or the behavior does, and why.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "0cc780626d3275afad14eb64c44abf8adb23d2ce"
	pinnedOracleRelease = "unreleased"
	configMarker        = "__CONFIG__"
	vaultMarker         = "__VAULT__"
	rootMarker          = "__ROOT__"
	defaultOutput       = "testdata/port/cli/config-yaml-syntax.json"
)

var productionSources = []string{
	"cmd/admin/config.go",
	"go.mod",
	"go.sum",
	"internal/cli/cli.go",
	"internal/config/config_load.go",
	"internal/config/config_merge.go",
	"internal/config/config_validate.go",
	"internal/config/dottedpath.go",
	"internal/errors/errors.go",
	"internal/health/doctor_mcp.go",
	"internal/health/doctor_session.go",
	"internal/health/doctor_vault.go",
}

// doctorIDs are the five checks that load config.yaml and quote the loader's
// error in their message.
var doctorIDs = []string{
	"vault.config.parses",
	"vault.config.validates",
	"auth.passphrase.rotation",
	"mcp.dynamic.engines",
	"mcp.agents",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type observation struct {
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	ExitCode  int      `json:"exit_code"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Unchanged *bool    `json:"config_unchanged,omitempty"`
}

type doctorResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
	Fixable bool   `json:"fixable"`
}

type doctorObservation struct {
	Args     []string       `json:"args"`
	ExitCode int            `json:"exit_code"`
	Results  []doctorResult `json:"results"`
}

// authObservation is the method `auth status` reports: the one line of its
// output that depends on the loaded config alone (the rest reads the host's
// keyring and biometrics).
type authObservation struct {
	Args     []string `json:"args"`
	ExitCode int      `json:"exit_code"`
	Method   string   `json:"method"`
}

type fixtureCase struct {
	Name         string            `json:"name"`
	Class        string            `json:"class"`
	Description  string            `json:"description"`
	ConfigHex    string            `json:"config_hex"`
	ConfigText   string            `json:"config_text"`
	Observations []observation     `json:"observations"`
	Doctor       doctorObservation `json:"doctor"`
	AgentList    *observation      `json:"agent_list,omitempty"`
	AuthMethod   *authObservation  `json:"auth_method,omitempty"`
}

type openDivergence struct {
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Kind         string             `json:"kind"`
	Reason       string             `json:"reason"`
	ConfigHex    string             `json:"config_hex"`
	ConfigText   string             `json:"config_text"`
	Observations []observation      `json:"observations"`
	Doctor       *doctorObservation `json:"doctor,omitempty"`
	AgentList    *observation       `json:"agent_list,omitempty"`
}

type fixture struct {
	SchemaVersion   int              `json:"schema_version"`
	Oracle          oracle           `json:"oracle"`
	DoctorIDs       []string         `json:"doctor_ids"`
	Cases           []fixtureCase    `json:"cases"`
	OpenDivergences []openDivergence `json:"open_divergences"`
	// LoaderWarningCounts (PLATFORM/CLI-005, ADR 0034 item 9): how often the
	// pinned Go CLI prints the `envWhitelist` deprecation warning for one
	// ordinary command. Go re-reads config.yaml at several unrelated seams, and
	// every read warns.
	LoaderWarningCounts loaderWarningCounts `json:"loader_warning_counts"`
}

type input struct {
	name, class, description string
	config                   []byte
}

// inputs lists the corpus. class is the libyaml stage that rejects the input
// ("scanner", "parser", "reader"), "node" for yaml.v3's own node builder (an
// alias to an anchor that was never defined; libyaml accepts it), "loader" for
// the loader's own multi-document rejection, "decode" for a document that
// parses but that yaml.v3 cannot decode into the typed config, or "accepted"
// for an input the loader must keep accepting.
func inputs() []input {
	all := []input{
		{"flow_sequence_unterminated", "parser", "flow sequence ends at end of input", []byte("vaultDir: [\n")},
		{"flow_mapping_unterminated", "parser", "flow mapping ends at end of input", []byte("vaultDir: {a: 1\n")},
		{"flow_sequence_unterminated_later_line", "parser", "unterminated flow sequence on a later line", []byte("a:\n  b: 1\n  c: [\n")},
		{"flow_sequence_missing_comma", "parser", "flow sequence items without a separator", []byte("a: [1, 2\n")},
		{"flow_mapping_value_missing", "parser", "flow mapping with a key and no value before a bad entry", []byte("{a, b: [}\n")},
		{"flow_comma_after_scalar", "parser", "comma and closing bracket outside a flow collection", []byte("a: 1,\nb: ]\n")},
		{"stray_closing_brace", "parser", "a lone closing brace", []byte("}\n")},
		{"stray_closing_bracket", "parser", "a lone closing bracket", []byte("]\n")},
		{"flow_question_unterminated", "parser", "explicit key inside an unterminated flow mapping", []byte("{? a: b\n")},
		{"complex_key_unterminated", "parser", "explicit mapping key followed by an unterminated flow sequence", []byte("? a\n: b\n? [\n")},
		{"document_start_inside_flow", "parser", "document marker inside a flow sequence", []byte("a: [1,\n---\n]\n")},
		{"deep_flow_sequence", "parser", "fifty nested, never-closed flow sequences", append([]byte("a: "), append(bytes.Repeat([]byte("["), 50), '\n')...)},
		{"carriage_return_flow", "parser", "bare CR line break after an opening bracket", []byte("a: [\r")},
		{"crlf_flow", "parser", "CRLF line break after an opening bracket", []byte("a: [\r\n")},
		{"block_sequence_after_mapping", "parser", "sequence entry directly after a mapping entry", []byte("a: 1\n- b\n")},
		{"mapping_dedent_misaligned", "parser", "mapping key outdented to a column no open block uses", []byte("a:\n  b: 1\n c: 2\n")},
		{"sequence_dedent_misaligned", "parser", "sequence entry outdented to a column no open block uses", []byte("a:\n    - 1\n  - 2\n")},
		{"sequence_missing_dash_indent", "parser", "sequence entries at two different indents", []byte("a:\n  - x\n - y\n")},
		{"duplicate_yaml_directive", "parser", "two %YAML directives", []byte("%YAML 1.1\n%YAML 1.1\n---\na: 1\n")},
		{"duplicate_tag_directive", "parser", "two %TAG directives for the same handle", []byte("%TAG ! tag:a\n%TAG ! tag:b\n---\na: 1\n")},
		{"incompatible_yaml_version", "parser", "%YAML directive with an unsupported version", []byte("%YAML 9.9\n---\na: 1\n")},
		{"undefined_tag_handle", "parser", "tag with a handle no %TAG directive declares", []byte("a: !x!y z\n")},
		{"mapping_value_on_first_line", "scanner", "second colon in a plain scalar on the first line", []byte("a: b: c\n")},
		{"mapping_value_nested", "scanner", "second colon in a plain scalar on a later line", []byte("vaultDir: /x\nagents:\n  a: b: c\n")},
		{"mapping_value_plain_scalar", "scanner", "colon inside a plain value", []byte("a: b:c d: e\n")},
		{"mapping_key_not_allowed", "scanner", "explicit key marker where a value is expected", []byte("a: ? b\n")},
		{"block_sequence_entry_not_allowed", "scanner", "dash after a key on the same line", []byte("a: - b\n")},
		{"tab_indentation", "scanner", "tab used as block indentation", []byte("agents:\n\tfoo: 1\n")},
		{"tab_after_colon_then_blank", "scanner", "tab on an otherwise blank continuation line", []byte("a:\n\t\n")},
		{"tab_violates_plain_indent", "scanner", "tab inside a multi-line plain scalar", []byte("a:\n  b\n\tc\n")},
		{"tab_in_block_scalar_indent", "scanner", "tab in the indentation of a block scalar line", []byte("a: |\n  x\n \t y\n")},
		{"double_quote_unterminated", "scanner", "double-quoted scalar without a closing quote", []byte("vaultDir: \"abc\n")},
		{"single_quote_unterminated", "scanner", "single-quoted scalar without a closing quote", []byte("vaultDir: 'abc\n")},
		{"document_indicator_in_quoted", "scanner", "document marker inside a quoted scalar", []byte("a: \"x\n---\ny\"\n")},
		{"unknown_escape", "scanner", "unknown backslash escape on the first line", []byte("vaultDir: \"a\\qb\"\n")},
		{"hex_escape_invalid", "scanner", "non-hex digits in a \\x escape", []byte("vaultDir: \"a\\xZZ\"\n")},
		{"hex_escape_invalid_later_line", "scanner", "non-hex digits in a \\u escape on a continuation line", []byte("a: \"x\n  \\u12G4\"\n")},
		{"unicode_escape_surrogate", "scanner", "escape code that is not a Unicode scalar value", []byte("a: \"\\uD800\"\n")},
		{"character_cannot_start_token_at", "scanner", "@ at the start of a value", []byte("vaultDir: @foo\n")},
		{"character_cannot_start_token_backtick", "scanner", "backtick at the start of a value", []byte("vaultDir: `foo\n")},
		{"unknown_directive", "scanner", "directive name other than YAML or TAG", []byte("%FOO\nvaultDir: x\n")},
		{"directive_without_name", "scanner", "percent sign with no directive name", []byte("%\n---\na: 1\n")},
		{"directive_name_non_alphabetic", "scanner", "non-alphabetic character in a directive name", []byte("%YA!ML 1.1\n---\na: 1\n")},
		{"yaml_directive_bad_digit", "scanner", "non-digit in a %YAML version", []byte("%YAML 1x\n---\na: 1\n")},
		{"yaml_directive_no_version", "scanner", "%YAML directive with no number", []byte("%YAML .\n---\na: 1\n")},
		{"yaml_directive_long_version", "scanner", "%YAML version number with ten digits", []byte("%YAML 1234567890.1\n---\na: 1\n")},
		{"directive_trailing_text", "scanner", "text after a complete %YAML directive", []byte("%YAML 1.1 x\n---\na: 1\n")},
		{"tag_directive_without_handle", "scanner", "%TAG directive with no arguments", []byte("%TAG\n---\na: 1\n")},
		{"tag_verbatim_unterminated", "scanner", "verbatim tag without a closing angle bracket", []byte("a: !<bad\n")},
		{"tag_verbatim_no_separator", "scanner", "verbatim tag glued to its value", []byte("a: !<x>y\n")},
		{"tag_verbatim_empty", "scanner", "empty verbatim tag", []byte("a: !<>\n")},
		{"tag_uri_bad_escape", "scanner", "percent escape that is not hexadecimal in a tag", []byte("a: !<%zz>\n")},
		{"tag_uri_bad_utf8_escape", "scanner", "percent escape forming an invalid UTF-8 lead octet", []byte("a: !<%ff>\n")},
		{"tag_handle_without_suffix", "scanner", "named tag handle with no suffix", []byte("a: !x!\n")},
		{"anchor_without_name", "scanner", "anchor marker with no name", []byte("a: &\n")},
		{"alias_without_name", "scanner", "alias marker with no name", []byte("a: *\n")},
		{"simple_key_without_colon", "scanner", "bare word where a key needs its colon", []byte("a: 1\nb: 2\nc\n")},
		{"simple_key_without_colon_second_line", "scanner", "bare word after the first entry", []byte("a: 1\nb\n")},
		{"block_scalar_indent_zero", "scanner", "block scalar indentation indicator 0", []byte("a: |0\n  x\n")},
		{"block_scalar_bad_header", "scanner", "block scalar header with two chomping indicators", []byte("a: |++\n  x\n")},
		{"control_character", "reader", "C0 control character in a value", []byte("a: \x01\n")},
		{"nul_byte", "reader", "NUL byte in a value", []byte("a: \x00\n")},
		{"noncharacter_fffe", "reader", "U+FFFE noncharacter", []byte("a: \xef\xbf\xbe\n")},
		{"utf8_invalid_lead_octet", "reader", "0xFF is never a UTF-8 lead octet", []byte("a: \xff\n")},
		{"utf8_overlong_length", "reader", "five-byte UTF-8 sequence", []byte("a: \xf8\x88\x80\x80\x80\n")},
		{"utf8_invalid_trailing_octet", "reader", "continuation octet missing", []byte("a: \xc3\x28\n")},
		{"utf8_incomplete_sequence", "reader", "multi-byte sequence cut off by end of input", []byte("a: \xe2\x82")},
		{"utf8_invalid_in_tag_directive", "reader", "invalid trailing octet inside a %TAG directive", []byte("%TAG ! tag:a\xe2\x82\n---\na: 1\n")},
		{"multiple_documents", "loader", "two documents: the loader rejects the stream, not the parser", []byte("a: 1\n---\nb: 2\n")},
		{"accepted_flow_colon_plain", "accepted", "a plain scalar containing a colon inside a flow sequence parses", []byte("a: [x:y]\n")},
		{"accepted_anchor_reuse", "accepted", "a redefined anchor parses", []byte("a: &x 1\nb: &x 2\nc: *x\n")},
		{"accepted_tab_after_colon", "accepted", "a tab between the colon and the value parses", []byte("a:\t b\n")},
		{"utf8_invalid_after_space", "reader", "bytes that are not UTF-8 after white space: not a blank config", []byte(" \xff\n")},
		{"unknown_anchor_value", "node", "alias to an anchor that is never defined", []byte("a: *nope\n")},
		{"unknown_anchor_later_line", "node", "alias on a later line to an anchor that is only defined afterwards", []byte("vaultDir: /x\nagents:\n  a: *later\nb: &later 1\n")},
		{"unknown_anchor_in_flow", "node", "undefined alias inside a flow sequence", []byte("a: [1, *nope]\n")},
		{"unknown_anchor_as_key", "node", "undefined alias used as a mapping key", []byte("*nope : 1\n")},
		{"unknown_anchor_name_characters", "node", "anchor name with digits, dash and underscore", []byte("a: *nope-1_x\n")},
		{"unknown_anchor_before_syntax_error", "node", "the undefined alias comes before an unterminated flow sequence and wins", []byte("a: *nope\nb: [\n")},
		{"unknown_anchor_after_non_ascii", "node", "multi-byte characters before the undefined alias", []byte("ключ: значение\nb: *nope\n")},
		{"unknown_anchor_crlf", "node", "undefined alias in a CRLF document", []byte("a: 1\r\nb: *nope\r\n")},
		{"second_document_flow_unterminated", "accepted", "an unreadable second document does not count as a trailing document", []byte("a: 1\n---\n[\n")},
		{"document_end_then_flow_unterminated", "accepted", "text after a document end marker is an unreadable second document", []byte("a: 1\n...\nb: [\n")},
		{"second_document_scanner_failure", "accepted", "a scanner failure in the second document, away from the first", []byte("a: 1\n---\nb: c: d\n")},
		{"second_document_quote_unterminated", "accepted", "an unterminated quote on a later line of the second document", []byte("a: 1\n---\nb: \"x\n")},
		{"document_end_then_scanner_failure", "accepted", "scanner failure in the document after a document end marker", []byte("a: 1\n...\nb: c: d\n")},
		{"whitespace_vertical_tab", "accepted", "only a vertical tab and a newline: Go trims it as white space and serves the defaults", []byte("\v\n")},
		{"whitespace_vertical_tab_without_newline", "accepted", "a lone vertical tab", []byte("\v")},
		{"whitespace_no_break_space", "accepted", "only U+00A0 and a newline", []byte("\u00a0\n")},
		{"whitespace_next_line", "accepted", "only U+0085 and a newline", []byte("\u0085\n")},
		{"whitespace_ideographic_space", "accepted", "only U+3000 and a newline", []byte("\u3000\n")},
		{"whitespace_line_separator", "accepted", "only U+2028 and a newline", []byte("\u2028\n")},
		{"whitespace_mixed_unicode", "accepted", "ASCII and Unicode white space mixed", []byte(" \t\r\n\v\f\u00a0\u0085\u3000 \n")},
		{"empty_flow_mapping_root", "accepted", "a document that is an empty flow mapping", []byte("{}\n")},
	}
	all = append(all, decodeInputs()...)
	all = append(all, loadInputs()...)
	all = append(all, sectionInputs()...)
	return append(all, residInputs()...)
}

// decodeInputs are documents that parse but that yaml.v3 cannot decode into the
// typed config. Unlike the "accepted" and "loader" classes they record `config
// get` and `config set` too: those commands read the node tree, so they decide
// for themselves whether the same bytes are an error.
func decodeInputs() []input {
	return []input{
		{"agents_scalar", "decode", "a scalar where the agents mapping belongs: yaml.v3's decode error `cannot unmarshal !!str `x` into map[string]config.AgentProfile`", []byte("agents: x\n")},
	}
}

// loadInputs are configs that parse as YAML and are accepted or rejected by
// the loader's own rules (CONFIG-LOAD-001). "loader" here means Go exits 6 with
// the loader's or validator's text, "accepted" means it exits 0.
func loadInputs() []input {
	return []input{
		// vaultDir: an empty text is not a value, so the resolved default stays.
		{"load_vault_dir_empty", "accepted", "an empty vaultDir keeps the resolved default: Config.Validate sees a non-empty path", []byte("vaultDir: ''\n")},
		{"load_vault_dir_null", "accepted", "a null vaultDir decodes to the empty string and keeps the default too", []byte("vaultDir: null\n")},
		// Agent profile enums, checked while the file loads.
		{"load_prompt_injection_mode_invalid", "loader", "an unknown promptInjectionMode is rejected by the loader, not by validate", []byte("agents:\n  x:\n    promptInjectionMode: weird\n")},
		{"load_prompt_injection_mode_valid", "accepted", "every promptInjectionMode the loader allows, the empty string included", []byte("agents:\n  a:\n    promptInjectionMode: log-only\n  b:\n    promptInjectionMode: wrap\n  c:\n    promptInjectionMode: deny\n  d:\n    promptInjectionMode: off\n  e:\n    promptInjectionMode: ''\n")},
		{"load_approval_mode_invalid", "loader", "an unknown approvalMode is rejected by the loader with its own text", []byte("agents:\n  x:\n    approvalMode: bogus\n")},
		{"load_agent_enum_order", "loader", "an invalid promptInjectionMode in one profile and an invalid approvalMode in another: the approvalMode loop runs first", []byte("agents:\n  a:\n    promptInjectionMode: weird\n  b:\n    approvalMode: bogus\n")},
		{"load_prompt_injection_mode_null", "accepted", "a null promptInjectionMode is a nil pointer and leaves the profile alone", []byte("agents:\n  x:\n    promptInjectionMode: null\n")},
		// Sections the typed Config decodes before it merges anything.
		{"load_audit_max_size_mb_string", "loader", "a word where audit.maxSizeMb wants an integer", []byte("audit:\n  maxSizeMb: abc\n")},
		{"load_audit_section_scalar", "loader", "a scalar where the audit section belongs", []byte("audit: 5\n")},
		{"load_logging_level_sequence", "loader", "a sequence where logging.level wants a string", []byte("logging:\n  level: [1]\n")},
		{"load_logging_valid", "accepted", "logging.level and logging.format as strings", []byte("logging:\n  level: debug\n  format: json\n")},
		{"load_security_flag_string", "loader", "a word where security.disable_env_passphrase wants a boolean", []byte("security:\n  disable_env_passphrase: maybe\n")},
		{"alias_value_for_string_field", "accepted", "an alias to a scalar anchor used as the value of a string field: yaml.v3 decodes the alias into the field (closed by CONFIG-LOAD-001; was an open divergence)", []byte("a: &x 1\nvaultDir: *x\n")},
		{"load_vault_dir_integer", "accepted", "a non-string scalar decodes into a string field as its text", []byte("vaultDir: 12\n")},
		{"load_default_agent_integer", "accepted", "an integer defaultAgent is the text 7, and ensureAgentDefaults creates that profile", []byte("defaultAgent: 7\n")},
		{"load_prompt_injection_mode_integer", "loader", "an integer promptInjectionMode is the text 5 and not a valid mode", []byte("agents:\n  x:\n    promptInjectionMode: 5\n")},
		{"load_vault_dir_sequence", "loader", "a sequence where vaultDir wants a string", []byte("vaultDir: [a]\n")},
		// authMethod: an unknown method is swallowed by the merge.
		{"load_auth_method_unknown", "accepted", "an unknown top-level authMethod is dropped by the merge and validates", []byte("authMethod: bogus\n")},
		{"load_auth_method_unknown_with_touch_id_flag", "accepted", "an unknown authMethod still counts as written, so useTouchID: true selects nothing", []byte("authMethod: bogus\nuseTouchID: true\n")},
		{"load_auth_method_integer", "accepted", "a non-string authMethod decodes as text and is dropped the same way", []byte("authMethod: 5\n")},
		{"load_auth_method_alias", "accepted", "a method spelled in capitals with padding normalizes", []byte("authMethod: ' BIOMETRIC '\n")},
		{"load_vault_auth_method_unknown", "loader", "an unknown vault.authMethod loads and validate rejects it, quoting it as written", []byte("vault:\n  authMethod: ' Bogus '\n")},
		{"load_vault_auth_method_integer", "loader", "a non-string vault.authMethod is rejected by validate as text", []byte("vault:\n  authMethod: 5\n")},
		// Session durations: zero and negative values are rejected with the value.
		{"load_session_timeout_zero", "loader", "sessionTimeout 0s names the parsed value", []byte("sessionTimeout: 0s\n")},
		{"load_session_timeout_bare_zero", "loader", "a quoted bare 0 is a valid time.ParseDuration input and a zero duration", []byte("sessionTimeout: '0'\n")},
		{"load_session_timeout_negative", "loader", "a negative sessionTimeout is rendered the way Go prints a Duration", []byte("sessionTimeout: -5m\n")},
		{"load_session_timeout_negative_millis", "loader", "a negative sub-minute duration with a fraction", []byte("sessionTimeout: -1500ms\n")},
		{"load_session_timeout_null", "loader", "a present but null sessionTimeout decodes to zero", []byte("sessionTimeout: null\n")},
		{"load_session_timeout_integer", "loader", "an integer is not a time.Duration for yaml.v3", []byte("sessionTimeout: 0\n")},
		{"load_session_max_lifetime_zero", "loader", "sessionMaxLifetime 0s", []byte("sessionMaxLifetime: 0s\n")},
		{"load_session_durations_both_invalid", "loader", "both session durations wrong: Go joins the two messages", []byte("sessionTimeout: 0s\nsessionMaxLifetime: -90m\n")},
		{"load_session_timeout_fraction", "accepted", "a fractional positive duration loads", []byte("sessionTimeout: 1.5h\n")},
		// mcp.bind: an empty bind is a loader rejection.
		{"load_mcp_bind_empty", "loader", "an empty mcp.bind is rejected by the loader", []byte("mcp:\n  bind: ''\n")},
	}
}

// residInputs are the CONFIG-RESID cases: the Config.Validate checks on the
// audit and paymentPolicies sections that the native Config used to skip, and
// the deprecation warnings the loader prints to stderr. They were open
// divergences (load_audit_max_size_mb_zero and _null,
// load_payment_policy_without_instrument, load_agent_payment_policy_unknown)
// or unrecorded (the warnings); every case here is replayed byte for byte.
//
// Go walks the paymentPolicies and agents maps in random order and reports
// the first failing entry, so no case below has two failing entries in the
// same map: the message would not be deterministic on the Go side.
func residInputs() []input {
	const policy = "paymentPolicies:\n  p:\n    instrument: card\n"
	return []input{
		// audit.maxFileSize: maxSizeMb times 1 MiB, in int64.
		{"load_audit_max_size_mb_zero", "loader", "audit.maxSizeMb 0 loads and fails validation (audit.maxFileSize)", []byte("audit:\n  maxSizeMb: 0\n")},
		{"load_audit_max_size_mb_null", "loader", "audit.maxSizeMb null decodes to 0 and fails validation (audit.maxFileSize)", []byte("audit:\n  maxSizeMb: null\n")},
		{"resid_audit_max_size_mb_empty_value", "loader", "a maxSizeMb key with no value is null", []byte("audit:\n  maxSizeMb:\n")},
		{"resid_audit_max_size_mb_negative", "loader", "a negative maximum size", []byte("audit:\n  maxSizeMb: -3\n  maxBackups: 7\n")},
		{"resid_audit_max_size_mb_wraps_negative", "loader", "the product with 1 MiB wraps in int64: MaxInt64 MiB is -1 MiB", []byte("audit:\n  maxSizeMb: 9223372036854775807\n")},
		{"resid_audit_max_size_mb_wraps_to_zero", "loader", "2^44 MiB wraps to exactly zero bytes", []byte("audit:\n  maxSizeMb: 17592186044416\n")},
		{"resid_audit_max_size_mb_hex_zero", "loader", "0x0 is the integer zero", []byte("audit:\n  maxSizeMb: 0x0\n")},
		{"resid_audit_max_size_mb_float_zero", "loader", "0.0 decodes into the int64 as zero", []byte("audit:\n  maxSizeMb: 0.0\n")},
		{"resid_audit_max_size_mb_fraction_to_zero", "loader", "0.5 truncates to zero when it decodes into the int64", []byte("audit:\n  maxSizeMb: 0.5\n")},
		{"resid_audit_max_size_mb_fraction_truncates", "accepted", "2.5 truncates to two when it decodes into the int64", []byte("audit:\n  maxSizeMb: 2.5\n")},
		{"resid_audit_max_size_mb_valid", "accepted", "a positive maximum size", []byte("audit:\n  maxSizeMb: 5\n")},
		{"resid_audit_max_size_mb_hex", "accepted", "a hexadecimal maximum size", []byte("audit:\n  maxSizeMb: 0x10\n")},
		{"resid_audit_max_size_mb_float_whole", "accepted", "2.0 decodes into the int64 as two", []byte("audit:\n  maxSizeMb: 2.0\n")},
		{"resid_audit_empty", "accepted", "an empty audit mapping keeps the 100 MiB default", []byte("audit: {}\n")},
		{"resid_audit_null", "accepted", "a null audit section is not merged", []byte("audit: null\n")},
		{"resid_audit_max_backups_null", "accepted", "null in the other audit fields does not touch the size", []byte("audit:\n  maxBackups: null\n  maxAgeDays: null\n")},
		{"resid_audit_max_size_mb_via_merge", "accepted", "a maxSizeMb merged in through << was not written, so the default stays", lines("base: &b", "  maxSizeMb: 0", "audit:", "  <<: *b")},

		// paymentPolicies.<name>: first failing check of a policy.
		{"load_payment_policy_without_instrument", "loader", "a payment policy with no instrument", []byte("paymentPolicies:\n  p: {}\n")},
		{"load_agent_payment_policy_unknown", "loader", "an agent that names a payment policy no section defines", []byte("agents:\n  x:\n    paymentPolicy: abc\n")},
		{"resid_payment_policy_name_newline", "loader", "a policy name containing a newline splits into several reported lines", lines("paymentPolicies:", "  \"a\\nb\":", "    instrument: ''")},
		{"resid_payment_policy_null_entry", "loader", "a null entry is the zero policy", lines("paymentPolicies:", "  p: null")},
		{"resid_payment_policy_blank_instrument", "loader", "white space is not an instrument", lines("paymentPolicies:", "  p:", "    instrument: '  '", "    allowed_merchants: [acme]")},
		{"resid_payment_policy_no_limits", "loader", "an instrument alone constrains nothing", []byte(policy)},
		{"resid_payment_policy_empty_allowlist", "loader", "an empty allowlist is no allowlist", lines("paymentPolicies:", "  p:", "    instrument: card", "    allowed_merchants: []")},
		{"resid_payment_policy_null_max_amount", "loader", "a null max_amount is no limit", lines("paymentPolicies:", "  p:", "    instrument: card", "    max_amount: null")},
		{"resid_payment_policy_limit_without_currency", "loader", "a limit needs a currency", lines("paymentPolicies:", "  p:", "    instrument: card", "    max_amount:", "      per_day: '5'")},
		{"resid_payment_policy_blank_currency", "loader", "a blank currency is no currency", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: ' '", "    max_amount:", "      per_transaction: '5'")},
		{"resid_payment_policy_key_integer", "loader", "an integer policy name is its text in the message", lines("paymentPolicies:", "  5:", "    instrument: ''")},
		{"resid_payment_per_transaction_word", "loader", "letters in a decimal amount", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: abc")},
		{"resid_payment_per_transaction_two_points", "loader", "two decimal points", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '1.2.3'")},
		{"resid_payment_per_transaction_inner_minus", "loader", "a minus sign after the first byte", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '5-1'")},
		{"resid_payment_per_transaction_only_minus", "loader", "a sign and no digits", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '-'")},
		{"resid_payment_per_transaction_only_point", "loader", "a point and no digits", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '.'")},
		{"resid_payment_per_transaction_plus", "loader", "a plus sign is not accepted", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '+5'")},
		{"resid_payment_per_transaction_too_long", "loader", "thirty-one bytes are one too many", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '1234567890123456789012345678901'")},
		{"resid_payment_per_transaction_unicode_digit", "loader", "an Arabic-Indic digit is not an ASCII digit", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '٣'")},
		{"resid_payment_per_transaction_exponent_scalar", "loader", "an unquoted 1e3 is the text 1e3 in a string field", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: 1e3")},
		{"resid_payment_per_day_word", "loader", "the per-day limit is checked after the per-transaction one", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '5'", "      per_day: x")},
		{"resid_payment_both_amounts_bad", "loader", "the per-transaction message wins over the per-day one", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: 'a'", "      per_day: 'b'")},
		{"resid_payment_policies_null", "accepted", "a null paymentPolicies section is a nil map", lines("paymentPolicies: null")},
		{"resid_payment_policies_empty", "accepted", "an empty paymentPolicies section", lines("paymentPolicies: {}")},
		{"resid_payment_policy_allowlist_only", "accepted", "an allowlist is a constraint on its own", lines("paymentPolicies:", "  p:", "    instrument: card", "    allowed_merchants: [acme]")},
		{"resid_payment_policy_instrument_integer", "accepted", "an integer instrument is its text", lines("paymentPolicies:", "  p:", "    instrument: 5", "    allowed_merchants: [acme]")},
		{"resid_payment_policy_float_scalar_amount", "accepted", "an unquoted 5.50 is the text 5.50 in a string field", lines("paymentPolicies:", "  p:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: 5.50")},
		{"resid_payment_policy_decimal_forms", "accepted", "5., .5, a negative amount and the thirty-byte boundary", lines("paymentPolicies:", "  a:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '5.'", "  b:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_day: '.5'", "  c:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_transaction: '-0.25'", "  d:", "    instrument: card", "    currency: EUR", "    max_amount:", "      per_day: '123456789012345678901234567890'")},
		{"resid_agent_payment_policy_defined", "accepted", "an agent bound to a defined policy", lines("paymentPolicies:", "  p:", "    instrument: card", "    allowed_merchants: [acme]", "agents:", "  x:", "    paymentPolicy: p")},
		{"resid_agent_payment_policy_empty", "accepted", "an empty paymentPolicy names nothing", lines("agents:", "  x:", "    paymentPolicy: ''")},
		{"resid_agent_payment_policy_null", "accepted", "a null paymentPolicy is a nil pointer", lines("agents:", "  x:", "    paymentPolicy: null")},
		{"resid_agent_payment_policy_integer_defined", "accepted", "an integer paymentPolicy finds the policy named by the same text", lines("paymentPolicies:", "  5:", "    instrument: card", "    allowed_merchants: [acme]", "agents:", "  x:", "    paymentPolicy: 5")},
		{"resid_agent_payment_policy_integer_unknown", "loader", "an integer paymentPolicy is quoted as its text", lines("agents:", "  x:", "    paymentPolicy: 5")},
		{"resid_agent_payment_policy_case_sensitive", "loader", "policy names are case-sensitive", lines("paymentPolicies:", "  p:", "    instrument: card", "    allowed_merchants: [acme]", "agents:", "  x:", "    paymentPolicy: P")},
		{"resid_agent_payment_policy_and_policy_error", "loader", "the policy error comes before the agent reference error", lines("paymentPolicies:", "  p: {}", "agents:", "  x:", "    paymentPolicy: q")},
		{"resid_validate_error_order", "loader", "audit, clipboard, payment and Argon2id errors in Go's order after the agent ones", lines("vaultDir: '  '", "agents:", "  x:", "    allowedPaths: ['[']", "    paymentPolicy: q", "audit:", "  maxSizeMb: 0", "clipboard:", "  auto_clear_duration: -2", "paymentPolicies:", "  p: {}", "vault:", "  argon2id_time: 1")},

		// Deprecation warnings: cliout.Warnf on stderr, once per Load, after
		// the document decoded and before it is merged. --quiet does NOT
		// silence them: Go copies QuietMode into cliout before cobra parses
		// the persistent flag (the quiet cases below record exactly that).
		{"resid_warn_env_whitelist", "accepted", "envWhitelist warns", lines("envWhitelist: [a]")},
		{"resid_warn_env_whitelist_empty", "accepted", "an empty envWhitelist is a non-nil list and warns", lines("envWhitelist: []")},
		{"resid_warn_env_whitelist_null", "accepted", "a null envWhitelist is nil and does not warn", lines("envWhitelist: null")},
		{"resid_warn_env_whitelist_and_allowlist", "accepted", "the deprecated list warns even when the replacement is set", lines("envAllowlist: [b]", "envWhitelist: [a]")},
		{"resid_warn_mcp_approval_required", "accepted", "mcp.approval_required: true warns", lines("mcp:", "  approval_required: true")},
		{"resid_warn_mcp_approval_required_false", "accepted", "mcp.approval_required: false does not warn", lines("mcp:", "  approval_required: false")},
		{"resid_warn_mcp_approval_required_via_merge", "accepted", "the warning reads the decoded value, merged keys included", lines("base: &b", "  approval_required: true", "mcp:", "  <<: *b")},
		{"resid_warn_clipboard_print_by_default", "accepted", "clipboard.printByDefault warns once per process", lines("clipboard:", "  printByDefault: true")},
		{"resid_warn_clipboard_print_by_default_false", "accepted", "a false printByDefault still warns", lines("clipboard:", "  printByDefault: false")},
		{"resid_warn_clipboard_copy_by_default_wins", "accepted", "copyByDefault written: printByDefault is ignored and does not warn", lines("clipboard:", "  copyByDefault: false", "  printByDefault: true")},
		{"resid_warn_all_three", "accepted", "the three warnings in load order", lines("clipboard:", "  printByDefault: true", "mcp:", "  approval_required: true", "envWhitelist: [a]")},
		{"resid_warn_then_loader_rejection", "loader", "Go prints the warning and then rejects the document", lines("envWhitelist: [a]", "mcp:", "  bind: ''")},
		{"resid_warn_then_validation_error", "loader", "Go prints the warning, then validate reports the audit error", lines("envWhitelist: [a]", "audit:", "  maxSizeMb: 0")},
		{"resid_warn_not_when_decode_fails", "loader", "a document that does not decode warns about nothing", lines("envWhitelist: [a]", "mcp:", "  port: abc")},
	}
}

// lines joins config lines into a document, one newline after each.
func lines(rows ...string) []byte { return []byte(strings.Join(rows, "\n") + "\n") }

// sectionInputs are the CONFIG-SECTIONS-001 cases: what yaml.v3's typed decode
// makes of a scalar in each kind of config field (string, bool, int, pointer,
// duration, string list) and how the loader's merge then treats it. Each
// coercion class has the accepted input and a rejected sibling, and the cases
// are chosen so that the coerced value shows in a message where Go prints one.
func sectionInputs() []input {
	return []input{
		// A string field holds the scalar's source text.
		{"load_vault_auth_method_hex", "loader", "vault.authMethod 0x10 is the text 0x10, which validate quotes as written", lines("vault:", "  authMethod: 0x10")},
		{"load_approval_mode_integer", "loader", "an integer approvalMode is the text 5", lines("agents:", "  x:", "    approvalMode: 5")},
		{"load_approval_mode_bool", "loader", "a boolean approvalMode is the text true", lines("agents:", "  x:", "    approvalMode: true")},
		{"load_approval_mode_hex", "loader", "a hexadecimal approvalMode keeps its source text", lines("agents:", "  x:", "    approvalMode: 0x10")},
		{"load_prompt_injection_mode_hex", "loader", "a hexadecimal promptInjectionMode keeps its source text", lines("agents:", "  x:", "    promptInjectionMode: 0x10")},
		{"load_default_agent_hex", "accepted", "a hexadecimal defaultAgent names the profile 0x10", lines("defaultAgent: 0x10")},
		{"load_section_string_fields_non_string", "accepted", "scalars of every kind in the string fields of the vault, git and mcp sections", lines(
			"vault:", "  path: 5", "git:", "  commit_template: true",
			"mcp:", "  bind: 1.5", "  httpTokenFile: 7", "  tls_cert_file: true", "  tls_key_file: 0x10", "  tls_client_ca_file: 1e3")},
		{"load_agent_string_pointers_non_string", "accepted", "scalars of every kind in the *string fields tier, skillPath and skillVersion", lines(
			"agents:", "  x:", "    tier: 5", "    skillPath: true", "    skillVersion: 0x10")},
		{"load_profile_strings_non_string", "accepted", "scalars in defaultProfile and a profile's vault path", lines(
			"defaultProfile: 5", "profiles:", "  p:", "    vault: 6")},
		{"load_vault_dir_mapping", "loader", "a mapping where a string field belongs is still refused", lines("vaultDir:", "  a: 1")},

		// An int field truncates a float and reads YAML 1.1 spellings.
		{"load_vault_argon2id_time_float", "loader", "1.5 truncates to 1 and falls below the argon2id_time floor", lines("vault:", "  argon2id_time: 1.5")},
		{"load_vault_argon2id_time_exponent", "loader", "1e3 is the integer 1000 for an int field", lines("vault:", "  argon2id_time: 1e3")},
		{"load_vault_argon2id_time_underscore", "loader", "1_000 reads as 1000", lines("vault:", "  argon2id_time: 1_000")},
		{"load_vault_argon2id_time_old_octal", "loader", "0100 is octal 64", lines("vault:", "  argon2id_time: 0100")},
		{"load_vault_argon2id_time_octal_prefix", "accepted", "0o10 is octal 8, inside the argon2id_time range", lines("vault:", "  argon2id_time: 0o10")},
		{"load_clipboard_auto_clear_negative_float", "loader", "-1.5 truncates to -1, which validate refuses", lines("clipboard:", "  auto_clear_duration: -1.5")},
		{"load_clipboard_auto_clear_truncates_to_zero", "accepted", "-0.5 truncates to 0, which validate accepts", lines("clipboard:", "  auto_clear_duration: -0.5")},
		{"load_section_int_fields_float_and_exponent", "accepted", "floats and exponents in the int fields of the vault, mcp and clipboard sections", lines(
			"vault:", "  search_workers: 1.5", "  config_cache_entries: 1e3", "  scrypt_work_factor: 1.5", "  format_version: 2.9", "  manifest_generation: 1e3",
			"mcp:", "  port: 1.5", "  rate_limit: 1e3", "clipboard:", "  auto_clear_duration: 1e3")},
		{"load_mcp_int_underscore_and_octal", "accepted", "1_000 and 017 are integers for mcp.port and mcp.rate_limit", lines("mcp:", "  port: 1_000", "  rate_limit: 017")},
		{"load_agent_int_pointers", "accepted", "a float, an exponent and an octal in the *int fields of a profile", lines(
			"agents:", "  x:", "    max_reads_per_hour: 1.5", "    max_reads_per_day: 1e3", "    max_secrets_in_session: 0100")},
		{"load_mcp_port_overflow", "loader", "an integer beyond int64 is refused by the typed decode", lines("mcp:", "  port: 99999999999999999999")},
		{"load_mcp_port_word", "loader", "a word where mcp.port wants an integer", lines("mcp:", "  port: abc")},

		// null: a pointer stays nil, any other scalar field is zero.
		{"load_agent_null_pointers", "accepted", "null in every pointer field of a profile leaves it unset", lines(
			"agents:", "  x:", "    tier: null", "    approvalMode: null", "    canWrite: null", "    canRunCommands: null", "    canManageConfig: null",
			"    canUseClipboard: null", "    canUseAutotype: null", "    canReadValues: null", "    exposeValueTools: null", "    autoUnseal: null",
			"    requireApproval: null", "    approvalTimeout: null", "    max_reads_per_hour: null", "    max_reads_per_day: null",
			"    max_secrets_in_session: null", "    promptInjectionMode: null", "    skillPath: null", "    skillVersion: null",
			"    exposePaymentValues: null", "    paymentPolicy: null")},
		{"load_agent_null_lists", "accepted", "null in every list field of a profile", lines(
			"agents:", "  x:", "    allowedPaths: null", "    redactFields: null", "    allowed_tools: null", "    allowedEnvVars: null", "    allowedExecutables: null")},
		{"load_agent_null_items_dropped", "loader", "a null list item is dropped, so the bad glob after it is entry 0", lines("agents:", "  x:", "    allowedPaths: [null, '[']")},
		{"load_agent_non_string_items_index", "loader", "non-string list items are kept as text, so the bad glob after them is entry 2", lines("agents:", "  x:", "    allowedPaths: [5, true, '[']")},
		{"load_agent_non_string_items", "accepted", "numbers and booleans as the items of every string list of a profile", lines(
			"agents:", "  x:", "    allowedPaths: [5, true]", "    redactFields: [1.5]", "    allowed_tools: [0x10]", "    allowedEnvVars: [7]", "    allowedExecutables: [x, null]")},
		{"load_agent_profile_null", "accepted", "a null profile is the zero profile", lines("agents:", "  x: null", "  y: ~")},
		{"load_agents_null", "accepted", "a null agents section is a nil map", lines("agents: null")},
		{"load_agents_tilde", "accepted", "a ~ agents section is a nil map", lines("agents: ~")},
		{"load_section_scalars_null", "accepted", "null in the scalar fields of every section is the zero value", lines(
			"vault:", "  path: null", "  confirm_remove: null", "  legacy_mode: null", "  search_index: null", "  search_workers: null", "  argon2id_time: null", "  listing_cache_ttl: null",
			"git:", "  auto_push: null", "  commit_template: null", "  auto_pull_interval: null",
			"mcp:", "  port: null", "  stdio: null", "  rate_limit: null", "  approval_timeout: null",
			"update:", "  cache_ttl: null", "clipboard:", "  auto_clear_duration: null")},
		{"load_mcp_bind_null", "loader", "a null mcp.bind is the empty string, which the loader refuses", lines("mcp:", "  bind: null")},

		// Durations in the sections are kept as written, negative included.
		{"load_section_negative_durations", "accepted", "negative durations in the vault, git, mcp and update sections", lines(
			"vault:", "  listing_cache_ttl: -1s", "git:", "  auto_pull_interval: -5m",
			"mcp:", "  approval_timeout: -1s", "  read_timeout: -2s", "  oauth:", "    access_token_ttl: -1s",
			"update:", "  cache_ttl: -1h")},
		{"load_agent_negative_approval_timeout", "accepted", "a negative approvalTimeout is kept", lines("agents:", "  x:", "    approvalTimeout: -1s")},
		{"load_agent_approval_timeout_integer", "loader", "an integer is not a duration for approvalTimeout", lines("agents:", "  x:", "    approvalTimeout: 5")},
		{"load_mcp_approval_timeout_integer", "loader", "an integer is not a duration for mcp.approval_timeout", lines("mcp:", "  approval_timeout: 5")},

		// A bool field takes the YAML 1.1 spellings.
		{"load_section_bool_fields_yaml11", "accepted", "yes/no/on/off/y/n in the bool fields of the git, vault, mcp and clipboard sections", lines(
			"git:", "  auto_push: yes", "  auto_pull: Off", "vault:", "  confirm_remove: n", "  search_index: On", "mcp:", "  stdio: ON", "clipboard:", "  copyByDefault: y")},
		{"load_agent_bool_pointers_yaml11", "accepted", "the same spellings in the *bool fields of a profile", lines(
			"agents:", "  x:", "    canWrite: yes", "    canRunCommands: no", "    autoUnseal: on", "    requireApproval: Off")},
		{"load_git_bool_integer", "loader", "an integer where git.auto_push wants a boolean", lines("git:", "  auto_push: 5")},
		{"load_agent_bool_pointer_integer", "loader", "an integer where canWrite wants a boolean", lines("agents:", "  x:", "    canWrite: 5")},

		// A merge supplies decoded values, but the loader's field walk sees
		// only keys the mapping wrote itself.
		{"load_agent_merged_prompt_injection_mode", "loader", "a pointer field merged in through << is applied and validated", lines(
			"base: &base", "  promptInjectionMode: weird", "agents:", "  x:", "    <<: *base")},
		{"load_agent_merged_approval_mode_ignored", "accepted", "approvalMode is gated on the profile writing it, so a merged one is ignored", lines(
			"base: &base", "  approvalMode: bogus", "agents:", "  x:", "    <<: *base")},
		{"load_agents_alias_profile_ignored", "accepted", "a profile that is an alias has no written fields, so its approvalMode is ignored", lines(
			"base: &base", "  approvalMode: bogus", "agents:", "  x: *base")},
		{"load_mcp_bind_empty_via_merge", "accepted", "a bind merged in through << is not a field mcp wrote", lines(
			"base: &base", "  bind: ''", "mcp:", "  <<: *base")},
		{"load_mcp_section_alias_ignored", "accepted", "a section that is an alias has no written fields", lines(
			"base: &base", "  bind: ''", "mcp: *base")},
		{"load_session_timeout_zero_via_merge", "accepted", "a zero sessionTimeout merged in through << was not written, so it is not refused", lines(
			"base: &base", "  sessionTimeout: 0s", "<<: *base")},

		// The vault merge feeds the top-level method from the decoded
		// useTouchID (merged keys included) while the section's own flag keeps
		// only a written one: `auth status` shows the touchid method either way.
		{"load_vault_use_touch_id_via_merge", "accepted", "a useTouchID merged into vault through << still selects touchid as the top-level method", lines(
			"base: &b", "  useTouchID: true", "vault:", "  <<: *b")},
		{"load_vault_use_touch_id_via_merge_inline", "accepted", "the same merge written as an inline flow mapping", lines(
			"base: &b", "  useTouchID: true", "vault: {<<: *b}")},
		{"load_vault_use_touch_id_merged_then_overridden", "accepted", "a useTouchID the vault writes itself wins over the merged one", lines(
			"base: &b", "  useTouchID: true", "vault:", "  <<: *b", "  useTouchID: false")},

		// Go names a key by its node's Value, which is the anchor name for an
		// alias: an alias that resolves to another text writes nothing.
		{"load_agent_name_alias_fields_unwritten", "accepted", "agents.x is reached through an alias named a, so its approvalMode is not a written field", lines(
			"n: &a x", "agents:", "  *a :", "    approvalMode: bogus")},
		{"load_vault_section_alias_fields_unwritten", "accepted", "the vault section is reached through an alias named git, so its authMethod is not a written field", lines(
			"s: &git vault", "*git :", "  authMethod: ' Bogus '")},
		{"load_vault_field_alias_named_by_anchor", "accepted", "a vault key written as an alias counts under its anchor name authMethod, not under the text path it resolves to", lines(
			"k: &authMethod path", "vault:", "  *authMethod : ' Bogus '")},

		// The loader's bookkeeping must not swallow an operator's key.
		{"load_agent_name_nul_own", "accepted", "an agent named NUL+own is an ordinary agent", lines(
			"agents:", "  \"\\0own\":", "    canWrite: true")},

		// A local tag yaml.v3 does not know is ignored; the value decodes.
		{"custom_tag_on_value", "accepted", "a local tag on a plain scalar", lines("a: !t x")},

		// Only the first document is decoded.
		{"load_second_document_syntax_error_ignored", "accepted", "a syntax error in a later document does not reach the first", lines("vaultDir: a", "---", "[")},
	}
}

// Divergence kinds. "wording": both sides fail or succeed alike, with the same
// exit status and the same effect on the file, and only the text differs.
// "behavior": acceptance, exit status or the effect on the file differs.
const (
	kindWording  = "wording"
	kindBehavior = "behavior"
)

// openEntry is one recorded divergence: the input, the commands whose Go bytes
// are recorded for it (a subset of validate, validate_json, get, set, doctor),
// and what the native CLI does differently.
type openEntry struct {
	input
	kind     string
	commands []string
	reason   string
}

// lookaheadReason explains the common root cause of the same-line trailing
// token family.
const lookaheadReason = "yaml.v3 keeps a two-token scanner look-ahead behind the parser (yaml_parser_fetch_more_tokens, for comment association) while libyaml fetches a token only when the parser asks for it. " +
	"The parser rejects the trailing token in both, but yaml.v3 has already scanned the ':' after it and reports the scanner failure 'mapping values are not allowed in this context' (with its own line), where libyaml reports the parser failure 'did not find expected key'"

const nestingReason = "yaml.v3 decodes up to 10000 nested collections (config get prints the value, config set rewrites the file); the native config get and set parse the stream with yaml_edit, whose flow-depth limit is 256, and fail with exit 6 and an unchanged file"

// nestedFlowSequence is `a: [[...]]` with depth closed levels.
func nestedFlowSequence(depth int) []byte {
	out := append([]byte("a: "), bytes.Repeat([]byte("["), depth)...)
	out = append(out, bytes.Repeat([]byte("]"), depth)...)
	return append(out, '\n')
}

var textCommands = []string{"validate", "get", "set", "doctor"}

// openInputs are inputs on which the native CLI is known to differ from Go.
// They are recorded from the same Go binary so the gap is pinned rather than
// hidden, and the Rust replay fails the day one starts matching.
func openInputs() []openEntry {
	return []openEntry{
		// yaml.v3 scans two tokens ahead of the parser.
		{input{"trailing_token_after_double_quoted", "parser", "a plain scalar and a colon after a closed double-quoted value on the same line", []byte("a: \"x\" b: 1\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_single_quoted", "parser", "a trailing key after a single-quoted value", []byte("a: 'x' b: c: 1\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_flow_sequence", "parser", "a trailing key after a closed flow sequence", []byte("a: [1] b: 2\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_flow_sequence_later_line", "parser", "the same on the second line of the file", []byte("x: 1\na: [1] b: 2\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_flow_mapping", "parser", "a trailing key after a closed flow mapping", []byte("a: {b: 1} c: 2\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_empty_flow_mapping", "parser", "a trailing key after an empty flow mapping", []byte("a: {} b: 1\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_anchored_flow_sequence", "parser", "a trailing key after an anchored flow sequence", []byte("a: &x [1] c: 2\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_tagged_quoted", "parser", "a trailing key after a tagged double-quoted value", []byte("a: !!str \"x\" b: 2\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_alias", "parser", "a trailing key after an alias to a defined anchor", []byte("a: &x 1\nb: *x c: 2\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_multiline_flow_sequence", "parser", "a trailing key after a flow sequence that spans two lines", []byte("a: [1,\n  2] b: 3\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_nested_flow_sequence", "parser", "a trailing key after a flow sequence in a nested mapping", []byte("a:\n  b: [c] d: 1\n")},
			kindWording, textCommands, lookaheadReason},
		{input{"trailing_token_after_flow_sequence_in_block_sequence", "parser", "a trailing key after a flow sequence that is a sequence entry: the parser states differ as well", []byte("- [] b: 1\n")},
			kindWording, textCommands, "same two-token look-ahead as the other trailing_token_* entries; here the look-ahead also changes which block state libyaml is in when it rejects the token, so Go says \"did not find expected '-' indicator\" and libyaml \"did not find expected key\""},
		{input{"directive_without_document_start", "scanner", "content after a %YAML directive with no --- line", []byte("%YAML 1.1\na: 1\n")},
			kindWording, textCommands, "same two-token look-ahead: yaml.v3 reports the scanner error on line 2 (mapping values are not allowed) where libyaml reports the parser error 'did not find expected <document start>'"},
		// The look-ahead also reaches across a document boundary.
		{input{"scanner_failure_after_document_end", "scanner", "an unterminated quote as the first token of the second document", []byte("a: 1\n---\n\"x\n")},
			kindBehavior, []string{"validate", "doctor"}, "yaml.v3's two-token look-ahead scans the first token of the second document while it still reads the first one, so Go fails on the second document's scanner error with exit 6; libyaml in the native loader never reaches it and accepts the config"},
		{input{"third_document_scanner_look_ahead", "accepted", "an unterminated quote as the first token of a third document", []byte("a: 1\n---\nb: 2\n---\n\"x\n")},
			kindBehavior, []string{"validate"}, "Go's check for a second document decodes it with the same two-token look-ahead, which scans into the third document and fails, so Go sees no trailing document and accepts the config; the native loader decodes the second document fine and rejects the stream as multi-document"},
		{input{"second_document_unknown_anchor", "node", "an alias in the second document to an anchor that no document defines", []byte("a: 1\n---\nb: *nope\n")},
			kindBehavior, []string{"validate", "doctor"}, "Go fails to decode the second document, so it sees no trailing document and accepts the config; serde_yaml_ng scopes anchors to one document and yaml.v3 shares them across the stream, so the native loader cannot tell this alias from one to an anchor of the first document and keeps rejecting the stream as multi-document"},
		{input{"get_set_second_document_syntax_error", "parser", "an unterminated flow sequence in the second document, read by config get and config set", []byte("a: 1\n---\n[\n")},
			kindBehavior, []string{"get", "set"}, "Go's config get and config set read only the first document (yaml.Unmarshal into a node): get reports the missing key and set succeeds and rewrites the file; the native commands parse the whole stream with yaml_edit, fail on the later syntax error and leave the file alone"},
		// Not libyaml's scanner or parser at all.
		{input{"utf16_bom_only", "reader", "a lone UTF-16LE byte order mark", []byte("\xff\xfe")},
			kindBehavior, []string{"validate"}, "yaml.v3 decodes UTF-16 and accepts the empty stream; libyaml in serde_yaml_ng rejects the stream as invalid UTF-8"},
		{input{"bom_after_first_line", "scanner", "a UTF-8 byte order mark at the start of a later line", []byte("a: 1\n\xef\xbb\xbfb: 2\n")},
			kindBehavior, []string{"validate"}, "yaml.v3 skips the mark and accepts the stream; libyaml counts it as a column and rejects the mapping key"},
		// yaml.v3 decode and node layers, not syntax errors.
		{input{"scalar_root", "accepted", "a document that is a single scalar", []byte("just a scalar\n")},
			kindWording, append(append([]string(nil), textCommands...), "set_nested", "agent_list"), "the failure comes from yaml.v3's decoder and node layers, not from libyaml: validate says 'yaml: unmarshal errors: line 1: cannot unmarshal !!str `just a ...` into config.Config', get 'parent is a scalar node, not a mapping', set 'root node is a scalar, not a mapping'; the native CLI fails the same commands with the same exit status and leaves the file alone, with different text"},
		{input{"sequence_root", "accepted", "a document that is a block sequence", []byte("- 1\n- 2\n")},
			kindWording, append(append([]string(nil), textCommands...), "set_nested", "agent_list"), "yaml.v3 decoder and node layers again: 'cannot unmarshal !!seq into config.Config', 'parent is a sequence node, not a mapping', 'root node is a sequence, not a mapping'; same exit status and unchanged file natively, different text"},
		{input{"null_root", "accepted", "a document that is the scalar null", []byte("null\n")},
			kindWording, []string{"get", "set"}, "validate agrees (defaults); get and set fail on both sides with exit 6 and an unchanged file, Go with 'parent is a scalar node, not a mapping' and 'root node is a scalar, not a mapping', the native CLI with 'key \"vaultDir\" not found' and 'document has no root to descend into'"},
		{input{"comment_only", "accepted", "a config that contains only a comment", []byte("# nothing\n")},
			kindWording, []string{"get", "set"}, "validate agrees (defaults); get and set fail on both sides with exit 6 and an unchanged file, Go with 'parent is a unknown(0) node, not a mapping' and 'root node is a unknown(0), not a mapping', the native CLI with 'cannot load config: missing YAML document'"},
		{input{"document_start_only", "accepted", "a config that is only a document start marker", []byte("---\n")},
			kindWording, []string{"get", "set"}, "validate agrees (defaults); get and set fail on both sides with exit 6 and an unchanged file, Go with the scalar-node wording of null_root"},
		{input{"empty_file", "accepted", "a zero-byte config", []byte("")},
			kindWording, []string{"get", "set"}, "validate agrees (defaults); get and set fail on both sides with exit 6 and an unchanged file, Go with the 'unknown(0) node' wording of comment_only, the native CLI with 'missing YAML document'"},
		{input{"ascii_spaces_only", "accepted", "a config that is only spaces", []byte("   ")},
			kindWording, []string{"get", "set"}, "same as empty_file: Go reaches the node layer with an empty document, the native commands report a missing document"},
		{input{"no_break_space_only", "accepted", "a config that is only U+00A0 and a newline", []byte("\u00a0\n")},
			kindWording, []string{"get", "set"}, "validate and doctor agree (Go's blank check trims U+00A0, see whitespace_no_break_space); config get and set parse the file as a one-scalar document on the Go side and fail with its node wording, natively with different text; exit status and the unchanged file agree"},
		{input{"byte_order_mark_only", "accepted", "a config that is only a UTF-8 byte order mark", []byte("\xef\xbb\xbf")},
			kindWording, []string{"get", "set"}, "validate and doctor agree (defaults); config get and set differ in the node-layer wording of an empty document, exit status and unchanged file agree"},
		{input{"zero_width_space_root", "accepted", "a document that is only U+200B: not white space for Go, a plain scalar", []byte("\u200b\n")},
			kindWording, textCommands, "same decode-layer wording gap as scalar_root: yaml.v3 says 'cannot unmarshal !!str `\u200b` into config.Config', the native loader 'invalid type: string'; exit status and the unchanged file agree"},
		// ADR 0034 item 6: yaml.v3 accepts 10000 nested collections, the native
		// config get/set (yaml_edit) refuse beyond 256. config validate and doctor
		// are not recorded: the native read path has no such limit.
		{input{"nesting_depth_257", "accepted", "257 nested flow sequences, all closed, one level past the native limit", nestedFlowSequence(257)},
			kindBehavior, []string{"get_nested", "set"}, nestingReason},
		{input{"nesting_depth_10000", "accepted", "10000 nested flow sequences, all closed: the deepest document yaml.v3 accepts", nestedFlowSequence(10000)},
			kindBehavior, []string{"get_nested", "set"}, nestingReason},
		{input{"nesting_depth_10001", "accepted", "10001 nested flow sequences: yaml.v3 refuses with its own depth error", nestedFlowSequence(10001)},
			kindWording, []string{"get_nested", "set"}, "both refuse the document with exit 6 and leave the file alone: yaml.v3 says 'yaml: exceeded max depth of 10000', the native yaml_edit parser 'Collection nested too deeply (limit 256)'; this entry records Go's upper limit"},
		// ADR 0034 item 9: the loader warning is printed once per config load.
		{input{"completion_loader_warnings", "accepted", "the deprecated envWhitelist key in the global config, read by shell completion", []byte("envWhitelist: [FOO]\n")},
			kindWording, []string{"complete_get", "completion_bash"}, "Go loads the global config at startup for __complete and for completion <shell> (the root's vault-path resolution), so the deprecation warning is printed twice for __complete get '' and once for completion bash; the native completion path loads only what the completer needs: once and not at all. Exit status and stdout are equal (completion bash is compared by its sha256)"},
	}
}

func hexOf(value []byte) string { return hex.EncodeToString(value) }

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
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("verify oracle: %v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/yamlsyntaxgen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}
	cases, err := buildCases(*goBinary)
	if err != nil {
		fatal("build cases: %v", err)
	}
	divergences, err := buildDivergences(*goBinary)
	if err != nil {
		fatal("build open divergences: %v", err)
	}
	warningCounts, err := buildLoaderWarningCounts(*goBinary)
	if err != nil {
		fatal("build loader warning counts: %v", err)
	}
	content, err := marshalJSON(fixture{
		SchemaVersion:       1,
		Oracle:              oracle{commitLabel, resolved, releaseLabel, sources, sourceDigest, generatorDigest},
		DoctorIDs:           doctorIDs,
		Cases:               cases,
		OpenDivergences:     divergences,
		LoaderWarningCounts: warningCounts,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	if *check {
		existing, err := os.ReadFile(*output)
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS config YAML syntax fixture (%d cases, %d open divergences)\n", len(cases), len(divergences))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases, %d open divergences)\n", *output, len(cases), len(divergences))
}

func buildCases(goBinary string) ([]fixtureCase, error) {
	all := inputs()
	cases := make([]fixtureCase, 0, len(all))
	for _, item := range all {
		built, err := buildCase(goBinary, item)
		if err != nil {
			return nil, err
		}
		cases = append(cases, built)
	}
	return cases, nil
}

// commandSpec is one config command whose Go output is recorded.
type commandSpec struct {
	name         string
	args         []string
	captureAfter bool
}

var commandSpecs = []commandSpec{
	{"validate", []string{"config", "validate", configMarker}, false},
	{"validate_json", []string{"config", "validate", configMarker, "--json"}, false},
	{"get", []string{"config", "get", "vaultDir", "--file", configMarker}, false},
	{"set", []string{"config", "set", "vaultDir", "changed", "--file", configMarker}, true},
}

// openOnlySpecs are recorded for open divergences only: the regular corpus
// keeps one `set` per case, these probe a nested key.
var openOnlySpecs = []commandSpec{
	{"set_nested", []string{"config", "set", "agents.x.canWrite", "true", "--file", configMarker}, true},
	{"get_nested", []string{"config", "get", "a", "--file", configMarker}, false},
}

// homeSpecs are recorded for open divergences only: commands that read the
// global config at ~/.symvault/config.yaml of the sandbox HOME and take no
// --file flag (shell completion).
var homeSpecs = []commandSpec{
	{"complete_get", []string{"__complete", "get", ""}, false},
	{"completion_bash", []string{"completion", "bash"}, false},
}

func lookupHomeSpec(name string) (commandSpec, bool) {
	for _, spec := range homeSpecs {
		if spec.name == name {
			return spec, true
		}
	}
	return commandSpec{}, false
}

func lookupSpec(name string) (commandSpec, bool) {
	for _, spec := range append(append([]commandSpec(nil), commandSpecs...), openOnlySpecs...) {
		if spec.name == name {
			return spec, true
		}
	}
	return commandSpec{}, false
}

func buildCase(goBinary string, item input) (fixtureCase, error) {
	built := fixtureCase{
		Name: item.name, Class: item.class, Description: item.description,
		ConfigHex: hexOf(item.config), ConfigText: strconv.Quote(string(item.config)),
	}
	for _, command := range commandSpecs {
		// `get` and `set` on an accepted document reach key lookup and file
		// rewriting, which are different contracts (yaml.v3 node editing); only
		// the failure path is in scope for those two commands.
		if (item.class == "accepted" || item.class == "loader") && (command.name == "get" || command.name == "set") {
			continue
		}
		observed, err := runConfigCommand(goBinary, item, command.name, command.args, command.captureAfter)
		if err != nil {
			return fixtureCase{}, err
		}
		built.Observations = append(built.Observations, observed)
	}
	if quietCases[item.name] {
		observed, err := runConfigCommand(goBinary, item, "validate_quiet", []string{"config", "validate", configMarker, "--quiet"}, false)
		if err != nil {
			return fixtureCase{}, err
		}
		built.Observations = append(built.Observations, observed)
	}
	doctor, err := runDoctor(goBinary, item)
	if err != nil {
		return fixtureCase{}, err
	}
	built.Doctor = doctor
	if agentListCases[item.name] {
		observed, err := runAgentList(goBinary, item)
		if err != nil {
			return fixtureCase{}, err
		}
		built.AgentList = &observed
	}
	if authMethodCases[item.name] {
		observed, err := runAuthMethod(goBinary, item)
		if err != nil {
			return fixtureCase{}, err
		}
		built.AuthMethod = &observed
	}
	return built, nil
}

// quietCases also record `config validate --quiet`: the deprecation warnings
// the loader prints are cliout.Warnf messages, and --quiet does not silence
// them (cliout reads QuietMode before cobra has parsed the persistent flag).
var quietCases = map[string]bool{
	"resid_warn_env_whitelist":                   true,
	"resid_warn_mcp_approval_required":           true,
	"resid_warn_clipboard_print_by_default":      true,
	"resid_warn_all_three":                       true,
	"resid_warn_then_loader_rejection":           true,
	"resid_warn_then_validation_error":           true,
	"resid_warn_mcp_approval_required_via_merge": true,
}

// authMethodCases also record the resolved top-level auth method, the value
// the vault merge feeds from a useTouchID the vault block did not write itself.
var authMethodCases = map[string]bool{
	"load_vault_use_touch_id_via_merge":              true,
	"load_vault_use_touch_id_via_merge_inline":       true,
	"load_vault_use_touch_id_merged_then_overridden": true,
}

// agentListCases are the failures that also record `agent list`, a loader
// caller outside the config and doctor commands (`load config: <error>`).
var agentListCases = map[string]bool{
	"mapping_value_nested":         true,
	"flow_sequence_unterminated":   true,
	"control_character":            true,
	"multiple_documents":           true,
	"unknown_anchor_value":         true,
	"agents_scalar":                true,
	"alias_value_for_string_field": true,
	// A normal command that loads the config reports the loader's error bare
	// behind `load config:`.
	"load_prompt_injection_mode_invalid":  true,
	"load_approval_mode_invalid":          true,
	"load_audit_max_size_mb_string":       true,
	"load_logging_level_sequence":         true,
	"load_session_timeout_zero":           true,
	"load_session_durations_both_invalid": true,
	"load_mcp_bind_empty":                 true,
	// CONFIG-SECTIONS-001: loader callers outside the config commands.
	"load_approval_mode_integer":              true,
	"load_default_agent_hex":                  true,
	"load_agent_string_pointers_non_string":   true,
	"load_agent_int_pointers":                 true,
	"load_agent_null_pointers":                true,
	"load_agent_null_items_dropped":           true,
	"load_agent_profile_null":                 true,
	"load_agent_negative_approval_timeout":    true,
	"load_agent_approval_timeout_integer":     true,
	"load_agent_bool_pointers_yaml11":         true,
	"load_agent_merged_prompt_injection_mode": true,
	"load_agent_merged_approval_mode_ignored": true,
	"load_mcp_port_overflow":                  true,
	"load_mcp_bind_null":                      true,
	// The loader's own bookkeeping must not swallow an agent named NUL+own.
	"load_agent_name_nul_own": true,
	// CONFIG-RESID: the deprecation warnings reach every command that loads
	// the config, `agent list` included, and a rejected audit/payment config
	// is not a load error there (agent list does not validate).
	"resid_warn_env_whitelist":                    true,
	"resid_warn_env_whitelist_empty":              true,
	"resid_warn_env_whitelist_null":               true,
	"resid_warn_mcp_approval_required":            true,
	"resid_warn_mcp_approval_required_false":      true,
	"resid_warn_mcp_approval_required_via_merge":  true,
	"resid_warn_clipboard_print_by_default":       true,
	"resid_warn_clipboard_print_by_default_false": true,
	"resid_warn_clipboard_copy_by_default_wins":   true,
	"resid_warn_all_three":                        true,
	"resid_warn_then_loader_rejection":            true,
	"resid_warn_then_validation_error":            true,
	"resid_warn_not_when_decode_fails":            true,
	"load_audit_max_size_mb_null":                 true,
	"resid_payment_policy_null_entry":             true,
}

func buildDivergences(goBinary string) ([]openDivergence, error) {
	var divergences []openDivergence
	for _, entry := range openInputs() {
		recorded := openDivergence{
			Name: entry.name, Description: entry.description, Kind: entry.kind, Reason: entry.reason,
			ConfigHex: hexOf(entry.config), ConfigText: strconv.Quote(string(entry.config)),
		}
		for _, name := range entry.commands {
			if name == "doctor" {
				doctor, err := runDoctor(goBinary, entry.input)
				if err != nil {
					return nil, err
				}
				recorded.Doctor = &doctor
				continue
			}
			if name == "agent_list" {
				observed, err := runAgentList(goBinary, entry.input)
				if err != nil {
					return nil, err
				}
				recorded.AgentList = &observed
				continue
			}
			if home, ok := lookupHomeSpec(name); ok {
				observed, err := runHomeCommand(goBinary, entry.input, home)
				if err != nil {
					return nil, err
				}
				recorded.Observations = append(recorded.Observations, observed)
				continue
			}
			spec, ok := lookupSpec(name)
			if !ok {
				return nil, fmt.Errorf("open divergence %s: unknown command %q", entry.name, name)
			}
			observed, err := runConfigCommand(goBinary, entry.input, spec.name, spec.args, spec.captureAfter)
			if err != nil {
				return nil, err
			}
			recorded.Observations = append(recorded.Observations, observed)
		}
		divergences = append(divergences, recorded)
	}
	return divergences, nil
}

// sandbox is one disposable HOME/XDG tree. Nothing from the operator's
// environment is inherited except PATH.
type sandbox struct {
	root string
	env  []string
}

func newSandbox() (*sandbox, error) {
	root, err := os.MkdirTemp("", "yamlsyntaxgen-")
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

func (s *sandbox) close() error { return os.RemoveAll(s.root) }

// normalize replaces the sandbox root, in both its lexical and symlink-resolved
// spellings, so recorded text is machine independent.
func (s *sandbox) normalize(raw []byte) (string, error) {
	text := string(raw)
	if !isUTF8(raw) {
		return "", errors.New("oracle output is not valid UTF-8")
	}
	roots := []string{s.root}
	if resolved, err := filepath.EvalSymlinks(s.root); err == nil && resolved != s.root {
		roots = append([]string{resolved}, roots...)
	}
	for _, root := range roots {
		text = strings.ReplaceAll(text, filepath.Join(root, "vault", "config.yaml"), vaultMarker+"/config.yaml")
		text = strings.ReplaceAll(text, filepath.Join(root, "vault"), vaultMarker)
		text = strings.ReplaceAll(text, filepath.Join(root, "config.yaml"), configMarker)
		text = strings.ReplaceAll(text, root, rootMarker)
	}
	return text, nil
}

func isUTF8(raw []byte) bool { return strings.ToValidUTF8(string(raw), "\x00?") == string(raw) }

func runConfigCommand(goBinary string, item input, name string, argTemplate []string, captureAfter bool) (observation, error) {
	box, err := newSandbox()
	if err != nil {
		return observation{}, err
	}
	configPath := filepath.Join(box.root, "config.yaml")
	if setupErr := os.WriteFile(configPath, item.config, 0o600); setupErr != nil {
		return observation{}, errors.Join(setupErr, box.close())
	}
	args := replaceArgs(argTemplate, configMarker, configPath)
	code, stdout, stderr, err := runOracle(goBinary, box, args)
	if err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s %s: %w", item.name, name, err), box.close())
	}
	result := observation{Command: name, Args: argTemplate, ExitCode: code}
	if result.Stdout, err = box.normalize(stdout); err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s %s stdout: %w", item.name, name, err), box.close())
	}
	if result.Stderr, err = box.normalize(stderr); err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s %s stderr: %w", item.name, name, err), box.close())
	}
	if captureAfter {
		// #nosec G304 -- fixed path under this case's private sandbox.
		after, readErr := os.ReadFile(configPath)
		if readErr != nil {
			return observation{}, errors.Join(readErr, box.close())
		}
		unchanged := bytes.Equal(after, item.config)
		result.Unchanged = &unchanged
	}
	return result, box.close()
}

// runHomeCommand records a command that reads the global config of the sandbox
// HOME (~/.symvault/config.yaml) and no vault: the case's bytes are that file.
// The output of `completion` is the generated script, recorded as its sha256.
func runHomeCommand(goBinary string, item input, spec commandSpec) (observation, error) {
	box, err := newSandbox()
	if err != nil {
		return observation{}, err
	}
	global := filepath.Join(box.root, "home", ".symvault")
	if setupErr := os.MkdirAll(global, 0o700); setupErr != nil {
		return observation{}, errors.Join(setupErr, box.close())
	}
	if setupErr := os.WriteFile(filepath.Join(global, "config.yaml"), item.config, 0o600); setupErr != nil {
		return observation{}, errors.Join(setupErr, box.close())
	}
	code, stdout, stderr, err := runOracle(goBinary, box, spec.args)
	if err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s %s: %w", item.name, spec.name, err), box.close())
	}
	result := observation{Command: spec.name, Args: spec.args, ExitCode: code}
	if spec.name == "completion_bash" {
		sum := sha256.Sum256(stdout)
		result.Stdout = "sha256:" + hex.EncodeToString(sum[:])
	} else if result.Stdout, err = box.normalize(stdout); err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s %s stdout: %w", item.name, spec.name, err), box.close())
	}
	if result.Stderr, err = box.normalize(stderr); err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s %s stderr: %w", item.name, spec.name, err), box.close())
	}
	return result, box.close()
}

// runAgentList records `agent list` against a vault directory whose
// config.yaml holds the case's bytes.
func runAgentList(goBinary string, item input) (observation, error) {
	box, err := newSandbox()
	if err != nil {
		return observation{}, err
	}
	vault := filepath.Join(box.root, "vault")
	if setupErr := os.MkdirAll(vault, 0o700); setupErr != nil {
		return observation{}, errors.Join(setupErr, box.close())
	}
	if setupErr := os.WriteFile(filepath.Join(vault, "config.yaml"), item.config, 0o600); setupErr != nil {
		return observation{}, errors.Join(setupErr, box.close())
	}
	template := []string{"--vault", vaultMarker, "agent", "list"}
	code, stdout, stderr, err := runOracle(goBinary, box, replaceArgs(template, vaultMarker, vault))
	if err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s agent list: %w", item.name, err), box.close())
	}
	result := observation{Command: "agent_list", Args: template, ExitCode: code}
	if result.Stdout, err = box.normalize(stdout); err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s agent list stdout: %w", item.name, err), box.close())
	}
	if result.Stderr, err = box.normalize(stderr); err != nil {
		return observation{}, errors.Join(fmt.Errorf("case %s agent list stderr: %w", item.name, err), box.close())
	}
	return result, box.close()
}

// runAuthMethod records the `Auth method:` line of `auth status` against a
// vault directory whose config.yaml holds the case's bytes (and an empty
// identity.age).
func runAuthMethod(goBinary string, item input) (authObservation, error) {
	box, err := newSandbox()
	if err != nil {
		return authObservation{}, err
	}
	vault := filepath.Join(box.root, "vault")
	if setupErr := os.MkdirAll(vault, 0o700); setupErr != nil {
		return authObservation{}, errors.Join(setupErr, box.close())
	}
	if setupErr := os.WriteFile(filepath.Join(vault, "config.yaml"), item.config, 0o600); setupErr != nil {
		return authObservation{}, errors.Join(setupErr, box.close())
	}
	// `auth status` refuses a vault without an identity file; its content is
	// never read.
	if setupErr := os.WriteFile(filepath.Join(vault, "identity.age"), nil, 0o600); setupErr != nil {
		return authObservation{}, errors.Join(setupErr, box.close())
	}
	template := []string{"--vault", vaultMarker, "auth", "status"}
	code, stdout, stderr, err := runOracle(goBinary, box, replaceArgs(template, vaultMarker, vault))
	if err != nil {
		return authObservation{}, errors.Join(fmt.Errorf("case %s auth status: %w", item.name, err), box.close())
	}
	result := authObservation{Args: template, ExitCode: code}
	for _, line := range strings.Split(string(stdout), "\n") {
		if method, ok := strings.CutPrefix(line, "Auth method: "); ok {
			result.Method = method
		}
	}
	if code != 0 || result.Method == "" {
		return authObservation{}, errors.Join(fmt.Errorf("case %s auth status: exit %d, stdout %q, stderr %q", item.name, code, stdout, stderr), box.close())
	}
	return result, box.close()
}

func runDoctor(goBinary string, item input) (doctorObservation, error) {
	box, err := newSandbox()
	if err != nil {
		return doctorObservation{}, err
	}
	vault := filepath.Join(box.root, "vault")
	if setupErr := os.MkdirAll(vault, 0o700); setupErr != nil {
		return doctorObservation{}, errors.Join(setupErr, box.close())
	}
	if setupErr := os.WriteFile(filepath.Join(vault, "config.yaml"), item.config, 0o600); setupErr != nil {
		return doctorObservation{}, errors.Join(setupErr, box.close())
	}
	template := []string{"--vault", vaultMarker, "doctor", "--only", strings.Join(doctorIDs, ","), "--json", "--no-network"}
	code, stdout, stderr, err := runOracle(goBinary, box, replaceArgs(template, vaultMarker, vault))
	if err != nil {
		return doctorObservation{}, errors.Join(fmt.Errorf("case %s doctor: %w", item.name, err), box.close())
	}
	var payload struct {
		Results []doctorResult `json:"results"`
	}
	if err := json.Unmarshal(stdout, &payload); err != nil {
		return doctorObservation{}, errors.Join(fmt.Errorf("case %s doctor JSON: %w (stderr %q)", item.name, err, stderr), box.close())
	}
	selected := make([]doctorResult, 0, len(doctorIDs))
	for _, id := range doctorIDs {
		found := false
		for _, result := range payload.Results {
			if result.ID != id {
				continue
			}
			message, mErr := box.normalize([]byte(result.Message))
			hint, hErr := box.normalize([]byte(result.Hint))
			if mErr != nil || hErr != nil {
				return doctorObservation{}, errors.Join(errors.Join(mErr, hErr), box.close())
			}
			result.Message, result.Hint = message, hint
			selected = append(selected, result)
			found = true
			break
		}
		if !found {
			return doctorObservation{}, errors.Join(fmt.Errorf("case %s: doctor did not report %s", item.name, id), box.close())
		}
	}
	return doctorObservation{Args: template, ExitCode: code, Results: selected}, box.close()
}

func runOracle(goBinary string, box *sandbox, args []string) (int, []byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// #nosec G204 -- validateGoBinary checked the pinned, clean oracle before this command.
	cmd := exec.CommandContext(ctx, goBinary, args...)
	cmd.Dir = box.root
	cmd.Env = box.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return 0, nil, nil, ctx.Err()
	}
	code := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return 0, nil, nil, runErr
		}
		code = exitErr.ExitCode()
	}
	return code, stdout.Bytes(), stderr.Bytes(), nil
}

func replaceArgs(args []string, marker, value string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = strings.ReplaceAll(arg, marker, value)
	}
	return out
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

// loaderWarningRun is one ordinary command whose stderr is counted for the
// `envWhitelist is deprecated` line.
type loaderWarningRun struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	// Layout is where the vault lives: "vault_env" selects it through
	// SYMVAULT_VAULT (the global config is never read to find it),
	// "legacy_default" is the existing ~/.symvault directory, whose config.yaml
	// is the global config and the vault config at once.
	Layout string `json:"layout"`
	// GoMin and GoMax bound the count over repeated runs. They differ only
	// where Go builds the in-memory search index on a goroutine that may not
	// finish before the process exits (`go_race`); the generator fails when a
	// run falls outside them.
	GoMin int `json:"go_min"`
	GoMax int `json:"go_max"`
	// GoRace names the optional goroutine read when GoMax > GoMin.
	GoRace string `json:"go_race,omitempty"`
	// GoSites are the config reads that print, in order, from an
	// instrumented build of the pinned sources (runtime.Callers in warnf);
	// they document the bounds and are not measured by the generator.
	GoSites []string `json:"go_sites"`
}

type loaderWarningCounts struct {
	Note   string             `json:"note"`
	Runs   int                `json:"runs_per_case"`
	Config string             `json:"config"`
	Cases  []loaderWarningRun `json:"cases"`
}

const (
	siteRootPreRun   = "internal/cli.NewRootCmd PersistentPreRunE (cli.go:289) -> VaultPath -> config.Load(global config) [reads only when the vault is not given by --vault/SYMVAULT_VAULT]"
	siteOwnVaultPath = "the command's own VaultPath (WithVault/WithVaultRaw/WithVaultForScripting or the command body) -> config.Load(global config) [same condition]"
	siteResolve      = "internal/cli.resolveConfig (unlockVault) -> config.Load(vault config)"
	siteOpen         = "internal/vault.Open (OpenWithPassphrase) -> config.Load(vault config)"
	siteOpList       = "internal/vault.List -> listWithBudget -> loadVaultConfig -> config.Load(vault config)"
	siteOpGet        = "internal/vault.ReadEntry -> readEntryInner -> loadVaultConfig -> config.Load(vault config)"
	siteOpFind       = "internal/vault.FindWithOptions -> listWithBudget -> loadVaultConfig -> config.Load(vault config)"
	siteOpVerify     = "internal/vault.VerifyManifestIntegrity -> loadVaultConfig -> config.Load(vault config)"
	siteRace         = "internal/vault.EncryptedIndex.BuildMemoryOnly -> buildIndex -> listWithBudget -> loadVaultConfig -> config.Load(vault config), on a goroutine: printed only when it finishes before the process exits"
)

func loaderWarningTable() []loaderWarningRun {
	unlock := []string{siteResolve, siteOpen}
	vaultEnv := func(command string, args []string, min, max int, race string, sites ...string) loaderWarningRun {
		return loaderWarningRun{Command: command, Args: args, Layout: "vault_env", GoMin: min, GoMax: max, GoRace: race, GoSites: sites}
	}
	legacy := func(command string, args []string, min, max int, race string, sites ...string) loaderWarningRun {
		return loaderWarningRun{Command: command, Args: args, Layout: "legacy_default", GoMin: min, GoMax: max, GoRace: race, GoSites: sites}
	}
	global := []string{siteRootPreRun, siteOwnVaultPath}
	join := func(parts ...[]string) []string {
		var out []string
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	op := func(site string) []string { return []string{site} }
	return []loaderWarningRun{
		vaultEnv("list", []string{"list"}, 3, 4, siteRace, join(unlock, op(siteOpList))...),
		legacy("list", []string{"list"}, 5, 6, siteRace, join(global, unlock, op(siteOpList))...),
		vaultEnv("get", []string{"get", "demo/entry.password", "--print"}, 3, 4, siteRace, join(unlock, op(siteOpGet))...),
		legacy("get", []string{"get", "demo/entry.password", "--print"}, 5, 6, siteRace, join(global, unlock, op(siteOpGet))...),
		vaultEnv("find", []string{"find", "demo"}, 3, 4, siteRace, join(unlock, op(siteOpFind))...),
		legacy("find", []string{"find", "demo"}, 5, 6, siteRace, join(global, unlock, op(siteOpFind))...),
		vaultEnv("verify", []string{"verify"}, 3, 4, siteRace, join(unlock, op(siteOpVerify))...),
		legacy("verify", []string{"verify"}, 5, 6, siteRace, join(global, unlock, op(siteOpVerify))...),
		vaultEnv("recipients list", []string{"recipients", "list"}, 0, 0, ""),
		legacy("recipients list", []string{"recipients", "list"}, 2, 2, "", global...),
		vaultEnv("lock", []string{"lock"}, 0, 0, ""),
		legacy("lock", []string{"lock"}, 2, 2, "", global...),
		vaultEnv("generate", []string{"generate"}, 0, 0, ""),
		legacy("generate", []string{"generate"}, 1, 1, "", siteRootPreRun),
		// agent list is annotated requires-vault=false: no PreRun read, and
		// the command loads its own config twice in the legacy layout.
		vaultEnv("agent list", []string{"agent", "list"}, 1, 1, "", "cmd/mcp.newAgentListCmd -> config.Load(vault config)"),
		legacy("agent list", []string{"agent", "list"}, 2, 2, "", "cmd/mcp.newAgentListCmd -> config.Load(global config)", "cmd/mcp.newAgentListCmd -> config.Load(vault config)"),
	}
}

const loaderWarningRuns = 8

func buildLoaderWarningCounts(goBinary string) (loaderWarningCounts, error) {
	out := loaderWarningCounts{
		Note:   "Number of `envWhitelist is deprecated ...` lines on stderr for one run of the command, with `envWhitelist: [a]` appended to the vault config after the vault was initialized and one entry added. Go re-reads config.yaml at every seam listed in go_sites and every read warns; the per-operation reads (vault.List, ReadEntry, FindWithOptions, VerifyManifestIntegrity) and the second global read are incidental to Go's structure. Counts are bounds over repeated runs, not single observations.",
		Runs:   loaderWarningRuns,
		Config: "envWhitelist: [a]\n",
	}
	for _, row := range loaderWarningTable() {
		for run := 0; run < loaderWarningRuns; run++ {
			count, err := countLoaderWarnings(goBinary, row)
			if err != nil {
				return out, err
			}
			if count < row.GoMin || count > row.GoMax {
				return out, fmt.Errorf("%s (%s) printed the envWhitelist warning %d times, outside the declared bounds [%d, %d]", row.Command, row.Layout, count, row.GoMin, row.GoMax)
			}
		}
		if row.GoSites == nil {
			row.GoSites = []string{}
		}
		out.Cases = append(out.Cases, row)
	}
	return out, nil
}

// countLoaderWarnings builds a fresh vault with the oracle, appends the
// deprecated key to its config and counts the warning lines of one run.
func countLoaderWarnings(goBinary string, row loaderWarningRun) (int, error) {
	box, err := newSandbox()
	if err != nil {
		return 0, err
	}
	home := filepath.Join(box.root, "home")
	vault := filepath.Join(home, "vault")
	box.env = append(box.env,
		"SYMVAULT_PASSPHRASE=loader-warning-count", "SYMVAULT_ALLOW_ENV_PASSPHRASE=1", "SYMVAULT_TEST_KEYRING=memory")
	args := []string{"init"}
	switch row.Layout {
	case "vault_env":
		args = append(args, vault)
		box.env = append(box.env, "SYMVAULT_VAULT="+vault)
	case "legacy_default":
		vault = filepath.Join(home, ".symvault")
		if mkErr := os.MkdirAll(vault, 0o700); mkErr != nil {
			return 0, errors.Join(mkErr, box.close())
		}
	default:
		return 0, errors.Join(fmt.Errorf("unknown layout %q", row.Layout), box.close())
	}
	for _, step := range [][]string{args, {"add", "demo/entry", "--value", "demo-value-1234"}} {
		code, _, stderr, runErr := runOracle(goBinary, box, step)
		if runErr != nil || code != 0 {
			return 0, errors.Join(fmt.Errorf("setup %v: exit %d %v %q", step, code, runErr, stderr), box.close())
		}
	}
	configPath := filepath.Join(vault, "config.yaml")
	// #nosec G304 G302 -- fixed path inside this case's private sandbox.
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, errors.Join(err, box.close())
	}
	if _, werr := f.WriteString("envWhitelist: [a]\n"); werr != nil {
		return 0, errors.Join(werr, f.Close(), box.close())
	}
	if cerr := f.Close(); cerr != nil {
		return 0, errors.Join(cerr, box.close())
	}
	code, _, stderr, err := runOracle(goBinary, box, row.Args)
	if err != nil {
		return 0, errors.Join(err, box.close())
	}
	if code != 0 {
		return 0, errors.Join(fmt.Errorf("%s exited %d: %q", row.Command, code, stderr), box.close())
	}
	count := strings.Count(string(stderr), "envWhitelist is deprecated and will be removed in a future version; use envAllowlist instead\n")
	return count, box.close()
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
