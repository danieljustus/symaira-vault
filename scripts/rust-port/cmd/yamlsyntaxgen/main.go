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

type fixtureCase struct {
	Name         string            `json:"name"`
	Class        string            `json:"class"`
	Description  string            `json:"description"`
	ConfigHex    string            `json:"config_hex"`
	ConfigText   string            `json:"config_text"`
	Observations []observation     `json:"observations"`
	Doctor       doctorObservation `json:"doctor"`
	AgentList    *observation      `json:"agent_list,omitempty"`
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
}

type input struct {
	name, class, description string
	config                   []byte
}

// inputs lists the corpus. class is the libyaml stage that rejects the input
// ("scanner", "parser", "reader"), "node" for yaml.v3's own node builder (an
// alias to an anchor that was never defined; libyaml accepts it), "loader" for
// the loader's own multi-document rejection, or "accepted" for an input the
// loader must keep accepting.
func inputs() []input {
	return []input{
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

var (
	allCommands  = []string{"validate", "validate_json", "get", "set", "doctor"}
	textCommands = []string{"validate", "get", "set", "doctor"}
)

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
		{input{"alias_value_for_string_field", "accepted", "an alias to a scalar anchor used as the value of a string field", []byte("a: &x 1\nvaultDir: *x\n")},
			kindBehavior, []string{"validate", "set_nested", "doctor", "agent_list"}, "yaml.v3 decodes the alias into the string field and accepts the config (so validate, doctor and agent list succeed and config set of a nested key succeeds); the native loader reads the alias through serde_yaml_ng and rejects 'vaultDir must be a string', and config set writes the file before that post-update load fails"},
		{input{"custom_tag_on_value", "accepted", "a local tag on a plain scalar", []byte("a: !t x\n")},
			kindBehavior, textCommands, "yaml.v3 ignores a local tag it does not know and decodes the value; serde_yaml_ng keeps it as a tagged value that the native loader rejects"},
		// yaml.v3 decode and node layers, not syntax errors.
		{input{"scalar_root", "accepted", "a document that is a single scalar", []byte("just a scalar\n")},
			kindWording, append(append([]string(nil), textCommands...), "set_nested", "agent_list"), "the failure comes from yaml.v3's decoder and node layers, not from libyaml: validate says 'yaml: unmarshal errors: line 1: cannot unmarshal !!str `just a ...` into config.Config', get 'parent is a scalar node, not a mapping', set 'root node is a scalar, not a mapping'; the native CLI fails the same commands with the same exit status and leaves the file alone, with different text"},
		{input{"sequence_root", "accepted", "a document that is a block sequence", []byte("- 1\n- 2\n")},
			kindWording, append(append([]string(nil), textCommands...), "set_nested", "agent_list"), "yaml.v3 decoder and node layers again: 'cannot unmarshal !!seq into config.Config', 'parent is a sequence node, not a mapping', 'root node is a sequence, not a mapping'; same exit status and unchanged file natively, different text"},
		{input{"agents_scalar", "accepted", "a scalar where the agents mapping belongs", []byte("agents: x\n")},
			kindWording, append(append([]string(nil), textCommands...), "agent_list"), "yaml.v3 decode error 'cannot unmarshal !!str `x` into map[string]config.AgentProfile'; get reports the key text differently, and set rewrites the file before the post-update load fails on both sides"},
		{input{"null_root", "accepted", "a document that is the scalar null", []byte("null\n")},
			kindWording, []string{"get", "set"}, "validate agrees (defaults); get and set fail on both sides with exit 6 and an unchanged file, Go with 'parent is a scalar node, not a mapping' and 'root node is a scalar, not a mapping', the native CLI with 'key \"vaultDir\" not found' and 'document has no root to descend into'"},
		{input{"comment_only", "accepted", "a config that contains only a comment", []byte("# nothing\n")},
			kindWording, []string{"get", "set"}, "validate agrees (defaults); get and set fail on both sides with exit 6 and an unchanged file, Go with 'parent is a unknown(0) node, not a mapping' and 'root node is a unknown(0), not a mapping', the native CLI with 'cannot load config: missing YAML document'"},
		{input{"document_start_only", "accepted", "a config that is only a document start marker", []byte("---\n")},
			kindWording, []string{"get", "set"}, "validate agrees (defaults); get and set fail on both sides with exit 6 and an unchanged file, Go with the scalar-node wording of null_root"},
		{input{"empty_flow_mapping_root", "accepted", "a document that is an empty flow mapping", []byte("{}\n")},
			kindWording, []string{"get"}, "validate agrees; config get fails on both sides with exit 6, Go with `key \"vaultDir\" not found: key \"vaultDir\" not found` (the cause is appended), the native CLI with the bare message"},
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
	content, err := marshalJSON(fixture{
		SchemaVersion:   1,
		Oracle:          oracle{commitLabel, resolved, releaseLabel, sources, sourceDigest, generatorDigest},
		DoctorIDs:       doctorIDs,
		Cases:           cases,
		OpenDivergences: divergences,
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
	return built, nil
}

// agentListCases are the failures that also record `agent list`, a loader
// caller outside the config and doctor commands (`load config: <error>`).
var agentListCases = map[string]bool{
	"mapping_value_nested":       true,
	"flow_sequence_unterminated": true,
	"control_character":          true,
	"multiple_documents":         true,
	"unknown_anchor_value":       true,
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
	if err := os.WriteFile(configPath, item.config, 0o600); err != nil {
		return observation{}, errors.Join(err, box.close())
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

// runAgentList records `agent list` against a vault directory whose
// config.yaml holds the case's bytes.
func runAgentList(goBinary string, item input) (observation, error) {
	box, err := newSandbox()
	if err != nil {
		return observation{}, err
	}
	vault := filepath.Join(box.root, "vault")
	if err := os.MkdirAll(vault, 0o700); err != nil {
		return observation{}, errors.Join(err, box.close())
	}
	if err := os.WriteFile(filepath.Join(vault, "config.yaml"), item.config, 0o600); err != nil {
		return observation{}, errors.Join(err, box.close())
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

func runDoctor(goBinary string, item input) (doctorObservation, error) {
	box, err := newSandbox()
	if err != nil {
		return doctorObservation{}, err
	}
	vault := filepath.Join(box.root, "vault")
	if err := os.MkdirAll(vault, 0o700); err != nil {
		return doctorObservation{}, errors.Join(err, box.close())
	}
	if err := os.WriteFile(filepath.Join(vault, "config.yaml"), item.config, 0o600); err != nil {
		return doctorObservation{}, errors.Join(err, box.close())
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
