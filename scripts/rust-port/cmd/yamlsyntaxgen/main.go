// Command yamlsyntaxgen freezes the pinned Go CLI's rendering of config.yaml
// syntax failures (CLI-005: the go-yaml scanner/parser/reader error dialect).
//
// Every case is a config.yaml whose bytes the go-yaml (gopkg.in/yaml.v3)
// scanner, parser or reader rejects. The pinned Go binary is run over the same
// five commands that surface the failure — `config validate`, `config validate
// --json`, `config get`, `config set` and the five `doctor` checks that load the
// config — and its exit status, stdout and stderr are recorded byte for byte.
// The Rust integration test replays the identical cases against the native CLI.
//
// Expected output always comes from the pinned Go binary; nothing is derived
// from the Rust side. A small `open_divergences` list records inputs on which
// the two YAML implementations are known to differ in more than wording, so the
// gap stays explicit instead of being dropped from the corpus.
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
}

type openDivergence struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Reason      string      `json:"reason"`
	ConfigHex   string      `json:"config_hex"`
	ConfigText  string      `json:"config_text"`
	Validate    observation `json:"validate"`
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
// ("scanner", "parser", "reader"), "loader" for the loader's own multi-document
// rejection, or "accepted" for a control the parser must keep accepting.
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
	}
}

// openInputs are inputs on which the Go and Rust YAML front ends disagree in
// more than wording. They are recorded from the same Go binary so the gap is
// pinned rather than hidden.
func openInputs() []struct {
	input
	reason string
} {
	type entry = struct {
		input
		reason string
	}
	return []entry{
		{input{"directive_without_document_start", "scanner", "content after a %YAML directive with no --- line", []byte("%YAML 1.1\na: 1\n")},
			"yaml.v3 reports a scanner error on line 2 (mapping values are not allowed) where libyaml reports the parser error 'did not find expected <document start>'"},
		{input{"utf16_bom_only", "reader", "a lone UTF-16LE byte order mark", []byte("\xff\xfe")},
			"yaml.v3 decodes UTF-16 and accepts the empty stream; libyaml in serde_yaml_ng rejects the stream as invalid UTF-8"},
		{input{"bom_after_first_line", "scanner", "a UTF-8 byte order mark at the start of a later line", []byte("a: 1\n\xef\xbb\xbfb: 2\n")},
			"yaml.v3 skips the mark and accepts the stream; libyaml counts it as a column and rejects the mapping key"},
		{input{"second_document_syntax_error", "parser", "a syntax error in the second document of the stream", []byte("a: 1\n---\n[\n")},
			"Go reads only the first document and treats an unreadable second one as absent; the Rust loader rejects the stream as multi-document"},
		{input{"unknown_anchor", "parser", "alias to an anchor that was never defined", []byte("a: *nope\n")},
			"yaml.v3 words this as \"unknown anchor 'nope' referenced\" at the decoder; serde_yaml_ng reports 'unknown anchor' with a mark and no name"},
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

func buildCase(goBinary string, item input) (fixtureCase, error) {
	commands := []struct {
		name      string
		args      []string
		captureAt bool
	}{
		{"validate", []string{"config", "validate", configMarker}, false},
		{"validate_json", []string{"config", "validate", configMarker, "--json"}, false},
		{"get", []string{"config", "get", "vaultDir", "--file", configMarker}, false},
		{"set", []string{"config", "set", "vaultDir", "changed", "--file", configMarker}, true},
	}
	built := fixtureCase{
		Name: item.name, Class: item.class, Description: item.description,
		ConfigHex: hexOf(item.config), ConfigText: strconv.Quote(string(item.config)),
	}
	for _, command := range commands {
		// `get` and `set` on an accepted document reach key lookup and file
		// rewriting, which are different contracts (yaml.v3 node editing); only
		// the syntax-failure path is in scope for those two commands.
		if (item.class == "accepted" || item.class == "loader") && (command.name == "get" || command.name == "set") {
			continue
		}
		observed, err := runConfigCommand(goBinary, item, command.name, command.args, command.captureAt)
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
	return built, nil
}

func buildDivergences(goBinary string) ([]openDivergence, error) {
	var divergences []openDivergence
	for _, entry := range openInputs() {
		observed, err := runConfigCommand(goBinary, entry.input, "validate", []string{"config", "validate", configMarker}, false)
		if err != nil {
			return nil, err
		}
		divergences = append(divergences, openDivergence{
			Name: entry.name, Description: entry.description, Reason: entry.reason,
			ConfigHex: hexOf(entry.config), ConfigText: strconv.Quote(string(entry.config)),
			Validate: observed,
		})
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
