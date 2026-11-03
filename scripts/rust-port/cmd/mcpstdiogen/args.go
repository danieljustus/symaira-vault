package main

// MCP-004 / ADR 0034 item 15: how the oracle decodes tools/call `arguments`.
//
// The frame keeps `arguments` as a json.RawMessage; executeTool later runs
// json.Unmarshal(args, &map[string]any) BEFORE it looks the tool up. That makes
// the decode observable in two ways at the transport boundary: a decode error
// is `-32603 parse arguments: json: ...`, and an accepted decode continues to
// the tool (here generate_template --dry-run, whose masked output shows which
// duplicate member, key spelling and rune survived).
//
// A tool needs a real Server, and the working tree's server package has moved
// since the pinned oracle (server_dispatch.go, tool_registry.go), so the
// byte-for-byte provenance check used for the other sections cannot cover it.
// Instead the pinned commit is extracted with `git archive` (immutable object
// contents) and argsprobe/main.go is run INSIDE that extraction, so the bytes
// recorded here are produced by the oracle's own code.

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	argsProbeSource = "scripts/rust-port/cmd/mcpstdiogen/argsprobe/main.go"
	// The extraction needs only the module files and the packages the probe
	// imports; everything else in the repository is irrelevant to the decode.
	argsOracleRoots = "go.mod go.sum internal pkg"
)

// argsHandshake is sent before every probe frame; its single response (the
// initialize result) is dropped from the recorded stream.
const argsHandshake = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}` + "\n" +
	`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"

// argsNonce matches the random per-call data-fence id of an embedded result.
var argsNonce = regexp.MustCompile(`DATA_[0-9a-f]{16}`)

const argsNonceMask = "DATA_<nonce>"

// argsProbe describes one frame by shape so a deep payload is rebuilt from the
// description instead of being embedded.
type argsProbe struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	// Frame = FramePrefix + Fill*FillCount + Leaf + Close*CloseCount +
	// FrameSuffix + "\n".
	FramePrefix string `json:"frame_prefix"`
	Fill        string `json:"fill"`
	FillCount   int    `json:"fill_count"`
	Leaf        string `json:"leaf"`
	Close       string `json:"close"`
	CloseCount  int    `json:"close_count"`
	FrameSuffix string `json:"frame_suffix"`
	// StdoutAfterInitialize is every byte the oracle wrote for the probe frame
	// (the initialize response is dropped), with the random data-fence id
	// replaced by argsNonceMask.
	StdoutAfterInitialize string `json:"stdout_after_initialize"`
}

func (p argsProbe) input() string {
	return argsHandshake + p.FramePrefix + strings.Repeat(p.Fill, p.FillCount) + p.Leaf +
		strings.Repeat(p.Close, p.CloseCount) + p.FrameSuffix + "\n"
}

type argsSection struct {
	Handshake string `json:"handshake"`
	// OracleCommitSHA is the object `git archive` extracted; ProbeDigest is the
	// digest of the program that ran inside it.
	OracleCommitSHA string      `json:"oracle_commit_sha"`
	ExtractedRoots  string      `json:"extracted_roots"`
	ProbeSource     string      `json:"probe_source"`
	ProbeDigest     string      `json:"probe_digest"`
	NonceMask       string      `json:"nonce_mask"`
	Probes          []argsProbe `json:"probes"`
}

// callFrame builds a tools/call frame around the members of params.
func callFrame(paramsMembers string) (prefix, suffix string) {
	return `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{` + paramsMembers, `}}`
}

const tmplHead = `"name":"generate_template","arguments":`

// tmplBase is a dry-run k8s-secret render with one alias.
const tmplBase = `"template_type":"k8s-secret","name":"demo","secret_refs":{"A":"x.y"},"dry_run":true`

func plainArgs(name, why, arguments string) argsProbe {
	prefix, suffix := callFrame(tmplHead + arguments)
	return argsProbe{Name: name, Why: why, FramePrefix: prefix, FrameSuffix: suffix}
}

func rawParams(name, why, members string) argsProbe {
	prefix, suffix := callFrame(members)
	return argsProbe{Name: name, Why: why, FramePrefix: prefix, FrameSuffix: suffix}
}

// deepArgs nests `fill` count times inside the member "x" of an otherwise valid
// dry-run render: arguments = {<base>,"x":<fill*count><close*count>}. The total
// frame depth is 3 (frame, params, arguments) + count.
func deepArgs(name, why, fill, leaf, closeRune string, count int) argsProbe {
	prefix, suffix := callFrame(tmplHead + `{` + tmplBase + `,"x":`)
	return argsProbe{
		Name: name, Why: why, FramePrefix: prefix, Fill: fill, FillCount: count, Leaf: leaf,
		Close: closeRune, CloseCount: count, FrameSuffix: `}` + suffix,
	}
}

func buildArgsInputs() []argsProbe {
	var probes []argsProbe
	add := func(p argsProbe) { probes = append(probes, p) }

	add(plainArgs("args_baseline",
		"control: the dry-run render the other probes vary. The alias A is listed with its value masked",
		`{`+tmplBase+`}`))

	// Duplicate keys. encoding/json into map[string]any assigns every member
	// in document order, so the LAST one wins; null is a value (it replaces),
	// unlike a struct field where null is a no-op.
	add(plainArgs("args_duplicate_top_level_last_wins",
		"a repeated top-level key is last-wins: the second name ('second') is rendered although 'first' came earlier",
		`{"template_type":"k8s-secret","name":"first","name":"second","secret_refs":{"A":"x.y"},"dry_run":true}`))
	add(plainArgs("args_duplicate_top_level_invalid_last",
		"last-wins also applies when the later duplicate is the invalid one: template_type 'nope' wins over the earlier valid k8s-secret",
		`{"template_type":"k8s-secret","template_type":"nope","secret_refs":{"A":"x.y"},"dry_run":true}`))
	add(plainArgs("args_duplicate_top_level_null_replaces",
		"unlike a struct field, a trailing null REPLACES the earlier value in a map: name falls back to its default 'app'",
		`{"template_type":"k8s-secret","name":"demo","name":null,"secret_refs":{"A":"x.y"},"dry_run":true}`))
	add(plainArgs("args_duplicate_nested_last_wins_drops_wrong_typed_alias",
		"a repeated key inside secret_refs is last-wins: A is 5 at the end, a non-string, so only B is rendered",
		`{"template_type":"k8s-secret","name":"demo","secret_refs":{"A":"x.y","A":5,"B":"p.q"},"dry_run":true}`))
	add(plainArgs("args_duplicate_nested_last_wins_keeps_string_alias",
		"mirror of the previous probe: the wrong-typed duplicate comes first and the string after it wins, so A and B are both rendered",
		`{"template_type":"k8s-secret","name":"demo","secret_refs":{"A":5,"A":"x.y","B":"p.q"},"dry_run":true}`))
	add(plainArgs("args_duplicate_nested_null_replaces",
		"a trailing A:null replaces the earlier reference, so A is not rendered",
		`{"template_type":"k8s-secret","name":"demo","secret_refs":{"A":"x.y","B":"p.q","A":null},"dry_run":true}`))
	add(plainArgs("args_duplicate_nested_object_is_replaced_not_merged",
		"a repeated secret_refs OBJECT replaces the earlier one (a map element is overwritten, not merged into), so only B is rendered",
		`{"template_type":"k8s-secret","name":"demo","secret_refs":{"A":"x.y"},"secret_refs":{"B":"p.q"},"dry_run":true}`))
	add(plainArgs("args_duplicate_deep_nested_last_wins",
		"duplicates two levels down inside an unrelated member do not disturb the call (decoded, last-wins, ignored by the tool)",
		`{`+tmplBase+`,"x":{"y":{"z":1,"z":2},"y":{"w":3}}}`))

	// Case sensitivity: map keys are exact; only struct fields fold case.
	add(plainArgs("args_keys_are_case_sensitive_top_level",
		"a map key is matched exactly: TEMPLATE_TYPE does not select template_type, so the (valid) exact key is used",
		`{"TEMPLATE_TYPE":"nope","template_type":"k8s-secret","name":"demo","dry_run":true}`))
	add(plainArgs("args_wrong_case_key_selects_nothing",
		"only the wrong-case spelling is present, so template_type is missing",
		`{"Template_Type":"k8s-secret","dry_run":true}`))
	add(plainArgs("args_keys_are_case_sensitive_nested",
		"secret_refs keys A and a are two different aliases and both are rendered",
		`{"template_type":"k8s-secret","name":"demo","secret_refs":{"A":"x.y","a":"p.q"},"dry_run":true}`))
	add(plainArgs("args_escaped_key_is_unquoted_before_it_is_stored",
		`a key spelled with an escape (template\u005ftype) is the same key as template_type once unquoted, so as the later duplicate it wins over 'nope'`,
		`{"template_type":"nope","template\u005ftype":"k8s-secret","name":"demo","dry_run":true}`))

	// Lone surrogates decode to U+FFFD wherever a string can be.
	add(plainArgs("args_lone_surrogate_in_value",
		`encoding/json decodes the lone escape \uD800 to U+FFFD and carries on: the rendered name contains the replacement character`,
		`{"template_type":"k8s-secret","name":"a\uD800b","dry_run":true}`))
	add(plainArgs("args_lone_surrogate_in_nested_key_and_value",
		`lone surrogates in a nested key and in a nested value are decoded, not rejected`,
		`{"template_type":"k8s-secret","name":"demo","secret_refs":{"\uDC00":"x\uD800.y","B":"p.q"},"dry_run":true}`))
	add(plainArgs("args_lone_surrogate_in_unused_members",
		`lone surrogates anywhere in a member the tool never reads (keys, array items, nested objects) do not fail the call`,
		`{`+tmplBase+`,"zz":["\uD800",{"\uDBFF":"\uDFFF"}]}`))
	add(plainArgs("args_valid_surrogate_pair_is_one_rune",
		`control: a valid pair is a single astral rune`,
		`{"template_type":"k8s-secret","name":"\uD83D\uDE00","dry_run":true}`))
	add(plainArgs("args_surrogate_halves_are_not_merged",
		`a high surrogate followed by a non-low escape is U+FFFD followed by that second escape`,
		`{"template_type":"k8s-secret","name":"\uD800\u0041","dry_run":true}`))

	// Numbers: every JSON number lands in a float64; ParseFloat range errors
	// are decode errors, underflow is not.
	add(plainArgs("args_number_overflow_top_level_member",
		`1e400 does not fit a float64: the decode fails with -32603 'parse arguments: json: cannot unmarshal number 1e400 into Go value of type float64' even though the tool never reads the member`,
		`{`+tmplBase+`,"n":1e400}`))
	add(plainArgs("args_number_overflow_negative_nested",
		`the same failure for a negative overflow nested in an array and an object`,
		`{`+tmplBase+`,"x":[1,{"y":-1e400}]}`))
	add(plainArgs("args_number_overflow_first_in_document_order_is_reported",
		`encoding/json saves the first conversion error and keeps decoding: the message names 1e500, the first overflow, not 1e400`,
		`{`+tmplBase+`,"x":[1e500,1e400]}`))
	add(plainArgs("args_number_overflow_exponent_spellings",
		`the offending number is quoted as it is spelled: 1E+400`,
		`{`+tmplBase+`,"n":1E+400}`))
	add(plainArgs("args_number_just_above_float64_max_overflows",
		`1.7976931348623159e308 rounds past the largest finite float64 and is a range error`,
		`{`+tmplBase+`,"n":1.7976931348623159e308}`))
	add(plainArgs("args_number_float64_max_is_accepted",
		`1.7976931348623157e308 is MaxFloat64 and decodes`,
		`{`+tmplBase+`,"n":1.7976931348623157e308}`))
	add(plainArgs("args_number_underflow_is_accepted",
		`underflow is not a range error: ParseFloat returns 0 for 1e-400 and 5e-324 and -1e-999 and decoding succeeds`,
		`{`+tmplBase+`,"a":1e-400,"b":5e-324,"c":-1e-999}`))
	add(plainArgs("args_number_looking_string_is_not_a_number",
		`a string that spells an overflowing number is just a string`,
		`{`+tmplBase+`,"n":"1e400"}`))
	add(plainArgs("args_number_overflow_inside_a_string_key_is_not_a_number",
		`a key that spells an overflowing number is just a key`,
		`{`+tmplBase+`,"1e400":1}`))
	add(plainArgs("args_big_integer_beyond_int64_is_accepted",
		`an integer beyond int64 is a float64 and decodes`,
		`{`+tmplBase+`,"n":123456789012345678901234567890}`))
	add(rawParams("args_number_overflow_precedes_unknown_tool",
		`the decode runs before the tool lookup: an unknown tool with overflowing arguments reports the decode error, not 'unknown tool'`,
		`"name":"nope","arguments":{"n":1e400}`))
	add(rawParams("args_unknown_tool_with_valid_arguments",
		`control: the same unknown tool with decodable arguments reaches the lookup`,
		`"name":"nope","arguments":{"n":1}`))

	// arguments is not an object.
	add(rawParams("args_scalar_number_overflow_is_a_type_error",
		`arguments:1e400 is a number into a map: the type error names 'number' (no literal), because a scalar is never converted`,
		tmplHead+`1e400`))
	add(rawParams("args_array_is_a_type_error",
		`an array into a map; its items (including 1e400) are skipped, never converted`,
		tmplHead+`[1e400]`))
	add(rawParams("args_string_is_a_type_error",
		`a string into a map`,
		tmplHead+`"text"`))
	add(rawParams("args_true_is_a_type_error",
		`a bool into a map`,
		tmplHead+`true`))
	add(rawParams("args_null_is_empty_arguments",
		`arguments:null is treated as no arguments: the call reaches the tool and template_type is missing`,
		tmplHead+`null`))
	add(rawParams("args_absent_is_empty_arguments",
		`no arguments member at all is the same as no arguments`,
		`"name":"generate_template"`))
	add(rawParams("args_member_duplicate_last_wins",
		`a repeated arguments member is a RawMessage assigned twice: the last object is decoded`,
		tmplHead+`{"template_type":"nope"},"arguments":{`+tmplBase+`}`))
	add(rawParams("args_member_name_matched_case_insensitively",
		`the params struct field matches ARGUMENTS case-insensitively`,
		`"name":"generate_template","ARGUMENTS":{`+tmplBase+`}`))
	add(deepArgsArrayTypeError())

	// Nesting. Total depth counts the frame object (1), params (2) and
	// arguments (3), then the arrays. 9997 arrays is total depth 10000.
	for _, n := range []int{126, 127, 128, 129} {
		add(deepArgs(fmt.Sprintf("args_nested_arrays_%d_levels_in_a_member", n),
			fmt.Sprintf("%d array levels inside a member of arguments (total depth %d): serde_json's Value parse stops at 128 levels, encoding/json does not", n, n+3),
			"[", "", "]", n))
	}
	add(deepArgs("args_nested_arrays_1000_levels_in_a_member",
		"1000 array levels inside a member of arguments (total depth 1003)", "[", "", "]", 1000))
	add(deepArgs("args_nested_objects_129_levels_in_a_member",
		`129 object levels ({"a":{"a":...}}) inside a member of arguments`, `{"a":`, `0`, `}`, 129))
	add(deepArgs("args_total_depth_10000_is_accepted",
		"9997 array levels: total depth 10000, the deepest the transport still dispatches",
		"[", "", "]", 9997))
	add(deepArgs("args_total_depth_10001_is_rejected_by_the_frame",
		"9998 array levels: total depth 10001, rejected as -32700 'exceeded max depth' before any handler runs",
		"[", "", "]", 9998))
	return probes
}

func deepArgsArrayTypeError() argsProbe {
	prefix, suffix := callFrame(tmplHead)
	return argsProbe{
		Name:        "args_deeply_nested_array_is_a_type_error",
		Why:         "arguments as an array 5000 levels deep is a plain type error ('array into map'); the array is skipped, not converted",
		FramePrefix: prefix, Fill: "[", FillCount: 5000, Close: "]", CloseCount: 5000, FrameSuffix: suffix,
	}
}

type argsProbeIn struct {
	Name  string `json:"name"`
	Input string `json:"input"`
}

type argsProbeOut struct {
	Name      string `json:"name"`
	StdoutRaw string `json:"stdout_raw"`
}

// runArgsProbe extracts the oracle commit, runs the probe program inside it
// and returns each probe with the oracle's recorded stream.
func runArgsProbe(root, oracleSHA string, probes []argsProbe) ([]argsProbe, error) {
	dir, err := os.MkdirTemp("", "mcpstdiogen-oracle-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := extractOracle(root, oracleSHA, dir); err != nil {
		return nil, err
	}
	probeDir := filepath.Join(dir, "cmd", "argsprobe")
	if err := os.MkdirAll(probeDir, 0o750); err != nil {
		return nil, err
	}
	source, err := os.ReadFile(filepath.Join(root, argsProbeSource)) // #nosec G304 -- fixed generator input
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(probeDir, "main.go"), source, 0o600); err != nil {
		return nil, err
	}

	in := make([]argsProbeIn, len(probes))
	for i, p := range probes {
		in[i] = argsProbeIn{Name: p.Name, Input: p.input()}
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "run", "./cmd/argsprobe") // #nosec G204 -- fixed arguments
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run probe in the oracle extraction: %w: %s", err, stderr.String())
	}
	var out []argsProbeOut
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("decode probe output: %w", err)
	}
	if len(out) != len(probes) {
		return nil, fmt.Errorf("probe returned %d results for %d probes", len(out), len(probes))
	}
	recorded := make([]argsProbe, len(probes))
	for i, p := range probes {
		if out[i].Name != p.Name {
			return nil, fmt.Errorf("probe result %d is %q, want %q", i, out[i].Name, p.Name)
		}
		stream := out[i].StdoutRaw
		first, rest, ok := strings.Cut(stream, "\n")
		if !ok || !strings.Contains(first, `"id":1`) || !strings.Contains(first, `"protocolVersion"`) {
			return nil, fmt.Errorf("probe %s: stream does not start with the initialize response: %q", p.Name, stream)
		}
		if !utf8Valid(rest) {
			return nil, fmt.Errorf("probe %s: stdout is not valid UTF-8", p.Name)
		}
		p.StdoutAfterInitialize = argsNonce.ReplaceAllString(rest, argsNonceMask)
		recorded[i] = p
	}
	return recorded, nil
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

// extractOracle writes the immutable tree of `git archive <sha> <roots>` below dir.
func extractOracle(root, sha, dir string) error {
	archive := exec.Command("git", append([]string{"-C", root, "archive", "--format=tar", sha}, strings.Fields(argsOracleRoots)...)...) // #nosec G204 -- fixed arguments
	pipe, err := archive.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	archive.Stderr = &stderr
	if err := archive.Start(); err != nil {
		return err
	}
	reader := tar.NewReader(pipe)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = archive.Wait()
			return fmt.Errorf("read oracle archive: %w", err)
		}
		target := filepath.Join(dir, filepath.FromSlash(header.Name))
		if rel, relErr := filepath.Rel(dir, target); relErr != nil || strings.HasPrefix(rel, "..") {
			_ = archive.Wait()
			return fmt.Errorf("oracle archive entry escapes the extraction: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- checked above
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, reader); err != nil { // #nosec G110 -- trusted local git object
				_ = file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		default:
			// Symlinks and special files carry no Go source.
		}
	}
	if err := archive.Wait(); err != nil {
		return fmt.Errorf("git archive %s: %w: %s", sha, err, stderr.String())
	}
	return nil
}

func buildArgsSection(root, oracleSHA string) (argsSection, error) {
	probes, err := runArgsProbe(root, oracleSHA, buildArgsInputs())
	if err != nil {
		return argsSection{}, err
	}
	digest, err := provenance.Digest(root, []string{argsProbeSource})
	if err != nil {
		return argsSection{}, err
	}
	return argsSection{
		Handshake: argsHandshake, OracleCommitSHA: oracleSHA, ExtractedRoots: argsOracleRoots,
		ProbeSource: argsProbeSource, ProbeDigest: digest, NonceMask: argsNonceMask, Probes: probes,
	}, nil
}
