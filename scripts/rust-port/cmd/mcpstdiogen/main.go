// Command mcpstdiogen freezes the MCP-004 stdio-hygiene contract from the
// pinned Go oracle.
//
// Like mcpinitgen it drives the real production transport and handler and
// records the exact stdout byte stream; it reimplements nothing. Where
// mcpinitgen covers well-formed traffic, this generator covers the frames a
// hostile or careless client actually sends: unterminated lines, CRLF, stray
// whitespace, NUL bytes, non-object frames, duplicate keys, oversized payloads
// and pathological nesting.
//
// Two facts it records are contract *findings*, not design choices, and both
// contradict the row's original one-line description:
//
//   - Input is NOT bounded. The oracle reads with bufio ReadString, which grows
//     without limit; a five-megabyte frame is accepted and answered.
//   - A line with no trailing newline is silently DISCARDED. ReadString returns
//     the partial data together with io.EOF and the read loop returns on EOF
//     before dispatching it, so the client gets silence rather than an error.
//
// The fixture records what the oracle does. Repairing either one is a product
// decision about the Go side, not something the Rust port may invent.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"

	fixtureServerName    = "symvault"
	fixtureServerVersion = "0.0.0-fixture"

	runtimeTextSentinel = "<runtime-error-text>"
)

// contractAuthoredData mirrors mcpinitgen: the oracle's own literals stay
// pinned, everything else in a string `data` is encoding/json's wording.
var contractAuthoredData = map[string]bool{
	"jsonrpc must be 2.0": true,
	"method is required":  true,
}

var productionSources = []string{
	"internal/mcp/server/protocol.go",
	"internal/mcp/transport/stdio.go",
	"internal/mcp/transport/transport.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type hygieneCase struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	// Input is the verbatim stdin byte stream. Unlike mcpinitgen's line list,
	// this is one string so a case can deliberately omit the final newline.
	Input string `json:"input"`
	// StdoutRaw is every byte written to stdout, verbatim, including the
	// trailing newline the transport emits after each frame.
	StdoutRaw string `json:"stdout_raw"`
	// Frames is StdoutRaw split per emitted line and masked, for the cases
	// whose error data is the decoder's own wording.
	Frames            []json.RawMessage `json:"frames"`
	RuntimeTextMasked bool              `json:"runtime_text_masked"`
}

// boundsProbe records a size/shape limit without embedding megabytes of payload
// in the fixture. The input is described by its shape and length, and the Rust
// side rebuilds it from that description.
type boundsProbe struct {
	Name      string `json:"name"`
	Why       string `json:"why"`
	Prefix    string `json:"prefix"`
	FillRune  string `json:"fill_rune"`
	FillCount int    `json:"fill_count"`
	// CloseRune/CloseCount are the balancing fill. Recording them keeps the
	// shape fields load-bearing: a replay rebuilds the exact input from this
	// description alone, with no per-probe special case keyed on the name.
	CloseRune  string `json:"close_rune"`
	CloseCount int    `json:"close_count"`
	Suffix     string `json:"suffix"`
	InputBytes int    `json:"input_bytes"`
	StdoutRaw  string `json:"stdout_raw"`
	Masked     bool   `json:"masked"`
}

// divergence records a case the Rust port deliberately does not reproduce,
// together with what the oracle actually does, so the gap is visible in the
// fixture itself rather than only in prose.
type divergence struct {
	Name                string `json:"name"`
	OracleBehavior      string `json:"oracle_behavior"`
	OracleStdoutB64Note string `json:"oracle_stdout_note"`
	RustBehavior        string `json:"rust_behavior"`
	Rationale           string `json:"rationale"`
}

type fixture struct {
	SchemaVersion       int    `json:"schema_version"`
	Oracle              oracle `json:"oracle"`
	ServerName          string `json:"server_name"`
	ServerVersion       string `json:"server_version"`
	RuntimeTextSentinel string `json:"runtime_text_sentinel"`
	InputIsBounded      bool   `json:"input_is_bounded"`
	// MaxAcceptedNestingDepth is the deepest TOTAL nesting the oracle still
	// dispatches, counting the enclosing frame object itself. Measured by
	// binary search, not read off encoding/json's constant.
	MaxAcceptedNestingDepth int           `json:"max_accepted_nesting_depth"`
	Cases                   []hygieneCase `json:"cases"`
	Bounds                  []boundsProbe `json:"bounds"`
	Divergences             []divergence  `json:"divergences"`
}

func runStream(input string) (string, error) {
	handler := mcpserver.NewProtocolHandler(fixtureServerName, fixtureServerVersion, nil)
	var stdout bytes.Buffer
	tr := transport.NewStdioTransportWithIO(strings.NewReader(input), &stdout)
	if err := tr.Start(context.Background(), handler.HandleMessage); err != nil {
		return "", fmt.Errorf("transport: %w", err)
	}
	return stdout.String(), nil
}

func maskFrames(stdout string) ([]json.RawMessage, bool, error) {
	if stdout == "" {
		return []json.RawMessage{}, false, nil
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	frames := make([]json.RawMessage, 0, len(lines))
	anyMasked := false
	for _, line := range lines {
		var generic map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &generic); err != nil {
			return nil, false, fmt.Errorf("emitted line is not JSON (%q): %w", line, err)
		}
		if rawErr, ok := generic["error"]; ok {
			var errObj map[string]json.RawMessage
			if err := json.Unmarshal(rawErr, &errObj); err != nil {
				return nil, false, err
			}
			if data, ok := errObj["data"]; ok {
				var text string
				if json.Unmarshal(data, &text) == nil && !contractAuthoredData[text] {
					sentinel, err := json.Marshal(runtimeTextSentinel)
					if err != nil {
						return nil, false, err
					}
					errObj["data"] = sentinel
					anyMasked = true
					re, err := canonical(errObj)
					if err != nil {
						return nil, false, err
					}
					generic["error"] = re
				}
			}
		}
		out, err := canonical(generic)
		if err != nil {
			return nil, false, err
		}
		frames = append(frames, out)
	}
	return frames, anyMasked, nil
}

func canonical(obj map[string]json.RawMessage) (json.RawMessage, error) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		enc, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(enc)
		buf.WriteByte(':')
		buf.Write(obj[k])
	}
	buf.WriteByte('}')
	return json.RawMessage(buf.Bytes()), nil
}

const ping = `{"jsonrpc":"2.0","id":1,"method":"ping"}`

func caseInputs() []struct{ name, why, input string } {
	return []struct{ name, why, input string }{
		{
			"unterminated_frame_is_discarded",
			"a frame with no trailing newline is never dispatched: ReadString returns it together with io.EOF and the loop returns on EOF first. The client gets silence, not an error",
			ping,
		},
		{
			"unterminated_frame_after_complete_frame",
			"the terminated frame is answered and the unterminated remainder is dropped, so a client that forgets the last newline loses exactly one request",
			ping + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		},
		{
			"crlf_line_ending",
			"a CRLF client works: the carriage return stays on the line and the JSON decoder skips it as trailing whitespace",
			ping + "\r\n",
		},
		{
			"leading_whitespace",
			"leading whitespace before the frame is tolerated by the decoder",
			"   " + ping + "\n",
		},
		{
			"trailing_whitespace",
			"trailing whitespace after the frame is tolerated by the decoder",
			ping + "   \n",
		},
		{
			"nul_byte_in_frame",
			"an embedded NUL is a decode failure, answered as -32700 rather than crashing the reader",
			"{\"jsonrpc\":\"2.0\",\"id\":\x00,\"method\":\"ping\"}\n",
		},
		{
			"two_objects_on_one_line",
			"frames are newline-delimited, not self-delimiting: a second object on the same line is trailing garbage",
			`{"jsonrpc":"2.0","id":1,"method":"ping"}{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n",
		},
		{
			"array_frame",
			"a non-object top-level frame is -32700, not a crash",
			"[1,2,3]\n",
		},
		{
			"bare_string_frame",
			"a bare JSON string is -32700",
			"\"hello\"\n",
		},
		{
			"null_frame",
			"literal null decodes to a zero-valued message whose jsonrpc is empty, so it is -32600 and not -32700",
			"null\n",
		},
		{
			"only_newlines",
			"each blank line is its own parse error; three blank lines produce three frames",
			"\n\n\n",
		},
		{
			"empty_stream",
			"an empty stream writes nothing and shuts down cleanly",
			"",
		},
		{
			"unicode_method_name",
			"a non-ASCII method name round-trips into the not-found message without escaping",
			`{"jsonrpc":"2.0","id":1,"method":"pïng✓"}` + "\n",
		},
		{
			"bignum_id_preserved_verbatim",
			"an ID far beyond int64 is echoed back byte-for-byte because it is never decoded into a number",
			`{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"ping"}` + "\n",
		},
		{
			"interleaved_valid_and_invalid",
			"a hostile client cannot desynchronise the stream: every frame is answered in order regardless of the failures between them",
			ping + "\n" + "garbage\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n" + "[]\n" + `{"jsonrpc":"2.0","id":3,"method":"ping"}` + "\n",
		},
	}
}

func buildCases() ([]hygieneCase, error) {
	inputs := caseInputs()
	cases := make([]hygieneCase, 0, len(inputs))
	for _, in := range inputs {
		stdout, err := runStream(in.input)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", in.name, err)
		}
		if !utf8.ValidString(stdout) {
			return nil, fmt.Errorf("case %s: stdout is not valid UTF-8; it belongs in divergences, not cases", in.name)
		}
		frames, masked, err := maskFrames(stdout)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", in.name, err)
		}
		cases = append(cases, hygieneCase{
			Name: in.name, Why: in.why, Input: in.input,
			StdoutRaw: stdout, Frames: frames, RuntimeTextMasked: masked,
		})
	}
	return cases, nil
}

func buildBounds() ([]boundsProbe, error) {
	probes := []struct {
		name, why, prefix, fill, closeRune, suffix string
		count, closeCount                          int
	}{
		{
			"oversized_five_megabyte_frame",
			"input is NOT bounded: the oracle's reader grows without limit and answers a five-megabyte frame normally. The row's 'bounded input' wording describes an intent the oracle does not implement",
			`{"jsonrpc":"2.0","id":3,"method":"ping","pad":"`, "x", "", `"}` + "\n", 5_000_000, 0,
		},
		{
			"brackets_inside_a_string_are_not_nesting",
			"a payload of bracket CHARACTERS inside a string literal is depth 1, not deep nesting. The oracle dispatches it, so a depth guard that scans without tracking string state would reject a frame the oracle accepts",
			`{"jsonrpc":"2.0","id":1,"method":"ping","p":"`, "[", "", `"}` + "\n", 10001, 0,
		},
		{
			"escaped_quote_before_bracket_fill_is_still_a_string",
			"the depth scanner has to track backslash escapes, not just quotes: after an escaped quote the scanner is STILL inside the string, so these brackets are characters and the frame is dispatched. A scanner that treated the escaped quote as closing the string would count them as nesting and wrongly reject",
			`{"jsonrpc":"2.0","id":1,"method":"ping","p":"\"`, "[", "", `"}` + "\n", 10001, 0,
		},
		{
			"pathological_nesting_is_rejected",
			"nesting is the one real bound, and it comes from encoding/json rather than the transport: past its max depth the frame is -32700 instead of exhausting the stack",
			`{"jsonrpc":"2.0","id":1,"method":"ping","p":`, "[", "]", "}" + "\n", 20000, 20000,
		},
	}
	out := make([]boundsProbe, 0, len(probes))
	for _, p := range probes {
		input := p.prefix + strings.Repeat(p.fill, p.count)
		if p.closeCount > 0 {
			input += strings.Repeat(p.closeRune, p.closeCount)
		}
		input += p.suffix
		stdout, err := runStream(input)
		if err != nil {
			return nil, fmt.Errorf("bounds %s: %w", p.name, err)
		}
		_, masked, err := maskFrames(stdout)
		if err != nil {
			return nil, fmt.Errorf("bounds %s: %w", p.name, err)
		}
		out = append(out, boundsProbe{
			Name: p.name, Why: p.why, Prefix: p.prefix, FillRune: p.fill,
			FillCount: p.count, CloseRune: p.closeRune, CloseCount: p.closeCount,
			Suffix: p.suffix, InputBytes: len(input),
			StdoutRaw: stdout, Masked: masked,
		})
	}
	return out, nil
}

// measureNestingBoundary binary-searches the deepest nesting the oracle still
// accepts. It is measured rather than copied from encoding/json's constant so
// the fixture fails if a toolchain change moves it.
func measureNestingBoundary() (int, error) {
	accepted := func(n int) (bool, error) {
		in := `{"jsonrpc":"2.0","id":1,"method":"ping","p":` +
			strings.Repeat("[", n) + strings.Repeat("]", n) + "}\n"
		out, err := runStream(in)
		if err != nil {
			return false, err
		}
		return !strings.Contains(out, "max depth"), nil
	}
	lo, hi := 1, 40000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		ok, err := accepted(mid)
		if err != nil {
			return 0, err
		}
		if ok {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	// lo counts the brackets inside the payload field; the enclosing frame
	// object is one more level, and total depth is the number that means
	// something on its own.
	return lo + 1, nil
}

func main() {
	output := flag.String("output", "testdata/port/mcp/stdio-hygiene.json", "MCP-004 fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	commitLabel, releaseLabel, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	root, err := repositoryRoot()
	if err != nil {
		fatal("%v", err)
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("%v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/mcpstdiogen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}

	maxDepth, err := measureNestingBoundary()
	if err != nil {
		fatal("measure nesting boundary: %v", err)
	}

	cases, err := buildCases()
	if err != nil {
		fatal("build cases: %v", err)
	}
	bounds, err := buildBounds()
	if err != nil {
		fatal("build bounds: %v", err)
	}

	// Both divergences are recorded by executing the oracle, not by reading it.
	const dupFrame = `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}` + "\n"
	dupOut, err := runStream(dupFrame)
	if err != nil {
		fatal("probe duplicate keys: %v", err)
	}
	if !strings.Contains(dupOut, `"id":2`) {
		fatal("duplicate-key probe no longer reproduces last-wins (%q); the divergence must be re-adjudicated", dupOut)
	}

	invalidUTF8 := "{\"jsonrpc\":\"2.0\",\"id\":\"\xff\xfe\",\"method\":\"ping\"}\n"
	invalidOut, err := runStream(invalidUTF8)
	if err != nil {
		fatal("probe invalid utf-8: %v", err)
	}
	if utf8.ValidString(invalidOut) {
		fatal("invalid-utf8 probe no longer reproduces: the oracle returned valid UTF-8, so this divergence must be re-adjudicated")
	}

	built := fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: commitLabel, CommitSHA: resolved, Release: releaseLabel,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest,
		},
		ServerName:              fixtureServerName,
		ServerVersion:           fixtureServerVersion,
		RuntimeTextSentinel:     runtimeTextSentinel,
		InputIsBounded:          false,
		MaxAcceptedNestingDepth: maxDepth,
		Cases:                   cases,
		Bounds:                  bounds,
		Divergences: []divergence{{
			Name:                "duplicate_object_keys_last_wins",
			OracleBehavior:      "The oracle accepts a frame carrying the id key twice and answers with the LAST occurrence, silently: encoding/json resolves duplicates by last-wins. Verified by executing it in this generator, which fails if it stops reproducing. SCOPE: this covers duplicated ENVELOPE fields only. A key duplicated inside params is -32602 here rather than -32700, and a duplicate inside an id or an unknown top-level key is still accepted last-wins exactly as the oracle does, because those are carried as raw values and never decoded into a struct. The tool-call payload an intermediary would audit is therefore NOT yet covered; closing it belongs with MCP-002/003.",
			OracleStdoutB64Note: strings.TrimSuffix(dupOut, "\n"),
			RustBehavior:        "Rust answers -32700 and does not dispatch the frame.",
			Rationale:           "serde rejects duplicate struct fields and the adjudication keeps that rather than relaxing it to match. Last-wins is the classic duplicate-key smuggling shape: an intermediary that logs, audits or applies policy to a frame reads the first occurrence while the server acts on the last, so the two disagree about what was requested. SymVault has exactly such a policy and audit layer, which makes this security-relevant rather than cosmetic. Rejecting is the stricter side, and the migration contract names duplicate keys as a case to decide deliberately rather than inherit. Recorded, not silent; reversing it is a coordinator decision.",
		}, {
			Name:                "invalid_utf8_id_echoed_verbatim",
			OracleBehavior:      "The oracle accepts a frame whose id contains invalid UTF-8 and echoes those bytes back on stdout unchanged, because json.RawMessage is []byte and Go strings are not required to be valid UTF-8. Verified by executing it in this generator, which fails if it stops reproducing.",
			OracleStdoutB64Note: "not embedded: the byte sequence is not valid UTF-8 and so cannot be carried in this JSON fixture",
			RustBehavior:        "Rust answers -32700 and emits no invalid bytes.",
			Rationale:           "serde_json's RawValue is backed by str and cannot hold invalid UTF-8, so byte-verbatim echo is not reachable without replacing the JSON envelope wholesale. The adjudicated behavior is to reject fail-closed, which is also the stricter of the two: the oracle's behavior puts attacker-chosen invalid bytes onto the same stdout stream the client parses as framing. This is a deliberate, recorded divergence and not a silent one; reversing it is a coordinator decision.",
		}},
	}
	content, err := marshalJSON(built)
	if err != nil {
		fatal("marshal fixture: %v", err)
	}

	if *check {
		existing, readErr := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; run make mcp-stdio-fixtures-generate")
		}
		fmt.Printf("PASS MCP-004 stdio-hygiene fixture (%d cases, %d bounds, %d divergences)\n",
			len(built.Cases), len(built.Bounds), len(built.Divergences))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases, %d bounds)\n", *output, len(cases), len(bounds))
}

func resolveOracle(check bool, commit, release string) (string, string, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return "", "", fmt.Errorf("oracle commit %q is not the pinned commit %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release %q is not the pinned release %q", release, pinnedOracleRelease)
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("--oracle-commit and --oracle-release are required when generating a new fixture")
	}
	return commit, release, nil
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
