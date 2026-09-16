// Command mcpinitgen freezes the MCP-001 initialize/handshake contract from the
// pinned Go oracle.
//
// The fixture is produced by driving the real production stdio transport
// (internal/mcp/transport) against the real production protocol handler
// (internal/mcp/server) with raw input lines, and capturing the exact bytes the
// server writes to stdout. Nothing is reimplemented here: the generator owns the
// case list, not the behavior.
//
// Two observable facts are recorded per case. `output_raw` is the verbatim byte
// stream, which is what a stdout-hygiene claim has to be made against.
// `output` is the same stream parsed into messages with runtime-authored error
// `data` replaced by a sentinel, because that text is the Go JSON decoder's
// wording and is deliberately outside the contract (see the MCP-001 row).
// Everything Symaira Vault itself authors — codes, messages, IDs, negotiated
// versions, capabilities and instructions — stays pinned byte-for-byte.
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

	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"

	// Fixed so the fixture describes the contract, not this machine.
	fixtureServerName    = "symvault"
	fixtureServerVersion = "0.0.0-fixture"

	// runtimeTextSentinel replaces error `data` that is the Go runtime's own
	// decoder wording. A Rust port cannot reproduce that string and is not
	// asked to; it must still produce *some* non-empty diagnostic there.
	runtimeTextSentinel = "<runtime-error-text>"
)

// contractAuthoredData are the error `data` strings the oracle writes as its own
// literals rather than forwarding from the JSON decoder. They stay pinned
// byte-for-byte; masking them would silently drop them from the contract.
// Anything else in a string `data` came from encoding/json and is masked.
var contractAuthoredData = map[string]bool{
	"jsonrpc must be 2.0": true,
	"method is required":  true,
}

// productionSources are the files whose behavior this fixture claims.
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

type handshakeCase struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	// Input is the verbatim stdin stream, line by line, exactly as written.
	Input []string `json:"input"`
	// OutputRaw is every byte the server wrote to stdout, split on the
	// newline the transport itself emits. Empty means "wrote nothing",
	// which is the whole contract for notifications.
	OutputRaw []string `json:"output_raw"`
	// Output is OutputRaw parsed, with runtime-authored error data masked.
	Output []json.RawMessage `json:"output"`
	// RuntimeTextMasked records whether masking actually changed anything,
	// so a reader can tell which cases are byte-exact and which are not.
	RuntimeTextMasked bool `json:"runtime_text_masked"`
}

type fixture struct {
	SchemaVersion int    `json:"schema_version"`
	Oracle        oracle `json:"oracle"`
	// ServerName/Version are generator-chosen inputs, recorded so the Rust
	// side constructs an identically-configured server.
	ServerName    string `json:"server_name"`
	ServerVersion string `json:"server_version"`
	// SupportedVersions and Instructions are contract constants lifted from
	// the oracle so a drift in either fails this fixture, not just a case.
	SupportedVersions   []string        `json:"supported_versions"`
	LatestVersion       string          `json:"latest_version"`
	RuntimeTextSentinel string          `json:"runtime_text_sentinel"`
	Cases               []handshakeCase `json:"cases"`
}

// cases is the MCP-001 case list: negotiation across every supported version and
// below/above it, ID shapes, notification silence, and the malformed-frame
// negatives that decide stdout hygiene.
func caseInputs() []struct {
	name  string
	why   string
	input []string
} {
	return []struct {
		name  string
		why   string
		input []string
	}{
		{
			"initialize_latest_version",
			"the happy path pins capabilities, serverInfo and the instructions blob",
			[]string{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}`},
		},
		{
			"initialize_older_supported_2025_06_18",
			"a supported version is echoed back, not upgraded",
			[]string{`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}`},
		},
		{
			"initialize_older_supported_2025_03_26",
			"the HTTP default version is also a valid stdio request",
			[]string{`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}`},
		},
		{
			"initialize_oldest_supported_2024_11_05",
			"the oldest supported version must not be silently upgraded",
			[]string{`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}`},
		},
		{
			"initialize_unsupported_version_negotiates_latest",
			"an unknown version negotiates down to the latest supported one rather than failing",
			[]string{`{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"1999-01-01","clientInfo":{"name":"probe","version":"1.0"},"capabilities":{}}}`},
		},
		{
			"initialize_missing_protocol_version",
			"an absent version is treated as unspecified, not as an error",
			[]string{`{"jsonrpc":"2.0","id":6,"method":"initialize","params":{"clientInfo":{"name":"probe","version":"1.0"}}}`},
		},
		{
			"initialize_empty_protocol_version",
			"an explicit empty string takes the same path as an absent one",
			[]string{`{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"","clientInfo":{"name":"probe","version":"1.0"}}}`},
		},
		{
			"initialize_no_params",
			"params is optional; ParseParams returns early and negotiation still runs",
			[]string{`{"jsonrpc":"2.0","id":8,"method":"initialize"}`},
		},
		{
			"initialize_string_id",
			"a string ID is echoed verbatim, including its quotes",
			[]string{`{"jsonrpc":"2.0","id":"abc","method":"initialize","params":{"protocolVersion":"2025-11-25"}}`},
		},
		{
			"initialize_null_id",
			"an explicit null ID is four bytes, not absent, so this is a request and must be answered",
			[]string{`{"jsonrpc":"2.0","id":null,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`},
		},
		{
			"initialize_invalid_params_type",
			"params of the wrong shape is -32602, and the diagnostic is runtime text",
			[]string{`{"jsonrpc":"2.0","id":9,"method":"initialize","params":"not-an-object"}`},
		},
		{
			"initialize_params_null",
			"an explicit null params is legal JSON-RPC and the oracle treats it as a no-op: Unmarshal leaves the zero value and negotiation proceeds. A port that rejects it refuses the handshake to a conforming client",
			[]string{`{"jsonrpc":"2.0","id":20,"method":"initialize","params":null}`},
		},
		{
			"initialize_protocol_version_null",
			"an explicit null version is also a no-op against a string field, so it negotiates to the latest rather than erroring",
			[]string{`{"jsonrpc":"2.0","id":21,"method":"initialize","params":{"protocolVersion":null}}`},
		},
		{
			"initialize_client_info_wrong_type",
			"clientInfo is typed *ClientInfo in the oracle, so a string there is -32602. Ignoring the field would make the port MORE permissive than the oracle",
			[]string{`{"jsonrpc":"2.0","id":22,"method":"initialize","params":{"clientInfo":"oops"}}`},
		},
		{
			"initialize_protocol_version_wrong_type",
			"a non-string version is -32602 rather than being coerced or ignored",
			[]string{`{"jsonrpc":"2.0","id":23,"method":"initialize","params":{"protocolVersion":42}}`},
		},
		{
			"initialize_field_name_case_insensitive",
			"encoding/json falls back to a case-insensitive field match, so this selects a real version. A port matching only exactly would silently negotiate a DIFFERENT protocol version than the oracle",
			[]string{`{"jsonrpc":"2.0","id":24,"method":"initialize","params":{"PROTOCOLVERSION":"2024-11-05"}}`},
		},
		{
			"html_characters_are_escaped_in_output",
			"json.Marshal escapes <, > and & by default. The method name is attacker-chosen and is echoed into the error message, so a port using serde_json's defaults puts raw angle brackets on the stdout stream the client parses for framing",
			[]string{`{"jsonrpc":"2.0","id":25,"method":"a<b>&c"}`},
		},
		{
			"html_characters_in_string_id_are_escaped",
			"the same escaping applies to an echoed id, which is equally attacker-chosen",
			[]string{`{"jsonrpc":"2.0","id":"<&>","method":"ping"}`},
		},
		{
			"structured_id_is_compacted",
			"json.Marshal compacts a RawMessage, so interior whitespace in a structured id does not survive the echo",
			[]string{`{"jsonrpc":"2.0","id":{"a":  1,  "b": "x"},"method":"ping"}`},
		},
		{
			"notification_initialized",
			"the bare notification name writes nothing at all",
			[]string{`{"jsonrpc":"2.0","method":"initialized"}`},
		},
		{
			"notification_notifications_initialized",
			"the namespaced notification name writes nothing at all",
			[]string{`{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		},
		{
			"notification_unknown_method_is_silent",
			"an unknown notification must not produce a method-not-found frame",
			// "cancelled" is the MCP specification's own spelling of this
			// method name, so it is protocol data rather than prose.
			//nolint:misspell // protocol method name, not English text
			[]string{`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`},
		},
		{
			"ping_returns_empty_object",
			"ping's result is an empty object, not null",
			[]string{`{"jsonrpc":"2.0","id":10,"method":"ping"}`},
		},
		{
			"unknown_method_with_id",
			"an unknown request is -32601 and names the method",
			[]string{`{"jsonrpc":"2.0","id":11,"method":"does/not/exist"}`},
		},
		{
			"malformed_json_is_parse_error",
			"a broken frame is -32700 with a null ID and must not kill the stream",
			[]string{`{"jsonrpc":"2.0","id":12,`},
		},
		{
			"wrong_jsonrpc_version",
			"a non-2.0 envelope is -32600 before dispatch",
			[]string{`{"jsonrpc":"1.0","id":13,"method":"initialize"}`},
		},
		{
			"missing_method_with_id",
			"a request without a method is -32600",
			[]string{`{"jsonrpc":"2.0","id":14}`},
		},
		{
			"initialize_then_ping_sequence",
			"state carries across frames and each frame gets exactly one line",
			[]string{
				`{"jsonrpc":"2.0","id":15,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
				`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
				`{"jsonrpc":"2.0","id":16,"method":"ping"}`,
			},
		},
		{
			"malformed_frame_does_not_break_following_frame",
			"the stream survives a bad frame: recovery is the stdout-hygiene claim",
			[]string{
				`{"jsonrpc":"2.0","id":17,`,
				`{"jsonrpc":"2.0","id":18,"method":"ping"}`,
			},
		},
		{
			"blank_line_emits_parse_error",
			"a blank line is NOT skipped: ReadString keeps the delimiter, so the " +
				"len(line)==0 guard never fires and the empty frame reaches the JSON " +
				"decoder as \"\\n\". It answers -32700 and keeps reading",
			[]string{
				``,
				`{"jsonrpc":"2.0","id":19,"method":"ping"}`,
			},
		},
	}
}

// runCase feeds input through the real transport and handler and returns stdout.
func runCase(input []string) ([]string, error) {
	handler := mcpserver.NewProtocolHandler(fixtureServerName, fixtureServerVersion, nil)

	var stdin strings.Builder
	for _, line := range input {
		stdin.WriteString(line)
		stdin.WriteString("\n")
	}

	var stdout bytes.Buffer
	tr := transport.NewStdioTransportWithIO(strings.NewReader(stdin.String()), &stdout)
	if err := tr.Start(context.Background(), handler.HandleMessage); err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	raw := stdout.String()
	if raw == "" {
		return []string{}, nil
	}
	raw = strings.TrimSuffix(raw, "\n")
	return strings.Split(raw, "\n"), nil
}

// maskRuntimeText replaces an error `data` string with the sentinel. It reports
// whether it changed anything so the fixture can say which cases are byte-exact.
func maskRuntimeText(line string) (json.RawMessage, bool, error) {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &generic); err != nil {
		return nil, false, fmt.Errorf("parse emitted line %q: %w", line, err)
	}
	masked := false
	if rawErr, ok := generic["error"]; ok {
		var errObj map[string]json.RawMessage
		if err := json.Unmarshal(rawErr, &errObj); err != nil {
			return nil, false, fmt.Errorf("parse error object: %w", err)
		}
		if data, ok := errObj["data"]; ok {
			var text string
			// Only non-contract string data is runtime wording; structured data
			// and the oracle's own literals stay pinned.
			if json.Unmarshal(data, &text) == nil && !contractAuthoredData[text] {
				sentinel, err := json.Marshal(runtimeTextSentinel)
				if err != nil {
					return nil, false, err
				}
				errObj["data"] = sentinel
				masked = true
				reErr, err := marshalCanonical(errObj)
				if err != nil {
					return nil, false, err
				}
				generic["error"] = reErr
			}
		}
	}
	out, err := marshalCanonical(generic)
	if err != nil {
		return nil, false, err
	}
	return out, masked, nil
}

// marshalCanonical re-encodes an object map with sorted keys so the masked form
// is stable regardless of Go map iteration order.
func marshalCanonical(obj map[string]json.RawMessage) (json.RawMessage, error) {
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
		encoded, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)
		buf.WriteByte(':')
		buf.Write(obj[k])
	}
	buf.WriteByte('}')
	return json.RawMessage(buf.Bytes()), nil
}

func buildCases() ([]handshakeCase, error) {
	inputs := caseInputs()
	cases := make([]handshakeCase, 0, len(inputs))
	for _, in := range inputs {
		outRaw, err := runCase(in.input)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", in.name, err)
		}
		parsed := make([]json.RawMessage, 0, len(outRaw))
		anyMasked := false
		for _, line := range outRaw {
			m, masked, err := maskRuntimeText(line)
			if err != nil {
				return nil, fmt.Errorf("case %s: %w", in.name, err)
			}
			if masked {
				anyMasked = true
			}
			parsed = append(parsed, m)
		}
		cases = append(cases, handshakeCase{
			Name:              in.name,
			Why:               in.why,
			Input:             in.input,
			OutputRaw:         outRaw,
			Output:            parsed,
			RuntimeTextMasked: anyMasked,
		})
	}
	return cases, nil
}

// supportedVersionsFromOracle reads the contract constants back out of the
// production package rather than restating them here, so a drift in the
// oracle's supported set changes the fixture instead of hiding behind it.
func supportedVersionsFromOracle() []string {
	candidates := []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	supported := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if mcpserver.IsSupportedProtocolVersion(c) {
			supported = append(supported, c)
		}
	}
	return supported
}

func main() {
	output := flag.String("output", "testdata/port/mcp/initialize.json", "MCP-001 fixture path")
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
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/mcpinitgen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}

	cases, err := buildCases()
	if err != nil {
		fatal("build cases: %v", err)
	}

	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: commitLabel, CommitSHA: resolved, Release: releaseLabel,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest,
		},
		ServerName:          fixtureServerName,
		ServerVersion:       fixtureServerVersion,
		SupportedVersions:   supportedVersionsFromOracle(),
		LatestVersion:       mcpserver.LatestSupportedProtocolVersion,
		RuntimeTextSentinel: runtimeTextSentinel,
		Cases:               cases,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}

	if *check {
		existing, readErr := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; run make mcp-init-fixtures-generate")
		}
		fmt.Printf("PASS MCP-001 initialize fixture (%d cases)\n", len(cases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", *output, len(cases))
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
