//! MCP-004 differential: replays the Go-generated hostile-frame corpus and
//! asserts the stdout byte stream and retained five-megabyte compatibility.
//! ADR 0016 adds an explicitly adjudicated eight-megabyte frame bound.

use serde::Deserialize;
use std::sync::Arc;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    handle_line_bytes, read_only_tool_names, run_stream,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    runtime_text_sentinel: String,
    input_is_bounded: bool,
    max_accepted_nesting_depth: usize,
    cases: Vec<Case>,
    bounds: Vec<Bounds>,
    duplicate_envelope_probes: Vec<DuplicateProbe>,
    tools_call_arguments: ArgumentsSection,
    divergences: Vec<Divergence>,
}

#[derive(Debug, Deserialize)]
struct ArgumentsSection {
    handshake: String,
    oracle_commit_sha: String,
    nonce_mask: String,
    probes: Vec<ArgumentsProbe>,
}

#[derive(Debug, Deserialize)]
struct ArgumentsProbe {
    name: String,
    why: String,
    frame_prefix: String,
    fill: String,
    fill_count: usize,
    leaf: String,
    close: String,
    close_count: usize,
    frame_suffix: String,
    stdout_after_initialize: String,
}

impl ArgumentsProbe {
    fn input(&self, handshake: &str) -> String {
        format!(
            "{handshake}{}{}{}{}{}\n",
            self.frame_prefix,
            self.fill.repeat(self.fill_count),
            self.leaf,
            self.close.repeat(self.close_count),
            self.frame_suffix
        )
    }
}

#[derive(Debug, Deserialize)]
struct DuplicateProbe {
    name: String,
    why: String,
    input: String,
    oracle_stdout_raw: String,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    why: String,
    input: String,
    stdout_raw: String,
    frames: Vec<serde_json::Value>,
    runtime_text_masked: bool,
}

#[derive(Debug, Deserialize)]
struct Bounds {
    name: String,
    why: String,
    prefix: String,
    fill_rune: String,
    fill_count: usize,
    close_rune: String,
    close_count: usize,
    suffix: String,
    input_bytes: usize,
    stdout_raw: String,
    masked: bool,
}

#[derive(Debug, Deserialize)]
struct Divergence {
    name: String,
    oracle_stdout_note: String,
}

fn load() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/mcp/stdio-hygiene.json"
    );
    let bytes = std::fs::read(path).expect("read MCP-004 fixture");
    serde_json::from_slice(&bytes).expect("parse MCP-004 fixture")
}

fn contract_authored(text: &str) -> bool {
    matches!(text, "jsonrpc must be 2.0" | "method is required")
}

fn mask(line: &str, sentinel: &str) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_str(line).expect("rust output is JSON");
    if let Some(err) = value.get_mut("error").and_then(|e| e.as_object_mut())
        && let Some(data) = err.get("data").and_then(|d| d.as_str())
        && !contract_authored(data)
    {
        assert!(
            !data.is_empty(),
            "masked diagnostic must still be non-empty"
        );
        err.insert(
            "data".to_string(),
            serde_json::Value::String(sentinel.to_string()),
        );
    }
    value
}

/// Joins emitted frames back into the byte stream the transport would write,
/// newline-terminated per frame, so comparison is against stdout and not
/// against a convenient in-memory shape.
fn as_stdout(frames: &[String]) -> String {
    frames.iter().map(|f| format!("{f}\n")).collect()
}

#[test]
fn fixture_pins_the_expected_oracle() {
    let fx = load();
    assert_eq!(fx.oracle.commit, "caadd5e");
    assert_eq!(
        fx.oracle.commit_sha,
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
}

#[test]
fn hostile_frames_match_go_oracle() {
    let fx = load();
    assert!(!fx.cases.is_empty());
    for case in &fx.cases {
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&case.input, &mut handler).expect("rust transport ran");
        let stdout = as_stdout(&written);

        if case.runtime_text_masked {
            assert_eq!(
                written.len(),
                case.frames.len(),
                "case {}: frame count differs ({})",
                case.name,
                case.why
            );
            for (i, (got, want)) in written.iter().zip(case.frames.iter()).enumerate() {
                assert_eq!(
                    &mask(got, &fx.runtime_text_sentinel),
                    want,
                    "case {} frame {}: masked output differs ({})",
                    case.name,
                    i,
                    case.why
                );
            }
        } else {
            assert_eq!(
                stdout, case.stdout_raw,
                "case {}: stdout byte stream differs ({})",
                case.name, case.why
            );
        }
    }
}

/// The whole point of the row: nothing reaches stdout that is not a framed
/// JSON-RPC message, one per line, each newline-terminated.
#[test]
fn stdout_carries_only_framed_json_rpc() {
    let fx = load();
    for case in &fx.cases {
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&case.input, &mut handler).expect("rust transport ran");
        for frame in &written {
            assert!(
                !frame.contains('\n'),
                "case {}: a frame carries an embedded newline and would desynchronise framing",
                case.name
            );
            let parsed: serde_json::Value =
                serde_json::from_str(frame).expect("every stdout frame must be valid JSON");
            assert_eq!(
                parsed.get("jsonrpc").and_then(|v| v.as_str()),
                Some("2.0"),
                "case {}: a stdout frame is not a JSON-RPC message",
                case.name
            );
        }
    }
}

/// A frame with no trailing newline is never dispatched. This is the oracle's
/// behavior, not a convenience: getting it wrong means answering a request the
/// oracle silently drops.
#[test]
fn unterminated_frame_is_discarded() {
    let fx = load();
    let case = fx
        .cases
        .iter()
        .find(|c| c.name == "unterminated_frame_is_discarded")
        .expect("fixture carries the unterminated case");
    assert_eq!(case.stdout_raw, "", "the oracle answers nothing here");

    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let written = run_stream(&case.input, &mut handler).expect("rust transport ran");
    assert!(
        written.is_empty(),
        "an unterminated frame must be dropped, got {written:?}"
    );
}

/// Legacy Go is unbounded; Rust retains this measured five-megabyte input
/// below its explicitly documented eight-megabyte bound. Rebuilt from the fixture's shape
/// description rather than embedding megabytes in the corpus.
#[test]
fn bounds_match_go_oracle() {
    let fx = load();
    assert!(
        !fx.input_is_bounded,
        "the oracle does not bound input; a port that does has diverged"
    );
    for probe in &fx.bounds {
        // Rebuilt from the recorded shape alone. Keying this on the probe's
        // name instead would make the shape fields decorative: changing one
        // would not change what is replayed.
        let input = format!(
            "{}{}{}{}",
            probe.prefix,
            probe.fill_rune.repeat(probe.fill_count),
            probe.close_rune.repeat(probe.close_count),
            probe.suffix
        );
        assert_eq!(
            input.len(),
            probe.input_bytes,
            "probe {}: rebuilt input does not match the recorded size",
            probe.name
        );

        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&input, &mut handler).expect("rust transport ran");
        assert_eq!(
            written.len(),
            1,
            "probe {}: expected exactly one frame ({})",
            probe.name,
            probe.why
        );
        if probe.masked {
            let want: serde_json::Value = serde_json::from_str(
                probe
                    .stdout_raw
                    .strip_suffix('\n')
                    .unwrap_or(&probe.stdout_raw),
            )
            .expect("recorded probe output is JSON");
            let want = {
                // The recorded stream is unmasked; mask both sides by one rule.
                let mut v = want;
                if let Some(err) = v.get_mut("error").and_then(|e| e.as_object_mut())
                    && let Some(d) = err.get("data").and_then(|d| d.as_str())
                    && !contract_authored(d)
                {
                    err.insert(
                        "data".to_string(),
                        serde_json::Value::String(fx.runtime_text_sentinel.clone()),
                    );
                }
                v
            };
            assert_eq!(
                mask(&written[0], &fx.runtime_text_sentinel),
                want,
                "probe {}: masked output differs ({})",
                probe.name,
                probe.why
            );
        } else {
            assert_eq!(
                as_stdout(&written),
                probe.stdout_raw,
                "probe {}: stdout differs ({})",
                probe.name,
                probe.why
            );
        }
    }
}

/// The adjudicated divergence, asserted rather than only described: invalid
/// UTF-8 is rejected fail-closed and no invalid byte reaches stdout.
#[test]
fn invalid_utf8_is_rejected_fail_closed() {
    let fx = load();
    assert!(
        fx.divergences
            .iter()
            .any(|d| d.name == "invalid_utf8_id_echoed_verbatim"),
        "the fixture must still record this divergence"
    );

    let frame = b"{\"jsonrpc\":\"2.0\",\"id\":\"\xff\xfe\",\"method\":\"ping\"}";
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let written = handle_line_bytes(frame, &mut handler)
        .expect("rust transport ran")
        .expect("an invalid frame is answered, not dropped");

    assert!(written.is_ascii(), "no invalid byte may reach stdout");
    let parsed: serde_json::Value = serde_json::from_str(&written).expect("answer is JSON");
    assert_eq!(parsed["error"]["code"], -32700);
    assert!(
        parsed.get("id").is_none(),
        "an unparseable frame has no id to echo"
    );
}

/// Valid UTF-8 still flows through the byte entry point unchanged, so the
/// rejection above is specific rather than the byte path being broken.
#[test]
fn byte_entry_point_passes_valid_frames_through() {
    let fx = load();
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let written = handle_line_bytes(
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}",
        &mut handler,
    )
    .expect("rust transport ran")
    .expect("a valid frame is answered");
    assert_eq!(written, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
}

/// Negative control: the sweep would be vacuous if an empty corpus passed.
#[test]
fn corpus_is_not_empty() {
    let fx = load();
    assert!(fx.cases.len() >= 15, "corpus shrank unexpectedly");
    assert_eq!(fx.bounds.len(), 9);
    assert_eq!(fx.divergences.len(), 3);
    assert_eq!(fx.duplicate_envelope_probes.len(), 8);
}

/// The nesting bound is asserted at both sides of the measured boundary, so a
/// port that drops the guard or moves it by one fails here.
#[test]
fn nesting_boundary_matches_the_measured_oracle_limit() {
    let fx = load();
    assert_eq!(
        fx.max_accepted_nesting_depth,
        symvault_mcp::MAX_ACCEPTED_NESTING_DEPTH,
        "the Rust bound drifted from the depth measured against the oracle"
    );

    // `total` counts the enclosing frame object, so the payload carries one
    // bracket pair fewer.
    let frame = |total: usize| {
        let inner = total - 1;
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"p\":{}{}}}\n",
            "[".repeat(inner),
            "]".repeat(inner)
        )
    };

    // One below the boundary: dispatched normally.
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let accepted = run_stream(&frame(fx.max_accepted_nesting_depth), &mut handler)
        .expect("rust transport ran");
    assert_eq!(accepted.len(), 1);
    assert!(
        accepted[0].contains("\"result\""),
        "depth {} is accepted by the oracle and must be dispatched, got {}",
        fx.max_accepted_nesting_depth,
        accepted[0]
    );

    // One above: rejected, matching the oracle rather than being more lenient.
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let rejected = run_stream(&frame(fx.max_accepted_nesting_depth + 1), &mut handler)
        .expect("rust transport ran");
    assert_eq!(rejected.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&rejected[0]).expect("answer is JSON");
    assert_eq!(
        parsed["error"]["code"],
        -32700,
        "depth {} is rejected by the oracle and must be rejected here too",
        fx.max_accepted_nesting_depth + 1
    );
}

/// The adjudicated duplicate-key divergence, asserted rather than only written
/// down: the oracle answers id 2, this port refuses the frame.
#[test]
fn duplicate_keys_are_rejected_fail_closed() {
    let fx = load();
    let recorded = fx
        .divergences
        .iter()
        .find(|d| d.name == "duplicate_object_keys_last_wins")
        .expect("the fixture must still record this divergence");
    assert!(
        recorded.oracle_stdout_note.contains("\"id\":2"),
        "the recorded oracle behavior must still be last-wins"
    );

    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let written = run_stream(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"method\":\"ping\"}\n",
        &mut handler,
    )
    .expect("rust transport ran");
    assert_eq!(written.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&written[0]).expect("answer is JSON");
    assert_eq!(
        parsed["error"]["code"], -32700,
        "a duplicated key must not be silently resolved to the last occurrence"
    );
}

/// ADR 0034 item 15 (MCP-004), measured: a key duplicated inside `params` is
/// NOT rejected. The oracle's encoding/json resolves it last-wins (recorded
/// from the real transport as case `duplicate_key_inside_params`: initialize
/// negotiates the second `protocolVersion`) and the port does exactly the
/// same, so this is parity and not a divergence. The ADR's expected `-32602`
/// for this shape does not hold at the pinned revision.
#[test]
fn duplicate_key_inside_params_is_last_wins_like_go_not_invalid_params() {
    let fx = load();
    let case = fx
        .cases
        .iter()
        .find(|c| c.name == "duplicate_key_inside_params")
        .expect("the corpus must carry the Go-recorded duplicate-in-params case");
    assert_eq!(case.frames.len(), 1);
    assert!(
        case.frames[0].get("error").is_none()
            && case.frames[0]["result"]["protocolVersion"] == "2025-03-26",
        "Go must still answer with the LAST protocolVersion: {}",
        case.stdout_raw
    );
    assert!(!case.runtime_text_masked);

    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let written = run_stream(&case.input, &mut handler).expect("rust transport ran");
    assert_eq!(as_stdout(&written), case.stdout_raw);
    let parsed: serde_json::Value = serde_json::from_str(&written[0]).expect("answer is JSON");
    assert_eq!(parsed["result"]["protocolVersion"], "2025-03-26");
    assert!(
        parsed.get("error").is_none(),
        "a duplicate inside params is not -32602 here: {parsed}"
    );

    // The envelope-level duplicate stays rejected, so the two shapes are
    // distinguished by this pair of tests and not collapsed into one rule.
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let envelope = run_stream(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"method\":\"ping\"}\n",
        &mut handler,
    )
    .expect("rust transport ran");
    let envelope: serde_json::Value = serde_json::from_str(&envelope[0]).expect("answer is JSON");
    assert_eq!(envelope["error"]["code"], -32700);
}

/// MCP-004-DUP: how `encoding/json` treats duplicated and wrong-typed members
/// inside `params`, recorded from the real Go transport and replayed here.
/// A plain duplicate is last-wins (above); a WRONG-TYPED earlier duplicate
/// fails the whole decode with `-32602`, `null` is a no-op that keeps an
/// earlier value, and case variants of one name all land in the same field in
/// document order. Each case is asserted against both the recorded Go frame
/// and the Rust output, so neither side can drift alone.
#[test]
fn duplicate_and_wrong_typed_params_members_follow_encoding_json() {
    enum Expect {
        /// The last frame is a result carrying this negotiated version.
        Version(&'static str),
        /// The last frame is a JSON-RPC error with this code and message.
        Error(i64, &'static str),
    }
    let expectations = [
        ("duplicate_key_inside_params", Expect::Version("2025-03-26")),
        (
            "duplicate_params_wrong_typed_first",
            Expect::Error(-32602, "Invalid params"),
        ),
        (
            "duplicate_params_wrong_typed_last",
            Expect::Error(-32602, "Invalid params"),
        ),
        (
            "duplicate_params_null_after_string_keeps_string",
            Expect::Version("2024-11-05"),
        ),
        (
            "duplicate_params_case_variants_last_member_wins",
            Expect::Version("2025-03-26"),
        ),
        (
            "duplicate_params_case_variants_exact_last",
            Expect::Version("2025-03-26"),
        ),
        (
            "duplicate_params_clientinfo_wrong_typed_then_null",
            Expect::Error(-32602, "Invalid params"),
        ),
        (
            "clientinfo_inner_member_wrong_typed",
            Expect::Error(-32602, "Invalid params"),
        ),
        (
            "clientinfo_inner_duplicate_wrong_typed_first",
            Expect::Error(-32602, "Invalid params"),
        ),
        (
            "clientinfo_inner_duplicate_plain_is_accepted",
            Expect::Version("2025-03-26"),
        ),
        (
            "prompts_get_duplicate_name_wrong_typed_first",
            Expect::Error(-32602, "Invalid params"),
        ),
        (
            "prompts_get_duplicate_name_null_keeps_name",
            Expect::Error(-32602, "Unknown prompt: nope"),
        ),
        (
            "prompts_get_duplicate_arguments_merge",
            Expect::Error(-32602, "Missing required argument: to_agent"),
        ),
        (
            "prompts_get_duplicate_arguments_wrong_typed_value_first",
            Expect::Error(-32602, "Invalid params"),
        ),
        (
            "prompts_get_duplicate_arguments_null_clears",
            Expect::Error(-32602, "Missing required argument: query"),
        ),
    ];

    let fx = load();
    for (name, expect) in expectations {
        let case = fx
            .cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("the corpus must carry the Go-recorded case {name}"));

        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&case.input, &mut handler).expect("rust transport ran");
        let rust_frames: Vec<serde_json::Value> = written
            .iter()
            .map(|line| serde_json::from_str(line).expect("answer is JSON"))
            .collect();
        assert_eq!(rust_frames.len(), case.frames.len(), "{name}: frame count");

        for (side, last) in [
            ("Go", case.frames.last().expect("recorded frame")),
            ("Rust", rust_frames.last().expect("rust frame")),
        ] {
            match &expect {
                Expect::Version(version) => {
                    assert!(last.get("error").is_none(), "{name}: {side}: {last}");
                    assert_eq!(
                        last["result"]["protocolVersion"], *version,
                        "{name}: {side}"
                    );
                }
                Expect::Error(code, message) => {
                    assert_eq!(last["error"]["code"], *code, "{name}: {side}: {last}");
                    assert_eq!(last["error"]["message"], *message, "{name}: {side}");
                }
            }
        }
    }
}

/// PIN-LOW: the decoder error text of `initialize` params is compared EXACTLY,
/// not through the mask. Every recorded case and bounds probe whose Go answer
/// is an `InitializeParams`/`ClientInfo` decode error must be reproduced byte
/// for byte by Rust, so the struct and field path in the message
/// (`ClientInfo.clientInfo.name`, not `ClientInfo.name`) cannot drift behind
/// the `<runtime-error-text>` sentinel.
#[test]
fn initialize_decode_error_text_matches_go_exactly() {
    let fx = load();
    let mut inputs: Vec<(String, String, String)> = fx
        .cases
        .iter()
        .map(|c| (c.name.clone(), c.input.clone(), c.stdout_raw.clone()))
        .collect();
    for probe in &fx.bounds {
        let input = format!(
            "{}{}{}{}",
            probe.prefix,
            probe.fill_rune.repeat(probe.fill_count),
            probe.close_rune.repeat(probe.close_count),
            probe.suffix
        );
        inputs.push((probe.name.clone(), input, probe.stdout_raw.clone()));
    }

    let mut compared = Vec::new();
    for (name, input, go_stdout) in &inputs {
        if !go_stdout.contains("Go struct field InitializeParams.")
            && !go_stdout.contains("Go struct field ClientInfo.")
            && !go_stdout.contains("into Go value of type server.InitializeParams")
        {
            continue;
        }
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(input, &mut handler).expect("rust transport ran");
        assert_eq!(
            &as_stdout(&written),
            go_stdout,
            "{name}: initialize decode error text differs from the recorded Go frame"
        );
        compared.push(name.as_str());
    }
    for required in [
        "duplicate_params_wrong_typed_first",
        "duplicate_params_wrong_typed_last",
        "duplicate_params_clientinfo_wrong_typed_then_null",
        "clientinfo_inner_member_wrong_typed",
        "clientinfo_inner_duplicate_wrong_typed_first",
        "initialize_deep_unknown_member_then_wrong_typed_version",
        "initialize_deep_clientinfo_extra_member_then_wrong_typed_name",
    ] {
        assert!(
            compared.contains(&required),
            "{required} must be among the exactly-compared error texts: {compared:?}"
        );
    }
    assert!(
        inputs
            .iter()
            .any(|(n, _, out)| n == "clientinfo_inner_member_wrong_typed"
                && out.contains("Go struct field ClientInfo.clientInfo.name of type string")),
        "the recorded Go frame must carry the ClientInfo.clientInfo.name path"
    );
}

/// MCP-004-ENV-DATA: `RPCError.Data` is an `any`, so `encoding/json` decodes
/// it and rejects a number overflowing float64 wherever it sits (top level,
/// nested array, nested object). The Go frame is compared EXACTLY (no mask)
/// through stdio, answered 400 over HTTP, and a large-but-finite number (and
/// an underflow) is still a response.
#[test]
fn error_data_number_overflow_matches_go_exactly() {
    let fx = load();
    let find = |name: &str| {
        fx.cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("corpus lost case {name}"))
    };
    for (name, number) in [
        ("envelope_error_data_number_overflow", "1e400"),
        ("envelope_error_data_number_overflow_negative", "-1e400"),
        ("envelope_error_data_number_overflow_nested_array", "1e400"),
        (
            "envelope_error_data_number_overflow_nested_object",
            "-1e999",
        ),
    ] {
        let case = find(name);
        assert!(
            case.stdout_raw.contains(&format!(
                "json: cannot unmarshal number {number} into Go struct field RPCError.error.data of type float64"
            )) && case.stdout_raw.contains("\"code\":-32700"),
            "{name}: the recorded Go frame changed: {}",
            case.stdout_raw
        );
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&case.input, &mut handler).expect("rust transport ran");
        assert_eq!(as_stdout(&written), case.stdout_raw, "{name}: stdio");
        let body = single_frame(&case.input).expect("single frame");
        assert_eq!(http_post(&fx, body).status, 400, "{name}: HTTP");
    }
    let accepted = find("envelope_error_data_large_finite_number_is_accepted");
    assert!(
        accepted
            .stdout_raw
            .starts_with("{\"error\":{\"message\":\"Internal error\"")
    );
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let written = run_stream(&accepted.input, &mut handler).expect("rust transport ran");
    assert_eq!(as_stdout(&written), accepted.stdout_raw, "accepted: stdio");
}

/// PIN-LOW: `encoding/json` accepts a lone surrogate escape in `params`
/// (decoded to U+FFFD) and nesting up to the 10000-level frame limit, inside
/// `capabilities` (a `json.RawMessage`), unknown members, keys and
/// `clientInfo`; a `serde_json::Value` parse rejects the former and stops at
/// 128 levels. The Go frames are asserted first so the expectation is the
/// oracle's, then Rust must produce the same bytes.
#[test]
fn lone_surrogates_and_deep_params_are_accepted_like_go() {
    let fx = load();
    let expectations = [
        (
            "initialize_lone_surrogate_in_protocol_version",
            "2025-11-25",
        ),
        (
            "initialize_lone_surrogate_in_unknown_members_and_keys",
            "2024-11-05",
        ),
        (
            "initialize_lone_surrogate_in_capabilities_and_clientinfo",
            "2025-03-26",
        ),
        (
            "initialize_escaped_field_name_selects_the_field",
            "2024-11-05",
        ),
        (
            "initialize_lone_surrogate_pair_halves_are_not_merged",
            "2024-11-05",
        ),
    ];
    for (name, version) in expectations {
        let case = fx
            .cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing Go-recorded case {name}"));
        assert_eq!(
            case.frames[0]["result"]["protocolVersion"], version,
            "{name}: Go"
        );
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&case.input, &mut handler).expect("rust transport ran");
        assert_eq!(
            as_stdout(&written),
            case.stdout_raw,
            "{name}: Rust vs Go bytes"
        );
    }

    for (name, version) in [
        (
            "initialize_capabilities_nested_to_the_depth_limit",
            "2024-11-05",
        ),
        (
            "initialize_unknown_member_nested_to_the_depth_limit",
            "2025-03-26",
        ),
    ] {
        let probe = fx
            .bounds
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("missing Go-recorded probe {name}"));
        let go: serde_json::Value =
            serde_json::from_str(probe.stdout_raw.trim_end()).expect("Go frame is JSON");
        assert_eq!(go["result"]["protocolVersion"], version, "{name}: Go");
        let input = format!(
            "{}{}{}{}",
            probe.prefix,
            probe.fill_rune.repeat(probe.fill_count),
            probe.close_rune.repeat(probe.close_count),
            probe.suffix
        );
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&input, &mut handler).expect("rust transport ran");
        assert_eq!(
            as_stdout(&written),
            probe.stdout_raw,
            "{name}: Rust vs Go bytes"
        );
    }
}

/// MCP-004-ENV: the envelope members follow `encoding/json` (null no-ops,
/// case-insensitive names with the U+017F fold, first type error wins). The
/// replay in `hostile_frames_match_go_oracle` is only meaningful if these
/// recorded shapes are really in the corpus, so pin their presence and the
/// oracle answers that distinguish Go from a derived serde decode.
#[test]
fn envelope_member_semantics_are_in_the_replayed_corpus() {
    let fx = load();
    let answer = |name: &str| -> String {
        fx.cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("corpus lost case {name}"))
            .stdout_raw
            .clone()
    };
    // Null members are no-ops: an Invalid Request, never a parse error.
    assert!(answer("envelope_method_null_is_noop").contains("\"code\":-32600"));
    assert!(answer("envelope_jsonrpc_null_is_noop").contains("jsonrpc must be 2.0"));
    assert!(answer("envelope_id_null_is_a_present_id").contains("\"id\":null"));
    // Case-folded names select the member.
    for name in [
        "envelope_method_uppercase_key",
        "envelope_method_titlecase_key",
        "envelope_jsonrpc_titlecase_key",
        "envelope_jsonrpc_uppercase_key",
        "envelope_escaped_method_key",
    ] {
        assert_eq!(
            answer(name),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
            "{name}"
        );
    }
    assert!(answer("envelope_id_uppercase_key").contains("\"id\":9"));
    for name in [
        "envelope_params_uppercase_key",
        "envelope_params_long_s_literal_key",
        "envelope_params_long_s_escaped_key",
    ] {
        assert!(
            answer(name).contains("\"protocolVersion\":\"2024-11-05\""),
            "{name}"
        );
    }
    // The Kelvin sign folds to k but no envelope member contains one.
    assert!(
        answer("envelope_kelvin_sign_does_not_select_an_envelope_member")
            .contains("method is required")
    );
    // A wrong-typed member fails the decode wherever its duplicate sits.
    for name in [
        "envelope_method_wrong_typed_earlier_duplicate_case_variant",
        "envelope_method_wrong_typed_later_duplicate_case_variant",
        "envelope_jsonrpc_wrong_typed_earlier_duplicate",
    ] {
        assert!(answer(name).contains("\"code\":-32700"), "{name}");
    }
}

/// ADR 0032 row 4 extended to case variants and `null` duplicates: every frame
/// below is ACCEPTED by `encoding/json` (the answer is recorded from the real
/// transport) and REJECTED here with `-32700`, never dispatched. Each probe is
/// asserted from both sides so neither the recorded oracle behavior nor the
/// fail-closed rejection can drift unnoticed.
#[test]
fn duplicate_envelope_members_are_rejected_fail_closed() {
    let fx = load();
    assert!(!fx.duplicate_envelope_probes.is_empty());
    for probe in &fx.duplicate_envelope_probes {
        assert!(
            !probe.oracle_stdout_raw.contains("\"code\":-32700"),
            "probe {}: the oracle must accept it, otherwise it belongs in cases ({})",
            probe.name,
            probe.why
        );
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let written = run_stream(&probe.input, &mut handler).expect("rust transport ran");
        assert_eq!(
            written.len(),
            probe.input.lines().count(),
            "probe {}: every input line is answered",
            probe.name
        );
        let first: serde_json::Value = serde_json::from_str(&written[0]).expect("answer is JSON");
        assert_eq!(
            first["error"]["code"], -32700,
            "probe {}: a repeated envelope member must be refused ({})",
            probe.name, probe.why
        );
        assert!(
            first.get("id").is_none(),
            "probe {}: no id to echo",
            probe.name
        );
        // The refusal is specific to the repeat: the first spelling alone is
        // dispatched. A probe whose single-member form were also refused
        // would only prove the parser is broken.
        if probe.name == "duplicate_method_case_variant_last_wins" {
            let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
            let single = run_stream(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"METHOD\":\"ping\"}\n",
                &mut handler,
            )
            .expect("rust transport ran");
            assert_eq!(single, vec![r#"{"jsonrpc":"2.0","id":1,"result":{}}"#]);
        }
    }
}

/// Posts one frame body through the HTTP adapter with a fresh handler.
fn http_post(fx: &Fixture, body: &str) -> symvault_mcp::http::HttpResponse {
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    symvault_mcp::http::handle_request(
        symvault_mcp::http::HttpRequest {
            method: "POST",
            path: "/mcp",
            content_type: "application/json",
            accept: "application/json, text/event-stream",
            protocol_version: "",
            body,
        },
        &mut handler,
    )
    .expect("http adapter ran")
}

/// The single-line body of a recorded frame, when it is one.
fn single_frame(input: &str) -> Option<&str> {
    let body = input.strip_suffix('\n')?;
    (!body.contains('\n')).then_some(body)
}

/// MCP-004-ENV, HTTP side. Go's HTTP handler decodes into the same
/// `transport.Message` and calls the same `HandleMessage` as the stdio loop,
/// minus the stdio `jsonrpc`/`method` guards, so the envelope outcomes the
/// stdio generator recorded from the real transport are also the HTTP
/// oracle for the decode: a frame Go's decoder rejects is a 400 here, and a
/// frame that reaches the handler is answered with the recorded bytes. A
/// dedicated Go-recorded HTTP generator exists (`http001initgen`), but it can
/// only be regenerated in its frozen historical checkout, so its 27-case
/// corpus is not extended; this replay is the HTTP coverage for the envelope.
#[test]
fn http_envelope_decode_follows_the_recorded_go_envelope_outcomes() {
    let fx = load();
    let mut replayed = 0;
    let mut rejected = 0;
    let mut dispatched = 0;
    for case in fx.cases.iter().filter(|c| c.name.starts_with("envelope_")) {
        let Some(body) = single_frame(&case.input) else {
            continue;
        };
        let response = http_post(&fx, body);
        let go_rejects = case.stdout_raw.contains("\"code\":-32700");
        let guard_failed = case.stdout_raw.contains("jsonrpc must be 2.0")
            || case.stdout_raw.contains("method is required");
        replayed += 1;
        if go_rejects {
            rejected += 1;
            assert_eq!(
                response.status, 400,
                "case {}: Go's decoder rejects it, so HTTP answers 400 ({})",
                case.name, case.why
            );
        } else if guard_failed {
            // Only the stdio loop has these guards; HTTP dispatches the
            // decoded message, so the decode itself must have succeeded.
            assert_ne!(
                response.status, 400,
                "case {}: Go decodes it, so HTTP must not reject it as invalid JSON ({})",
                case.name, case.why
            );
        } else {
            dispatched += 1;
            assert_eq!(response.status, 200, "case {}", case.name);
            assert_eq!(
                String::from_utf8(response.body).expect("utf-8"),
                case.stdout_raw,
                "case {}: HTTP answer differs from the recorded Go answer ({})",
                case.name,
                case.why
            );
        }
    }
    assert!(
        replayed >= 30 && rejected >= 8 && dispatched >= 14,
        "the HTTP replay went vacuous: {replayed} replayed, {rejected} rejected, {dispatched} dispatched"
    );
}

/// HTTP keeps Go's own last-wins for repeated envelope members (only the stdio
/// loop rejects them by ADR 0032 row 4), so every single-line duplicate probe
/// is answered with exactly the bytes the Go transport recorded.
#[test]
fn http_envelope_duplicates_resolve_last_wins_like_go() {
    let fx = load();
    let mut replayed = 0;
    for probe in &fx.duplicate_envelope_probes {
        let Some(body) = single_frame(&probe.input) else {
            continue;
        };
        replayed += 1;
        let response = http_post(&fx, body);
        assert_eq!(response.status, 200, "probe {}", probe.name);
        assert_eq!(
            String::from_utf8(response.body).expect("utf-8"),
            probe.oracle_stdout_raw,
            "probe {}: HTTP differs from the recorded Go answer ({})",
            probe.name,
            probe.why
        );
    }
    assert_eq!(
        replayed, 7,
        "the single-line duplicate probes were not all replayed"
    );
}

// ---------------------------------------------------------------------------
// tools/call `arguments` (ADR 0034 item 15). The probes are recorded by running
// the oracle commit's own code with a real tool Server (`mcpstdiogen`
// `tools_call_arguments`), because a Server-less handler answers "vault locked"
// before it decodes params.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct EmptyStore;

impl ReadOnlyStore for EmptyStore {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String> {
        Ok(Vec::new())
    }

    fn get(&self, _path: &str) -> Result<Option<ReadOnlyEntry>, String> {
        Ok(None)
    }
}

fn tool_runtime() -> Arc<ReadOnlyRuntime<EmptyStore>> {
    let mut available_tools = read_only_tool_names();
    available_tools.push("generate_template".into());
    Arc::new(ReadOnlyRuntime::new(
        EmptyStore,
        ReadOnlyRuntimeConfig {
            server_name: "symvault".into(),
            server_version: "0.0.0-fixture".into(),
            transport: "stdio".into(),
            agent_name: "fixture".into(),
            approval_mode: "none".into(),
            allowed_paths: vec!["*".into()],
            available_tools,
            vault_dir: "<fixture-vault>".into(),
            vault_unlocked: true,
            ..ReadOnlyRuntimeConfig::default()
        },
    ))
}

/// Replaces the random 16-hex data-fence id with the fixture's mask.
fn mask_nonce(text: &str, mask: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("DATA_") {
        out.push_str(&rest[..at]);
        let id = rest.get(at + 5..at + 21);
        if id.is_some_and(|id| id.bytes().all(|b| b.is_ascii_hexdigit())) {
            out.push_str(mask);
            rest = &rest[at + 21..];
        } else {
            out.push_str("DATA_");
            rest = &rest[at + 5..];
        }
    }
    out.push_str(rest);
    out
}

fn mask_value(value: &mut serde_json::Value, nonce_mask: &str) {
    match value {
        serde_json::Value::String(text) => *text = mask_nonce(text, nonce_mask),
        serde_json::Value::Array(items) => items.iter_mut().for_each(|v| mask_value(v, nonce_mask)),
        serde_json::Value::Object(map) => map.values_mut().for_each(|v| mask_value(v, nonce_mask)),
        _ => {}
    }
}

fn expected_frames(
    probe: &ArgumentsProbe,
    nonce_mask: &str,
    sentinel: &str,
) -> Vec<serde_json::Value> {
    probe
        .stdout_after_initialize
        .lines()
        .map(|line| {
            let mut value = mask(line, sentinel);
            mask_value(&mut value, nonce_mask);
            value
        })
        .collect()
}

/// The Rust frames for one probe (the initialize answer dropped).
fn rust_frames(fx: &Fixture, probe: &ArgumentsProbe) -> Vec<serde_json::Value> {
    let mut handler = ProtocolHandler::with_tool_call_runtime(
        &fx.server_name,
        &fx.server_version,
        tool_runtime(),
    );
    let section = &fx.tools_call_arguments;
    let lines = run_stream(&probe.input(&section.handshake), &mut handler)
        .unwrap_or_else(|e| panic!("probe {}: rust transport: {e}", probe.name));
    lines
        .iter()
        .skip(1)
        .map(|line| {
            let mut value = mask(line, &fx.runtime_text_sentinel);
            mask_value(&mut value, &section.nonce_mask);
            value
        })
        .collect()
}

/// Probes where Rust is stricter than the oracle and says so (ADR 0034 item 15,
/// "Not ported (Rust stricter)"): every one of them nests an object `arguments`
/// past what a `serde_json::Value` holds (the arguments object plus 126 array
/// levels is the deepest Rust accepts; 127 levels in a member is the first
/// rejected). The set is asserted exactly, in both
/// directions, by the two tests below.
const DEPTH_STRICTER: [&str; 6] = [
    "args_nested_arrays_127_levels_in_a_member",
    "args_nested_arrays_128_levels_in_a_member",
    "args_nested_arrays_129_levels_in_a_member",
    "args_nested_arrays_1000_levels_in_a_member",
    "args_nested_objects_129_levels_in_a_member",
    "args_total_depth_10000_is_accepted",
];

#[test]
fn tools_call_arguments_fixture_is_the_pinned_oracle_and_covers_the_boundaries() {
    let fx = load();
    let section = &fx.tools_call_arguments;
    assert_eq!(
        section.oracle_commit_sha,
        "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
    );
    assert_eq!(fx.oracle.commit_sha, section.oracle_commit_sha);
    assert_eq!(section.probes.len(), 47, "the probe corpus changed size");
    let names: Vec<&str> = section.probes.iter().map(|p| p.name.as_str()).collect();
    for needed in [
        "args_duplicate_top_level_last_wins",
        "args_duplicate_nested_last_wins_drops_wrong_typed_alias",
        "args_keys_are_case_sensitive_nested",
        "args_lone_surrogate_in_nested_key_and_value",
        "args_number_overflow_top_level_member",
        "args_nested_arrays_129_levels_in_a_member",
        "args_nested_arrays_1000_levels_in_a_member",
        "args_total_depth_10000_is_accepted",
        "args_total_depth_10001_is_rejected_by_the_frame",
    ] {
        assert!(names.contains(&needed), "missing probe {needed}");
    }
    for name in DEPTH_STRICTER {
        assert!(names.contains(&name), "missing depth probe {name}");
    }
    // The recorded oracle really executed the tool for every accepted shape and
    // really failed the decode for the overflow shapes (not a vacuous corpus).
    let by_name = |n: &str| {
        section
            .probes
            .iter()
            .find(|p| p.name == n)
            .unwrap_or_else(|| panic!("missing probe {n}"))
    };
    assert!(
        by_name("args_total_depth_10000_is_accepted")
            .stdout_after_initialize
            .contains("\"isError\":false")
    );
    assert!(
        by_name("args_number_overflow_top_level_member")
            .stdout_after_initialize
            .contains(
                "parse arguments: json: cannot unmarshal number 1e400 into Go value of type float64"
            )
    );
    assert!(
        !by_name("args_baseline").why.is_empty(),
        "every probe carries its reason"
    );
}

/// Every recorded probe outside the declared depth difference is answered with
/// exactly the oracle's frames: duplicate members (top level and nested),
/// case-sensitive keys, lone surrogates, float64 overflow and its precedence
/// over the tool lookup, non-object kinds, and nesting up to 127 levels.
#[test]
fn tools_call_arguments_match_the_oracle_outside_the_declared_depth_difference() {
    let fx = load();
    let mut compared = 0;
    for probe in &fx.tools_call_arguments.probes {
        if DEPTH_STRICTER.contains(&probe.name.as_str()) {
            continue;
        }
        let expected = expected_frames(
            probe,
            &fx.tools_call_arguments.nonce_mask,
            &fx.runtime_text_sentinel,
        );
        assert_eq!(
            rust_frames(&fx, probe),
            expected,
            "probe {} ({}) differs from the oracle",
            probe.name,
            probe.why
        );
        compared += 1;
    }
    assert_eq!(
        compared,
        fx.tools_call_arguments.probes.len() - DEPTH_STRICTER.len()
    );
}

/// ADR 0034 item 15 (ratified): an object `arguments` nested beyond serde_json's
/// 128-level `Value` limit is `-32602` in Rust where the oracle executes the
/// tool. Pinned from both sides: the oracle's acceptance is recorded in the
/// fixture, Rust's rejection (and its exact set) is asserted here, and a
/// frame past the 10000-level total is `-32700` in both.
#[test]
fn tools_call_arguments_nesting_beyond_the_value_limit_is_rust_stricter() {
    let fx = load();
    let recorded = fx
        .divergences
        .iter()
        .find(|d| d.name == "tools_call_arguments_nesting_beyond_serde_value_limit")
        .expect("the fixture must still record this divergence");
    assert!(recorded.oracle_stdout_note.contains("tools_call_arguments"));

    let mut stricter = Vec::new();
    for probe in &fx.tools_call_arguments.probes {
        let expected = expected_frames(
            probe,
            &fx.tools_call_arguments.nonce_mask,
            &fx.runtime_text_sentinel,
        );
        let actual = rust_frames(&fx, probe);
        if actual != expected {
            stricter.push(probe.name.as_str());
            assert_eq!(actual.len(), 1, "probe {}", probe.name);
            assert_eq!(actual[0]["error"]["code"], -32602, "probe {}", probe.name);
            assert_eq!(actual[0]["error"]["message"], "Invalid params");
            assert!(
                expected[0].get("result").is_some(),
                "probe {}: the oracle must have executed the tool",
                probe.name
            );
        }
    }
    let mut want: Vec<&str> = DEPTH_STRICTER.to_vec();
    want.sort_unstable();
    stricter.sort_unstable();
    assert_eq!(stricter, want, "the Rust-stricter set moved");
}
