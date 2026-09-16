//! MCP-004 differential: replays the Go-generated hostile-frame corpus and
//! asserts the stdout byte stream, the absence of bounds the oracle does not
//! have, and the one adjudicated divergence.

use serde::Deserialize;
use symvault_mcp::{ProtocolHandler, handle_line_bytes, run_stream};

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
    divergences: Vec<Divergence>,
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

/// Input is not bounded in the oracle, so the port must not invent a bound: a
/// five-megabyte frame is answered normally. Rebuilt from the fixture's shape
/// description rather than embedding megabytes in the corpus.
#[test]
fn bounds_match_go_oracle() {
    let fx = load();
    assert!(
        !fx.input_is_bounded,
        "the oracle does not bound input; a port that does has diverged"
    );
    for probe in &fx.bounds {
        let input = if probe.name == "pathological_nesting_is_rejected" {
            format!(
                "{}{}{}}}\n",
                probe.prefix,
                "[".repeat(probe.fill_count),
                "]".repeat(probe.fill_count)
            )
        } else {
            format!(
                "{}{}{}",
                probe.prefix,
                probe.fill_rune.repeat(probe.fill_count),
                probe.suffix
            )
        };
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
    assert_eq!(fx.bounds.len(), 3);
    assert_eq!(fx.divergences.len(), 2);
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
