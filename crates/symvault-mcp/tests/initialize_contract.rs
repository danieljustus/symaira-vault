//! MCP-001 differential: replays the Go-generated initialize/handshake corpus
//! against the Rust transport and asserts the observable output.
//!
//! Cases the oracle answers entirely from its own literals are compared as raw
//! bytes, because the byte stream — including JSON key order — is the contract.
//! The four cases whose error `data` is the Go JSON decoder's own wording are
//! compared in the fixture's masked form instead; the mask is applied to the
//! Rust output by the same rule the generator used, and those cases still assert
//! that Rust produced *some* non-empty diagnostic there.

use serde::Deserialize;
use symvault_mcp::{
    LATEST_SUPPORTED_PROTOCOL_VERSION, ProtocolHandler, SUPPORTED_PROTOCOL_VERSIONS,
    is_supported_protocol_version, negotiate_protocol_version, run_stream,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    supported_versions: Vec<String>,
    latest_version: String,
    runtime_text_sentinel: String,
    cases: Vec<Case>,
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
    input: Vec<String>,
    output_raw: Vec<String>,
    output: Vec<serde_json::Value>,
    runtime_text_masked: bool,
}

fn load() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/port/mcp/initialize.json"
    );
    let bytes = std::fs::read(path).expect("read MCP-001 fixture");
    serde_json::from_slice(&bytes).expect("parse MCP-001 fixture")
}

/// The generator's rule, restated: a string `data` is the runtime's wording
/// unless it is one of the oracle's own literals.
fn contract_authored(text: &str) -> bool {
    matches!(text, "jsonrpc must be 2.0" | "method is required")
}

fn mask(line: &str, sentinel: &str) -> (serde_json::Value, bool) {
    let mut value: serde_json::Value = serde_json::from_str(line).expect("rust output is JSON");
    let mut masked = false;
    if let Some(err) = value.get_mut("error").and_then(|e| e.as_object_mut())
        && let Some(data) = err.get("data").and_then(|d| d.as_str())
        && !contract_authored(data)
    {
        assert!(
            !data.is_empty(),
            "masked diagnostic must still be non-empty, got an empty string"
        );
        err.insert(
            "data".to_string(),
            serde_json::Value::String(sentinel.to_string()),
        );
        masked = true;
    }
    (value, masked)
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

/// The protocol constants are part of the contract, not incidental. Pinning them
/// against the fixture means a drift in the oracle's supported set fails here
/// rather than quietly reshaping every negotiation case.
#[test]
fn protocol_constants_match_go_oracle() {
    let fx = load();
    assert_eq!(fx.latest_version, LATEST_SUPPORTED_PROTOCOL_VERSION);
    assert_eq!(
        fx.supported_versions, SUPPORTED_PROTOCOL_VERSIONS,
        "supported protocol version set drifted from the oracle"
    );
    for version in &fx.supported_versions {
        assert!(
            is_supported_protocol_version(version),
            "{version} is supported by the oracle but not by Rust"
        );
        assert_eq!(
            negotiate_protocol_version(version),
            version,
            "a supported version must be echoed back, not upgraded"
        );
    }
}

#[test]
fn handshake_matches_go_oracle() {
    let fx = load();
    assert!(!fx.cases.is_empty(), "fixture carries no cases");

    for case in &fx.cases {
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let mut input = String::new();
        for line in &case.input {
            input.push_str(line);
            input.push('\n');
        }

        let actual = run_stream(&input, &mut handler).expect("rust transport ran");

        assert_eq!(
            actual.len(),
            case.output_raw.len(),
            "case {}: wrote {} line(s), oracle wrote {} ({})",
            case.name,
            actual.len(),
            case.output_raw.len(),
            case.why
        );

        if case.runtime_text_masked {
            for (i, (got, want)) in actual.iter().zip(case.output.iter()).enumerate() {
                let (masked_got, _) = mask(got, &fx.runtime_text_sentinel);
                assert_eq!(
                    &masked_got, want,
                    "case {} line {}: masked output differs ({})",
                    case.name, i, case.why
                );
            }
        } else {
            assert_eq!(
                &actual, &case.output_raw,
                "case {}: byte stream differs ({})",
                case.name, case.why
            );
        }
    }
}

/// Notifications are the one case where writing nothing is the whole contract,
/// so it is asserted on its own rather than only as a length check in the sweep.
#[test]
fn notifications_write_nothing() {
    let fx = load();
    for case in fx
        .cases
        .iter()
        .filter(|c| c.name.starts_with("notification_"))
    {
        assert!(
            case.output_raw.is_empty(),
            "fixture case {} is not silent; the corpus, not the port, is wrong",
            case.name
        );
        let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
        let input = format!("{}\n", case.input[0]);
        let actual = run_stream(&input, &mut handler).expect("rust transport ran");
        assert!(
            actual.is_empty(),
            "case {}: expected stdout silence, got {actual:?}",
            case.name
        );
    }
}

/// An explicit `"id": null` is a present ID, so it must be answered. Getting this
/// wrong turns a request into a notification and hangs the client.
#[test]
fn explicit_null_id_is_a_request_not_a_notification() {
    let fx = load();
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let actual = run_stream(
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}\n",
        &mut handler,
    )
    .expect("rust transport ran");
    assert_eq!(
        actual,
        vec!["{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":{}}".to_string()]
    );
}

/// A bad frame must not take the stream down with it: the oracle answers -32700
/// and keeps reading. This is the stdout-hygiene claim in its smallest form.
#[test]
fn malformed_frame_does_not_stop_the_stream() {
    let fx = load();
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let actual = run_stream(
        "{\"jsonrpc\":\"2.0\",\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
        &mut handler,
    )
    .expect("rust transport ran");
    assert_eq!(
        actual.len(),
        2,
        "expected an error frame and then the answer"
    );
    assert!(
        actual[0].contains("-32700"),
        "first frame must be a parse error"
    );
    assert_eq!(actual[1], "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
}

/// Negative control: if the comparison were vacuous, this would pass too.
#[test]
fn differential_rejects_a_wrong_answer() {
    let fx = load();
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    let actual = run_stream(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
        &mut handler,
    )
    .expect("rust transport ran");
    assert_ne!(
        actual[0], "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}",
        "ping must return an empty object, not null"
    );
}

/// `initialize` flips the handler's state; the oracle sets it unconditionally on
/// a successful handshake.
#[test]
fn initialize_marks_the_connection_initialized() {
    let fx = load();
    let mut handler = ProtocolHandler::new(&fx.server_name, &fx.server_version);
    assert!(!handler.is_initialized());
    run_stream(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n",
        &mut handler,
    )
    .expect("rust transport ran");
    assert!(handler.is_initialized());
}

/// An unknown version negotiates down rather than failing, and an unsupported
/// one is never echoed back.
#[test]
fn unsupported_version_negotiates_to_latest() {
    assert_eq!(
        negotiate_protocol_version("1999-01-01"),
        LATEST_SUPPORTED_PROTOCOL_VERSION
    );
    assert_eq!(
        negotiate_protocol_version(""),
        LATEST_SUPPORTED_PROTOCOL_VERSION
    );
    assert!(!is_supported_protocol_version("1999-01-01"));
}
