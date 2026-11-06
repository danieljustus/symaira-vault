//! Operator-path guard for committed Go-oracle recordings.
//!
//! A recording is shared test data: it must never carry the path of the
//! machine it was captured on (`/Volumes/...`, `/Users/...`, the macOS
//! `/var/folders/...` / `/private/var/...` temp roots). Frozen vault trees hide
//! such paths inside base64 file contents (a `config.yaml` `vaultDir`, a backup
//! marker), so the scan decodes every base64-looking string -- and JSON nested
//! in it -- before looking.
//!
//! Used by both recorders (a capture refuses to write a leaking recording) and
//! by `recordings_have_no_operator_paths.rs` (the committed files stay clean).
#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

/// Path prefixes that identify the capturing machine.
pub const PREFIXES: [&str; 4] = ["/Volumes/", "/Users/", "/var/folders/", "/private/var/"];

const MAX_DEPTH: usize = 4;

/// `Some(excerpt)` when `bytes` contains an operator path.
pub fn bytes_hit(bytes: &[u8]) -> Option<String> {
    for prefix in PREFIXES {
        let needle = prefix.as_bytes();
        if let Some(at) = bytes.windows(needle.len()).position(|w| w == needle) {
            let end = bytes[at..]
                .iter()
                .position(|b| b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<'))
                .map_or(bytes.len(), |n| at + n)
                .min(at + 120);
            return Some(String::from_utf8_lossy(&bytes[at..end]).into_owned());
        }
    }
    None
}

fn looks_like_base64(text: &str) -> bool {
    text.len() >= 8
        && text.len().is_multiple_of(4)
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

fn string_hits(label: &str, text: &str, depth: usize, out: &mut Vec<String>) {
    if let Some(hit) = bytes_hit(text.as_bytes()) {
        out.push(format!("{label}: {hit}"));
    }
    if depth >= MAX_DEPTH || !looks_like_base64(text) {
        return;
    }
    let Ok(decoded) = STANDARD.decode(text) else {
        return;
    };
    if let Some(hit) = bytes_hit(&decoded) {
        out.push(format!("{label} (base64): {hit}"));
    }
    if let Ok(nested) = serde_json::from_slice::<Value>(&decoded) {
        value_hits(&format!("{label} (base64 JSON)"), &nested, depth + 1, out);
    }
}

/// Every operator path in `value` (object keys and string leaves, base64
/// decoded), labelled with a JSON pointer-like location.
pub fn value_hits(label: &str, value: &Value, depth: usize, out: &mut Vec<String>) {
    match value {
        Value::String(text) => string_hits(label, text, depth, out),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                value_hits(&format!("{label}[{index}]"), item, depth, out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                string_hits(&format!("{label}.<key>"), key, depth, out);
                value_hits(&format!("{label}.{key}"), item, depth, out);
            }
        }
        _ => {}
    }
}

/// Convenience wrapper: all hits of a whole recording.
pub fn hits_in(label: &str, value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    value_hits(label, value, 0, &mut out);
    out
}

/// Capture-side guard.
pub fn assert_clean(what: &str, value: &Value) {
    let hits = hits_in("$", value);
    assert!(
        hits.is_empty(),
        "{what}: refusing to record the capturing machine's paths (mask them with a \
         placeholder first):\n{}",
        hits.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
    );
}
