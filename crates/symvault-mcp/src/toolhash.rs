//! Tool-registry content hash, byte-compatible with Go's
//! `mcp.ComputeToolRegistryHash` (`internal/mcp/toolhash.go`).
//!
//! The hash is stamped into every scoped token at issue time and compared at
//! call time (`server_dispatch.go`), so a changed tool definition invalidates
//! previously issued tokens. Go and Rust must agree on the digest for the same
//! registry or a token issued by one binary would be refused by the other —
//! the dual-binary rollback path depends on it.
//!
//! Hash material, per tool sorted by name (byte order):
//! `"%s|%s|%s|%v|%v\n"` of name, description, `json.Marshal(inputSchema)`
//! (`{}` on marshal error), readOnlyHint, destructiveHint. Go marshals the
//! schema as a `map[string]any`: object keys sorted, `<`, `>`, `&`, U+2028 and
//! U+2029 escaped, float64 numbers formatted Go-style. All of that is
//! reproduced here independent of serde_json's `preserve_order` feature.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// One tool as the hash sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolHashDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub read_only_hint: bool,
    pub destructive_hint: bool,
}

/// Go `ComputeToolRegistryHash`: lowercase hex SHA-256 over the sorted tools.
pub fn compute_tool_registry_hash(defs: &[ToolHashDef]) -> String {
    let mut sorted: Vec<&ToolHashDef> = defs.iter().collect();
    // Go sorts with sort.Slice on Name: byte-wise string order. Rust's String
    // ordering is byte-wise too. Names are unique in a real registry.
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    let mut hasher = Sha256::new();
    for def in sorted {
        let schema = go_marshal(&def.input_schema);
        let line = format!(
            "{}|{}|{}|{}|{}\n",
            def.name, def.description, schema, def.read_only_hint, def.destructive_hint
        );
        hasher.update(line.as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Hash of the full Rust tool catalog (all 35 definitions, not tier- or
/// availability-filtered), i.e. what Go's `server.init()` stores in
/// `auth.CurrentToolRegistryHash`.
pub fn current_tool_registry_hash() -> Result<String, String> {
    static HASH: OnceLock<Result<String, String>> = OnceLock::new();
    HASH.get_or_init(|| Ok(compute_tool_registry_hash(&crate::tools::hash_defs()?)))
        .clone()
}

/// The catalog as hash definitions, for callers that mutate a copy.
pub fn catalog_hash_defs() -> Result<Vec<ToolHashDef>, String> {
    crate::tools::hash_defs()
}

/// `true` when a token issued against `token_hash` must be refused: Go's
/// `IsToolRegistryDriftDetected`. An empty hash is a legacy token and never
/// drifts.
pub fn is_drift(token_hash: &str, current_hash: &str) -> bool {
    !token_hash.is_empty() && token_hash != current_hash
}

fn go_marshal(value: &Value) -> String {
    // Go: json.Marshal(nil map) is "null", which is also Value::Null here.
    let mut out = String::new();
    write_go_json(value, &mut out);
    out
}

fn write_go_string(text: &str, out: &mut String) {
    // Serializing a str cannot fail.
    out.push_str(&symvault_gojson::to_string(text).unwrap_or_else(|_| "\"\"".to_owned()));
}

/// Go `encoding/json` for a decoded `any` tree: object keys sorted (byte
/// order), HTML-safe string escaping, Go float formatting. Independent of
/// serde_json's map implementation and of its `preserve_order` feature.
fn write_go_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => match number.as_f64() {
            Some(float) if number.is_f64() => out.push_str(&go_float(float)),
            _ => out.push_str(&number.to_string()),
        },
        Value::String(text) => write_go_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_go_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (index, (key, inner)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_go_string(key, out);
                out.push(':');
                write_go_json(inner, out);
            }
            out.push('}');
        }
    }
}

/// Go formats float64 like `strconv.AppendFloat(b, f, fmt, -1, 64)`: the
/// exponent form below 1e-6 and from 1e21 (`e+21`, and `e-07` cleaned to
/// `e-7`), otherwise the shortest round-trip decimal.
fn go_float(float: f64) -> String {
    let abs = float.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        let formatted = format!("{float:e}");
        let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
        let exponent: i32 = exponent.parse().unwrap_or(0);
        if exponent < 0 {
            format!("{mantissa}e-{}", -exponent)
        } else {
            format!("{mantissa}e+{exponent:02}")
        }
    } else {
        format!("{float}")
    }
}
