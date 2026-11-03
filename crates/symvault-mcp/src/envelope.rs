//! Go-compatible decoding of the JSON-RPC envelope (`transport.Message`).
//!
//! Both transports decode a frame into the same Go struct with
//! `encoding/json`, so both go through this one walker. It reads the object
//! member by member ([`crate::go_params::object_members`]) and applies what
//! `encoding/json` does with a struct target instead of what a derived serde
//! `Deserialize` does:
//!
//! * member names are matched to the envelope fields case-insensitively with
//!   Go's simple Unicode folding ([`crate::go_params::go_field_matches`]:
//!   `"METHOD"`, `"Jsonrpc"`, `"param\u{17f}"` all select a field), after the
//!   name has been unquoted;
//! * `jsonrpc` and `method` are Go strings: a JSON `null` is a no-op that
//!   leaves any earlier value alone, a lone surrogate escape decodes to
//!   U+FFFD, and any other kind is an `UnmarshalTypeError`;
//! * `id`, `params` and `result` are `json.RawMessage`: they keep their
//!   (compacted) text, an explicit `null` included, so `"id":null` is a
//!   present id and a trailing `"id":null` replaces an earlier id;
//! * `error` is a `*RPCError`: `null` is nil, an object is non-nil whatever it
//!   holds (its members are optional), `code` must be an integer that fits
//!   Go's 64-bit `int` and `message` a string or `null`;
//! * a top-level `null` is a no-op that yields the zero message, every other
//!   non-object is an error;
//! * a wrong-typed member fails the whole decode even when a later duplicate
//!   would have been valid, because `encoding/json` returns the first type
//!   error.
//!
//! What happens when a field appears twice (exactly or as case variants) is the
//! caller's [`Duplicates`] policy. `encoding/json` resolves it last-wins; the
//! stdio transport rejects the frame by ADR 0032 row 4, and the HTTP transport
//! keeps Go's last-wins.
use crate::go_params::{self, Kind};
use crate::{Message, RpcError};
use serde_json::value::RawValue;

/// What a repeated envelope field (or a case variant of it) does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Duplicates {
    /// `encoding/json`'s own rule: every matching member is stored in
    /// document order, so the last one wins (a `null` is still a no-op for the
    /// string fields).
    LastWins,
    /// Reject the frame. Last-wins is the duplicate-key smuggling shape: an
    /// auditing intermediary may read the first occurrence while the server
    /// acts on the last.
    Reject,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Jsonrpc,
    Method,
    Id,
    Params,
    Result,
    Error,
}

const FIELDS: [(Field, &str); 6] = [
    (Field::Jsonrpc, "jsonrpc"),
    (Field::Method, "method"),
    (Field::Id, "id"),
    (Field::Params, "params"),
    (Field::Result, "result"),
    (Field::Error, "error"),
];

fn envelope_field(key: &str) -> Option<(usize, Field, &'static str)> {
    FIELDS
        .iter()
        .enumerate()
        .find(|(_, (_, name))| go_params::go_field_matches(key, name))
        .map(|(index, (field, name))| (index, *field, *name))
}

fn type_error(kind: Kind, target: &str, expected: &str) -> String {
    format!(
        "json: cannot unmarshal {} into Go struct field {target} of type {expected}",
        kind.go_name()
    )
}

/// `string` or `null`; `Ok(None)` leaves any previous value in place.
fn optional_string(raw: &str, target: &str) -> Result<Option<String>, String> {
    match go_params::kind(raw) {
        Kind::Null => Ok(None),
        Kind::String => Ok(Some(go_params::decode_string(raw))),
        other => Err(type_error(other, target, "string")),
    }
}

/// A `json.RawMessage` as `json.Marshal` would emit it: compacted, with
/// `<`, `>` and `&` escaped. Textual, so an id beyond i64 survives exactly.
fn present_raw(raw: &str) -> Result<Box<RawValue>, String> {
    RawValue::from_string(symvault_gojson::compact(raw)).map_err(|error| error.to_string())
}

/// Whether a JSON number is spelled as Go's `int` accepts it (no fraction or
/// exponent, within 64 bits).
fn is_go_int(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && text.parse::<i64>().is_ok()
}

fn decode_error(raw: &str, duplicates: Duplicates) -> Result<Option<RpcError>, String> {
    match go_params::kind(raw) {
        Kind::Null => return Ok(None),
        Kind::Object => {}
        other => return Err(type_error(other, "Message.error", "transport.RPCError")),
    }
    let mut seen = [false; 3];
    for (key, value) in go_params::object_members(raw)? {
        let slot = ["code", "message", "data"]
            .iter()
            .position(|name| go_params::go_field_matches(&key, name));
        let Some(slot) = slot else { continue };
        if duplicates == Duplicates::Reject && std::mem::replace(&mut seen[slot], true) {
            return Err(format!(
                "duplicate field `{}` in error",
                ["code", "message", "data"][slot]
            ));
        }
        match slot {
            0 => match go_params::kind(value) {
                Kind::Null => {}
                Kind::Number if is_go_int(value) => {}
                Kind::Number => {
                    return Err(format!(
                        "json: cannot unmarshal number {value} into Go struct field RPCError.error.code of type int"
                    ));
                }
                other => {
                    return Err(type_error(other, "RPCError.error.code", "int"));
                }
            },
            1 => {
                optional_string(value, "RPCError.error.message")?;
            }
            _ => {}
        }
    }
    // Only the presence of `error` matters downstream (it makes the message a
    // response); the members are validated above and not carried.
    Ok(Some(RpcError {
        data: None,
        message: String::new(),
        code: 0,
    }))
}

/// Decodes one complete JSON value as Go's `transport.Message`.
///
/// The caller owns the frame-level nesting guard; this function never
/// recurses, so depth costs no stack.
pub(crate) fn decode(text: &str, duplicates: Duplicates) -> Result<Message, String> {
    // `RawValue` validates the whole text (trailing data included) with
    // serde_json's iterative scanner, and keeps lone surrogate escapes that a
    // typed parse would reject; nothing is built from it yet.
    let whole = serde_json::from_str::<Box<RawValue>>(text).map_err(|error| error.to_string())?;
    let mut message = Message {
        error: None,
        jsonrpc: String::new(),
        method: String::new(),
        id: None,
        params: None,
        result: None,
    };
    match go_params::kind(whole.get()) {
        // `null` is a no-op against any target: the zero message.
        Kind::Null => return Ok(message),
        Kind::Object => {}
        other => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type transport.Message",
                other.go_name()
            ));
        }
    }
    let mut seen = [false; FIELDS.len()];
    for (key, value) in go_params::object_members(whole.get())? {
        let Some((index, field, name)) = envelope_field(&key) else {
            continue;
        };
        if duplicates == Duplicates::Reject && std::mem::replace(&mut seen[index], true) {
            return Err(format!("duplicate field `{name}`"));
        }
        match field {
            Field::Jsonrpc => {
                if let Some(text) = optional_string(value, "Message.jsonrpc")? {
                    message.jsonrpc = text;
                }
            }
            Field::Method => {
                if let Some(text) = optional_string(value, "Message.method")? {
                    message.method = text;
                }
            }
            Field::Id => message.id = Some(present_raw(value)?),
            Field::Params => message.params = Some(present_raw(value)?),
            Field::Result => message.result = Some(present_raw(value)?),
            Field::Error => message.error = decode_error(value, duplicates)?,
        }
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Message {
        decode(text, Duplicates::Reject).expect("decodes")
    }

    #[test]
    fn null_members_are_noops_and_keys_fold_case() {
        let message = ok(r#"{"JSONRPC":"2.0","Id":null,"METHOD":"ping"}"#);
        assert_eq!(message.jsonrpc, "2.0");
        assert_eq!(message.method, "ping");
        assert_eq!(message.id.expect("id").get(), "null");

        let message = ok(r#"{"jsonrpc":null,"method":null}"#);
        assert_eq!(message.jsonrpc, "");
        assert_eq!(message.method, "");
        assert!(message.id.is_none());
    }

    #[test]
    fn long_s_folds_and_kelvin_selects_nothing() {
        let message = ok("{\"param\u{17f}\":1,\"\u{212a}\":2}");
        assert_eq!(message.params.expect("params").get(), "1");
        assert!(message.method.is_empty());
        let escaped = ok(r#"{"param\u017f":1}"#);
        assert_eq!(escaped.params.expect("params").get(), "1");
    }

    #[test]
    fn duplicate_policy_is_the_callers_choice() {
        let dup = r#"{"method":"ping","METHOD":"nope","id":1,"id":null}"#;
        assert!(decode(dup, Duplicates::Reject).is_err());
        let message = decode(dup, Duplicates::LastWins).expect("last wins");
        assert_eq!(message.method, "nope");
        assert_eq!(message.id.expect("id").get(), "null");
        let message = decode(r#"{"method":"ping","method":null}"#, Duplicates::LastWins)
            .expect("null is a no-op");
        assert_eq!(message.method, "ping");
        assert!(decode(r#"{"error":{"code":1,"CODE":2}}"#, Duplicates::Reject).is_err());
        assert!(decode(r#"{"error":{"code":1,"CODE":2}}"#, Duplicates::LastWins).is_ok());
    }

    #[test]
    fn wrong_typed_member_fails_even_before_a_valid_duplicate() {
        for text in [
            r#"{"method":5,"METHOD":"ping"}"#,
            r#"{"jsonrpc":2}"#,
            r#"{"error":5}"#,
            r#"{"error":{"code":"x"}}"#,
            r#"{"error":{"code":1.5}}"#,
            r#"{"error":{"MESSAGE":5}}"#,
            "[1]",
            "\"s\"",
            "{} {}",
        ] {
            assert!(decode(text, Duplicates::LastWins).is_err(), "{text}");
        }
        assert!(decode(r#"{"error":{"code":3000000000}}"#, Duplicates::Reject).is_ok());
        assert!(decode(r#"{"error":{}}"#, Duplicates::Reject).is_ok());
    }

    #[test]
    fn lone_surrogates_decode_in_keys_and_values() {
        let message = ok(r#"{"\uDC00":1,"METHOD":"a\uD800b"}"#);
        assert_eq!(message.method, "a\u{FFFD}b");
    }
}
