//! Go-compatible decoding of the HTTP `/mcp` JSON-RPC envelope.
//!
//! The Go HTTP handler decodes the first JSON value of a request body into
//! `transport.Message` with `encoding/json` and hands it straight to the
//! protocol handler. It does **not** apply the stdio loop's `jsonrpc == "2.0"`
//! / method-required guards. This module reproduces the decoder's observable
//! rules so the HTTP adapter can dispatch the same messages:
//!
//! * the top level must be a JSON object or `null` (`null` decodes to the zero
//!   message); arrays and scalars fail;
//! * keys match the field names case-insensitively using Go's simple Unicode
//!   folding (`ſ` folds to `s`, the Kelvin sign to `k`), and the last
//!   occurrence of a repeated key wins;
//! * `jsonrpc` and `method` must be strings or `null` (`null` leaves the
//!   previous value untouched); `id`, `params` and `result` keep their raw
//!   text, including an explicit `null`; `error` must be an object or `null`
//!   whose `code` is an integer and `message` a string when present.
//!
//! Rust still requires exactly one complete JSON value (ADR 0017): trailing
//! input is a rejection rather than silently ignored.
use crate::{Message, RpcError};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

/// Entries of one JSON object in source order; `None` is the literal `null`.
struct Entries(Option<Vec<(String, Box<RawValue>)>>);

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntriesVisitor;
        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = Entries;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object or null")
            }

            fn visit_unit<E>(self) -> Result<Entries, E> {
                Ok(Entries(None))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Entries, A::Error> {
                let mut entries = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    entries.push((key, map.next_value::<Box<RawValue>>()?));
                }
                Ok(Entries(Some(entries)))
            }
        }
        deserializer.deserialize_any(EntriesVisitor)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Jsonrpc,
    Method,
    Id,
    Params,
    Result,
    Error,
    Code,
    Message,
    Data,
}

/// Go's `foldName`: ASCII upper-casing plus the non-ASCII members of the
/// simple-fold sets that occur in the envelope field names.
fn fold(key: &str) -> String {
    key.chars()
        .map(|character| match character {
            '\u{17f}' => 'S',
            '\u{212a}' => 'K',
            other => other.to_ascii_uppercase(),
        })
        .collect()
}

fn envelope_field(key: &str) -> Option<Field> {
    match fold(key).as_str() {
        "JSONRPC" => Some(Field::Jsonrpc),
        "METHOD" => Some(Field::Method),
        "ID" => Some(Field::Id),
        "PARAMS" => Some(Field::Params),
        "RESULT" => Some(Field::Result),
        "ERROR" => Some(Field::Error),
        _ => None,
    }
}

fn error_field(key: &str) -> Option<Field> {
    match fold(key).as_str() {
        "CODE" => Some(Field::Code),
        "MESSAGE" => Some(Field::Message),
        "DATA" => Some(Field::Data),
        _ => None,
    }
}

type RawEntries = Vec<(String, Box<RawValue>)>;

fn entries(text: &str) -> Result<Option<RawEntries>, ()> {
    serde_json::from_str::<Entries>(text)
        .map(|entries| entries.0)
        .map_err(|_| ())
}

fn present_raw(raw: &RawValue) -> Result<Box<RawValue>, ()> {
    RawValue::from_string(symvault_gojson::compact(raw.get())).map_err(|_| ())
}

/// `string` or `null`; `Ok(None)` leaves any previous value in place.
fn optional_string(raw: &RawValue) -> Result<Option<String>, ()> {
    serde_json::from_str::<Option<String>>(raw.get()).map_err(|_| ())
}

fn is_go_int(raw: &RawValue) -> bool {
    let text = raw.get();
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && text.parse::<i64>().is_ok()
}

fn decode_error(raw: &RawValue) -> Result<Option<RpcError>, ()> {
    let Some(fields) = entries(raw.get())? else {
        return Ok(None);
    };
    for (key, value) in fields {
        match error_field(&key) {
            Some(Field::Code) if value.get() != "null" && !is_go_int(&value) => return Err(()),
            Some(Field::Message) => {
                optional_string(&value)?;
            }
            _ => {}
        }
    }
    Ok(Some(RpcError {
        data: None,
        message: String::new(),
        code: 0,
    }))
}

/// Decodes one complete request body as Go's `transport.Message`.
pub(super) fn decode(body: &str) -> Result<Message, ()> {
    if crate::max_nesting_depth(body) > crate::MAX_ACCEPTED_NESTING_DEPTH {
        return Err(());
    }
    let mut message = Message {
        error: None,
        jsonrpc: String::new(),
        method: String::new(),
        id: None,
        params: None,
        result: None,
    };
    let Some(fields) = entries(body)? else {
        return Ok(message);
    };
    for (key, value) in fields {
        match envelope_field(&key) {
            Some(Field::Jsonrpc) => {
                if let Some(text) = optional_string(&value)? {
                    message.jsonrpc = text;
                }
            }
            Some(Field::Method) => {
                if let Some(text) = optional_string(&value)? {
                    message.method = text;
                }
            }
            Some(Field::Id) => message.id = Some(present_raw(&value)?),
            Some(Field::Params) => message.params = Some(present_raw(&value)?),
            Some(Field::Result) => message.result = Some(present_raw(&value)?),
            Some(Field::Error) => message.error = decode_error(&value)?,
            _ => {}
        }
    }
    Ok(message)
}

/// Whether a bounded prefix is a definitive syntax/type error (not merely
/// incomplete), mirroring the streaming decoder's early rejection.
pub(super) fn prefix_is_definitively_invalid(prefix: &[u8]) -> bool {
    serde_json::from_slice::<Entries>(prefix).is_err_and(|error| !error.is_eof())
}

/// Streaming variant of [`prefix_is_definitively_invalid`] for a bounded reader.
pub(super) fn parse_reader<R: std::io::Read>(reader: R) -> Result<(), serde_json::Error> {
    serde_json::from_reader::<_, Entries>(reader).map(|_| ())
}
