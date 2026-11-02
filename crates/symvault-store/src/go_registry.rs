//! Go-compatible decoding of the on-disk MCP token registry.
//!
//! Go reads `mcp-tokens.json` with `encoding/json`. The semantics reproduced
//! here are the ones where a looser reading would make the Rust side more
//! permissive than Go (an ignored revocation, a forgiven type error).
//!
//! Declared divergences, all in the *stricter* direction (Rust rejects a
//! document Go adopts): a repeated `allowed_tools` array that carries a `null`
//! element. Because a live reload keeps the last good registry when a document
//! is rejected, a stricter rejection is not harmless: Go adopts the new
//! document while Rust keeps serving the previous one. Every divergence is
//! therefore listed in `docs/rust-port/cli-gap-inventory.md`.

use serde::Deserialize;
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};

/// Go's `encoding/json` nesting limit (`maxNestingDepth`).
const GO_MAX_NESTING_DEPTH: usize = 10_000;

/// Parses `text` exactly as Go's `time.Parse(time.RFC3339, text)` does, which
/// is what `Time.UnmarshalJSON` falls back to (its strict mode is disabled in
/// Go 1.26): a one- or two-digit hour, a `,` or `.` fraction of any length (the
/// first nine digits count), a numeric offset of up to `24:60`. Lowercase
/// `t`/`z`, a space separator and any escape sequence are rejected: Go hands
/// the *raw* JSON bytes to the parser, so `\u005a` is not `Z`.
pub fn parse_go_rfc3339(text: &str) -> Option<OffsetDateTime> {
    fn two(bytes: &[u8]) -> Option<u8> {
        match bytes {
            [a @ b'0'..=b'9', b @ b'0'..=b'9', ..] => Some((a - b'0') * 10 + (b - b'0')),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let digits4 = bytes.get(..4)?;
    if !digits4.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year = digits4
        .iter()
        .fold(0_i32, |acc, digit| acc * 10 + i32::from(digit - b'0'));
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') || bytes.get(10) != Some(&b'T') {
        return None;
    }
    let month = Month::try_from(two(bytes.get(5..)?)?).ok()?;
    let day = two(bytes.get(8..)?)?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    // Go's `15` takes one or two digits.
    let mut at = 11;
    let hour = match (bytes.get(at), bytes.get(at + 1)) {
        (Some(a @ b'0'..=b'9'), Some(b @ b'0'..=b'9')) => {
            at += 2;
            (a - b'0') * 10 + (b - b'0')
        }
        (Some(a @ b'0'..=b'9'), _) => {
            at += 1;
            a - b'0'
        }
        _ => return None,
    };
    if bytes.get(at) != Some(&b':') || bytes.get(at + 3) != Some(&b':') {
        return None;
    }
    let minute = two(bytes.get(at + 1..)?)?;
    let second = two(bytes.get(at + 4..)?)?;
    at += 6;
    let mut nanos = 0_u32;
    if matches!(bytes.get(at), Some(b'.' | b','))
        && bytes.get(at + 1).is_some_and(u8::is_ascii_digit)
    {
        let fraction: Vec<u8> = bytes[at + 1..]
            .iter()
            .copied()
            .take_while(u8::is_ascii_digit)
            .collect();
        at += 1 + fraction.len();
        for index in 0..9 {
            nanos = nanos * 10
                + fraction
                    .get(index)
                    .map_or(0, |digit| u32::from(digit - b'0'));
        }
    }
    let offset = match &bytes[at..] {
        [b'Z'] => UtcOffset::UTC,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let hours = i32::from(two(&[*h1, *h2])?);
            let minutes = i32::from(two(&[*m1, *m2])?);
            // Go's range tests are `> 24` and `> 60`.
            if hours > 24 || minutes > 60 {
                return None;
            }
            let seconds = (hours * 60 + minutes) * 60;
            UtcOffset::from_whole_seconds(if *sign == b'-' { -seconds } else { seconds }).ok()?
        }
        _ => return None,
    };
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(
        date.with_time(Time::from_hms_nano(hour, minute, second, nanos).ok()?)
            .assume_offset(offset),
    )
}

/// What Go prints for a registry timestamp in the token/agent tables:
/// `time.Time.Format("2006-01-02 15:04")` of the *parsed* value. Go keeps the
/// offset written in the file, so this is that wall clock (zero-padded, hour
/// `9` -> `09`, fraction and zone dropped), never the process zone and never a
/// slice of the raw text. `None` when Go would not have parsed `text`.
pub fn format_go_minute(text: &str) -> Option<String> {
    let value = parse_go_rfc3339(text)?;
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute()
    ))
}

/// Go's `time.Time{}` (0001-01-01 00:00:00 UTC) as nanoseconds since the Unix
/// epoch.
const GO_ZERO_TIME_NANOS: i128 = -62_135_596_800 * 1_000_000_000;

/// The latest timestamp that is strictly `After(time.Time{})`, as
/// `agent list` computes its last-seen column: it starts from the zero time and
/// replaces it only with a strictly later instant, so a value at or before the
/// zero instant never shows, and of two equal instants the first one wins.
/// Unparseable values are skipped (Go would have refused the registry).
pub fn latest_after_go_zero<'a>(timestamps: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let mut best: Option<(&str, i128)> = None;
    for text in timestamps {
        let Some(value) = parse_go_rfc3339(text) else {
            continue;
        };
        let nanos = value.unix_timestamp_nanos();
        if nanos > best.map_or(GO_ZERO_TIME_NANOS, |(_, current)| current) {
            best = Some((text, nanos));
        }
    }
    best.map(|(text, _)| text)
}

/// Whether the *raw* JSON value text (as it stands in the file) is a value Go's
/// `Time.UnmarshalJSON` accepts: `null`, or a quoted string without any
/// escape sequence that `parse_go_rfc3339` accepts.
fn raw_timestamp_is_valid(raw: &str) -> bool {
    if raw == "null" {
        return true;
    }
    raw.len() >= 2
        && raw.starts_with('"')
        && raw.ends_with('"')
        && !raw.contains('\\')
        && parse_go_rfc3339(&raw[1..raw.len() - 1]).is_some()
}

/// One scan over the (already UTF-8 repaired) document that mirrors two Go
/// decoder behaviours the Rust JSON parser does not share:
/// - nesting deeper than Go's limit of 10 000 is a syntax error;
/// - a `\u` surrogate escape that is not part of a valid pair decodes to
///   U+FFFD instead of failing, so it is rewritten to `\ufffd` here.
fn go_prepass(text: &str) -> Result<String, std::io::Error> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let (mut depth, mut in_string, mut index) = (0_usize, false, 0_usize);
    let hex4 = |at: usize| -> Option<u32> {
        let digits = bytes.get(at..at + 4)?;
        digits.iter().try_fold(0_u32, |acc, digit| {
            Some(acc * 16 + char::from(*digit).to_digit(16)?)
        })
    };
    while index < bytes.len() {
        let byte = bytes[index];
        if !in_string {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > GO_MAX_NESTING_DEPTH {
                        return Err(registry_invalid("exceeded max depth"));
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
            out.push(byte);
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = false;
                out.push(byte);
                index += 1;
            }
            b'\\' if bytes.get(index + 1) == Some(&b'u') => match hex4(index + 2) {
                Some(unit) if (0xd800..0xe000).contains(&unit) => {
                    let low = (bytes.get(index + 6) == Some(&b'\\')
                        && bytes.get(index + 7) == Some(&b'u'))
                    .then(|| hex4(index + 8))
                    .flatten();
                    if unit < 0xdc00 && low.is_some_and(|low| (0xdc00..0xe000).contains(&low)) {
                        out.extend_from_slice(&bytes[index..index + 12]);
                        index += 12;
                    } else {
                        out.extend_from_slice(b"\\ufffd");
                        index += 6;
                    }
                }
                _ => {
                    out.extend_from_slice(&bytes[index..index + 2]);
                    index += 2;
                }
            },
            b'\\' => {
                out.extend_from_slice(&bytes[index..(index + 2).min(bytes.len())]);
                index += 2;
            }
            _ => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| registry_invalid("token registry is not valid UTF-8"))
}

/// Deserializes a JSON object (or `null`, as `None`) into its members without
/// a recursion limit (Go's own limit of 10 000 is enforced by `go_prepass`);
/// member values stay unparsed so deeply nested unknown members never recurse.
fn parse_members(text: &str) -> Result<Option<OrderedMembers>, std::io::Error> {
    let to_io = |error: serde_json::Error| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
    };
    let mut deserializer = serde_json::Deserializer::from_str(text);
    deserializer.disable_recursion_limit();
    let members = Option::<OrderedMembers>::deserialize(&mut deserializer).map_err(to_io)?;
    deserializer.end().map_err(to_io)?;
    Ok(members)
}

/// JSON object members in document order, duplicates kept, values unparsed.
struct OrderedMembers(Vec<(String, Box<serde_json::value::RawValue>)>);

impl<'de> Deserialize<'de> for OrderedMembers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = OrderedMembers;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry()? {
                    members.push(member);
                }
                Ok(OrderedMembers(members))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

const REGISTRY_ROOT_FIELDS: &[&str] = &["version", "tokens"];
const REGISTRY_ENTRY_FIELDS: &[&str] = &[
    "id",
    "label",
    "hash",
    "prefix",
    "allowed_tools",
    "tool_registry_hash",
    "agent_name",
    "created_at",
    "expires_at",
    "last_used_at",
    "revoked",
    "revoked_at",
    "refresh_token_hash",
    "refresh_expires_at",
];
/// Fields Go decodes into non-pointer scalars: a JSON `null` leaves them as is.
const NULL_IS_NOOP_FIELDS: &[&str] = &[
    "version",
    "id",
    "label",
    "hash",
    "prefix",
    "tool_registry_hash",
    "agent_name",
    "created_at",
    "revoked",
    "refresh_token_hash",
];

/// `encoding/json` simple case folding for ASCII field names: U+017F folds to
/// `s` and U+212A (Kelvin) to `k`, everything else by Unicode lowercase.
fn go_fold_name(name: &str) -> String {
    name.chars()
        .flat_map(|character| match character {
            '\u{17f}' => 's'.to_lowercase(),
            '\u{212a}' => 'k'.to_lowercase(),
            other => other.to_lowercase(),
        })
        .collect()
}

/// The struct field Go's `json.Unmarshal` would bind `key` to: an exact match,
/// else a case-insensitive one; unknown keys are returned unchanged.
fn go_field_name<'a>(key: &'a str, fields: &'static [&'static str]) -> &'a str {
    if fields.contains(&key) {
        return key;
    }
    let folded = go_fold_name(key);
    fields
        .iter()
        .find(|field| go_fold_name(field) == folded)
        .copied()
        .unwrap_or(key)
}

fn registry_invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_owned())
}

/// Whether `field` is acceptable for the entry member `key` under Go's
/// `json.Unmarshal` into `TokenRegistryEntry` (a type error fails the document).
fn entry_field_is_valid(key: &str, field: &serde_json::Value) -> bool {
    fn timestamp(value: &serde_json::Value) -> bool {
        value.is_null()
            || value
                .as_str()
                .is_some_and(|text| parse_go_rfc3339(text).is_some())
    }
    match key {
        "id" | "label" | "hash" | "prefix" | "tool_registry_hash" | "agent_name"
        | "refresh_token_hash" => field.is_null() || field.is_string(),
        "allowed_tools" => {
            field.is_null()
                || field.as_array().is_some_and(|tools| {
                    tools.iter().all(|tool| tool.is_null() || tool.is_string())
                })
        }
        "revoked" => field.is_null() || field.is_boolean(),
        "created_at" | "expires_at" | "last_used_at" | "revoked_at" | "refresh_expires_at" => {
            timestamp(field)
        }
        _ => true,
    }
}

const TIMESTAMP_FIELDS: &[&str] = &[
    "created_at",
    "expires_at",
    "last_used_at",
    "revoked_at",
    "refresh_expires_at",
];

/// Folds one JSON object the way Go decodes it, in document order. Every
/// member value is type-checked *before* a later duplicate may override it:
/// Go decodes each occurrence into the same field, records the first type
/// error and fails the whole document, so a bad earlier value is never
/// forgiven by a good later one. Struct fields: the last duplicate wins, a
/// JSON `null` leaves non-pointer scalars untouched. The root `tokens` map is
/// merged across duplicates (later ids replace earlier entries wholesale).
/// Members that are not struct fields are syntax-checked only (never parsed),
/// so they cannot fail the document by their content or their depth.
fn fold_members(
    members: OrderedMembers,
    fields: &'static [&'static str],
) -> Result<serde_json::Map<String, serde_json::Value>, std::io::Error> {
    let root = fields == REGISTRY_ROOT_FIELDS;
    let parse = |text: &str| {
        serde_json::from_str::<serde_json::Value>(text)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    };
    let mut folded = serde_json::Map::new();
    // Go overlays a repeated `allowed_tools` array on the previous slice, so a
    // `null` element can keep or re-expose an earlier element. That is not
    // modelled: the combination is rejected, which is stricter than Go.
    let mut tools_may_overlay = false;
    for (key, raw) in members.0 {
        let name = go_field_name(&key, fields).to_owned();
        if !fields.contains(&name.as_str()) {
            continue;
        }
        let mut value = if root && name == "tokens" {
            let tokens = fold_tokens(raw.get())?;
            match (folded.get_mut("tokens"), tokens) {
                (Some(serde_json::Value::Object(existing)), serde_json::Value::Object(more)) => {
                    existing.extend(more);
                    continue;
                }
                (_, tokens) => tokens,
            }
        } else {
            // Go hands a timestamp the raw JSON bytes: no unescaping first.
            if !root
                && TIMESTAMP_FIELDS.contains(&name.as_str())
                && !raw_timestamp_is_valid(raw.get())
            {
                return Err(registry_invalid(
                    "token registry entry field has the wrong type",
                ));
            }
            parse(raw.get())?
        };
        if root && name == "version" {
            if !value.is_null() && value.as_i64().is_none() {
                return Err(registry_invalid(
                    "token registry version must be an integer",
                ));
            }
        } else if !root && !entry_field_is_valid(&name, &value) {
            return Err(registry_invalid(
                "token registry entry field has the wrong type",
            ));
        }
        if value.is_null() && NULL_IS_NOOP_FIELDS.contains(&name.as_str()) {
            continue;
        }
        if name == "allowed_tools" {
            match value.as_array_mut() {
                Some(tools) => {
                    let has_null = tools.iter().any(serde_json::Value::is_null);
                    if has_null && tools_may_overlay {
                        return Err(registry_invalid(
                            "duplicate allowed_tools with null element is unsupported",
                        ));
                    }
                    tools_may_overlay = !tools.is_empty();
                    // A null element decodes into a Go string as the empty string.
                    for tool in tools.iter_mut().filter(|tool| tool.is_null()) {
                        *tool = serde_json::Value::String(String::new());
                    }
                }
                None => tools_may_overlay = false,
            }
        }
        // Later members override earlier ones, as repeated Go assignments do.
        folded.insert(name, value);
    }
    Ok(folded)
}

/// Folds each entry of one `tokens` object. Ids are case-sensitive map keys;
/// Go decodes every id into a zeroed element, so the last duplicate replaces
/// the earlier entry wholesale. Only `null` or an object may be an entry (a
/// type error even in a superseded duplicate fails the document), and only
/// `null` or an object may be the map itself.
fn fold_tokens(text: &str) -> Result<serde_json::Value, std::io::Error> {
    let text = text.trim();
    let Some(members) = (match text.as_bytes().first() {
        Some(b'n' | b'{') => parse_members(text)?,
        _ => return Err(registry_invalid("token registry tokens must be an object")),
    }) else {
        return Ok(serde_json::Value::Null);
    };
    let mut folded = serde_json::Map::new();
    for (id, raw) in members.0 {
        // A string, number, boolean or array entry is a serde type error here.
        let entry = match parse_members(raw.get().trim())? {
            Some(members) => {
                serde_json::Value::Object(fold_members(members, REGISTRY_ENTRY_FIELDS)?)
            }
            None => serde_json::Value::Null,
        };
        folded.insert(id, entry);
    }
    Ok(serde_json::Value::Object(folded))
}

/// Go's `encoding/json` replaces every invalid UTF-8 byte inside a string with
/// U+FFFD (one per byte) instead of rejecting the document. Applying the same
/// replacement to the whole file is equivalent: an invalid byte outside a
/// string is a syntax error for Go and, as U+FFFD, for the Rust parser too.
pub(crate) fn go_lossy_utf8(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                return out;
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                out.push('\u{fffd}');
                rest = &after[1..];
            }
        }
    }
}

/// Decodes a token registry the way Go's `json.Unmarshal` into
/// `TokenRegistryFile` does: invalid UTF-8 inside strings is replaced, struct
/// fields bind case-insensitively, duplicate members are decoded in document
/// order (a type error anywhere fails the document, the later value wins, the
/// root `tokens` map merges) and a type error of any kind is an error. A root
/// `null` is Go's empty registry. Lone `\u` surrogates decode to U+FFFD and
/// nesting up to Go's limit of 10 000 is accepted.
/// Struct field names are matched the way Go matches them, so
/// `{"TOKENS":{"a":{"REVOKED":true}}}` revokes a token and is never read as an
/// unknown, ignored key.
pub fn decode_go_registry(bytes: &[u8]) -> Result<serde_json::Value, std::io::Error> {
    let text = go_prepass(&go_lossy_utf8(bytes))?;
    // A root `null` leaves Go's zero-value registry untouched: empty, not an error.
    let members = parse_members(&text)?.unwrap_or(OrderedMembers(Vec::new()));
    let value = serde_json::Value::Object(fold_members(members, REGISTRY_ROOT_FIELDS)?);
    validate_go_registry(&value)?;
    Ok(value)
}

/// Go's `json.Unmarshal` into `TokenRegistryFile` fails the whole registry on
/// any type error, including a malformed timestamp; one bad entry must never
/// leave the rest of the file half-trusted.
fn validate_go_registry(value: &serde_json::Value) -> Result<(), std::io::Error> {
    fn invalid(message: &str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_owned())
    }
    let root = value
        .as_object()
        .ok_or_else(|| invalid("token registry must be a JSON object"))?;
    if root
        .get("version")
        .is_some_and(|version| !version.is_null() && version.as_i64().is_none())
    {
        return Err(invalid("token registry version must be an integer"));
    }
    let tokens = match root.get("tokens") {
        None | Some(serde_json::Value::Null) => return Ok(()),
        Some(serde_json::Value::Object(tokens)) => tokens,
        Some(_) => return Err(invalid("token registry tokens must be an object")),
    };
    for entry in tokens.values() {
        let fields = match entry {
            serde_json::Value::Null => continue,
            serde_json::Value::Object(fields) => fields,
            _ => return Err(invalid("token registry entry must be an object")),
        };
        for (key, field) in fields {
            if !entry_field_is_valid(key, field) {
                return Err(invalid("token registry entry field has the wrong type"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(text: &str) -> Result<serde_json::Value, std::io::Error> {
        decode_go_registry(text.as_bytes())
    }

    #[test]
    fn any_member_with_a_type_error_fails_the_document_even_when_superseded() {
        for bad in [
            r#"{"tokens":{"a":{"revoked":"yes","revoked":false}}}"#,
            r#"{"tokens":{"a":{"REVOKED":"yes","revoked":false}}}"#,
            r#"{"version":"1","version":2}"#,
            r#"{"tokens":{"a":{"hash":1}},"tokens":{}}"#,
            r#"{"tokens":3,"tokens":{}}"#,
            r#"{"tokens":{"a":1,"a":{}}}"#,
            r#"{"tokens":{"a":{"expires_at":"x","expires_at":null}}}"#,
        ] {
            assert!(decode(bad).is_err(), "{bad}");
        }
        assert!(decode(r#"{"tokens":{"a":{"zzz":1,"zzz":"x"}}}"#).is_ok());
    }

    #[test]
    fn repeated_tokens_object_merges_and_null_resets() {
        let merged = decode(
            r#"{"tokens":{"a":{"id":"a"},"b":{"id":"b"}},"tokens":{"b":{"id":"B"},"c":{}}}"#,
        )
        .expect("merge");
        assert_eq!(merged["tokens"]["a"]["id"], "a");
        assert_eq!(merged["tokens"]["b"]["id"], "B");
        assert!(merged["tokens"]["c"].is_object());
        let reset = decode(r#"{"tokens":{"a":{}},"TOKENS":null}"#).expect("reset");
        assert!(reset["tokens"].is_null());
        // A repeated id replaces the entry wholesale; it does not merge fields.
        let replaced = decode(r#"{"tokens":{"a":{"revoked":true}},"tokens":{"a":{"id":"a"}}}"#)
            .expect("replace");
        assert!(replaced["tokens"]["a"].get("revoked").is_none());
    }

    #[test]
    fn invalid_utf8_inside_a_string_is_accepted() {
        let mut bytes = br#"{"tokens":{"a":{"label":"x"#.to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice(br#""}}}"#);
        assert_eq!(
            decode_go_registry(&bytes).expect("lossy")["tokens"]["a"]["label"],
            "x\u{fffd}"
        );
        bytes.push(0xff);
        assert!(decode_go_registry(&bytes).is_err());
    }

    #[test]
    fn invalid_utf8_is_replaced_per_byte_like_go() {
        assert_eq!(
            go_lossy_utf8(&[b'a', 0xe2, 0x82, b'b']),
            "a\u{fffd}\u{fffd}b"
        );
        assert_eq!(
            go_lossy_utf8(&[0xed, 0xa0, 0x80]),
            "\u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(go_lossy_utf8("héllo".as_bytes()), "héllo");
    }

    /// Outcomes recorded from Go 1.26.6 (`encoding/json` into a `*time.Time`
    /// field, `scripts/rust-port/go_timestamp_oracle.go.txt`) for 1055 raw JSON
    /// values: well-formed and mutated RFC3339 strings, escape sequences,
    /// fraction and offset sweeps. Rust must agree in both directions.
    #[test]
    fn timestamp_acceptance_matches_recorded_go_outcomes() {
        let cases: Vec<(String, bool)> =
            serde_json::from_str(include_str!("../tests/fixtures/go_timestamp_cases.json"))
                .expect("fixture");
        assert!(cases.len() > 900);
        let mut disagreements = Vec::new();
        for (raw, go_accepts) in &cases {
            let document = format!(r#"{{"tokens":{{"a":{{"expires_at":{raw}}}}}}}"#);
            if decode(&document).is_ok() != *go_accepts {
                disagreements.push((raw.clone(), *go_accepts));
            }
        }
        assert!(disagreements.is_empty(), "{disagreements:?}");
    }

    /// What Go 1.26.6 prints (`Format("2006-01-02 15:04")`) for every accepted
    /// non-null timestamp in the acceptance sweep, and whether it is
    /// `After(time.Time{})`, recorded by `scripts/rust-port/go_timestamp_fixtures.py`.
    fn display_cases() -> Vec<(String, String, bool)> {
        let cases: Vec<(String, String, bool)> = serde_json::from_str(include_str!(
            "../tests/fixtures/go_timestamp_display_cases.json"
        ))
        .expect("fixture");
        assert!(cases.len() > 200);
        cases
            .into_iter()
            .map(|(raw, display, after_zero)| {
                let text: String = serde_json::from_str(&raw).expect("quoted string");
                (text, display, after_zero)
            })
            .collect()
    }

    #[test]
    fn display_matches_recorded_go_format() {
        let mut disagreements = Vec::new();
        for (text, display, _) in display_cases() {
            if format_go_minute(&text).as_deref() != Some(display.as_str()) {
                disagreements.push((text, display));
            }
        }
        assert!(disagreements.is_empty(), "{disagreements:?}");
        assert_eq!(
            format_go_minute("2026-01-01T1:00:00Z").as_deref(),
            Some("2026-01-01 01:00")
        );
        assert_eq!(format_go_minute("2026-01-01 00:00:00Z"), None);
    }

    #[test]
    fn last_seen_selection_matches_recorded_go_after_zero() {
        for (text, _, after_zero) in display_cases() {
            let picked = latest_after_go_zero([text.as_str()]);
            assert_eq!(picked.is_some(), after_zero, "{text}");
        }
        // Strictly later wins; of equal instants the first one stays.
        assert_eq!(
            latest_after_go_zero(["2026-01-01T10:00:00Z", "2026-01-01T11:00:00+01:00"]),
            Some("2026-01-01T10:00:00Z")
        );
        assert_eq!(
            latest_after_go_zero(["2026-01-01T09:59:59Z", "2026-01-01T9:00:00-01:00"]),
            Some("2026-01-01T9:00:00-01:00")
        );
    }

    #[test]
    fn timestamps_go_rejects_are_rejected_on_the_raw_bytes() {
        for raw in [
            r#""2026-01-01t00:00:00Z""#,
            r#""2026-01-01T00:00:00z""#,
            r#""2026-01-01 00:00:00Z""#,
            r#""2026-01-01T00:00:00\u005a""#,
            r#""2026-01-01\u005400:00:00Z""#,
            r#""2026-01-01T00:00:00+25:00""#,
        ] {
            for field in [
                "created_at",
                "expires_at",
                "last_used_at",
                "revoked_at",
                "refresh_expires_at",
            ] {
                let document = format!(r#"{{"tokens":{{"a":{{"{field}":{raw}}}}}}}"#);
                assert!(decode(&document).is_err(), "{field} {raw}");
            }
        }
        for raw in [
            r#""2026-01-01T00:00:00Z""#,
            r#""2026-01-01T1:00:00Z""#,
            r#""2026-01-01T00:00:00,5Z""#,
            r#""2026-01-01T00:00:00+24:00""#,
            r#""2026-01-01T00:00:00+00:60""#,
            "null",
        ] {
            let document = format!(r#"{{"tokens":{{"a":{{"expires_at":{raw}}}}}}}"#);
            assert!(decode(&document).is_ok(), "{raw}");
        }
        let parsed = parse_go_rfc3339("2026-01-01T00:00:00,5+24:60").expect("go accepts");
        assert_eq!(parsed.unix_timestamp(), 1_767_225_600 - 90_000);
        assert_eq!(parsed.nanosecond(), 500_000_000);
    }

    #[test]
    fn extreme_accepted_instants_compare_without_panicking() {
        let now = OffsetDateTime::now_utc();
        for text in [
            "9999-12-31T23:59:59.999999999-24:60",
            "0000-01-01T00:00:00+24:60",
            "0000-01-01T00:00:00-24:60",
            "9999-12-31T23:59:59+24:60",
        ] {
            let parsed = parse_go_rfc3339(text).expect(text);
            let _ = (now <= parsed, parsed.unix_timestamp(), now - parsed);
        }
    }

    #[test]
    fn root_null_is_an_empty_registry_like_go() {
        for text in ["null", " null\n"] {
            let value = decode(text).expect(text);
            assert!(value.as_object().is_some_and(serde_json::Map::is_empty));
        }
        for bad in ["[]", "5", "\"x\"", "true", "", "nul"] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn lone_surrogate_escapes_decode_to_the_replacement_character() {
        let value = decode(
            r#"{"tokens":{"a":{"label":"\ud800x\udc00y\ud83d\ude00z\ud800\ud800","REVOKED":true}}}"#,
        )
        .expect("lone surrogates");
        assert_eq!(
            value["tokens"]["a"]["label"],
            "\u{fffd}x\u{fffd}y\u{1f600}z\u{fffd}\u{fffd}"
        );
        assert_eq!(value["tokens"]["a"]["revoked"], true);
        // The same inside an unknown member name and a key that folds onto a field.
        assert!(decode(r#"{"tokens":{"a":{"zz\ud800":1,"re\u0076oked":true}}}"#).is_ok());
    }

    #[test]
    fn nesting_up_to_gos_limit_is_accepted_for_unknown_members() {
        let nested = |levels: usize| {
            format!(
                r#"{{"tokens":{{"a":{{"zz":{}{}}}}}}}"#,
                "[".repeat(levels),
                "]".repeat(levels)
            )
        };
        // root, tokens and the entry take three levels of Go's 10 000.
        assert!(decode(&nested(9_997)).is_ok());
        assert!(decode(&nested(9_998)).is_err());
        // Known fields never accept a deep value in Go either (a type error).
        let deep = format!(
            r#"{{"tokens":{{"a":{{"hash":{}{}}}}}}}"#,
            "[".repeat(500),
            "]".repeat(500)
        );
        assert!(decode(&deep).is_err());
    }
}
