//! Go-compatible decoding of the on-disk MCP token registry.
//!
//! Go reads `mcp-tokens.json` with `encoding/json`. The semantics reproduced
//! here are the ones where a looser reading would make the Rust side more
//! permissive than Go (an ignored revocation, a forgiven type error).

use serde::Deserialize;

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
            || value.as_str().is_some_and(|text| {
                time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
                    .is_ok()
            })
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

/// Folds one JSON object the way Go decodes it, in document order. Every
/// member value is type-checked *before* a later duplicate may override it:
/// Go decodes each occurrence into the same field, records the first type
/// error and fails the whole document, so a bad earlier value is never
/// forgiven by a good later one. Struct fields: the last duplicate wins, a
/// JSON `null` leaves non-pointer scalars untouched. The root `tokens` map is
/// merged across duplicates (later ids replace earlier entries wholesale).
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
    // modelled: the combination is rejected, which is never more permissive.
    let mut tools_may_overlay = false;
    for (key, raw) in members.0 {
        let name = go_field_name(&key, fields).to_owned();
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
    let to_io = |error: serde_json::Error| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
    };
    let tokens: serde_json::Value = serde_json::from_str(text).map_err(to_io)?;
    if tokens.is_null() {
        return Ok(tokens);
    }
    if !tokens.is_object() {
        return Err(registry_invalid("token registry tokens must be an object"));
    }
    let mut folded = serde_json::Map::new();
    for (id, raw) in serde_json::from_str::<OrderedMembers>(text)
        .map_err(to_io)?
        .0
    {
        let entry: serde_json::Value = serde_json::from_str(raw.get()).map_err(to_io)?;
        let entry = if entry.is_object() {
            let members = serde_json::from_str::<OrderedMembers>(raw.get()).map_err(to_io)?;
            serde_json::Value::Object(fold_members(members, REGISTRY_ENTRY_FIELDS)?)
        } else if entry.is_null() {
            entry
        } else {
            return Err(registry_invalid("token registry entry must be an object"));
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
/// root `tokens` map merges) and a type error of any kind is an error.
/// Struct field names are matched the way Go matches them, so
/// `{"TOKENS":{"a":{"REVOKED":true}}}` revokes a token and is never read as an
/// unknown, ignored key.
pub fn decode_go_registry(bytes: &[u8]) -> Result<serde_json::Value, std::io::Error> {
    let text = go_lossy_utf8(bytes);
    let root: OrderedMembers = serde_json::from_str(&text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let value = serde_json::Value::Object(fold_members(root, REGISTRY_ROOT_FIELDS)?);
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
}
