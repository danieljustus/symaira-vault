//! Token-level reading of an already-framed `params` value with
//! `encoding/json` semantics, for the methods whose Go handler decodes into a
//! struct or map.
//!
//! `serde_json::Value` is not a faithful stand-in for what Go does with
//! `params`, in two ways that matter at the trust boundary:
//!
//!   - `serde_json` caps recursion at 128 levels when it builds a `Value` (or a
//!     typed value), while `encoding/json` accepts nesting up to 10000. The
//!     frame-level guard ([`crate::MAX_ACCEPTED_NESTING_DEPTH`]) already bounds
//!     the total depth, so the walker here only has to be iterative.
//!   - `serde_json` rejects a lone surrogate escape such as `"\uD800"`, where
//!     `encoding/json` decodes it to U+FFFD and carries on.
//!
//! The text handed to this module is a `RawValue`, so it is already known to be
//! structurally valid JSON. Nothing here re-validates it; members that no
//! consumer selects are skipped by an iterative, string-aware scanner and are
//! never parsed, exactly like Go's `d.skip()` for unknown fields and for a
//! `json.RawMessage` target.

/// The JSON kind of a value, as `encoding/json` names it in decoder errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

impl Kind {
    /// Go's wording for the kind in an `UnmarshalTypeError`.
    pub(crate) fn go_name(self) -> &'static str {
        match self {
            Kind::Null => "null",
            Kind::Bool => "bool",
            Kind::Number => "number",
            Kind::String => "string",
            Kind::Array => "array",
            Kind::Object => "object",
        }
    }
}

/// Classifies one JSON value from its first significant byte.
pub(crate) fn kind(raw: &str) -> Kind {
    match raw
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .as_bytes()
        .first()
    {
        Some(b'{') => Kind::Object,
        Some(b'[') => Kind::Array,
        Some(b'"') => Kind::String,
        Some(b't' | b'f') => Kind::Bool,
        Some(b'n') => Kind::Null,
        _ => Kind::Number,
    }
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        i += 1;
    }
    i
}

/// Index one past the closing quote of the string starting at `bytes[i] == '"'`.
fn skip_string(bytes: &[u8], mut i: usize) -> Result<usize, String> {
    i += 1;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err("unexpected end of JSON input".to_string())
}

/// Index one past the value starting at `bytes[i]`. Iterative, so nesting depth
/// costs no stack.
fn skip_value(bytes: &[u8], mut i: usize) -> Result<usize, String> {
    match bytes.get(i) {
        Some(b'"') => skip_string(bytes, i),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            while let Some(&b) = bytes.get(i) {
                match b {
                    b'"' => {
                        i = skip_string(bytes, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Err("unexpected end of JSON input".to_string())
        }
        Some(_) => {
            while let Some(&b) = bytes.get(i) {
                if matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                    break;
                }
                i += 1;
            }
            Ok(i)
        }
        None => Err("unexpected end of JSON input".to_string()),
    }
}

fn hex4(bytes: &[u8], at: usize) -> Option<u32> {
    let digits = bytes.get(at..at + 4)?;
    let mut value = 0u32;
    for &d in digits {
        value = value * 16 + (d as char).to_digit(16)?;
    }
    Some(value)
}

/// Decodes a JSON string token (quotes included) the way `encoding/json`'s
/// `unquote` does. A surrogate half that does not form a pair becomes U+FFFD,
/// and the escape after a lone high half is not consumed.
pub(crate) fn decode_string(token: &str) -> String {
    let bytes = token.as_bytes();
    let inner = bytes.get(1..bytes.len().saturating_sub(1)).unwrap_or(&[]);
    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] != b'\\' {
            // Copy the run up to the next escape; the token came from a `&str`
            // and escapes are ASCII, so run boundaries are char boundaries.
            let start = i;
            while i < inner.len() && inner[i] != b'\\' {
                i += 1;
            }
            out.push_str(&String::from_utf8_lossy(&inner[start..i]));
            continue;
        }
        match inner.get(i + 1) {
            Some(b'"') => out.push('"'),
            Some(b'\\') => out.push('\\'),
            Some(b'/') => out.push('/'),
            Some(b'b') => out.push('\u{8}'),
            Some(b'f') => out.push('\u{c}'),
            Some(b'n') => out.push('\n'),
            Some(b'r') => out.push('\r'),
            Some(b't') => out.push('\t'),
            Some(b'u') => {
                let Some(first) = hex4(inner, i + 2) else {
                    out.push('\u{FFFD}');
                    i += 2;
                    continue;
                };
                i += 6;
                let decoded = if (0xD800..0xDC00).contains(&first) {
                    if inner.get(i) == Some(&b'\\')
                        && inner.get(i + 1) == Some(&b'u')
                        && let Some(second) = hex4(inner, i + 2)
                        && (0xDC00..0xE000).contains(&second)
                    {
                        i += 6;
                        char::from_u32(0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00))
                    } else {
                        None
                    }
                } else {
                    char::from_u32(first)
                };
                out.push(decoded.unwrap_or('\u{FFFD}'));
                continue;
            }
            _ => out.push('\u{FFFD}'),
        }
        i += 2;
    }
    out
}

/// Splits one JSON object into its members in document order, duplicates
/// preserved, keys decoded and values left as the exact source slice.
pub(crate) fn object_members(text: &str) -> Result<Vec<(String, &str)>, String> {
    let bytes = text.as_bytes();
    let mut i = skip_ws(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return Err("expected a JSON object".to_string());
    }
    i = skip_ws(bytes, i + 1);
    let mut members = Vec::new();
    if bytes.get(i) == Some(&b'}') {
        return Ok(members);
    }
    loop {
        if bytes.get(i) != Some(&b'"') {
            return Err("expected an object key".to_string());
        }
        let key_end = skip_string(bytes, i)?;
        let key = decode_string(&text[i..key_end]);
        i = skip_ws(bytes, key_end);
        if bytes.get(i) != Some(&b':') {
            return Err("expected ':' after an object key".to_string());
        }
        i = skip_ws(bytes, i + 1);
        let end = skip_value(bytes, i)?;
        members.push((key, &text[i..end]));
        i = skip_ws(bytes, end);
        match bytes.get(i) {
            Some(b',') => i = skip_ws(bytes, i + 1),
            Some(b'}') => return Ok(members),
            _ => return Err("expected ',' or '}' in an object".to_string()),
        }
    }
}

/// Rewrites every lone surrogate `\uXXXX` escape inside a JSON string to
/// `\uFFFD`, leaving valid pairs and everything else byte for byte as it was.
///
/// This is `encoding/json`'s decode rule applied to the text instead of to the
/// decoded value, so a typed `serde_json` parse of the result yields what Go
/// stores for the same input (serde rejects the lone escape outright). The scan
/// is string-aware: an escaped backslash followed by `uD800` is plain text.
pub(crate) fn replace_lone_surrogates(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("\\u") {
        return std::borrow::Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    let mut in_string = false;
    let mut changed = false;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'\\' if in_string => {
                if bytes.get(i + 1) == Some(&b'u')
                    && let Some(first) = hex4(bytes, i + 2)
                    && (0xD800..0xE000).contains(&first)
                {
                    let paired = (0xD800..0xDC00).contains(&first)
                        && bytes.get(i + 6) == Some(&b'\\')
                        && bytes.get(i + 7) == Some(&b'u')
                        && hex4(bytes, i + 8).is_some_and(|s| (0xDC00..0xE000).contains(&s));
                    if paired {
                        i += 12;
                    } else {
                        out.push_str(&text[copied..i]);
                        out.push_str("\\uFFFD");
                        i += 6;
                        copied = i;
                        changed = true;
                    }
                    continue;
                }
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    if !changed {
        return std::borrow::Cow::Borrowed(text);
    }
    out.push_str(&text[copied..]);
    std::borrow::Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lone_surrogates_decode_to_replacement_without_swallowing_the_next_escape() {
        assert_eq!(decode_string(r#""\uD800""#), "\u{FFFD}");
        assert_eq!(decode_string(r#""\uDC00""#), "\u{FFFD}");
        assert_eq!(decode_string(r#""\uD800\u0041""#), "\u{FFFD}A");
        assert_eq!(decode_string(r#""\uD800\uD800""#), "\u{FFFD}\u{FFFD}");
        assert_eq!(decode_string(r#""\uD83D\uDE00""#), "😀");
        assert_eq!(decode_string(r#""a\n\"\\\/\u00e9é""#), "a\n\"\\/éé");
    }

    #[test]
    fn lone_surrogate_escapes_are_rewritten_in_strings_only() {
        let rewrite = |t: &str| replace_lone_surrogates(t).into_owned();
        assert_eq!(rewrite(r#"{"a":"\uD800"}"#), r#"{"a":"\uFFFD"}"#);
        assert_eq!(rewrite(r#"["\uDC00x\uDBFF"]"#), r#"["\uFFFDx\uFFFD"]"#);
        assert_eq!(
            rewrite(r#"{"\uD800":"\uD800\u0041"}"#),
            r#"{"\uFFFD":"\uFFFD\u0041"}"#
        );
        // Valid pair and escaped backslash are untouched.
        assert_eq!(rewrite(r#""\uD83D\uDE00""#), r#""\uD83D\uDE00""#);
        assert_eq!(rewrite(r#""\\uD800""#), r#""\\uD800""#);
        assert_eq!(
            rewrite(r#""\uD800\uD800\uDC00""#),
            r#""\uFFFD\uD800\uDC00""#
        );
        assert!(matches!(
            replace_lone_surrogates(r#"{"a":"\u00e9"}"#),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn members_keep_duplicates_and_raw_values_in_order() {
        let members =
            object_members(r#" {"a" : 1, "a":[{"x":"]"}], "\uD800":{"deep":[[[]]]},"b":null } "#)
                .expect("members");
        let seen: Vec<_> = members.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(
            seen,
            vec![
                ("a", "1"),
                ("a", r#"[{"x":"]"}]"#),
                ("\u{FFFD}", r#"{"deep":[[[]]]}"#),
                ("b", "null"),
            ]
        );
        assert!(object_members("{}").expect("empty").is_empty());
    }

    #[test]
    fn nesting_far_beyond_serde_recursion_limit_is_walked_without_recursion() {
        let depth = 9_998;
        let text = format!(
            r#"{{"capabilities":{}{},"k":true}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let members = object_members(&text).expect("members");
        assert_eq!(members.len(), 2);
        assert_eq!(kind(members[0].1), Kind::Array);
        assert_eq!(members[1], ("k".to_string(), "true"));
    }

    #[test]
    fn kinds_are_named_like_encoding_json() {
        for (text, want) in [
            ("null", "null"),
            ("true", "bool"),
            ("false", "bool"),
            ("-1.5e3", "number"),
            ("\"s\"", "string"),
            ("[1]", "array"),
            ("{}", "object"),
        ] {
            assert_eq!(kind(text).go_name(), want, "{text}");
        }
    }
}
