//! `encoding/json`-compatible serialization.
//!
//! `serde_json::to_string` and Go's `json.Marshal` agree on almost everything
//! and disagree on one thing that matters here: Go escapes `<`, `>` and `&` as
//! `<`, `>` and `&`, and escapes U+2028/U+2029, by default.
//! `serde_json` emits all five literally.
//!
//! That difference is not cosmetic anywhere this crate is used:
//!
//!   - MCP-001/004 treat the emitted stdout byte stream as the contract, and
//!     both the method name and the echoed id are attacker-chosen, so the two
//!     implementations would put different bytes on the wire.
//!   - GIT-003's conflict tiebreak orders two entries by comparing their
//!     serialized metadata. `\` (0x5C) and `<` (0x3C) sort on opposite sides of
//!     `=` (0x3D), so an escapable character in a user-controlled tag makes Go
//!     and Rust pick *different winners* for the same pair — a silent data
//!     divergence in sync reconciliation.
//!
//! This lives in its own crate rather than in `symvault-store` because
//! `symvault-mcp` needs it and must not take a dependency on the storage layer,
//! and duplicating it in two crates would let the two copies drift.

use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};
use std::io;

/// A `serde_json` formatter that escapes the characters Go escapes.
#[derive(Clone, Debug, Default)]
pub struct GoFormatter;

impl Formatter for GoFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        // serde_json hands this the runs between the escapes it already
        // performs, so only Go's extra five characters need handling here.
        let mut start = 0;
        for (index, ch) in fragment.char_indices() {
            let escaped = match ch {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            if start < index {
                writer.write_all(&fragment.as_bytes()[start..index])?;
            }
            writer.write_all(escaped.as_bytes())?;
            start = index + ch.len_utf8();
        }
        if start < fragment.len() {
            writer.write_all(&fragment.as_bytes()[start..])?;
        }
        Ok(())
    }
}

/// Serializes exactly as Go's `json.Marshal` would.
pub fn to_string<T>(value: &T) -> Result<String, serde_json::Error>
where
    T: ?Sized + Serialize,
{
    let mut buffer = Vec::with_capacity(128);
    let mut serializer = Serializer::with_formatter(&mut buffer, GoFormatter);
    value.serialize(&mut serializer)?;
    // The formatter only ever emits ASCII escapes over what serde_json already
    // produced, so the result is still valid UTF-8.
    Ok(String::from_utf8(buffer).expect("serde_json emits UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_characters_go_escapes() {
        assert_eq!(to_string("a<b>&c").unwrap(), "\"a\\u003cb\\u003e\\u0026c\"");
        assert_eq!(to_string("\u{2028}\u{2029}").unwrap(), "\"\\u2028\\u2029\"");
    }

    #[test]
    fn leaves_everything_else_alone() {
        assert_eq!(to_string("plain").unwrap(), r#""plain""#);
        // serde_json's own escapes still run.
        assert_eq!(to_string("a\"b\\c\nd").unwrap(), r#""a\"b\\c\nd""#);
        // Non-ASCII that Go does not escape stays literal.
        assert_eq!(to_string("café✓").unwrap(), "\"café✓\"");
    }

    #[test]
    fn escapes_inside_nested_structures() {
        let value = serde_json::json!({"tags": ["<", "="]});
        assert_eq!(to_string(&value).unwrap(), "{\"tags\":[\"\\u003c\",\"=\"]}");
    }

    /// The ordering consequence, stated directly: the escape moves the byte
    /// from below `=` to above it, which is what flips a tiebreak.
    #[test]
    fn escaping_changes_lexicographic_order_against_equals() {
        let lt = to_string(&serde_json::json!(["<"])).unwrap();
        let eq = to_string(&serde_json::json!(["="])).unwrap();
        assert!(lt > eq, "escaped '<' must sort after '=' as Go's bytes do");
        assert!(
            serde_json::to_string(&serde_json::json!(["<"])).unwrap() < eq,
            "precondition: unescaped '<' sorts before '=', which is the bug"
        );
    }
}

/// Reproduces `encoding/json`'s `compact` with escaping enabled, which is what
/// `json.Marshal` applies to a `json.RawMessage`.
///
/// Two effects, both observable: insignificant whitespace outside strings is
/// dropped, and `<`, `>`, `&`, U+2028 and U+2029 are escaped.
///
/// This is a textual transform, exactly as Go's is, rather than a parse and
/// re-serialize. That matters: an MCP id may be an integer far beyond `i64`,
/// and round-tripping it through a JSON number type would silently change it.
pub fn compact(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut escaped = false;

    for ch in raw.chars() {
        if in_string {
            if escaped {
                escaped = false;
                out.push(ch);
                continue;
            }
            match ch {
                '\\' => {
                    escaped = true;
                    out.push(ch);
                }
                '"' => {
                    in_string = false;
                    out.push(ch);
                }
                '<' => out.push_str("\\u003c"),
                '>' => out.push_str("\\u003e"),
                '&' => out.push_str("\\u0026"),
                '\u{2028}' => out.push_str("\\u2028"),
                '\u{2029}' => out.push_str("\\u2029"),
                _ => out.push(ch),
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            // Insignificant whitespace between tokens.
            ' ' | '\t' | '\n' | '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod compact_tests {
    use super::compact;

    #[test]
    fn drops_insignificant_whitespace() {
        assert_eq!(
            compact("{\"a\":  1,  \"b\": \"x\"}"),
            "{\"a\":1,\"b\":\"x\"}"
        );
    }

    #[test]
    fn keeps_whitespace_inside_strings() {
        assert_eq!(compact("{\"a\":\"x  y\"}"), "{\"a\":\"x  y\"}");
    }

    #[test]
    fn escapes_html_characters() {
        assert_eq!(compact("\"<&>\""), "\"\\u003c\\u0026\\u003e\"");
    }

    /// A number too large for i64 must survive untouched, which is the reason
    /// this is a textual transform rather than a parse.
    #[test]
    fn preserves_oversized_numbers_exactly() {
        let big = "123456789012345678901234567890";
        assert_eq!(compact(big), big);
    }

    #[test]
    fn leaves_an_escaped_quote_alone() {
        assert_eq!(compact("\"a\\\"<b\""), "\"a\\\"\\u003cb\"");
    }
}
