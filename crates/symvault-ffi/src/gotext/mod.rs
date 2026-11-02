//! Reproduction of the Go standard-library and `filippo.io/age` error texts
//! that the gomobile bridge hands to Swift unchanged.
//!
//! Go formats `error` values as free text, and the mobile client displays
//! them. The Rust crates keep typed failure classes instead; this module is the
//! single place where those classes are mapped back to Go's exact wording. Every
//! mapping is pinned by `testdata/port/ffi/mobilebind.json`.

pub(crate) mod agehdr;
pub(crate) mod bech32;
pub(crate) mod entryjson;
pub(crate) mod timefmt;

use std::io;

/// Go `strconv.Quote` (`%q`) over arbitrary bytes. Invalid UTF-8 becomes `\xNN`
/// per byte, exactly as Go does for a string that is not valid UTF-8.
pub(crate) fn quote_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    let mut rest = bytes;
    while !rest.is_empty() {
        let (decoded, width) = decode_rune(rest);
        match decoded {
            None => out.push_str(&format!("\\x{:02x}", rest[0])),
            Some(c) => push_escaped(&mut out, c),
        }
        rest = &rest[width..];
    }
    out.push('"');
    out
}

fn decode_rune(bytes: &[u8]) -> (Option<char>, usize) {
    let first = bytes[0];
    let width = match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return (None, 1),
    };
    if bytes.len() < width {
        return (None, 1);
    }
    match std::str::from_utf8(&bytes[..width]) {
        Ok(text) => (text.chars().next(), width),
        Err(_) => (None, 1),
    }
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\u{7}' => out.push_str("\\a"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{b}' => out.push_str("\\v"),
        c if symvault_core::go_is_print(c) => out.push(c),
        c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
        c if (c as u32) < 0x1_0000 => out.push_str(&format!("\\u{:04x}", c as u32)),
        c => out.push_str(&format!("\\U{:08x}", c as u32)),
    }
}

/// `%q` of a valid string.
pub(crate) fn quote(text: &str) -> String {
    quote_bytes(text.as_bytes())
}

/// The lower-case `strerror` wording Go's `syscall.Errno` prints.
pub(crate) fn errno_text(error: &io::Error) -> String {
    symvault_store::zero_key::errno_text(error)
}

/// Go `*fs.PathError`: `op path: reason`.
pub(crate) fn path_error(op: &str, path: &str, error: &io::Error) -> String {
    format!("{op} {path}: {}", errno_text(error))
}

/// Go `strings.TrimSpace`. `char::is_whitespace` is the Unicode `White_Space`
/// property, which is the set Go's `unicode.IsSpace` implements.
pub(crate) fn trim_space(text: &str) -> &str {
    text.trim()
}

/// Go `base64.RawStdEncoding.Strict()` as used by age (`format.DecodeString`),
/// including the exact `CorruptInputError` offsets.
pub(crate) fn age_base64_decode(text: &str) -> Result<Vec<u8>, String> {
    if text.contains(['\n', '\r']) {
        return Err("unexpected newline character".to_owned());
    }
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut position = 0usize;
    while position < bytes.len() {
        let mut quantum = [0u8; 4];
        let mut length = 4usize;
        let mut index = 0usize;
        while index < 4 {
            if position == bytes.len() {
                if index == 1 {
                    return Err(corrupt(position - index));
                }
                length = index;
                break;
            }
            let byte = bytes[position];
            position += 1;
            match ALPHABET.iter().position(|candidate| *candidate == byte) {
                Some(value) => quantum[index] = value as u8,
                None => return Err(corrupt(position - 1)),
            }
            index += 1;
        }
        let value = u32::from(quantum[0]) << 18
            | u32::from(quantum[1]) << 12
            | u32::from(quantum[2]) << 6
            | u32::from(quantum[3]);
        let triple = [(value >> 16) as u8, (value >> 8) as u8, value as u8];
        match length {
            4 => out.extend_from_slice(&triple),
            3 => {
                out.extend_from_slice(&triple[..2]);
                if triple[2] != 0 {
                    return Err(corrupt(position - 1));
                }
            }
            2 => {
                out.push(triple[0]);
                if triple[1] != 0 || triple[2] != 0 {
                    return Err(corrupt(position - 2));
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

fn corrupt(offset: usize) -> String {
    format!("illegal base64 data at input byte {offset}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_matches_go_for_control_and_invalid_bytes() {
        assert_eq!(quote_bytes(b"a\x00b"), "\"a\\x00b\"");
        assert_eq!(quote_bytes(&[0xff, 0xfe, b'\n']), "\"\\xff\\xfe\\n\"");
        assert_eq!(quote("é✓"), "\"é✓\"");
        assert_eq!(quote("\u{2028}"), "\"\\u2028\"");
    }

    #[test]
    fn base64_errors_use_go_offsets() {
        assert_eq!(age_base64_decode("AAAA").unwrap(), vec![0, 0, 0]);
        assert_eq!(
            age_base64_decode("AA*A").unwrap_err(),
            "illegal base64 data at input byte 2"
        );
        assert_eq!(
            age_base64_decode("AAAAA").unwrap_err(),
            "illegal base64 data at input byte 4"
        );
        assert_eq!(
            age_base64_decode("AAB").unwrap_err(),
            "illegal base64 data at input byte 2"
        );
    }
}
