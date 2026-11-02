//! The text Go's `vault.OpenWithPassphrase` gives for an identity file the
//! passphrase cannot open (`internal/vault/vault.go`, `internal/crypto`).
//!
//! The Go error chain is reproduced in order, not by outcome class:
//!
//! * An Argon2id envelope that fails to unwrap (and is not a resource-policy
//!   error) goes through `tryHealZeroKeyIdentity`, whose
//!   `trustedZeroKeyAuthorities` reads `recipients.txt` first and so replaces
//!   the unwrap error with its own: a missing, symlinked, non-regular or
//!   unreadable file is `requires a trusted recipients.txt`; an empty, garbled
//!   or comment-only file is `requires valid recipients.txt authority`; only a
//!   valid file lets `RecoverZeroKeyIdentityWithAuthorities` run and report
//!   `zero-key recovery failed: decryption failed`.
//! * Any other envelope is read by `LoadIdentity`, which wraps the age library
//!   error as `decryption failed: <age error>`. The age header parser
//!   (`internal/format`) is mirrored here because its messages quote the
//!   offending bytes.

use std::{fs, path::Path};

use symvault_crypto::{EnvelopeFormat, FailureClass};

const TRUSTED: &str = "load identity: zero-key recovery requires a trusted recipients.txt";
const VALID_AUTHORITY: &str =
    "load identity: zero-key recovery requires valid recipients.txt authority";
const INTRO: &[u8] = b"age-encryption.org/v1\n";
const MAX_SCAN_TOKEN: usize = 64 * 1024;

/// `vault.OpenWithPassphrase`'s `load identity: ...` failure for `envelope`
/// opened with a non-empty `passphrase` (an empty one is refused before the
/// identity is read); `class` is why the Rust crypto layer refused it.
pub(crate) fn load_identity_error(
    vault: &Path,
    envelope: &[u8],
    passphrase: &[u8],
    class: FailureClass,
) -> String {
    if symvault_crypto::detect_envelope(envelope) == EnvelopeFormat::Argon2id {
        // `IsArgon2ResourceError` errors are returned as they are.
        match class {
            FailureClass::ResourcePolicy => {
                return "load identity: argon2id resource policy: use migrate kdf --allow-legacy-kdf for a historical identity"
                    .to_owned();
            }
            FailureClass::ResourceBusy => {
                return "load identity: argon2id resources busy".to_owned();
            }
            FailureClass::ParameterBounds => {
                return "load identity: argon2id parameters out of bounds".to_owned();
            }
            _ => {}
        }
        return match trusted_authority(vault) {
            Err(message) => message.to_owned(),
            Ok(()) if passphrase.len() > 1024 => {
                "load identity: zero-key length is invalid".to_owned()
            }
            Ok(()) => "load identity: zero-key recovery failed: decryption failed".to_owned(),
        };
    }
    format!("load identity: decryption failed: {}", age_error(envelope))
}

/// `trustedZeroKeyAuthorities`: `recipients.txt` must be a regular, readable
/// file (`SafeReadFile` refuses a symlink) listing at least one valid
/// recipient, with every other line blank or a comment.
fn trusted_authority(vault: &Path) -> Result<(), &'static str> {
    let path = vault.join("recipients.txt");
    let regular = fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file());
    let snapshot = if regular { fs::read(&path).ok() } else { None };
    let snapshot = snapshot.ok_or(TRUSTED)?;

    let mut recipients = 0usize;
    let mut rest = snapshot.as_slice();
    while !rest.is_empty() {
        let (line, terminated, next) = match rest.iter().position(|&byte| byte == b'\n') {
            Some(end) => (&rest[..end], true, &rest[end + 1..]),
            None => (rest, false, &rest[rest.len()..]),
        };
        // bufio.Scanner gives up on a line that fills its 64 KiB buffer.
        let held = line.len() + usize::from(terminated);
        if held > MAX_SCAN_TOKEN || (!terminated && held >= MAX_SCAN_TOKEN) {
            return Err(VALID_AUTHORITY);
        }
        rest = next;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = String::from_utf8_lossy(line);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if !text.starts_with("age1") || symvault_crypto::parse_recipient(text).is_err() {
            return Err(VALID_AUTHORITY);
        }
        recipients += 1;
    }
    if recipients == 0 {
        return Err(VALID_AUTHORITY);
    }
    Ok(())
}

struct Stanza {
    kind: String,
    args: Vec<String>,
    body_len: usize,
}

/// The error `age.Decrypt` returns for `raw` and a passphrase that does not
/// match (`ScryptIdentity`, as `LoadIdentity` builds it).
fn age_error(raw: &[u8]) -> String {
    let stanzas = match parse_header(raw) {
        Ok(stanzas) => stanzas,
        Err(message) => return format!("failed to read header: {message}"),
    };
    let has_scrypt = stanzas.iter().any(|stanza| stanza.kind == "scrypt");
    if has_scrypt && stanzas.len() != 1 {
        return "an scrypt recipient must be the only one".to_owned();
    }
    let wrapped = |cause: &str| {
        format!(
            "identity did not match any of the recipients: incorrect identity for recipient block: {cause}"
        )
    };
    let Some(stanza) = stanzas.iter().find(|stanza| stanza.kind == "scrypt") else {
        return wrapped("file is not passphrase-encrypted");
    };
    if stanza.args.len() != 2 {
        return "invalid scrypt recipient block".to_owned();
    }
    match decode_base64(&stanza.args[0]) {
        Err(cause) => return format!("failed to parse scrypt salt: {cause}"),
        Ok(salt) if salt.len() != 16 => return "invalid scrypt recipient block".to_owned(),
        Ok(_) => {}
    }
    let work = &stanza.args[1];
    if !(work.bytes().all(|byte| byte.is_ascii_digit()) && !work.starts_with('0')) {
        return format!(
            "scrypt work factor encoding invalid: {}",
            go_quote(work.as_bytes())
        );
    }
    match work.parse::<i64>() {
        Err(_) => {
            return format!(
                "failed to parse scrypt work factor: strconv.Atoi: parsing {}: value out of range",
                go_quote(work.as_bytes())
            );
        }
        Ok(log_n) if log_n > 22 => return format!("scrypt work factor too large: {log_n}"),
        Ok(_) => {}
    }
    if stanza.body_len != 32 {
        return "invalid scrypt recipient block: incorrect file key size".to_owned();
    }
    wrapped("incorrect passphrase")
}

/// Mirror of `format.Parse`'s header phase; the error is what `Parse` returns
/// (so what follows `failed to read header: `).
fn parse_header(raw: &[u8]) -> Result<Vec<Stanza>, String> {
    let parse_error = |message: String| format!("parsing age header: {message}");
    let mut position = 0usize;
    // Reads one line (delimiter included); the flag is false at EOF.
    let read_line = |position: &mut usize| -> (Vec<u8>, bool) {
        let rest = &raw[*position..];
        match rest.iter().position(|&byte| byte == b'\n') {
            Some(end) => {
                *position += end + 1;
                (rest[..=end].to_vec(), true)
            }
            None => {
                *position = raw.len();
                (rest.to_vec(), false)
            }
        }
    };

    let (line, complete) = read_line(&mut position);
    if !complete {
        if line.is_empty() {
            return Err(parse_error("file is empty".to_owned()));
        }
        return Err(parse_error(match describe_intro(&line) {
            Some(description) => format!("unexpected EOF reading intro: {description}"),
            None => format!("unexpected EOF reading intro, expected {}", go_quote(INTRO)),
        }));
    }
    if line != INTRO {
        return Err(parse_error(match describe_intro(&line) {
            Some(description) => format!("unexpected intro: {description}"),
            None => format!("unexpected intro, expected {}", go_quote(INTRO)),
        }));
    }

    let mut stanzas: Vec<Stanza> = Vec::new();
    loop {
        let remaining = &raw[position..];
        if remaining.len() < 3 {
            return Err(parse_error("failed to read header: EOF".to_owned()));
        }
        if &remaining[..3] == b"---" {
            let (line, complete) = read_line(&mut position);
            if !complete {
                return Err("failed to read header: EOF".to_owned());
            }
            let (prefix, args) = split_args(&line);
            if prefix != "---" || args.len() != 1 {
                return Err(parse_error(format!(
                    "malformed closing line: {}",
                    go_quote(&line)
                )));
            }
            match decode_base64(&args[0]) {
                Ok(mac) if mac.len() == 32 => {}
                Ok(_) => {
                    return Err(parse_error(format!(
                        "malformed closing line {}: <nil>",
                        go_quote(&line)
                    )));
                }
                Err(cause) => {
                    return Err(parse_error(format!(
                        "malformed closing line {}: {cause}",
                        go_quote(&line)
                    )));
                }
            }
            break;
        }
        if stanzas.len() == 1024 {
            return Err(parse_error(
                "header contains more than 1024 recipient stanzas".to_owned(),
            ));
        }
        stanzas.push(
            read_stanza(raw, &mut position)
                .map_err(|message| format!("failed to parse header: {message}"))?,
        );
    }
    if stanzas.is_empty() {
        return Err(parse_error("no recipient stanzas".to_owned()));
    }
    Ok(stanzas)
}

/// `StanzaReader.ReadStanza`; its errors are `ParseError`s only where Go
/// builds them with `errorf`.
fn read_stanza(raw: &[u8], position: &mut usize) -> Result<Stanza, String> {
    let next_line = |position: &mut usize| -> Result<Vec<u8>, String> {
        let rest = &raw[*position..];
        match rest.iter().position(|&byte| byte == b'\n') {
            Some(end) => {
                *position += end + 1;
                Ok(rest[..=end].to_vec())
            }
            None => {
                *position = raw.len();
                Err("failed to read line: EOF".to_owned())
            }
        }
    };
    let line = next_line(position)?;
    if !line.starts_with(b"->") {
        return Err(format!(
            "malformed stanza opening line: {}",
            go_quote(&line)
        ));
    }
    let (prefix, args) = split_args(&line);
    if prefix != "->" || args.is_empty() {
        return Err(format!("malformed stanza: {}", go_quote(&line)));
    }
    let mut stanza = Stanza {
        kind: args[0].clone(),
        args: args[1..].to_vec(),
        body_len: 0,
    };
    loop {
        let line = next_line(position)?;
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        let text = String::from_utf8_lossy(text);
        let decoded = if text.contains(['\n', '\r']) {
            Err("unexpected newline character".to_owned())
        } else {
            decode_base64(&text)
        };
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(cause) => {
                if line.starts_with(b"---") || line.starts_with(b"->") {
                    return Err(format!(
                        "malformed body line {}: stanza ended without a short line\nnote: this might be a file encrypted with an old beta version of age or rage; use age v1.0.0-beta6 or rage to decrypt it",
                        go_quote(&line)
                    ));
                }
                return Err(format!(
                    "parsing age header: malformed body line {}: {cause}",
                    go_quote(&line)
                ));
            }
        };
        if decoded.len() > 48 {
            return Err(format!(
                "parsing age header: malformed body line {}: too long",
                go_quote(&line)
            ));
        }
        stanza.body_len += decoded.len();
        if decoded.len() < 48 {
            return Ok(stanza);
        }
    }
}

/// `splitArgs`: the first token and its space separated arguments, each of
/// printable ASCII; any invalid argument (or more than 129) gives the whole
/// line as the prefix and no arguments.
fn split_args(line: &[u8]) -> (String, Vec<String>) {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let whole = || String::from_utf8_lossy(line).into_owned();
    let Some(cut) = line.iter().position(|&byte| byte == b' ') else {
        return (whole(), Vec::new());
    };
    let (prefix, rest) = (&line[..cut], &line[cut + 1..]);
    let mut args = Vec::new();
    for arg in rest.split(|&byte| byte == b' ') {
        if arg.is_empty() || !arg.iter().all(|byte| (33..=126).contains(byte)) || args.len() > 128 {
            return (whole(), Vec::new());
        }
        args.push(String::from_utf8_lossy(arg).into_owned());
    }
    (String::from_utf8_lossy(prefix).into_owned(), args)
}

/// `describeIntro`: a quoted copy of the bad intro line, empty (here `None`)
/// when it looks like private key material.
fn describe_intro(line: &[u8]) -> Option<String> {
    if line.starts_with(b"AGE-SECRET-KEY-") || line.starts_with(b"AGE-PLUGIN-") {
        return None;
    }
    Some(go_quote(&line[..line.len().min(INTRO.len())]))
}

/// age's strict, unpadded base64 (`base64.RawStdEncoding.Strict()`), with Go's
/// `CorruptInputError` text.
fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    if text.contains(['\n', '\r']) {
        return Err("unexpected newline character".to_owned());
    }
    let corrupt = |at: usize| format!("illegal base64 data at input byte {at}");
    let value = |byte: u8| -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut group = [0u32; 4];
        for (offset, &byte) in chunk.iter().enumerate() {
            group[offset] = value(byte).ok_or_else(|| corrupt(index * 4 + offset))?;
        }
        let len = chunk.len();
        if len == 1 {
            return Err(corrupt(bytes.len() - 1));
        }
        let word = group[0] << 18 | group[1] << 12 | group[2] << 6 | group[3];
        let (b0, b1, b2) = ((word >> 16) as u8, (word >> 8) as u8, word as u8);
        match len {
            4 => out.extend([b0, b1, b2]),
            3 => {
                if b2 != 0 {
                    return Err(corrupt(bytes.len() - 1));
                }
                out.extend([b0, b1]);
            }
            _ => {
                if b1 != 0 || b2 != 0 {
                    return Err(corrupt(bytes.len() - 2));
                }
                out.push(b0);
            }
        }
    }
    Ok(out)
}

/// `strconv.Quote` for a byte string (Go's `%q`): invalid UTF-8 bytes become
/// `\xNN`, control characters their escapes.
fn go_quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut rest = bytes;
    while !rest.is_empty() {
        let (text, bad) = match std::str::from_utf8(rest) {
            Ok(text) => (text, 0),
            Err(error) => {
                let valid = error.valid_up_to();
                let bad = error.error_len().unwrap_or(rest.len() - valid);
                (std::str::from_utf8(&rest[..valid]).unwrap_or(""), bad)
            }
        };
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{7}' => out.push_str("\\a"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{b}' => out.push_str("\\v"),
                ' ' => out.push(' '),
                c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                    out.push_str(&format!("\\x{:02x}", c as u32));
                }
                c if c.is_ascii() => out.push(c),
                c if c.is_control() || c.is_whitespace() || is_format(c) => {
                    if (c as u32) <= 0xffff {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    } else {
                        out.push_str(&format!("\\U{:08x}", c as u32));
                    }
                }
                c => out.push(c),
            }
        }
        rest = &rest[text.len()..];
        for &byte in &rest[..bad.min(rest.len())] {
            out.push_str(&format!("\\x{byte:02x}"));
        }
        rest = &rest[bad.min(rest.len())..];
    }
    out.push('"');
    out
}

/// Format characters Go's `unicode.IsPrint` rejects (category Cf and similar).
fn is_format(c: char) -> bool {
    matches!(
        c as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x180e | 0x200b..=0x200f
            | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff | 0xfff9..=0xfffb
            | 0xe0001 | 0xe0020..=0xe007f
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_matches_go_for_the_intro_shapes() {
        assert_eq!(
            go_quote(b"garbage not age data\n"),
            "\"garbage not age data\\n\""
        );
        assert_eq!(go_quote(&[b'a', 0xff, b'"', 0x01]), "\"a\\xff\\\"\\x01\"");
        assert_eq!(go_quote("é".as_bytes()), "\"é\"");
        assert_eq!(go_quote(&"é".as_bytes()[..1]), "\"\\xc3\"");
    }

    #[test]
    fn base64_errors_carry_go_offsets() {
        assert_eq!(decode_base64("AAAA").unwrap(), vec![0, 0, 0]);
        assert_eq!(
            decode_base64("A").unwrap_err(),
            "illegal base64 data at input byte 0"
        );
        assert_eq!(
            decode_base64("AB!A").unwrap_err(),
            "illegal base64 data at input byte 2"
        );
        assert_eq!(
            decode_base64("AAB").unwrap_err(),
            "illegal base64 data at input byte 2"
        );
        assert_eq!(
            decode_base64("AB").unwrap_err(),
            "illegal base64 data at input byte 0"
        );
        assert_eq!(
            decode_base64("AAA=").unwrap_err(),
            "illegal base64 data at input byte 3"
        );
    }

    #[test]
    fn header_errors_follow_the_age_parser() {
        assert_eq!(
            parse_header(b"").err().unwrap(),
            "parsing age header: file is empty"
        );
        assert_eq!(
            parse_header(b"garbage\n").err().unwrap(),
            "parsing age header: unexpected intro: \"garbage\\n\""
        );
        assert_eq!(
            parse_header(b"age-encryption.org/v1\n").err().unwrap(),
            "parsing age header: failed to read header: EOF"
        );
        assert_eq!(
            parse_header(b"age-encryption.org/v1\nxx\n").err().unwrap(),
            "failed to parse header: malformed stanza opening line: \"xx\\n\""
        );
    }
}
