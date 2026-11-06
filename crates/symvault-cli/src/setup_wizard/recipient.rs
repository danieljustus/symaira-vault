//! Go `crypto.ValidateRecipient` error text for the recipients step.
//!
//! The wizard prints the validator's message next to the offending line, so
//! the text has to match Go. The bech32 decoder below is a trimmed copy of the
//! one in `symvault-ffi` (`gotext/bech32.rs`), which is crate-private to a
//! crate this one does not depend on; the key parse itself stays in
//! `symvault-crypto`.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

fn polymod(values: &[u8]) -> u32 {
    let mut chk = 1u32;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let lower = symvault_core::go_to_lower(hrp);
    let mut out: Vec<u8> = lower.bytes().map(|byte| byte >> 5).collect();
    out.push(0);
    out.extend(lower.bytes().map(|byte| byte & 31));
    out
}

fn convert_bits(data: &[u8], from: u32, to: u32) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    let max = (1u32 << to) - 1;
    for (index, value) in data.iter().enumerate() {
        if u32::from(*value) >> from != 0 {
            return Err(format!(
                "invalid data range: data[{index}]={value} (frombits={from})"
            ));
        }
        acc = (acc << from) | u32::from(*value);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if bits >= from {
        return Err("illegal zero padding".to_owned());
    }
    if (acc << (to - bits)) & max != 0 {
        return Err("non-zero padding".to_owned());
    }
    Ok(out)
}

fn go_upper(text: &str) -> String {
    text.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => c,
            }
        })
        .collect()
}

/// `internal/bech32.Decode`.
fn decode(text: &str) -> Result<(String, Vec<u8>), String> {
    let lower = symvault_core::go_to_lower(text);
    if lower != text && go_upper(text) != text {
        return Err("mixed case".to_owned());
    }
    let position = text.rfind('1');
    let length = text.len();
    let shown = position.map_or(-1, |value| value as i64);
    match position {
        Some(pos) if pos >= 1 && pos + 7 <= length => {
            let hrp = &text[..pos];
            for (offset, c) in hrp.char_indices() {
                if (c as u32) < 33 || (c as u32) > 126 {
                    return Err(format!(
                        "invalid character human-readable part: s[{offset}]={}",
                        c as u32
                    ));
                }
            }
            let mut data = Vec::new();
            for (offset, c) in text[pos + 1..].char_indices() {
                let folded = c.to_ascii_lowercase();
                match CHARSET
                    .iter()
                    .position(|candidate| char::from(*candidate) == folded)
                {
                    Some(index) => data.push(index as u8),
                    None => {
                        return Err(format!(
                            "invalid character data part: s[{offset}]={}",
                            folded as u32
                        ));
                    }
                }
            }
            if data.len() < 6 {
                return Err("data part too short".to_owned());
            }
            let mut check = hrp_expand(hrp);
            check.extend_from_slice(&data);
            if polymod(&check) != 1 {
                return Err("invalid checksum".to_owned());
            }
            let payload = convert_bits(&data[..data.len() - 6], 5, 8)?;
            Ok((hrp.to_owned(), payload))
        }
        _ => Err(format!(
            "separator '1' at invalid position: pos={shown}, len={length}"
        )),
    }
}

/// Go `strconv.Quote` for a valid string.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
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
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if (c as u32) < 0x1_0000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// `ValidateRecipient(recipient)`; `Err` carries Go's `err.Error()` text.
pub(crate) fn validate_recipient(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("recipient string is empty".to_owned());
    }
    if !text.starts_with("age1") {
        return Err("invalid key format: recipient must start with 'age1'".to_owned());
    }
    let (hrp, key) = decode(text).map_err(|reason| {
        format!(
            "invalid key format: malformed recipient {}: {reason}",
            quote(text)
        )
    })?;
    if hrp != "age" {
        return Err(format!(
            "invalid key format: malformed recipient {}: invalid type {}",
            quote(text),
            quote(&hrp)
        ));
    }
    if key.len() != 32 {
        return Err(format!(
            "invalid key format: malformed recipient {}: invalid X25519 public key",
            quote(text)
        ));
    }
    symvault_crypto::parse_recipient(text)
        .map(|_| ())
        .map_err(|_| {
            format!(
                "invalid key format: malformed recipient {}: invalid X25519 public key",
                quote(text)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "age1mdwavk4nralsx6te8ucvdenyxjaepgdqpk8zh6m4glsnu064eczskcng9y";

    #[test]
    fn valid_recipient_passes() {
        assert_eq!(validate_recipient(VALID), Ok(()));
    }

    #[test]
    fn go_error_texts_are_reproduced() {
        assert_eq!(
            validate_recipient("").unwrap_err(),
            "recipient string is empty"
        );
        assert_eq!(
            validate_recipient("ssh-ed25519 AAAA").unwrap_err(),
            "invalid key format: recipient must start with 'age1'"
        );
        assert_eq!(
            validate_recipient("age1short").unwrap_err(),
            "invalid key format: malformed recipient \"age1short\": separator '1' at invalid position: pos=3, len=9"
        );
        let mut broken = VALID.to_owned();
        broken.replace_range(10..11, "q");
        assert_eq!(
            validate_recipient(&broken).unwrap_err(),
            format!(
                "invalid key format: malformed recipient {}: invalid checksum",
                quote(&broken)
            )
        );
    }
}
