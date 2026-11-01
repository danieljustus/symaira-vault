//! Go `internal/crypto.ValidateIdentity` / `ValidateRecipient` over
//! `filippo.io/age`'s bech32 decoder, reproduced down to the error text.
//!
//! The real key parsing stays in `symvault-crypto`; this module only decides
//! which Go error a malformed string produced, and returns the parsed key when
//! Go would have accepted the string.

use symvault_crypto::{Identity, Recipient, parse_identity, parse_recipient};

use super::{quote, trim_space};

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

/// Go simple-case folding, per rune.
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
    if symvault_core::go_to_lower(text) != text && go_upper(text) != text {
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
                let folded = if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c
                };
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

/// `ValidateIdentity(strings.TrimSpace(text))`.
pub(crate) fn validate_identity(text: &str) -> Result<Identity, String> {
    validate_identity_trimmed(trim_space(text))
}

fn validate_identity_trimmed(text: &str) -> Result<Identity, String> {
    if text.is_empty() {
        return Err("identity string is empty".to_owned());
    }
    if !text.starts_with("AGE-SECRET-KEY-") {
        return Err("invalid key format: identity must start with 'AGE-SECRET-KEY-'".to_owned());
    }
    let (hrp, key) = decode(text)
        .map_err(|reason| format!("invalid key format: malformed secret key: {reason}"))?;
    if hrp != "AGE-SECRET-KEY-" {
        return Err(format!(
            "invalid key format: malformed secret key: unknown type {}",
            quote(&hrp)
        ));
    }
    if key.len() != 32 {
        return Err(
            "invalid key format: malformed secret key: invalid X25519 secret key".to_owned(),
        );
    }
    parse_identity(text).map_err(|_| {
        "invalid key format: malformed secret key: invalid X25519 secret key".to_owned()
    })
}

/// `ValidateRecipient(strings.TrimSpace(text))`.
pub(crate) fn validate_recipient(text: &str) -> Result<Recipient, String> {
    let text = trim_space(text);
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
    parse_recipient(text).map_err(|_| {
        format!(
            "invalid key format: malformed recipient {}: invalid X25519 public key",
            quote(text)
        )
    })
}
