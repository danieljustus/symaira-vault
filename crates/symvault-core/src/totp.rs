#![deny(unsafe_code)]

//! RFC 6238 TOTP generation and validation with explicit clock input.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// A generated TOTP value and the end of its current period.
#[derive(Clone, Eq, PartialEq)]
pub struct TotpCode {
    pub code: String,
    pub expires_at: i64,
    pub period: i32,
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TotpCode(REDACTED)")
    }
}

/// TOTP validation or generation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpError(String);

impl TotpError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TotpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TotpError {}

/// Validates a Base32 TOTP secret and rejects trivially weak values.
pub fn validate_totp_secret(secret: &str) -> Result<(), TotpError> {
    let normalized = normalize_secret(secret);
    if normalized.len() > 256 {
        return Err(TotpError::new(
            "TOTP secret too long: maximum 256 base32 characters",
        ));
    }

    let decoded = decode_secret(&normalized)
        .ok_or_else(|| TotpError::new("TOTP secret must be Base32-encoded (spaces allowed)"))?;
    if decoded.len() < 16 {
        return Err(TotpError::new(
            "TOTP secret too short: minimum 16 bytes required (26 base32 characters)",
        ));
    }
    if decoded.windows(2).all(|window| window[0] == window[1]) {
        return Err(TotpError::new(
            "TOTP secret is trivially weak: all bytes identical",
        ));
    }
    if decoded
        .windows(2)
        .all(|window| window[1] == window[0].wrapping_add(1))
    {
        return Err(TotpError::new(
            "TOTP secret is trivially weak: bytes are sequential",
        ));
    }
    Ok(())
}

/// Validates RFC 6238 algorithm, digits, and period bounds.
pub fn validate_totp_params(
    algorithm: &str,
    digits: impl Into<i64>,
    period: impl Into<i64>,
) -> Result<(), TotpError> {
    let (digits, period) = (digits.into(), period.into());
    let algorithm_upper = algorithm.to_ascii_uppercase();
    if !algorithm_upper.is_empty()
        && !matches!(algorithm_upper.as_str(), "SHA1" | "SHA256" | "SHA512")
    {
        return Err(TotpError::new(format!(
            "invalid TOTP algorithm {algorithm:?}: must be SHA1, SHA256, or SHA512"
        )));
    }
    if digits != 0 && digits != 6 && digits != 8 {
        return Err(TotpError::new(format!(
            "invalid TOTP digits {digits}: must be 6 or 8"
        )));
    }
    if period != 0 && (period <= 0 || period > 3600) {
        return Err(TotpError::new(format!(
            "invalid TOTP period {period}: must be 1-3600 seconds"
        )));
    }
    Ok(())
}

/// Generates a TOTP using the current system clock.
pub fn generate_totp(
    secret: &str,
    algorithm: &str,
    digits: i32,
    period: i32,
) -> Result<TotpCode, TotpError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TotpError::new("system time is before Unix epoch"))?;
    generate_totp_at(secret, algorithm, digits, period, now.as_secs() as i64)
}

/// Generates a TOTP at an explicit Unix timestamp.
pub fn generate_totp_at(
    secret: &str,
    algorithm: &str,
    digits: i32,
    period: i32,
    unix_time: i64,
) -> Result<TotpCode, TotpError> {
    validate_totp_params(algorithm, digits, period)?;
    let algorithm = if algorithm.is_empty() {
        "SHA1"
    } else {
        algorithm
    };
    let digits = if digits == 0 { 6 } else { digits };
    let period = if period == 0 { 30 } else { period };
    let key = decode_secret(&normalize_secret(secret))
        .ok_or_else(|| TotpError::new("invalid TOTP secret"))?;
    if unix_time < 0 {
        return Err(TotpError::new("system time is before Unix epoch"));
    }

    let counter = unix_time / i64::from(period);
    let counter_bytes = counter.to_be_bytes();
    let digest = match algorithm.to_ascii_uppercase().as_str() {
        "SHA256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_slice())
                .expect("HMAC accepts keys of every length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key.as_slice())
                .expect("HMAC accepts keys of every length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key.as_slice())
                .expect("HMAC accepts keys of every length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let truncated = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    let modulus = 10_u32.pow(digits as u32);
    let value = truncated % modulus;
    let code = format!("{value:0width$}", width = digits as usize);
    let expires_at = (counter + 1) * i64::from(period);

    Ok(TotpCode {
        code,
        expires_at,
        period,
    })
}

fn normalize_secret(secret: &str) -> String {
    // Go: strings.ToUpper(strings.ReplaceAll(secret, " ", "")). ToUpper applies
    // the simple (single-rune) mapping, so a rune whose full mapping expands
    // (for example U+00DF) stays unchanged instead of becoming "SS".
    secret
        .chars()
        .filter(|character| *character != ' ')
        .map(|character| {
            let mut upper = character.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => character,
            }
        })
        .collect()
}

/// Port of Go `encoding/base32` `StdEncoding.DecodeString` followed, on error,
/// by `StdEncoding.WithPadding(NoPadding).DecodeString` (the order used by
/// `crypto.ValidateTOTPSecret` and `GenerateTOTPAt`).
fn decode_secret(secret: &str) -> Option<Zeroizing<Vec<u8>>> {
    // DecodeString strips CR and LF before decoding.
    let bytes: Vec<u8> = secret
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .collect();
    let decoded = go_base32_decode(&bytes, true).or_else(|| go_base32_decode(&bytes, false))?;
    (!decoded.is_empty()).then(|| Zeroizing::new(decoded))
}

fn base32_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'2'..=b'7' => Some(byte - b'2' + 26),
        _ => None,
    }
}

/// Mirrors `(*Encoding).decode`, including its quirks: with padding enabled a
/// pad run only has to cover the next `8-1-j` characters (anything after is
/// ignored), and with `NoPadding` a final group of 1, 3 or 6 characters is
/// silently dropped instead of rejected.
fn go_base32_decode(source: &[u8], padded: bool) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(source.len() / 8 * 5 + 5);
    let mut rest = source;
    let mut end = false;
    while !rest.is_empty() && !end {
        let mut block = [0u8; 8];
        let mut length = 8;
        let mut j = 0;
        while j < 8 {
            let Some((&input, tail)) = rest.split_first() else {
                if padded {
                    return None;
                }
                length = j;
                end = true;
                break;
            };
            rest = tail;
            if padded && input == b'=' && j >= 2 && rest.len() < 8 {
                if rest.len() + j < 8 - 1 {
                    return None;
                }
                for k in 0..(8 - 1 - j) {
                    if rest.len() > k && rest[k] != b'=' {
                        return None;
                    }
                }
                length = j;
                end = true;
                if matches!(length, 1 | 3 | 6) {
                    return None;
                }
                break;
            }
            block[j] = base32_value(input)?;
            j += 1;
        }
        // Go's switch on the group length falls through downwards; lengths
        // 0, 1, 3 and 6 match no case and contribute no bytes.
        let count = match length {
            8 => 5,
            7 => 4,
            5 => 3,
            4 => 2,
            2 => 1,
            _ => 0,
        };
        let packed = [
            block[0] << 3 | block[1] >> 2,
            block[1] << 6 | block[2] << 1 | block[3] >> 4,
            block[3] << 4 | block[4] >> 1,
            block[4] << 7 | block[5] << 2 | block[6] >> 3,
            block[6] << 5 | block[7],
        ];
        output.extend_from_slice(&packed[..count]);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_validation_follows_go_base32_decode_order() {
        // A trailing six-character group is dropped, not rejected (NoPadding).
        assert!(validate_totp_secret("JBSWY3DPEHPK3PXPJBSPXPJBSWY3DPEHPK3PXP").is_ok());
        assert_eq!(
            validate_totp_secret("JBSWY3DPEHPK3PWY3DPEHPK3PXP")
                .unwrap_err()
                .to_string(),
            "TOTP secret too short: minimum 16 bytes required (26 base32 characters)"
        );
        // Padding past the required run is ignored; a short run is rejected.
        assert!(validate_totp_secret("JBSWY3DPEHPK3PXPJBSWY3DPEH======ZZ").is_ok());
        assert!(validate_totp_secret("JBSWY3DPEHPK3PXPJBSWY3DPEH=====").is_err());
        // Simple case mapping: U+00DF does not become "SS".
        assert!(validate_totp_secret("\u{df}BSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn rfc6238_sha1_vectors_match() {
        let code =
            generate_totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30, 0).expect("TOTP");
        assert_eq!(code.code, "755224");
        assert_eq!(code.expires_at, 30);
    }

    #[test]
    fn defaults_and_validation_match_go() {
        let code = generate_totp_at(
            "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
            "",
            0,
            0,
            2_000_000_000,
        )
        .expect("TOTP");
        assert_eq!(code.period, 30);
        assert_eq!(code.expires_at, 2_000_000_010);
        assert_eq!(
            validate_totp_params("MD5", 6, 30).unwrap_err().to_string(),
            "invalid TOTP algorithm \"MD5\": must be SHA1, SHA256, or SHA512"
        );
    }

    #[test]
    fn secret_policy_rejects_weak_values() {
        assert_eq!(
            validate_totp_secret("A").unwrap_err().to_string(),
            "TOTP secret must be Base32-encoded (spaces allowed)"
        );
        assert_eq!(
            validate_totp_secret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap_err()
                .to_string(),
            "TOTP secret is trivially weak: all bytes identical"
        );
    }

    #[test]
    fn empty_decoded_secret_is_rejected_without_leaking_input() {
        let secret = "A";
        let validation_error = validate_totp_secret(secret).unwrap_err();
        assert_eq!(
            validation_error.to_string(),
            "TOTP secret must be Base32-encoded (spaces allowed)"
        );
        assert!(!format!("{validation_error:?}").contains(secret));

        let generation_error = generate_totp_at(secret, "SHA1", 6, 30, 0).unwrap_err();
        assert_eq!(generation_error.to_string(), "invalid TOTP secret");
        assert!(!format!("{generation_error:?}").contains(secret));
    }

    #[test]
    fn generated_code_debug_output_is_redacted() {
        let code =
            generate_totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30, 0).expect("TOTP");
        let debug = format!("{code:?}");
        assert_eq!(code.code, "755224");
        assert_eq!(debug, "TotpCode(REDACTED)");
        assert!(!debug.contains(&code.code));
    }
}
