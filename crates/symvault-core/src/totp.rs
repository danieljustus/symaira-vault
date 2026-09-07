#![deny(unsafe_code)]

//! RFC 6238 TOTP generation and validation with explicit clock input.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
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
pub fn validate_totp_params(algorithm: &str, digits: i32, period: i32) -> Result<(), TotpError> {
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
    secret
        .chars()
        .filter(|character| *character != ' ')
        .flat_map(char::to_uppercase)
        .collect()
}

fn decode_secret(secret: &str) -> Option<Zeroizing<Vec<u8>>> {
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret))?;
    (!decoded.is_empty()).then(|| Zeroizing::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

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
