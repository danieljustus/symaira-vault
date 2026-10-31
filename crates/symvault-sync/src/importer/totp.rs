use super::gourl;
use serde_json::{Value, json};
use symvault_core::totp::{validate_totp_params, validate_totp_secret};

/// Normalize imported bare secrets and otpauth URIs using the vault validators.
pub fn parse_totp(value: &str) -> Result<Value, String> {
    parse_totp_bytes(value.as_bytes())
}

/// [`parse_totp`] over a Go string that may hold invalid UTF-8. The URI is
/// parsed with a port of `net/url.Parse` so rejection and its error text match
/// Go (`parse "...": invalid URL escape "%zz"`).
pub fn parse_totp_bytes(value: &[u8]) -> Result<Value, String> {
    let value = super::pass::go_trim_space(value);
    if value.is_empty() {
        return Err("empty TOTP value".into());
    }
    let mut secret = value.to_vec();
    let mut algorithm = "SHA1".to_owned();
    let mut digits = 6;
    let mut period = 30;
    if value.len() >= 10 && value[..10].eq_ignore_ascii_case(b"otpauth://") {
        let parsed = gourl::parse(value).map_err(|error| format!("parse otpauth URI: {error}"))?;
        if !parsed.scheme.eq_ignore_ascii_case(b"otpauth") {
            return Err(format!(
                "unsupported TOTP scheme {}: only otpauth is supported",
                gourl::quote_bytes(&parsed.scheme)
            ));
        }
        if parsed.host.is_empty() {
            return Err("otpauth URI is missing the type (expected otpauth://totp/...)".into());
        }
        if !parsed.host.eq_ignore_ascii_case(b"totp") {
            return Err(format!(
                "unsupported otpauth type {}: only otpauth://totp/... is supported",
                gourl::quote_bytes(&parsed.host)
            ));
        }
        let query = gourl::query_first_values(&parsed.raw_query);
        secret = query
            .get(&b"secret"[..])
            .filter(|s| !s.is_empty())
            .ok_or("otpauth URI is missing the secret parameter")?
            .clone();
        if let Some(a) = query.get(&b"algorithm"[..]).filter(|s| !s.is_empty()) {
            algorithm = go_to_upper(&super::go_string_from_bytes(a));
        }
        if let Some(d) = query.get(&b"digits"[..]).filter(|s| !s.is_empty()) {
            let n = number(d, "digits")?;
            if n != 6 && n != 8 {
                return Err(format!(
                    "invalid TOTP digits {n} in otpauth URI: must be 6 or 8"
                ));
            }
            digits = n as i32;
        }
        if let Some(p) = query.get(&b"period"[..]).filter(|s| !s.is_empty()) {
            let n = number(p, "period")?;
            if !(1..=3600).contains(&n) {
                return Err(format!(
                    "invalid TOTP period {n} in otpauth URI: must be 1-3600 seconds"
                ));
            }
            period = n as i32;
        }
    }
    validated_totp(
        &super::go_string_from_bytes(&secret),
        &algorithm,
        digits.into(),
        period.into(),
    )
}

/// `strings.ToUpper`: Go applies the simple (one rune to one rune) mapping, so
/// a rune whose full Unicode uppercase expands (`ß` -> `SS`) stays as it is.
fn go_to_upper(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            let mut upper = character.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => character,
            }
        })
        .collect()
}

pub(super) fn validated_totp(
    secret: &str,
    algorithm: &str,
    digits: i64,
    period: i64,
) -> Result<Value, String> {
    validate_totp_secret(secret).map_err(|e| format!("invalid TOTP secret: {e}"))?;
    validate_totp_params(algorithm, digits, period)
        .map_err(|e| format!("invalid TOTP configuration: {e}"))?;
    Ok(json!({"secret":secret,"algorithm":algorithm,"digits":digits,"period":period}))
}
fn number(value: &[u8], field: &str) -> Result<i64, String> {
    let parsed = std::str::from_utf8(value)
        .map_err(|_| "invalid syntax")
        .and_then(|text| {
            text.parse::<i64>().map_err(|error| {
                if matches!(
                    error.kind(),
                    std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
                ) {
                    "value out of range"
                } else {
                    "invalid syntax"
                }
            })
        });
    parsed.map_err(|reason| {
        let quoted = gourl::quote_bytes(value);
        format!(
            "invalid TOTP {field} {quoted} in otpauth URI: strconv.Atoi: parsing {quoted}: {reason}"
        )
    })
}
