use serde_json::{Value, json};
use std::collections::BTreeMap;
use symvault_core::totp::{validate_totp_params, validate_totp_secret};

/// Normalize imported bare secrets and otpauth URIs using the vault validators.
pub fn parse_totp(value: &str) -> Result<Value, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty TOTP value".into());
    }
    let mut secret = value.to_owned();
    let mut algorithm = "SHA1".to_owned();
    let mut digits = 6;
    let mut period = 30;
    if value.to_ascii_lowercase().starts_with("otpauth://") {
        let parsed = url::Url::parse(value).map_err(|e| format!("parse otpauth URI: {e}"))?;
        let authority = value[10..].split(['/', '?', '#']).next().unwrap_or("");
        let host = authority.rsplit('@').next().unwrap_or("");
        if host.is_empty() {
            return Err("otpauth URI is missing the type (expected otpauth://totp/...)".into());
        }
        if !host.eq_ignore_ascii_case("totp") {
            return Err(format!(
                "unsupported otpauth type {host:?}: only otpauth://totp/... is supported"
            ));
        }
        let mut query = BTreeMap::new();
        // Go ParseQuery discards pairs with invalid escapes or raw semicolons.
        for pair in parsed.query().unwrap_or("").split('&') {
            if pair.contains(';') || !valid_escapes(pair) {
                continue;
            }
            for (key, value) in url::form_urlencoded::parse(pair.as_bytes()) {
                query
                    .entry(key.into_owned())
                    .or_insert_with(|| value.into_owned());
            }
        }
        secret = query
            .get("secret")
            .filter(|s| !s.is_empty())
            .ok_or("otpauth URI is missing the secret parameter")?
            .clone();
        if let Some(a) = query.get("algorithm").filter(|s| !s.is_empty()) {
            algorithm = a.to_uppercase();
        }
        if let Some(d) = query.get("digits").filter(|s| !s.is_empty()) {
            let n = number(d, "digits")?;
            if n != 6 && n != 8 {
                return Err(format!(
                    "invalid TOTP digits {n} in otpauth URI: must be 6 or 8"
                ));
            }
            digits = n as i32;
        }
        if let Some(p) = query.get("period").filter(|s| !s.is_empty()) {
            let n = number(p, "period")?;
            if !(1..=3600).contains(&n) {
                return Err(format!(
                    "invalid TOTP period {n} in otpauth URI: must be 1-3600 seconds"
                ));
            }
            period = n as i32;
        }
    }
    validated_totp(&secret, &algorithm, digits.into(), period.into())
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
fn number(value: &str, field: &str) -> Result<i64, String> {
    value.parse::<i64>().map_err(|error| {
        let reason = if matches!(error.kind(), std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow) { "value out of range" } else { "invalid syntax" };
        format!("invalid TOTP {field} {value:?} in otpauth URI: strconv.Atoi: parsing {value:?}: {reason}")
    })
}
fn valid_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return false;
            }
            i += 2;
        }
        i += 1;
    }
    true
}
