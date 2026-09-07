#![deny(unsafe_code)]

use base64::Engine;
use serde::Deserialize;
use symvault_core::{password, totp};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    password_cases: Vec<PasswordCase>,
    strength_cases: Vec<StrengthCase>,
    totp_secret_cases: Vec<TotpSecretCase>,
    totp_param_cases: Vec<TotpParamCase>,
    totp_cases: Vec<TotpCase>,
}

#[derive(Debug, Deserialize)]
struct PasswordCase {
    name: String,
    length: isize,
    use_symbols: bool,
    #[serde(default)]
    reader_bytes: String,
    #[serde(default)]
    expected: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
struct StrengthCase {
    name: String,
    input: String,
    weak: bool,
    #[serde(default)]
    message: String,
    entropy: f64,
    #[serde(default)]
    missing: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TotpSecretCase {
    name: String,
    input: String,
    valid: bool,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
struct TotpParamCase {
    name: String,
    algorithm: String,
    digits: i32,
    period: i32,
    valid: bool,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
struct TotpCase {
    name: String,
    secret: String,
    algorithm: String,
    digits: i32,
    period: i32,
    unix_time: i64,
    valid: bool,
    #[serde(default)]
    code: String,
    #[serde(default)]
    expires_at: i64,
    #[serde(default)]
    result_period: i32,
    #[serde(default)]
    error: String,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] =
        include_bytes!("../../../testdata/port/core/password-totp-contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated password/TOTP fixture")
}

#[test]
fn fixture_schema_and_password_generation_match_go() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    for case in fixture.password_cases {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&case.reader_bytes)
            .expect("decode deterministic reader bytes");
        let mut reader = std::io::Cursor::new(bytes);
        let result =
            password::generate_password_with_reader(case.length, case.use_symbols, &mut reader);
        if case.error.is_empty() {
            let generated = result.expect("password generation succeeds");
            assert_eq!(generated.as_str(), case.expected, "case {}", case.name);
            assert_eq!(
                generated.chars().count(),
                if case.length <= 0 {
                    16
                } else {
                    case.length as usize
                }
            );
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case.error,
                "case {}",
                case.name
            );
        }
    }
}

#[test]
fn password_strength_matches_go_fixture() {
    for case in fixture().strength_cases {
        let actual = password::assess_password_strength(&case.input);
        assert_eq!(actual.weak, case.weak, "case {}", case.name);
        assert_eq!(actual.message, case.message, "case {}", case.name);
        assert!(
            (actual.entropy - case.entropy).abs() < 1e-9,
            "case {}",
            case.name
        );
        assert_eq!(actual.missing, case.missing, "case {}", case.name);
    }
}

#[test]
fn totp_secret_validation_matches_go_fixture() {
    for case in fixture().totp_secret_cases {
        let result = totp::validate_totp_secret(&case.input);
        if case.valid {
            assert!(result.is_ok(), "case {}: {:?}", case.name, result);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case.error,
                "case {}",
                case.name
            );
        }
    }
}

#[test]
fn totp_parameter_validation_matches_go_fixture() {
    for case in fixture().totp_param_cases {
        let result = totp::validate_totp_params(&case.algorithm, case.digits, case.period);
        if case.valid {
            assert!(result.is_ok(), "case {}: {:?}", case.name, result);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case.error,
                "case {}",
                case.name
            );
        }
    }
}

#[test]
fn fixed_clock_totp_matches_go_fixture() {
    for case in fixture().totp_cases {
        let result = totp::generate_totp_at(
            &case.secret,
            &case.algorithm,
            case.digits,
            case.period,
            case.unix_time,
        );
        if case.valid {
            let generated = result.expect("TOTP generation succeeds");
            assert_eq!(generated.code, case.code, "case {}", case.name);
            assert_eq!(generated.expires_at, case.expires_at, "case {}", case.name);
            assert_eq!(generated.period, case.result_period, "case {}", case.name);
        } else if case.name == "invalid_secret" {
            let error = result.unwrap_err().to_string();
            assert!(
                error.starts_with("invalid TOTP secret"),
                "case {}: {error}",
                case.name
            );
            assert!(!error.contains(&case.secret), "secret leaked in error");
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case.error,
                "case {}",
                case.name
            );
        }
    }
}

#[test]
fn public_strength_validator_preserves_error_contract() {
    assert_eq!(
        password::validate_password_strength("123").unwrap_err(),
        "password too short: must be at least 10 characters"
    );
    assert!(password::validate_password_strength("StrongP@ssw0rd123").is_ok());
}

#[test]
fn unicode_digit_property_matches_go_nd_classification() {
    let decimal_digits = ['١', '१', '১', '๑', '１', '𝟠'];
    let non_decimal_numerics = ['Ⅷ', '½', '²', '①'];

    for character in decimal_digits {
        let input = format!("Aaabcdef{character}!!!");
        let result = password::assess_password_strength(&input);
        assert!(
            !result.missing.iter().any(|missing| missing == "digits"),
            "decimal digit U+{:04X} was not classified as a digit",
            character as u32
        );
    }

    for character in non_decimal_numerics {
        let input = format!("Aaabcdef{character}!!!");
        let result = password::assess_password_strength(&input);
        assert!(
            result.missing.iter().any(|missing| missing == "digits"),
            "non-decimal numeric U+{:04X} was classified as a digit",
            character as u32
        );
    }
}
