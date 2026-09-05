#![deny(unsafe_code)]

use serde::Deserialize;
use symvault_core::error::{
    CauseKind, CliError, ErrorCause, ErrorKind, ExitCode, exit_code_from_error, format_cli_error,
    from_corekit_exit_code, is_not_found, is_write_error, to_corekit_exit_code,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    exit_codes: Vec<NamedInt>,
    error_kinds: Vec<NamedInt>,
    cases: Vec<ErrorCase>,
    exit_resolutions: Vec<ExitResolution>,
    corekit_mappings: Vec<CodeMapping>,
    corekit_reverse_mappings: Vec<CodeMapping>,
}

#[derive(Debug, Deserialize)]
struct NamedInt {
    name: String,
    value: u8,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    name: String,
    code: u8,
    kind: u8,
    message: String,
    #[serde(default)]
    cause_kind: String,
    #[serde(default)]
    cause_message: String,
    #[serde(default)]
    hint: String,
    error: String,
    formatted: String,
    effective_exit_code: u8,
    is_not_found: bool,
    is_write_error: bool,
}

#[derive(Debug, Deserialize)]
struct ExitResolution {
    name: String,
    code: u8,
}

#[derive(Debug, Deserialize)]
struct CodeMapping {
    vault: u8,
    corekit: u8,
}

fn fixture() -> Fixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/core/error-contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated error fixture")
}

#[test]
fn stable_exit_codes_match_go() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    let names: Vec<&str> = fixture
        .exit_codes
        .iter()
        .map(|item| item.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "success",
            "general",
            "not_found",
            "not_initialized",
            "locked",
            "permission_denied",
            "config",
            "doctor_warn",
            "doctor_fail",
            "invalid_input",
            "usage",
            "update_available",
        ]
    );
    for item in fixture.exit_codes {
        let actual = match item.name.as_str() {
            "success" => ExitCode::Success,
            "general" => ExitCode::General,
            "not_found" => ExitCode::NotFound,
            "not_initialized" => ExitCode::NotInitialized,
            "locked" => ExitCode::Locked,
            "permission_denied" => ExitCode::PermissionDenied,
            "config" => ExitCode::Config,
            "doctor_warn" => ExitCode::DoctorWarn,
            "doctor_fail" => ExitCode::DoctorFail,
            "invalid_input" => ExitCode::InvalidInput,
            "usage" => ExitCode::USAGE,
            "update_available" => ExitCode::UpdateAvailable,
            other => panic!("unknown exit-code fixture {other}"),
        };
        assert_eq!(actual.value(), item.value, "{}", item.name);
        assert_eq!(ExitCode::from_u8(item.value), Some(actual), "{}", item.name);
    }
    assert_eq!(ExitCode::from_u8(11), None);
}

#[test]
fn stable_error_kinds_match_go() {
    let fixture = fixture();
    let names: Vec<&str> = fixture
        .error_kinds
        .iter()
        .map(|item| item.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "none",
            "not_found",
            "field_not_found",
            "read_failed",
            "write_failed"
        ]
    );
    for item in fixture.error_kinds {
        let actual = match item.name.as_str() {
            "none" => ErrorKind::None,
            "not_found" => ErrorKind::NotFound,
            "field_not_found" => ErrorKind::FieldNotFound,
            "read_failed" => ErrorKind::ReadFailed,
            "write_failed" => ErrorKind::WriteFailed,
            other => panic!("unknown error-kind fixture {other}"),
        };
        assert_eq!(actual.value(), item.value, "{}", item.name);
    }
}

#[test]
fn constructors_and_rendering_match_go() {
    for expected in fixture().cases {
        let actual = build_case(&expected);
        assert_eq!(
            actual.code().value(),
            expected.code,
            "{} code",
            expected.name
        );
        assert_eq!(
            actual.kind().value(),
            expected.kind,
            "{} kind",
            expected.name
        );
        assert_eq!(
            actual.message(),
            expected.message,
            "{} message",
            expected.name
        );
        assert_eq!(
            actual
                .cause()
                .map(|cause| cause.kind().as_str())
                .unwrap_or(""),
            expected.cause_kind,
            "{} cause kind",
            expected.name
        );
        assert_eq!(
            actual.cause().map(ErrorCause::message).unwrap_or(""),
            expected.cause_message,
            "{} cause message",
            expected.name
        );
        assert_eq!(
            actual.hint().unwrap_or(""),
            expected.hint,
            "{} hint",
            expected.name
        );
        assert_eq!(
            actual.to_string(),
            expected.error,
            "{} error",
            expected.name
        );
        assert_eq!(
            actual.formatted(),
            expected.formatted,
            "{} formatted",
            expected.name
        );
        assert_eq!(
            actual.effective_exit_code().value(),
            expected.effective_exit_code,
            "{} effective exit",
            expected.name
        );
        assert_eq!(
            actual.is_not_found(),
            expected.is_not_found,
            "{} not found",
            expected.name
        );
        assert_eq!(
            actual.is_write_error(),
            expected.is_write_error,
            "{} write",
            expected.name
        );
    }
}

#[test]
fn sentinel_and_plain_exit_resolution_match_go() {
    for expected in fixture().exit_resolutions {
        let actual = match expected.name.as_str() {
            "nil" => exit_code_from_error(None),
            "plain" => {
                let error = std::io::Error::other("plain");
                exit_code_from_error(Some(&error))
            }
            "entry_not_found" => exit_code_from_error(Some(&ErrorCause::new(
                CauseKind::EntryNotFound,
                "entry not found",
            ))),
            "vault_not_initialized" => exit_code_from_error(Some(&ErrorCause::new(
                CauseKind::VaultNotInitialized,
                "vault not initialized",
            ))),
            "vault_locked" => exit_code_from_error(Some(&ErrorCause::new(
                CauseKind::VaultLocked,
                "vault locked",
            ))),
            "permission_denied" => exit_code_from_error(Some(&ErrorCause::new(
                CauseKind::PermissionDenied,
                "permission denied",
            ))),
            other => panic!("unknown exit-resolution fixture {other}"),
        };
        assert_eq!(actual.value(), expected.code, "{}", expected.name);
    }
}

#[test]
fn generic_formatting_matches_plain_nil_and_typed_behavior() {
    #[derive(Debug)]
    struct Outer(CliError);
    impl std::fmt::Display for Outer {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("outer")
        }
    }
    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    let plain = std::io::Error::other("plain");
    let typed = CliError::internal("typed").with_hint("repair");
    let wrapped = Outer(CliError::locked("nested"));
    let wrapped_not_found = Outer(CliError::not_found("missing"));
    let wrapped_write = Outer(CliError::write_failed("write", None));
    assert_eq!(format_cli_error(None), "");
    assert_eq!(format_cli_error(Some(&plain)), "plain");
    assert_eq!(format_cli_error(Some(&typed)), "typed\nHint: repair");
    assert_eq!(
        format_cli_error(Some(&wrapped)),
        "nested: vault locked\nHint: Run: symvault unlock to unlock the vault, or set a passphrase via 'symvault auth set passphrase'."
    );
    assert_eq!(exit_code_from_error(Some(&wrapped)), ExitCode::Locked);
    assert!(is_not_found(&wrapped_not_found));
    assert!(!is_not_found(&plain));
    assert!(is_write_error(&wrapped_write));
    assert!(!is_write_error(&plain));
}

#[test]
fn corekit_numeric_mapping_matches_go() {
    for expected in fixture().corekit_mappings {
        let code = ExitCode::from_u8(expected.vault).expect("known vault code");
        assert_eq!(
            to_corekit_exit_code(code),
            expected.corekit,
            "vault {}",
            expected.vault
        );
    }
}

#[test]
fn reverse_corekit_numeric_mapping_matches_go() {
    for expected in fixture().corekit_reverse_mappings {
        assert_eq!(
            from_corekit_exit_code(expected.corekit).value(),
            expected.vault,
            "corekit {}",
            expected.corekit
        );
    }
}

fn build_case(expected: &ErrorCase) -> CliError {
    match expected.name.as_str() {
        "new" => CliError::new(
            ExitCode::Locked,
            "vault locked",
            Some(ErrorCause::new(CauseKind::Other, "passphrase missing")),
        ),
        "not_found" => CliError::not_found("entry \"github\" not found"),
        "field_not_found" => CliError::wrap(
            ExitCode::NotFound,
            ErrorKind::FieldNotFound,
            "field \"token\" missing",
            None,
        ),
        "read_failed" => CliError::read_failed("cannot read entry", Some("disk read".into())),
        "read_failed_nil" => CliError::read_failed("cannot read entry without cause", None),
        "write_failed" => CliError::write_failed("cannot write entry", Some("disk full".into())),
        "write_failed_nil" => CliError::write_failed("cannot write entry without cause", None),
        "not_initialized" => CliError::not_initialized("vault not initialized at /vault"),
        "new_vault_not_initialized" => CliError::vault_not_initialized(),
        "locked" => CliError::locked("session expired"),
        "permission_denied" => CliError::permission_denied("agent cannot write"),
        "invalid_input" => CliError::invalid_input("length must be positive"),
        "config_error" => CliError::config("config value is invalid"),
        "internal" => CliError::internal("unexpected state"),
        "already_exists" => CliError::already_exists("entry already exists"),
        "custom_hint" => CliError::new(ExitCode::General, "operation failed", None)
            .with_hint("Run symvault doctor"),
        "sentinel_priority" => CliError::new(
            ExitCode::General,
            "locked wrapper",
            Some(ErrorCause::new(
                CauseKind::VaultLocked,
                "outer: vault locked",
            )),
        ),
        other => panic!("unknown error fixture case {other}"),
    }
}
