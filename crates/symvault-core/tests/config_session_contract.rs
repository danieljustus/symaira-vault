#![deny(unsafe_code)]

use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use symvault_core::{
    config::{AuthMethod, Config},
    session::{Keyring, MemoryKeyring, SessionError, SessionManager},
};

#[derive(Debug, Deserialize)]
struct ConfigFixture {
    schema_version: u8,
    oracle: Oracle,
    cases: Vec<ConfigCase>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    release: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_digest: String,
}

#[derive(Debug, Deserialize)]
struct ConfigCase {
    name: String,
    input: String,
    expected: Option<ConfigExpected>,
    saved_yaml: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigExpected {
    vault_dir: String,
    default_agent: String,
    session_timeout_ns: u64,
    session_max_lifetime_ns: u64,
    auth_method: String,
    use_touch_id: bool,
    agents: std::collections::BTreeMap<String, AgentExpected>,
    mcp_port: Option<i64>,
    mcp_bind: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct AgentExpected {
    approval_mode: String,
    allowed_paths: Option<Vec<String>>,
    can_write: bool,
    can_run_commands: bool,
    expose_value_tools: bool,
    auto_unseal: bool,
    require_approval: bool,
    skill_path: String,
}

fn agent_snapshot(config: &Config) -> std::collections::BTreeMap<String, AgentExpected> {
    config
        .agents
        .iter()
        .map(|(name, profile)| {
            (
                name.clone(),
                AgentExpected {
                    approval_mode: profile.approval_mode.clone().unwrap_or_default(),
                    allowed_paths: (!profile.allowed_paths.is_empty())
                        .then(|| profile.allowed_paths.clone()),
                    can_write: profile.can_write,
                    can_run_commands: profile.can_run_commands,
                    expose_value_tools: profile.expose_value_tools,
                    auto_unseal: profile.auto_unseal,
                    require_approval: profile.require_approval,
                    skill_path: profile.skill_path.clone(),
                },
            )
        })
        .collect()
}

fn config_fixture() -> ConfigFixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/config/contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated config fixture")
}

#[test]
fn config_fixture_has_pinned_provenance_and_complete_case_set() {
    let fixture = config_fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(fixture.oracle.release, "v0.22.1");
    assert_eq!(fixture.oracle.source_files.len(), 9);
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);
    let names: Vec<_> = fixture
        .cases
        .iter()
        .map(|case| case.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "defaults",
            "explicit_presence",
            "field_presence_override",
            "unknown_fields_ignored",
            "invalid_empty_bind",
            "invalid_duration",
        ]
    );
}

#[test]
fn generated_config_cases_match_rust_loader_and_writer() {
    let fixture = config_fixture();
    for case in fixture.cases {
        let result = Config::load_from_bytes(case.input.as_bytes());
        match (result, case.expected, case.error) {
            (Ok(config), Some(expected), None) => {
                assert_eq!(
                    config.default_agent, expected.default_agent,
                    "{}",
                    case.name
                );
                assert_eq!(
                    config.session_timeout.as_nanos(),
                    u128::from(expected.session_timeout_ns)
                );
                assert_eq!(
                    config.session_max_lifetime.as_nanos(),
                    u128::from(expected.session_max_lifetime_ns)
                );
                assert_eq!(
                    config.auth_method.as_str(),
                    expected.auth_method,
                    "{}",
                    case.name
                );
                assert_eq!(
                    config.effective_auth_method() == AuthMethod::Touchid,
                    expected.use_touch_id,
                    "{}",
                    case.name
                );
                assert_eq!(agent_snapshot(&config), expected.agents, "{}", case.name);
                if let Some(port) = expected.mcp_port {
                    assert_eq!(
                        config.mcp.as_ref().map(|mcp| mcp.port),
                        Some(port),
                        "{}",
                        case.name
                    );
                    assert_eq!(
                        config.mcp.as_ref().map(|mcp| mcp.bind.as_str()),
                        expected.mcp_bind.as_deref(),
                        "{}",
                        case.name
                    );
                }
                match (case.name.as_str(), case.saved_yaml) {
                    (name, Some(saved_yaml)) if name != "defaults" => {
                        let actual = String::from_utf8(config.to_yaml_bytes().unwrap()).unwrap();
                        let expected_yaml = saved_yaml
                            .replace("/fixture/root/data/symaira-vault", &config.vault_dir);
                        assert_eq!(actual, expected_yaml, "{} writer", case.name);
                    }
                    _ => {}
                }
                if case.name == "defaults" {
                    assert!(
                        config.vault_dir.ends_with("symaira-vault")
                            || config.vault_dir.ends_with(".symvault"),
                        "{} default path: {:?}",
                        case.name,
                        config.vault_dir
                    );
                } else {
                    let expected_vault_dir = expected
                        .vault_dir
                        .replace("/fixture/root/data/symaira-vault", &config.vault_dir);
                    assert_eq!(config.vault_dir, expected_vault_dir, "{}", case.name);
                }
            }
            (Err(error), None, Some(expected)) => {
                assert!(
                    !expected.is_empty(),
                    "{} has an empty Go diagnostic",
                    case.name
                );
                assert!(
                    error.to_string().contains("invalid")
                        || error.to_string().contains("duration")
                        || error.to_string().contains("bind"),
                    "{}: {error}",
                    case.name
                );
            }
            (actual, expected, error) => panic!(
                "fixture shape mismatch for {}: result={actual:?}, expected={expected:?}, error={error:?}",
                case.name
            ),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SessionFixture {
    schema_version: u8,
    oracle: Oracle,
    cases: Vec<SessionCase>,
}

#[derive(Debug, Deserialize)]
struct SessionCase {
    name: String,
    expected: String,
    error_class: Option<String>,
}

fn session_fixture() -> SessionFixture {
    const CONTENT: &[u8] = include_bytes!("../../../testdata/port/session/contract.json");
    serde_json::from_slice(CONTENT).expect("decode Go-generated session fixture")
}

fn key(account: &str) -> String {
    format!("symvault:fixture-vault|{account}")
}

#[test]
fn generated_session_cases_match_rust_manager() {
    let fixture = session_fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle.commit, "caadd5e");
    assert_eq!(fixture.oracle.release, "v0.22.1");
    assert!(
        fixture.oracle.source_digest.len() == 64 && fixture.oracle.generator_digest.len() == 64
    );
    assert_eq!(fixture.cases.len(), 5);

    let cases = fixture.cases;
    let missing = cases.iter().find(|case| case.name == "missing").unwrap();
    let manager = SessionManager::with_system_clock(Arc::new(MemoryKeyring::new()));
    let error = manager.load_passphrase("fixture-vault").unwrap_err();
    assert_eq!(missing.expected, "error");
    assert_eq!(missing.error_class.as_deref(), Some("not_found"));
    assert!(matches!(error, SessionError::NotFound));

    let round_trip = cases
        .iter()
        .find(|case| case.name == "encrypted_round_trip")
        .unwrap();
    manager
        .save_passphrase(
            "fixture-vault",
            b"fixture-secret",
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        )
        .unwrap();
    assert_eq!(
        manager.load_passphrase("fixture-vault").unwrap(),
        b"fixture-secret"
    );
    assert_eq!(round_trip.expected, "fixture-secret");

    let legacy = cases
        .iter()
        .find(|case| case.name == "legacy_plaintext")
        .unwrap();
    let keyring = Arc::new(MemoryKeyring::new());
    keyring.set(&key("session"), br#"{"saved_at":"2099-01-01T00:00:00Z","last_access":"2099-01-01T00:00:00Z","passphrase":"legacy","ttl_ns":3600000000000}"#).unwrap();
    let error = SessionManager::with_system_clock(keyring)
        .load_passphrase("fixture-vault")
        .unwrap_err();
    assert_eq!(legacy.error_class.as_deref(), Some("legacy_plaintext"));
    assert!(matches!(error, SessionError::LegacyPlaintext));

    let expired = cases.iter().find(|case| case.name == "expired").unwrap();
    let keyring = Arc::new(MemoryKeyring::new());
    keyring.set(&key("session"), br#"{"saved_at":"2000-01-01T00:00:00Z","last_access":"2000-01-01T00:00:00Z","ttl_ns":1,"encrypted_passphrase":"x","nonce":"x"}"#).unwrap();
    let error = SessionManager::with_system_clock(keyring)
        .load_passphrase("fixture-vault")
        .unwrap_err();
    assert_eq!(expired.error_class.as_deref(), Some("expired"));
    assert!(matches!(error, SessionError::Expired(_)));

    let malformed = cases.iter().find(|case| case.name == "malformed").unwrap();
    let keyring = Arc::new(MemoryKeyring::new());
    keyring.set(&key("session"), b"not-json").unwrap();
    let error = SessionManager::with_system_clock(keyring)
        .load_passphrase("fixture-vault")
        .unwrap_err();
    assert_eq!(malformed.error_class.as_deref(), Some("malformed"));
    assert!(matches!(error, SessionError::Malformed(_)));
}
