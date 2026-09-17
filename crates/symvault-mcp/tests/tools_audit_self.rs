use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::sync::{Arc, Mutex};
use symvault_core::session::MemoryKeyring;
use symvault_crypto::generate_identity;
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_store::{Store, audit::RotationConfig};
use tempfile::TempDir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    input: Vec<String>,
    #[serde(default)]
    audit_log_hex: String,
    output: Vec<Value>,
}

fn fixture_vault() -> (
    TempDir,
    symvault_crypto::Identity,
    Arc<Mutex<symvault_store::audit::Logger>>,
) {
    let root = tempfile::tempdir().expect("synthetic vault tempdir");
    fs::write(
        root.path().join("config.yaml"),
        "vault:\n  format_version: 1\n",
    )
    .expect("synthetic vault config");
    fs::write(
        root.path().join("identity.age"),
        b"fixture identity placeholder",
    )
    .expect("synthetic identity marker");
    fs::create_dir(root.path().join("entries")).expect("synthetic entries directory");
    let identity = generate_identity();
    let store = Store::open(root.path(), &identity).expect("open synthetic vault");
    let _ = store;
    let keyring = MemoryKeyring::new();
    let logger = symvault_store::audit::open_with_keyring(
        "fixture",
        root.path(),
        &keyring,
        RotationConfig::default(),
    )
    .expect("open synthetic audit logger");
    (root, identity, Arc::new(Mutex::new(logger)))
}

fn runtime(
    root: &TempDir,
    identity: symvault_crypto::Identity,
    audit: Arc<Mutex<symvault_store::audit::Logger>>,
    server_name: &str,
    server_version: &str,
) -> ProtocolHandler {
    let config = ReadOnlyRuntimeConfig {
        server_name: server_name.into(),
        server_version: server_version.into(),
        transport: "stdio".into(),
        agent_name: "fixture".into(),
        approval_mode: "none".into(),
        allowed_paths: vec!["*".into()],
        available_tools: read_only_tool_names(),
        vault_dir: root.path().to_string_lossy().into_owned(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    };
    ProtocolHandler::with_store_read_only_runtime_and_audit(
        "symvault",
        server_version,
        root.path(),
        identity,
        config,
        None,
        None,
        Some(audit),
    )
    .expect("construct audit-self runtime")
}

#[test]
fn audit_self_matches_source_bound_go_fixture() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/tools-audit-self.json"
    ))
    .expect("valid Go audit-self fixture");
    assert_eq!(fixture.oracle.commit, "fca3f894");
    assert_eq!(
        fixture.oracle.commit_sha,
        "fca3f89401833b5e14ec4ec74ef736b0f63bca74"
    );
    assert_eq!(fixture.oracle.source_files.len(), 8);
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);

    for case in fixture.cases {
        let (root, identity, audit) = fixture_vault();
        let path = audit.lock().expect("audit logger lock").path().to_owned();
        if case.name == "missing_log_is_empty" {
            fs::remove_file(path).expect("remove synthetic audit log");
        } else {
            fs::write(path, decode_hex(&case.audit_log_hex)).expect("write synthetic audit log");
        }
        let mut handler = runtime(
            &root,
            identity,
            audit,
            &fixture.server_name,
            &fixture.server_version,
        );
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let actual = run_stream(&input, &mut handler)
            .expect("Rust audit-self stream dispatch")
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("Rust response JSON"))
            .collect::<Vec<_>>();
        assert_eq!(actual, case.output, "case {}", case.name);
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "fixture hex has odd length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("fixture hex digit");
            let low = (pair[1] as char).to_digit(16).expect("fixture hex digit");
            ((high << 4) | low) as u8
        })
        .collect()
}
