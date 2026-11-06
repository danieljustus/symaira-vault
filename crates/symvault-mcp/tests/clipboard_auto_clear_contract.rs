//! PLATFORM-001-FIDELITY: a non-positive `clipboard.auto_clear_duration`.
//!
//! `testdata/port/mcp/clipboard-auto-clear.json` is recorded from the real Go
//! MCP handlers (`copy_to_clipboard`, `generate_totp` with the clipboard
//! destination) with an in-memory clipboard: the configured number is used
//! verbatim, a value <= 0 starts no auto-clear, and `generate_totp` reports it
//! unchanged as `clipboard_clears_in` (negative included). The Rust runtime must
//! not clamp it to 0.

use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};
use symvault_core::platform::{Clipboard, PlatformError};
use symvault_mcp::store_adapter::StoreReadOnlyRuntime;
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit_sha: String,
    source_hash: String,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    tool: String,
    auto_clear_duration: i64,
    input: Vec<String>,
    output: Vec<Value>,
    clipboard_events: Vec<String>,
}

#[derive(Default)]
struct FakeClipboard {
    writes: Mutex<Vec<Vec<u8>>>,
}

impl Clipboard for FakeClipboard {
    fn set(&self, text: &[u8]) -> Result<(), PlatformError> {
        self.writes.lock().unwrap().push(text.to_vec());
        Ok(())
    }

    fn clear(&self) -> Result<(), PlatformError> {
        self.set(b"")
    }
}

const PASSWORD: &str = "fixture-password-value";

#[test]
fn non_positive_auto_clear_is_used_verbatim_like_go() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/clipboard-auto-clear.json"
    ))
    .expect("decode the Go clipboard auto-clear fixture");
    assert_eq!(
        fixture.oracle.commit_sha,
        "58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9"
    );
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);
    assert_eq!(fixture.cases.len(), 6);

    let mut negative_totp = 0;
    for case in &fixture.cases {
        let root = tempdir().expect("synthetic disposable vault");
        fs::write(
            root.path().join("config.yaml"),
            "vault:\n  format_version: 1\n",
        )
        .unwrap();
        fs::write(
            root.path().join("identity.age"),
            b"synthetic identity marker",
        )
        .unwrap();
        fs::create_dir(root.path().join("entries")).unwrap();
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(
            symvault_store::data_safety::test_support_pre_marked(root.path()),
            &identity,
        )
        .expect("open synthetic store");
        store
            .write_new_entry(
                "login",
                &Entry {
                    path: "login".into(),
                    data: BTreeMap::from([("password".into(), serde_json::json!(PASSWORD))]),
                    ..Entry::default()
                },
                &identity,
            )
            .unwrap();
        store
            .write_new_entry(
                "totp",
                &Entry {
                    path: "totp".into(),
                    data: BTreeMap::from([(
                        "totp".into(),
                        serde_json::json!({
                            "secret": "JBSWY3DPEHPK3PXP",
                            "algorithm": "SHA1",
                            "digits": 6,
                            "period": 30,
                        }),
                    )]),
                    ..Entry::default()
                },
                &identity,
            )
            .unwrap();
        let clipboard = Arc::new(FakeClipboard::default());
        let runtime = StoreReadOnlyRuntime::from_store(
            store,
            identity,
            ReadOnlyRuntimeConfig {
                server_name: fixture.server_name.clone(),
                server_version: fixture.server_version.clone(),
                transport: "stdio".into(),
                agent_name: "clipboard-fixture".into(),
                tier: "admin".into(),
                allowed_paths: vec!["*".into()],
                approval_mode: "none".into(),
                can_use_clipboard: true,
                available_tools: read_only_tool_names(),
                vault_dir: "<fixture-vault>".into(),
                vault_unlocked: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("construct synthetic runtime")
        .with_clipboard(clipboard.clone())
        .with_clipboard_auto_clear_seconds(case.auto_clear_duration);
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            Arc::new(runtime),
        );
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let actual: Vec<Value> = run_stream(&input, &mut handler)
            .expect("Rust protocol dispatch")
            .iter()
            .map(|line| serde_json::from_str(line).expect("Rust response is JSON"))
            .collect();
        assert_eq!(actual, case.output, "responses of {}", case.name);
        // A wrongly started timer would clear within this window (Go's check
        // waits 1.5 s; the shortest timer a bug could start here is 1 s).
        std::thread::sleep(Duration::from_millis(1500));
        let events: Vec<&str> = clipboard
            .writes
            .lock()
            .unwrap()
            .iter()
            .map(|value| if value.is_empty() { "clear" } else { "secret" })
            .collect();
        assert_eq!(
            events, case.clipboard_events,
            "clipboard events {}",
            case.name
        );
        assert_eq!(case.clipboard_events, ["secret"], "{}", case.name);
        negative_totp += usize::from(
            case.tool == "generate_totp"
                && case.auto_clear_duration < 0
                && serde_json::to_string(&actual).unwrap().contains(&format!(
                    "clipboard_clears_in\\\":{}",
                    case.auto_clear_duration
                )),
        );
    }
    assert_eq!(negative_totp, 2, "-5 and -1 are reported negative, not 0");
}
