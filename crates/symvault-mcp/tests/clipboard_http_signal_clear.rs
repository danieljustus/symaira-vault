//! HTTP `mcp` arms Go's clipboard `StartAutoClear` timer too (`copy_to_clipboard`
//! is served per request over HTTP). Go's timer subscribes SIGINT/SIGTERM next to
//! the server, so a shutdown signal clears the copied secret. The HTTP shutdown
//! (`symvault-cli` `mcp_shutdown::install_http`) calls
//! `approval::clear_armed_process_clipboards`; this test drives a real
//! `copy_to_clipboard` through the runtime and proves the registration is found.
#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
};
use symvault_core::platform::{Clipboard, PlatformError};
use symvault_mcp::store_adapter::StoreReadOnlyRuntime;
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Default)]
struct FakeClipboard {
    events: Mutex<Vec<&'static str>>,
}
impl Clipboard for FakeClipboard {
    fn set(&self, _: &[u8]) -> Result<(), PlatformError> {
        self.events.lock().unwrap().push("secret");
        Ok(())
    }
    fn clear(&self) -> Result<(), PlatformError> {
        self.events.lock().unwrap().push("clear");
        Ok(())
    }
}

fn copy_over_protocol(auto_clear_seconds: i64) -> Arc<FakeClipboard> {
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
                data: BTreeMap::from([("password".into(), serde_json::json!("fixture-secret"))]),
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
            server_name: "fixture".into(),
            server_version: "0".into(),
            transport: "http".into(),
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
    .with_clipboard_auto_clear_seconds(auto_clear_seconds);
    let mut handler = ProtocolHandler::with_tool_call_runtime("fixture", "0", Arc::new(runtime));
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"f","version":"1"},"capabilities":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"copy_to_clipboard","arguments":{"path":"login"}}}"#,
        "\n",
    );
    let output = run_stream(input, &mut handler).expect("protocol dispatch");
    assert!(
        output.last().unwrap().contains("\"isError\":false"),
        "{output:?}"
    );
    clipboard
}

/// One test body: the process-wide registry is shared by every test in this
/// binary, so the armed case, the negative control and the idempotence check
/// must not run concurrently.
#[test]
fn http_shutdown_clears_the_clipboard_armed_by_copy_to_clipboard() {
    // Control: no timer (auto_clear <= 0) means nothing is armed, nothing to clear.
    let unarmed = copy_over_protocol(0);
    assert_eq!(
        symvault_platform::approval::clear_armed_process_clipboards(),
        0
    );
    assert_eq!(*unarmed.events.lock().unwrap(), ["secret"]);

    let armed = copy_over_protocol(600);
    assert_eq!(*armed.events.lock().unwrap(), ["secret"]);
    assert_eq!(
        symvault_platform::approval::clear_armed_process_clipboards(),
        1
    );
    assert_eq!(*armed.events.lock().unwrap(), ["secret", "clear"]);
    // The timer thread was canceled: no second clear, and a repeat finds nothing.
    assert_eq!(
        symvault_platform::approval::clear_armed_process_clipboards(),
        0
    );
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(*armed.events.lock().unwrap(), ["secret", "clear"]);
}
