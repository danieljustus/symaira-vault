#![cfg(unix)]

//! PLATFORM-WIRE-001: MCP `copy_to_clipboard` with the command clipboard that
//! Go uses on Linux (`clipboard.DefaultClipboard()` -> atotto tool selection).
//!
//! `testdata/port/mcp/copy-clipboard-linux.json` is recorded from the real Go
//! `tools/call` handler on GOOS=linux with fake POSIX-shell tools on a
//! disposable PATH (generator:
//! `internal/mcp/server/mcp_copy_clipboard_linux_fixture_generator_test.go`).
//! Here the same shell scripts are executed as real processes by the real
//! `SystemHost` behind `CommandClipboard` - the type `native_command_clipboard`
//! returns on Linux - and the real MCP protocol handler: responses, tool argv
//! and stdin bytes (including the timer-driven clear) must equal Go's.

use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use symvault_mcp::store_adapter::StoreReadOnlyRuntime;
use symvault_mcp::{ProtocolHandler, ReadOnlyRuntimeConfig, read_only_tool_names, run_stream};
use symvault_platform::desktop_commands::{CommandClipboard, SystemHost, go_split_list};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    server_name: String,
    server_version: String,
    script_placeholders: Vec<String>,
    fake_tools: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    goos: String,
    atotto_clipboard_version: String,
    source_hash: String,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    path_tools: Option<Vec<String>>,
    wayland_display: String,
    tool_exit: i32,
    auto_clear_duration: u64,
    repeat: usize,
    want_calls: usize,
    input: Vec<String>,
    output: Vec<Value>,
    tool_calls: Vec<Call>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Call {
    tool: String,
    mode: String,
    argv: Vec<String>,
    stdin: String,
}

#[derive(Deserialize)]
struct DesktopFixture {
    script_placeholders: Vec<String>,
    fake_tools: BTreeMap<String, String>,
}

const PASSWORD: &str = "StrongP@ssw0rd123";

fn render(template: &str, rec: &Path, exit: i32) -> String {
    template
        .replace("@REC@", rec.to_str().unwrap())
        .replace("@EXIT@", &exit.to_string())
        .replace("@FOCUS1@", "")
        .replace("@FOCUS2@", "")
        .replace("@FOCUSEXIT@", "0")
}

/// The tools rewrite `seq` with a truncating redirect, so a concurrent read can
/// see it empty; that only means "not yet".
fn call_count(rec: &Path) -> usize {
    fs::read_to_string(rec.join("seq"))
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .unwrap_or(0)
}

fn read_calls(rec: &Path) -> Vec<Call> {
    let total: usize = match fs::read_to_string(rec.join("seq")) {
        Ok(raw) => raw.trim().parse().unwrap(),
        Err(_) => return Vec::new(),
    };
    (1..=total)
        .map(|n| {
            let raw = fs::read_to_string(rec.join(format!("call.{n}"))).unwrap();
            let lines: Vec<&str> = raw.lines().collect();
            let argc: usize = lines[2].parse().unwrap();
            assert_eq!(lines.len(), 3 + argc);
            Call {
                tool: lines[0].to_owned(),
                mode: lines[1].to_owned(),
                argv: lines[3..].iter().map(|s| (*s).to_owned()).collect(),
                stdin: fs::read(rec.join(format!("call.{n}.stdin")))
                    .map(|bytes| String::from_utf8(bytes).unwrap())
                    .unwrap_or_default(),
            }
        })
        .collect()
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/copy-clipboard-linux.json"
    ))
    .expect("decode the Go copy_to_clipboard Linux fixture")
}

#[test]
fn fixture_is_go_linux_derived_and_uses_the_desktop_fixture_tools() {
    let fixture = fixture();
    assert_eq!(fixture.oracle.goos, "linux");
    assert_eq!(fixture.oracle.atotto_clipboard_version, "v0.1.4");
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);
    assert_eq!(fixture.cases.len(), 13);
    let desktop: DesktopFixture = serde_json::from_str(include_str!(
        "../../../testdata/port/platform/desktop_linux.json"
    ))
    .expect("decode the Go desktop fixture");
    assert_eq!(fixture.script_placeholders, desktop.script_placeholders);
    assert_eq!(fixture.fake_tools.len(), 8);
    for (name, template) in &fixture.fake_tools {
        assert_eq!(
            desktop.fake_tools.get(name),
            Some(template),
            "fake tool {name} differs from desktop_linux.json"
        );
    }
}

#[test]
fn copy_to_clipboard_matches_go_linux_command_clipboard() {
    let fixture = fixture();
    let mut with_tool_calls = 0;
    let mut cleared = 0;
    for case in &fixture.cases {
        let sandbox = tempdir().expect("disposable sandbox");
        let bin = sandbox.path().join("bin");
        let rec = sandbox.path().join("rec");
        let home = sandbox.path().join("home");
        for dir in [&bin, &rec, &home] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(rec.join("paste"), b"").unwrap();
        for name in case.path_tools.as_deref().unwrap_or_default() {
            let path = bin.join(name);
            fs::write(
                &path,
                render(&fixture.fake_tools[name], &rec, case.tool_exit),
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path_value = bin.to_str().unwrap().to_owned();
        let mut env = HashMap::from([
            ("PATH".to_owned(), path_value.clone()),
            ("HOME".to_owned(), home.to_str().unwrap().to_owned()),
        ]);
        if !case.wayland_display.is_empty() {
            env.insert("WAYLAND_DISPLAY".to_owned(), case.wayland_display.clone());
        }
        let host = SystemHost::isolated(go_split_list(std::ffi::OsStr::new(&path_value)), env)
            .with_cwd(home.clone());
        // Tool selection happens here, once, like atotto's package init().
        let clipboard = Arc::new(CommandClipboard::new(Arc::new(host)));

        let vault = tempdir().expect("synthetic disposable vault");
        fs::write(
            vault.path().join("config.yaml"),
            "vault:\n  format_version: 1\n",
        )
        .unwrap();
        fs::write(
            vault.path().join("identity.age"),
            b"synthetic identity marker",
        )
        .unwrap();
        fs::create_dir(vault.path().join("entries")).unwrap();
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(vault.path(), &identity).expect("open synthetic store");
        store
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([
                        ("username".into(), serde_json::json!("fixture-user")),
                        ("password".into(), serde_json::json!(PASSWORD)),
                    ]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("seed password entry");
        let runtime = StoreReadOnlyRuntime::from_store(
            store,
            identity,
            ReadOnlyRuntimeConfig {
                server_name: fixture.server_name.clone(),
                server_version: fixture.server_version.clone(),
                transport: "stdio".into(),
                agent_name: "clipboard-linux-fixture".into(),
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
        .with_clipboard(clipboard)
        .with_clipboard_auto_clear_duration(Duration::from_secs(case.auto_clear_duration));
        let mut handler = ProtocolHandler::with_tool_call_runtime(
            &fixture.server_name,
            &fixture.server_version,
            Arc::new(runtime),
        );
        assert_eq!(case.input.len(), 2 + case.repeat, "{}", case.name);
        let input = case
            .input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let actual: Vec<Value> = run_stream(&input, &mut handler)
            .expect("Rust copy_to_clipboard protocol dispatch")
            .iter()
            .map(|line| serde_json::from_str(line).expect("Rust response is JSON"))
            .collect();
        assert_eq!(actual, case.output, "responses of {}", case.name);
        assert!(
            !serde_json::to_string(&actual).unwrap().contains(PASSWORD),
            "{} returned its synthetic password",
            case.name
        );

        // The clear runs on a timer; the bound is setup, not behavior.
        let deadline = Instant::now() + Duration::from_secs(30);
        while call_count(&rec) < case.want_calls && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        // An unexpected extra call (a clear after a failed copy, a second
        // clear for a refreshed timer) would show up shortly after.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            read_calls(&rec),
            case.tool_calls,
            "tool invocations of {}",
            case.name
        );
        with_tool_calls += usize::from(!case.tool_calls.is_empty());
        cleared += usize::from(case.tool_calls.iter().any(|call| call.stdin.is_empty()));
    }
    // Negative controls for the replay itself: a vacuous pass is impossible.
    assert_eq!(fixture.cases.len(), 13);
    assert_eq!(with_tool_calls, 12, "only the no-tool case has no call");
    assert_eq!(cleared, 4, "auto-clear cases that really cleared");
}
