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
//!
//! The fixture also records `generate_totp` with the clipboard destination
//! (same backend, same auto-clear) and the write-error path of atotto's
//! `writeAll` (a tool that closes its stdin without reading a large payload).
//! Go reads the system clock for TOTP, so the copied code is the placeholder
//! `@TOTP_CODE@` in the fixture; the replay injects a clock and requires the
//! tool to have received exactly the code of that clock.

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
    totp: TotpSpec,
    server_name: String,
    server_version: String,
    script_placeholders: Vec<String>,
    fake_tools: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    goos: String,
    atotto_clipboard_version: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_files: Vec<String>,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct TotpSpec {
    secret: String,
    algorithm: String,
    digits: i32,
    period: i32,
    code_placeholder: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    tool: String,
    arguments: String,
    approval_mode: String,
    #[serde(default)]
    password_repeat: usize,
    #[serde(default)]
    tool_overrides: BTreeMap<String, String>,
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
/// The injected clock of the replay; Go's handler reads the system clock.
const NOW_UNIX: i64 = 1_700_000_000;

/// The oracle pin the fixture must carry: the reachable commit whose Go sources
/// equal the working tree the capture ran against, and their digest. The
/// generator refuses to run when the working tree differs from this commit.
const ORACLE_COMMIT: &str = "5229f949";
const ORACLE_COMMIT_SHA: &str = "5229f9490cd25c22adb641677546a57802417304";
const ORACLE_SOURCE_HASH: &str = "0636bc61995371865381248a9ff631ddb27fb04362713541f2593d52d00f7655";
const ORACLE_SOURCE_FILES: [&str; 12] = [
    "go.mod",
    "go.sum",
    "internal/clipboard/clipboard.go",
    "internal/clipboard/clipboard_signal_unix.go",
    "internal/clipboard/interface.go",
    "internal/clipboard/provider.go",
    "internal/clipboard/system_clipboard.go",
    "internal/crypto/totp.go",
    "internal/mcp/server/server.go",
    "internal/mcp/server/server_authorize.go",
    "internal/mcp/server/tools_clipboard.go",
    "internal/mcp/server/tools_totp.go",
];

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

/// The TOTP code of the injected clock for the fixture's fixed secret.
fn expected_code(spec: &TotpSpec) -> String {
    symvault_core::totp::generate_totp_at(
        &spec.secret,
        &spec.algorithm,
        spec.digits,
        spec.period,
        NOW_UNIX,
    )
    .expect("TOTP code for the injected clock")
    .code
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
    // Provenance: the capture is pinned to a reachable commit (the generator
    // fails unless the working-tree Go sources equal that commit's blobs), and
    // the digest of exactly those sources is the one recorded here.
    assert_eq!(fixture.oracle.commit, ORACLE_COMMIT);
    assert_eq!(fixture.oracle.commit_sha, ORACLE_COMMIT_SHA);
    assert!(
        fixture
            .oracle
            .commit_sha
            .starts_with(&fixture.oracle.commit)
    );
    assert_eq!(fixture.oracle.source_files, ORACLE_SOURCE_FILES);
    assert_eq!(fixture.oracle.source_hash, ORACLE_SOURCE_HASH);
    // The generator digest follows the generator's own edits, so it is checked
    // for shape and for covering the generator itself.
    assert!(
        fixture
            .oracle
            .generator_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && fixture.oracle.generator_hash.len() == 64
    );
    assert!(fixture.oracle.generator_files.iter().any(|name| {
        name == "internal/mcp/server/mcp_copy_clipboard_linux_fixture_generator_test.go"
    }));
    assert!(
        fixture
            .oracle
            .generator_files
            .iter()
            .any(|name| { name == "internal/mcp/server/mcp_copy_clipboard_linux_pin_test.go" })
    );
    assert_eq!(fixture.totp.algorithm, "SHA1");
    assert_eq!(fixture.totp.digits, 6);
    assert_eq!(fixture.totp.period, 30);
    assert_eq!(fixture.cases.len(), 25);
    assert_eq!(
        fixture
            .cases
            .iter()
            .filter(|case| case.tool == "generate_totp")
            .count(),
        10
    );
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
    let mut totp_copies = 0;
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
            let template = case
                .tool_overrides
                .get(name)
                .unwrap_or(&fixture.fake_tools[name]);
            fs::write(&path, render(template, &rec, case.tool_exit)).unwrap();
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
        let store = Store::open(
            symvault_store::data_safety::test_support_pre_marked(vault.path()),
            &identity,
        )
        .expect("open synthetic store");
        store
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([
                        ("username".into(), serde_json::json!("fixture-user")),
                        ("password".into(), serde_json::json!(PASSWORD)),
                        (
                            "totp".into(),
                            serde_json::json!({
                                "algorithm": fixture.totp.algorithm,
                                "digits": fixture.totp.digits,
                                "period": fixture.totp.period,
                                "secret": fixture.totp.secret,
                            }),
                        ),
                    ]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("seed password entry");
        if case.password_repeat > 0 {
            store
                .write_new_entry(
                    "big",
                    &Entry {
                        path: "big".into(),
                        data: BTreeMap::from([
                            ("username".into(), serde_json::json!("fixture-user")),
                            (
                                "password".into(),
                                serde_json::json!("0123456789abcdef".repeat(case.password_repeat)),
                            ),
                        ]),
                        ..Entry::default()
                    },
                    &identity,
                )
                .expect("seed large password entry");
        }
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
                approval_mode: case.approval_mode.clone(),
                can_use_clipboard: true,
                now_unix: Some(NOW_UNIX),
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
        for call in &case.input[2..] {
            assert!(
                call.contains(&format!("\"name\":\"{}\"", case.tool))
                    && call.contains(&case.arguments),
                "{} replays a different call than its recorded tool/arguments",
                case.name
            );
        }
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
        let expected_calls: Vec<Call> = case
            .tool_calls
            .iter()
            .map(|call| Call {
                tool: call.tool.clone(),
                mode: call.mode.clone(),
                argv: call.argv.clone(),
                stdin: if call.stdin == fixture.totp.code_placeholder {
                    assert_eq!(case.tool, "generate_totp", "{}", case.name);
                    expected_code(&fixture.totp)
                } else {
                    call.stdin.clone()
                },
            })
            .collect();
        assert_eq!(
            read_calls(&rec),
            expected_calls,
            "tool invocations of {}",
            case.name
        );
        if case.tool == "generate_totp" {
            // Whatever reached the tool is the code of the injected clock and
            // nothing else leaked into the protocol output.
            let code = expected_code(&fixture.totp);
            assert!(
                !serde_json::to_string(&actual).unwrap().contains(&code),
                "{} returned the TOTP code",
                case.name
            );
            totp_copies += expected_calls
                .iter()
                .filter(|call| call.stdin == code)
                .count();
        }
        with_tool_calls += usize::from(!case.tool_calls.is_empty());
        cleared += usize::from(
            case.tool_overrides.is_empty()
                && case.tool_calls.iter().any(|call| call.stdin.is_empty()),
        );
    }
    // Negative controls for the replay itself: a vacuous pass is impossible.
    assert_eq!(fixture.cases.len(), 25);
    assert_eq!(
        with_tool_calls, 21,
        "the two no-tool cases and the two approval refusals have no call"
    );
    assert_eq!(cleared, 8, "auto-clear cases that really cleared");
    assert_eq!(
        totp_copies, 8,
        "TOTP codes the tools received: seven cases reach a tool, the refresh case copies twice"
    );
}
