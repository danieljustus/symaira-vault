#![cfg(unix)]

//! PLATFORM-WIRE-001: the TUI clipboard path (`OwnedTextClipboard` over the
//! command clipboard) with the Go-recorded atotto tool behavior.
//!
//! Go's TUI copies with `clipboard.WriteAll(text)`, clears with
//! `WriteAll("")` from `StartAutoClear` and again before quitting. The expected
//! argv and stdin bytes below are the ones the Go-recorded
//! `testdata/port/platform/desktop_linux.json` holds for `xclip` copy and
//! clear, executed by the real `SystemHost` with the same fake POSIX-shell
//! tools.

use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use symvault_platform::OwnedTextClipboard;
use symvault_platform::desktop_commands::{
    CommandClipboard, MISSING_CLIPBOARD_COMMANDS, SystemHost, go_split_list,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Call {
    tool: String,
    mode: String,
    argv: Vec<String>,
    stdin: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    calls: Vec<Call>,
    copy_error: String,
}

#[derive(Deserialize)]
struct Desktop {
    fake_tools: BTreeMap<String, String>,
    clipboard_cases: Vec<Case>,
}

fn desktop() -> Desktop {
    serde_json::from_str(include_str!(
        "../../../testdata/port/platform/desktop_linux.json"
    ))
    .expect("decode the Go desktop fixture")
}

/// `tempfile` is a dev-dependency of this crate on macOS and Windows only.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "symvault-owned-clip-{}-{label}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn clipboard(
    desktop: &Desktop,
    sandbox: &Sandbox,
    tools: &[&str],
) -> (OwnedTextClipboard, PathBuf) {
    let bin = sandbox.0.join("bin");
    let rec = sandbox.0.join("rec");
    let home = sandbox.0.join("home");
    for dir in [&bin, &rec, &home] {
        fs::create_dir_all(dir).unwrap();
    }
    fs::write(rec.join("paste"), b"").unwrap();
    for name in tools {
        let path = bin.join(name);
        let body = desktop.fake_tools[*name]
            .replace("@REC@", rec.to_str().unwrap())
            .replace("@EXIT@", "0")
            .replace("@FOCUS1@", "")
            .replace("@FOCUS2@", "")
            .replace("@FOCUSEXIT@", "0");
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path_value = bin.to_str().unwrap().to_owned();
    let env = HashMap::from([
        ("PATH".to_owned(), path_value.clone()),
        ("HOME".to_owned(), home.to_str().unwrap().to_owned()),
    ]);
    let host =
        SystemHost::isolated(go_split_list(std::ffi::OsStr::new(&path_value)), env).with_cwd(home);
    let backend = Arc::new(CommandClipboard::new(Arc::new(host)));
    (OwnedTextClipboard::new(backend).expect("owner"), rec)
}

fn call_count(rec: &Path) -> usize {
    fs::read_to_string(rec.join("seq"))
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .unwrap_or(0)
}

fn read_calls(rec: &Path) -> Vec<Call> {
    (1..=call_count(rec))
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

fn go_call(desktop: &Desktop, case: &str, index: usize) -> Call {
    desktop
        .clipboard_cases
        .iter()
        .find(|candidate| candidate.name == case)
        .unwrap_or_else(|| panic!("Go case {case}"))
        .calls[index]
        .clone()
}

fn wait_for_calls(rec: &Path, want: usize) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while call_count(rec) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(200));
}

#[test]
fn tui_copy_and_timer_clear_run_the_go_xclip_commands() {
    let desktop = desktop();
    let sandbox = Sandbox::new("timer");
    let (owned, rec) = clipboard(&desktop, &sandbox, &["xclip"]);
    owned
        .copy(b"secret", Duration::from_secs(1))
        .expect("copy through xclip");
    wait_for_calls(&rec, 2);
    assert_eq!(
        read_calls(&rec),
        [
            go_call(&desktop, "x11_xclip_only", 0),
            go_call(&desktop, "xclip_empty_payload_clear", 0),
        ]
    );
    assert!(matches!(owned.take_clear_result(), Some(Ok(()))));
}

#[test]
fn tui_quit_clears_a_live_copy_like_go() {
    let desktop = desktop();
    let sandbox = Sandbox::new("quit");
    let (owned, rec) = clipboard(&desktop, &sandbox, &["xclip"]);
    owned
        .copy(b"secret", Duration::ZERO)
        .expect("copy through xclip");
    drop(owned);
    assert_eq!(
        read_calls(&rec),
        [
            go_call(&desktop, "x11_xclip_only", 0),
            go_call(&desktop, "xclip_empty_payload_clear", 0),
        ]
    );
}

#[test]
fn tui_copy_without_any_tool_reports_the_go_error_and_runs_nothing() {
    let desktop = desktop();
    let sandbox = Sandbox::new("none");
    let (owned, rec) = clipboard(&desktop, &sandbox, &[]);
    let error = owned
        .copy(b"secret", Duration::from_secs(1))
        .expect_err("no clipboard utility");
    assert_eq!(error.message, MISSING_CLIPBOARD_COMMANDS);
    let go = desktop
        .clipboard_cases
        .iter()
        .find(|case| case.name == "x11_no_tools")
        .unwrap();
    assert_eq!(error.message, go.copy_error);
    assert!(go.calls.is_empty());
    assert_eq!(call_count(&rec), 0);
    // Nothing was copied, so nothing is cleared (and nothing is spawned).
    assert!(owned.clear().is_ok());
    assert_eq!(call_count(&rec), 0);
}
