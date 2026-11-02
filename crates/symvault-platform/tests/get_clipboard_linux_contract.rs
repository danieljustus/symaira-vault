#![cfg(unix)]

//! PLATFORM-WIRE-001: `symvault get <path.field>` with the command clipboard
//! Go uses on Linux (`clipboard.DefaultClipboard()` -> atotto tool selection).
//!
//! `testdata/port/platform/get_clipboard_linux.json` is recorded from the real
//! Go `get` command on GOOS=linux (generator:
//! `cmd/get_clipboard_linux_fixture_generator_test.go`) with fake POSIX-shell
//! tools on a disposable PATH; only the terminal decision and the auto-clear
//! timer are stubbed, as in `get_clipboard.json`. Here the same scripts are run
//! as real processes by the real `SystemHost` behind `command_text_clipboard`
//! (what `native_get_clipboard` returns on Linux), driven through the same
//! `copy_and_auto_clear` the CLI calls. Stderr, exit code and every tool
//! invocation (argv, stdin bytes) must equal Go's.

use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use symvault_platform::desktop_commands::{SystemHost, go_split_list};
use symvault_platform::get_clipboard::{
    CancelToken, Clock, CopyError, Wake, command_text_clipboard, copy_and_auto_clear,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    oracle: Oracle,
    script_placeholders: Vec<String>,
    fake_tools: BTreeMap<String, String>,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    goos: String,
    atotto_clipboard_version: String,
    source_hash: String,
    generator_hash: String,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    path_tools: Option<Vec<String>>,
    wayland_display: String,
    tool_exit: i32,
    secret: String,
    auto_clear_seconds: i64,
    timer_stub_ms: u64,
    paste_output: String,
    stdout: String,
    stderr: String,
    exit_code: i32,
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

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/platform/get_clipboard_linux.json"
    ))
    .expect("decode the Go get Linux fixture")
}

/// Time that never sleeps; `wake_at` models the stubbed `StartAutoClear` timer
/// the Go scenarios fire after `timer_stub_ms`.
struct VirtualClock {
    now: Mutex<Duration>,
    wake_at: Option<Duration>,
}

impl Clock for VirtualClock {
    fn elapsed(&self) -> Duration {
        *self.now.lock().unwrap()
    }

    fn wait_until(&self, at: Duration, cancel: &CancelToken, watch_signals: bool) -> Wake {
        if cancel.is_cancelled() {
            return Wake::Cancelled;
        }
        let mut now = self.now.lock().unwrap();
        if watch_signals && let Some(wake) = self.wake_at.filter(|wake| *wake <= at) {
            *now = (*now).max(wake);
            return Wake::Signal;
        }
        *now = (*now).max(at);
        Wake::Elapsed
    }
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

/// `tempfile` is a dev-dependency of this crate on macOS and Windows only.
struct Sandbox(std::path::PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("symvault-get-linux-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn fixture_is_go_linux_derived_and_uses_the_desktop_fixture_tools() {
    let fixture = fixture();
    assert_eq!(fixture.oracle.goos, "linux");
    assert_eq!(fixture.oracle.atotto_clipboard_version, "v0.1.4");
    assert_eq!(fixture.oracle.source_hash.len(), 64);
    assert_eq!(fixture.oracle.generator_hash.len(), 64);
    assert_eq!(fixture.scenarios.len(), 16);
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
fn get_matches_go_linux_command_clipboard() {
    let fixture = fixture();
    let (mut copied, mut failed, mut warned, mut cleared) = (0, 0, 0, 0);
    for s in &fixture.scenarios {
        let sandbox = Sandbox::new(&s.name);
        let bin = sandbox.path().join("bin");
        let rec = sandbox.path().join("rec");
        let home = sandbox.path().join("home");
        for dir in [&bin, &rec, &home] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(
            rec.join("paste"),
            s.paste_output.replace("@SECRET@", &s.secret),
        )
        .unwrap();
        for name in s.path_tools.as_deref().unwrap_or_default() {
            let path = bin.join(name);
            let body = fixture.fake_tools[name]
                .replace("@REC@", rec.to_str().unwrap())
                .replace("@EXIT@", &s.tool_exit.to_string())
                .replace("@FOCUS1@", "")
                .replace("@FOCUS2@", "")
                .replace("@FOCUSEXIT@", "0");
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path_value = bin.to_str().unwrap().to_owned();
        let mut env = HashMap::from([
            ("PATH".to_owned(), path_value.clone()),
            ("HOME".to_owned(), home.to_str().unwrap().to_owned()),
        ]);
        if !s.wayland_display.is_empty() {
            env.insert("WAYLAND_DISPLAY".to_owned(), s.wayland_display.clone());
        }
        let host = SystemHost::isolated(go_split_list(std::ffi::OsStr::new(&path_value)), env)
            .with_cwd(home.clone());
        let clipboard = command_text_clipboard(Arc::new(host));
        let clock = VirtualClock {
            now: Mutex::new(Duration::ZERO),
            wake_at: (s.timer_stub_ms > 0).then(|| Duration::from_millis(s.timer_stub_ms)),
        };

        let mut stderr = Vec::new();
        let result = copy_and_auto_clear(
            clipboard.as_ref(),
            &s.secret,
            s.auto_clear_seconds,
            &clock,
            &mut stderr,
        );
        let mut stderr = String::from_utf8(stderr).expect("utf-8 stderr");
        let exit_code = match result {
            Ok(()) => 0,
            Err(error) => {
                // Go prints the command error once through cobra and once
                // through ExecuteRoot.
                stderr = format!("Error: {error}\nError: {error}\n");
                i32::from(CopyError::EXIT_CODE)
            }
        };
        assert_eq!(stderr, s.stderr, "{} stderr", s.name);
        assert_eq!(exit_code, s.exit_code, "{} exit", s.name);
        assert_eq!(s.stdout, "", "{} stdout", s.name);
        assert_eq!(read_calls(&rec), s.tool_calls, "{} tool calls", s.name);
        assert!(!stderr.contains(&s.secret), "{} leaked the secret", s.name);
        copied += usize::from(!s.tool_calls.is_empty());
        failed += usize::from(exit_code != 0);
        warned += usize::from(s.stderr.contains("Warning:"));
        cleared += usize::from(s.stderr.contains("[clipboard cleared]"));
    }
    // A vacuous pass is impossible: the recorded set has all four outcomes.
    assert_eq!(fixture.scenarios.len(), 16);
    assert_eq!(copied, 15, "every scenario but the no-tool one ran a tool");
    assert_eq!(failed, 3, "no tool, xclip exit 1, xsel exit 3");
    assert_eq!(
        warned, 2,
        "restored secret via xclip and via powershell.exe"
    );
    assert_eq!(cleared, 10);
}
