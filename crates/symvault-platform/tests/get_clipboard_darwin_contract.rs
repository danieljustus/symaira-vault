#![cfg(target_os = "macos")]

//! PLATFORM-001-FIDELITY: `symvault get <path.field>` with the macOS pasteboard
//! Go uses (`clipboard.DefaultClipboard()` -> atotto v0.1.4 `pbcopy`/`pbpaste`).
//!
//! `testdata/port/platform/get_clipboard_darwin.json` is recorded from the real
//! Go `get` command on GOOS=darwin (generator:
//! `cmd/get_clipboard_darwin_fixture_generator_test.go`) with fake POSIX-shell
//! `pbcopy`/`pbpaste` tools on a disposable PATH; only the terminal decision
//! and the auto-clear timer are stubbed, as in `get_clipboard.json`. Here the
//! same scripts run as real processes behind `pasteboard_text_clipboard`
//! (what `native_get_clipboard` returns on macOS, minus the `/usr/bin` search
//! path), driven through the `copy_and_auto_clear` the CLI calls. Stderr, exit
//! code and every tool invocation must equal Go's, including the raw `os/exec`
//! error text: `exit status N`, `signal: <name>`, `write |1: broken pipe` and
//! `exec: "pbcopy": executable file not found in $PATH`.

use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use symvault_platform::desktop_commands::SystemHost;
use symvault_platform::get_clipboard::{
    CancelToken, Clock, CopyError, Wake, copy_and_auto_clear, pasteboard_text_clipboard,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    commit: String,
    goos: String,
    atotto_clipboard_version: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_hash: String,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    secret: String,
    #[serde(default)]
    secret_repeat: usize,
    auto_clear_seconds: i64,
    copy: String,
    paste: String,
    #[serde(default)]
    tool_stderr: String,
    pbcopy_script: Option<String>,
    pbpaste_script: Option<String>,
    stdout: String,
    stderr: String,
    exit_code: i32,
    tool_calls: Vec<Call>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Call {
    tool: String,
    stdin: String,
}

/// The reachable commit whose Go sources equal the working tree the capture ran
/// against, and their digest (the generator fails on drift).
const ORACLE_COMMIT: &str = "5229f9490cd25c22adb641677546a57802417304";

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/platform/get_clipboard_darwin.json"
    ))
    .expect("decode the Go get macOS fixture")
}

/// Time that never sleeps; the stubbed `StartAutoClear` timer of every Go
/// scenario fires 150 ms in.
struct VirtualClock {
    now: Mutex<Duration>,
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
        if watch_signals && Duration::from_millis(150) <= at {
            *now = (*now).max(Duration::from_millis(150));
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
            let tool = fs::read_to_string(rec.join(format!("call.{n}")))
                .unwrap()
                .trim()
                .to_owned();
            let stdin = fs::read(rec.join(format!("call.{n}.stdin"))).unwrap_or_default();
            // The Go recorder abbreviates payloads above 64 bytes.
            let stdin = if stdin.len() > 64 {
                format!("<{} bytes>", stdin.len())
            } else {
                String::from_utf8(stdin).unwrap()
            };
            Call { tool, stdin }
        })
        .collect()
}

struct Sandbox(std::path::PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "symvault-get-darwin-{}-{label}",
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

fn install(dir: &Path, name: &str, script: &str, rec: &Path) {
    let path = dir.join(name);
    fs::write(&path, script.replace("@REC@", rec.to_str().unwrap())).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn fixture_is_go_darwin_derived() {
    let fixture = fixture();
    assert_eq!(fixture.goos, "darwin");
    assert_eq!(fixture.atotto_clipboard_version, "v0.1.4");
    assert_eq!(fixture.commit, ORACLE_COMMIT);
    assert_eq!(fixture.source_files.len(), 9);
    for digest in [&fixture.source_hash, &fixture.generator_hash] {
        assert!(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert_eq!(fixture.scenarios.len(), 27);
}

#[test]
fn get_matches_go_pasteboard_error_text() {
    let fixture = fixture();
    let (mut failed, mut warned, mut cleared, mut signals, mut explained) = (0, 0, 0, 0, 0);
    for s in &fixture.scenarios {
        let sandbox = Sandbox::new(&s.name);
        let bin = sandbox.0.join("bin");
        let rec = sandbox.0.join("rec");
        for dir in [&bin, &rec] {
            fs::create_dir_all(dir).unwrap();
        }
        // A missing tool is a missing script, exactly as in the Go capture.
        assert_eq!(s.pbcopy_script.is_none(), s.copy == "missing", "{}", s.name);
        assert_eq!(
            s.pbpaste_script.is_none(),
            s.paste == "missing",
            "{}",
            s.name
        );
        if let Some(script) = &s.pbcopy_script {
            install(&bin, "pbcopy", script, &rec);
        }
        if let Some(script) = &s.pbpaste_script {
            install(&bin, "pbpaste", script, &rec);
        }
        let env = HashMap::from([("PATH".to_owned(), bin.to_str().unwrap().to_owned())]);
        let host = SystemHost::isolated(vec![bin.clone()], env);
        let clipboard = pasteboard_text_clipboard(Arc::new(host));
        let clock = VirtualClock {
            now: Mutex::new(Duration::ZERO),
        };
        let secret = s.secret.repeat(s.secret_repeat.max(1));
        let mut stderr = Vec::new();
        let result = copy_and_auto_clear(
            clipboard.as_ref(),
            &secret,
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
        // ADR 0034 item 23: a real pbcopy/pbpaste explains a failure on its own
        // stderr. atotto v0.1.4 never connects it, so Go's recorded text is the
        // bare `exit status N` / `signal: ...` and Rust must not surface the
        // tool's message either (the ratified difference is only that Rust
        // *could*; at this revision the texts are equal, which is pinned here).
        if !s.tool_stderr.is_empty() {
            explained += 1;
            assert!(
                !s.stderr.contains(&s.tool_stderr) && !stderr.contains(&s.tool_stderr),
                "{} surfaced the tool's own stderr message",
                s.name
            );
            let script = s.pbcopy_script.iter().chain(s.pbpaste_script.iter());
            assert!(
                script.into_iter().any(|text| text.contains(&s.tool_stderr)),
                "{} fake tool never writes the recorded message",
                s.name
            );
        }
        failed += usize::from(exit_code != 0);
        warned += usize::from(s.stderr.contains("Warning:"));
        cleared += usize::from(s.stderr.contains("[clipboard cleared]"));
        signals += usize::from(s.stderr.contains("signal: "));
    }
    // A vacuous pass is impossible: every outcome class was replayed.
    assert_eq!(
        failed, 16,
        "copy failures: three exit codes, missing, eight signals, two closed stdin, \
         and two with the tool's own stderr message"
    );
    assert_eq!(
        warned, 10,
        "clear failures and unreadable pasteboards (two more with a tool message)"
    );
    assert_eq!(cleared, 4);
    assert_eq!(
        signals, 12,
        "eight copy signals, one clear signal, two paste signals, one killed copy with a message"
    );
    assert_eq!(
        explained, 4,
        "copy exit, copy signal, clear exit and paste exit, each with a stderr message"
    );
}

/// ADR 0034 item 23, second half: atotto v0.1.4 leaves the tool's stderr
/// unconnected (`/dev/null`), so a message a real `pbcopy` writes there is
/// never seen by anyone. The replay above compares only the error *text*; this
/// re-runs it in a child process with stderr piped and requires that none of
/// the recorded tool messages reaches the process's own stderr (an inherited
/// child stderr would print them there without changing the text).
#[test]
fn tool_messages_never_reach_the_process_stderr() {
    let fixture = fixture();
    let messages: Vec<&str> = fixture
        .scenarios
        .iter()
        .filter(|s| !s.tool_stderr.is_empty())
        .map(|s| s.tool_stderr.as_str())
        .collect();
    assert_eq!(messages.len(), 4, "the recorded tool messages");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "get_matches_go_pasteboard_error_text",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("re-run the replay in a child process");
    assert!(
        output.status.success(),
        "child replay failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for message in messages {
        assert!(
            !stderr.contains(message),
            "the tool's stderr reached the process stderr: {message}"
        );
    }
}
