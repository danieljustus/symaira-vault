#![cfg(unix)]

//! ADR 0037 R7 and R8 (PLATFORM-001): the error text of the Go clipboard when
//! its tool dies by a signal (R7) or cannot be started (R8).
//!
//! `testdata/port/platform/clipboard_spawn_errors.json` holds what the
//! production `internal/clipboard.NewSystemClipboard()` (atotto/clipboard
//! v0.1.4) returned from `Copy` and `Read` at the archived oracle
//! `legacy/go-oracle` (`ce2390d7`), one re-executed child per scenario with a
//! disposable `PATH` (detached program `scripts/rust-port/clipboard_spawnobs.go.txt`).
//! Here the same files are written to a disposable directory and the real
//! `SystemHost` runs them behind `CommandClipboard` (Linux) or
//! `PasteboardClipboard` (macOS, with the fake directory instead of
//! `/usr/bin`, the declared security deviation). The text must be Go's:
//! `signal: <name>` per the GOOS signal table, `fork/exec <path>: <errno>` for
//! a start that fails after `LookPath` (ENOEXEC, EACCES, ENOENT of a shebang
//! interpreter) and `exec: "<tool>": executable file not found in $PATH` or
//! atotto's missing-tools text for a file that is not executable.
//!
//! The recording of the other GOOS is not replayed on this host; the test
//! counts what it compared and fails when a recorded run for the host is
//! missing.

use serde::Deserialize;
use std::{collections::HashMap, fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
use symvault_platform::Clipboard;
use symvault_platform::desktop_commands::{CommandClipboard, PasteboardClipboard, SystemHost};

#[derive(Deserialize)]
struct Document {
    oracle: Oracle,
    runs: Vec<Run>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    go_version: String,
    atotto_clipboard_version: String,
    program_sha256: String,
}

#[derive(Deserialize)]
struct Run {
    goos: String,
    group: String,
    uid_is_root: bool,
    observations: Vec<Observation>,
}

#[derive(Deserialize)]
struct Observation {
    name: String,
    files: HashMap<String, File>,
    result: GoResult,
}

#[derive(Deserialize)]
struct File {
    mode: String,
    content: String,
}

#[derive(Deserialize)]
struct GoResult {
    copy_error: Option<String>,
    read_error: Option<String>,
    read_value: String,
}

fn document() -> Document {
    serde_json::from_str(include_str!(
        "../../../testdata/port/platform/clipboard_spawn_errors.json"
    ))
    .expect("decode the Go clipboard spawn-error recording")
}

fn host_goos() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

fn sandbox(label: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("clipboard-spawn-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn run_scenario(obs: &Observation) -> (Option<String>, Option<String>, String) {
    let dir = sandbox(&obs.name);
    for (name, file) in &obs.files {
        let path = dir.join(name);
        let content = file.content.replace("@BIN@", &dir.to_string_lossy());
        fs::write(&path, content).unwrap();
        let mode = u32::from_str_radix(&file.mode, 8).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    let outcome = if cfg!(target_os = "macos") {
        let host = SystemHost::with_search_path(vec![dir.clone()]);
        let clipboard = PasteboardClipboard::new(Arc::new(host));
        (
            clipboard.set(b"secret-text").err().map(|e| e.message),
            clipboard.read().err().map(|e| e.message),
            String::new(),
        )
    } else {
        let env = HashMap::from([("PATH".to_owned(), dir.to_string_lossy().into_owned())]);
        let host = SystemHost::isolated(vec![dir.clone()], env);
        let clipboard = CommandClipboard::new(Arc::new(host));
        let copy = clipboard.set(b"secret-text").err().map(|e| e.message);
        let (read_error, value) = match clipboard.read() {
            Ok(bytes) => (None, String::from_utf8_lossy(&bytes).into_owned()),
            Err(e) => (Some(e.message), String::new()),
        };
        (copy, read_error, value)
    };
    let _ = fs::remove_dir_all(&dir);
    let bin = dir.to_string_lossy().into_owned();
    (
        outcome.0.map(|t| t.replace(&bin, "<BIN>")),
        outcome.1.map(|t| t.replace(&bin, "<BIN>")),
        outcome.2,
    )
}

fn replay(group: &str, expected_cases: usize) {
    let document = document();
    assert_eq!(document.oracle.go_version, "go1.26.6");
    assert_eq!(document.oracle.atotto_clipboard_version, "v0.1.4");
    assert_eq!(
        document.oracle.commit,
        "ce2390d748818a4beb413e97183b7795efa99411"
    );
    assert_eq!(document.oracle.program_sha256.len(), 64);
    let run = document
        .runs
        .iter()
        .find(|run| run.goos == host_goos() && run.group == group)
        .unwrap_or_else(|| panic!("no recorded {group} run for {}", host_goos()));
    assert!(
        !run.uid_is_root,
        "the recording was made as an unprivileged user"
    );
    assert!(
        rustix::process::geteuid().as_raw() != 0,
        "run as an unprivileged user: root ignores file modes like 0644"
    );
    assert_eq!(run.observations.len(), expected_cases);
    let mut differences = Vec::new();
    for obs in &run.observations {
        let (copy, read, value) = run_scenario(obs);
        if copy != obs.result.copy_error {
            differences.push(format!(
                "{}: copy {:?} != Go {:?}",
                obs.name, copy, obs.result.copy_error
            ));
        }
        if read != obs.result.read_error {
            differences.push(format!(
                "{}: read {:?} != Go {:?}",
                obs.name, read, obs.result.read_error
            ));
        }
        if cfg!(target_os = "linux") && value != obs.result.read_value {
            differences.push(format!(
                "{}: read value {:?} != Go {:?}",
                obs.name, value, obs.result.read_value
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "{} differences from Go:\n{}",
        differences.len(),
        differences.join("\n")
    );
}

/// R7: a clipboard tool ended by SIGKILL, SIGTERM, SIGSEGV and six more
/// signals is reported as `signal: <name>` from the GOOS table, in the copy
/// and the paste direction.
#[test]
fn clipboard_tool_ended_by_signal_matches_go() {
    replay("signals", 9);
}

/// R8: ENOEXEC (executable file that is no program), EACCES (shebang
/// interpreter without the execute bit), ENOENT (missing interpreter) and a
/// non-executable file on `PATH`.
#[test]
fn clipboard_tool_spawn_failure_matches_go() {
    replay("spawn", if cfg!(target_os = "linux") { 8 } else { 6 });
}
