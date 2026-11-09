#![cfg(unix)]
//! ADR 0037 R6 (CLI-006): forced-colour output of `doctor`, `auth status` and
//! the TUI.
//!
//! What Go does (`internal/ui/cliout`, `internal/ui/theme`, lipgloss/termenv):
//!
//! * `doctor` colours its check lines through `cliout.Colorize*`. A line is
//!   coloured only when **stderr is a terminal** and `NO_COLOR` is empty, and
//!   the lipgloss profile (taken from **stdout**) is not `Ascii`:
//!   `CLICOLOR_FORCE` (not `0`) forces the 16-colour profile; otherwise a
//!   terminal on stdout selects the profile from `TERM`/`COLORTERM` (and `CI`,
//!   `NO_COLOR`, `CLICOLOR=0`, `TERM=dumb` switch it off).
//! * The root `--color` flag is parsed but never reaches `cliout`
//!   (`--color never` with `CLICOLOR_FORCE=1` still colours).
//! * `auth status` prints plain text; no colour in any mode.
//!
//! The native `doctor` never emits ANSI. That is the **declared difference**
//! pinned here (`DECLARED_UNCOLOURED`): every case in which Go colours must
//! still come out uncoloured from the native binary with identical text, and
//! the test fails when native output starts to colour (then the case moves to
//! exact equality). The TUI is recorded as Go evidence only (the native TUI
//! needs a terminal that answers cursor-position requests, and its layout is
//! pinned by `tui-harness-check`); see ADR 0037 R6.
//!
//! A run is described host-independently: the exit code, the SGR sequence in
//! front of each of six stable check lines and of the `→` hint lines, and
//! whether any escape byte was written. Recorded from the Go oracle
//! (`legacy/go-oracle`, `ce2390d7`) into
//! `testdata/port/cli-observations/cli_forced_colour.json`.

#[path = "common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::{
    fs,
    io::Read,
    os::fd::{FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use go_oracle_ext::Observations;
use serde_json::{Map, Value, json};

const ORACLE: &str = "ce2390d748818a4beb413e97183b7795efa99411";
const DEADLINE: Duration = Duration::from_secs(60);

/// The check lines whose name does not depend on the host.
const STABLE_LINES: &[&str] = &[
    "Vault initialized",
    "Vault config parses",
    "Vault config validates",
    "Identity encrypted",
    "File permissions",
    "Auth method",
];

struct Sandbox {
    _guard: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
}

fn command(binary: &Path, sandbox: &Sandbox, env: &[(&str, &str)]) -> Command {
    let home = &sandbox.home;
    let mut command = Command::new(binary);
    command
        .arg("--vault")
        .arg(&sandbox.vault)
        .current_dir(home)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("LANG", "C")
        .env("TZ", "UTC");
    for (key, value) in env {
        command.env(key, value);
    }
    command
}

fn sandbox(rust: &Path, loosen_identity: bool) -> Sandbox {
    use std::os::unix::fs::PermissionsExt;
    let guard = tempfile::Builder::new()
        .prefix("symvault-r6-")
        .tempdir()
        .expect("sandbox");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let sandbox = Sandbox {
        vault: home.join("vault"),
        home,
        _guard: guard,
    };
    let init = command(
        rust,
        &sandbox,
        &[
            ("CI", "1"),
            ("SYMVAULT_PASSPHRASE", "synthetic-r6-passphrase"),
            ("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1"),
        ],
    )
    .args(["init", "--auth", "passphrase"])
    .output()
    .expect("init");
    assert!(init.status.success(), "init: {init:?}");
    // The first command after `init` prints a one-time legacy-token notice;
    // absorb it so the observed run starts from a settled vault.
    let settle = command(rust, &sandbox, &[("CI", "1")])
        .arg("doctor")
        .arg("--no-network")
        .output()
        .expect("settle");
    assert!(settle.status.code().is_some(), "settle: {settle:?}");
    if loosen_identity {
        fs::set_permissions(
            sandbox.vault.join("identity.age"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("chmod");
    }
    sandbox
}

/// A pseudo-terminal pair; the slave is handed to the child.
fn openpty() -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = 0;
    let mut slave: libc::c_int = 0;
    let mut size = libc::winsize {
        ws_row: 30,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty fills the two descriptors; the winsize outlives the call.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            // `*mut` on darwin, `*const` on Linux: a raw pointer fits both.
            std::ptr::addr_of_mut!(size),
        )
    };
    assert_eq!(rc, 0, "openpty");
    // SAFETY: both descriptors are fresh and owned here.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

struct Run {
    exit_code: Option<i32>,
    terminal: Vec<u8>,
    stdout: Vec<u8>,
}

/// Run `args` with stdin and stderr on a terminal, stdout on a terminal or a pipe.
fn run(
    binary: &Path,
    sandbox: &Sandbox,
    env: &[(&str, &str)],
    args: &[&str],
    tty_out: bool,
) -> Run {
    let (master, slave) = openpty();
    let mut cmd = command(binary, sandbox, env);
    cmd.args(args)
        .stdin(Stdio::from(slave.try_clone().expect("dup")))
        .stderr(Stdio::from(slave.try_clone().expect("dup")));
    if tty_out {
        cmd.stdout(Stdio::from(slave.try_clone().expect("dup")));
    } else {
        cmd.stdout(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn");
    drop(cmd);
    drop(slave);
    let terminal = Arc::new(Mutex::new(Vec::new()));
    let sink = terminal.clone();
    let reader = thread::spawn(move || {
        let mut file = fs::File::from(master);
        let mut buffer = [0u8; 4096];
        while let Ok(read) = file.read(&mut buffer) {
            if read == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&buffer[..read]);
        }
    });
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout).expect("stdout");
    }
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        assert!(started.elapsed() < DEADLINE, "{binary:?} {args:?} hangs");
        thread::sleep(Duration::from_millis(20));
    };
    let _ = reader.join();
    let terminal = terminal.lock().unwrap().clone();
    Run {
        exit_code: status.code(),
        terminal,
        stdout,
    }
}

/// The SGR sequences (`ESC [ ... m`) before the first visible character of `line`.
fn leading_sgr(line: &str) -> String {
    let mut rest = line;
    let mut found = String::new();
    while let Some(tail) = rest.strip_prefix("\u{1b}[") {
        let Some(end) = tail.find('m') else { break };
        found.push_str("\u{1b}[");
        found.push_str(&tail[..=end]);
        rest = &tail[end + 1..];
    }
    found
}

fn strip_sgr(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Host-independent description of a `doctor`/`auth status` run.
fn describe(run: &Run) -> Value {
    let text = String::from_utf8_lossy(&run.terminal).into_owned();
    let mut lines = Map::new();
    let mut hints = Vec::new();
    let mut plain = Vec::new();
    for line in text.split("\r\n") {
        let visible = strip_sgr(line);
        let trimmed = visible.trim();
        for name in STABLE_LINES {
            // " ✓  Vault initialized      config.yaml ..." (symbol, then the name).
            if trimmed
                .split_once(char::is_whitespace)
                .is_some_and(|(_, rest)| rest.trim_start().starts_with(name))
            {
                lines.insert((*name).to_owned(), json!(leading_sgr(line)));
                plain.push(visible.clone());
            }
        }
        if trimmed.starts_with('→') {
            let sgr = leading_sgr(line);
            if !hints.contains(&sgr) {
                hints.push(sgr);
            }
        }
    }
    hints.sort();
    json!({
        "exit_code": run.exit_code,
        "stdout_bytes_with_escape": run.stdout.contains(&0x1b),
        "escape_written": run.terminal.contains(&0x1b),
        "check_lines": lines,
        "hint_styles": hints,
        "plain_check_lines": plain,
    })
}

/// The same description with every escape sequence removed: what the native
/// `doctor` must print where Go colours (the declared difference).
fn uncoloured(value: &Value) -> Value {
    let mut copy = value.clone();
    copy["escape_written"] = json!(false);
    if let Some(lines) = copy["check_lines"].as_object_mut() {
        for entry in lines.values_mut() {
            *entry = json!("");
        }
    }
    if let Some(hints) = copy["hint_styles"].as_array_mut() {
        for entry in hints.iter_mut() {
            *entry = json!("");
        }
        hints.dedup();
    }
    copy
}

struct Case {
    name: &'static str,
    env: &'static [(&'static str, &'static str)],
    args: &'static [&'static str],
    tty_out: bool,
    /// `chmod 0644 identity.age` first (a failing `File permissions` check).
    loosen: bool,
}

const fn case(
    name: &'static str,
    env: &'static [(&'static str, &'static str)],
    args: &'static [&'static str],
    tty_out: bool,
) -> Case {
    Case {
        name,
        env,
        args,
        tty_out,
        loosen: false,
    }
}

const DOCTOR: &[&str] = &["doctor", "--no-network"];

const CASES: &[Case] = &[
    case("tty-no-term", &[], DOCTOR, true),
    case(
        "tty-term-256color",
        &[("TERM", "xterm-256color")],
        DOCTOR,
        true,
    ),
    case("tty-term-xterm", &[("TERM", "xterm")], DOCTOR, true),
    case("tty-term-dumb", &[("TERM", "dumb")], DOCTOR, true),
    case(
        "tty-truecolor",
        &[("TERM", "xterm-256color"), ("COLORTERM", "truecolor")],
        DOCTOR,
        true,
    ),
    case(
        "tty-force-color-3",
        &[("TERM", "xterm-256color"), ("FORCE_COLOR", "3")],
        DOCTOR,
        true,
    ),
    case(
        "pipe-out-term-256color",
        &[("TERM", "xterm-256color")],
        DOCTOR,
        false,
    ),
    case("clicolor-force", &[("CLICOLOR_FORCE", "1")], DOCTOR, true),
    case(
        "clicolor-force-stdout-pipe",
        &[("CLICOLOR_FORCE", "1")],
        DOCTOR,
        false,
    ),
    case(
        "clicolor-force-zero",
        &[("CLICOLOR_FORCE", "0")],
        DOCTOR,
        true,
    ),
    case(
        "clicolor-force-no-color",
        &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")],
        DOCTOR,
        true,
    ),
    case(
        "clicolor-zero",
        &[("TERM", "xterm-256color"), ("CLICOLOR", "0")],
        DOCTOR,
        true,
    ),
    case(
        "clicolor-force-in-ci",
        &[("CLICOLOR_FORCE", "1"), ("CI", "1")],
        DOCTOR,
        true,
    ),
    case(
        "term-256color-in-ci",
        &[("TERM", "xterm-256color"), ("CI", "1")],
        DOCTOR,
        true,
    ),
    case(
        "flag-always",
        &[],
        &["doctor", "--no-network", "--color", "always"],
        true,
    ),
    case(
        "flag-never-with-force",
        &[("CLICOLOR_FORCE", "1")],
        &["doctor", "--no-network", "--color", "never"],
        true,
    ),
    case(
        "flag-always-with-force",
        &[("CLICOLOR_FORCE", "1")],
        &["--color=always", "doctor", "--no-network"],
        true,
    ),
    Case {
        name: "failing-check-256color",
        env: &[("TERM", "xterm-256color")],
        args: DOCTOR,
        tty_out: true,
        loosen: true,
    },
    Case {
        name: "failing-check-forced",
        env: &[("CLICOLOR_FORCE", "1")],
        args: DOCTOR,
        tty_out: true,
        loosen: true,
    },
    case(
        "auth-status-256color",
        &[("TERM", "xterm-256color")],
        &["auth", "status"],
        true,
    ),
    case(
        "auth-status-forced",
        &[("CLICOLOR_FORCE", "1"), ("FORCE_COLOR", "3")],
        &["auth", "status", "--color", "always"],
        true,
    ),
];

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn doctor_and_status_forced_colour_match_go_modulo_the_declared_difference() {
    let obs = Observations::begin(
        "cli_forced_colour",
        "doctor_and_status_forced_colour_match_go_modulo_the_declared_difference",
        Some(ORACLE),
    );
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let mut declared = 0;
    for case in CASES {
        let go = obs.observe(case.name, |go_binary| {
            let sandbox = sandbox(&rust, case.loosen);
            describe(&run(go_binary, &sandbox, case.env, case.args, case.tty_out))
        });
        if obs.capturing() {
            continue;
        }
        let sandbox = sandbox(&rust, case.loosen);
        let native = describe(&run(&rust, &sandbox, case.env, case.args, case.tty_out));
        if go["escape_written"] == json!(true) {
            // DECLARED_UNCOLOURED: same text, same exit status, no colour.
            assert_eq!(
                native,
                uncoloured(&go),
                "{}: native output must be Go's text without colour",
                case.name
            );
            declared += 1;
        } else {
            assert_eq!(native, go, "{}", case.name);
        }
    }
    assert_eq!(obs.count(), CASES.len());
    if !obs.capturing() {
        assert_eq!(
            declared, DECLARED_UNCOLOURED,
            "the set of cases in which Go colours and native does not changed"
        );
    }
}

/// Cases in which Go colours `doctor` and the native binary does not.
const DECLARED_UNCOLOURED: usize = 11;

/// Evidence only: the SGR sequences Go's TUI writes on a 256-colour terminal
/// with `FORCE_COLOR=3`, from a scripted `ui` session on a pseudo-terminal
/// (open, wait, `q`). The native TUI is not run here (see the module comment);
/// the recorded set documents what ADR 0037 R6 ratifies as cosmetic.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn tui_forced_colour_is_recorded_as_go_evidence() {
    let obs = Observations::begin(
        "cli_forced_colour",
        "tui_forced_colour_is_recorded_as_go_evidence",
        Some(ORACLE),
    );
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let go = obs.observe("go-tui-sgr", |go_binary| {
        let sandbox = sandbox(&rust, false);
        let first_frame = tui_session(go_binary, &sandbox);
        let mut sgr: Vec<String> = Vec::new();
        let text = String::from_utf8_lossy(&first_frame).into_owned();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("\u{1b}[") {
            let tail = &rest[at + 2..];
            let end = tail.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(0);
            if tail[end..].starts_with('m') {
                let code = format!("ESC[{}m", &tail[..end]);
                if !sgr.contains(&code) {
                    sgr.push(code);
                }
            }
            rest = &tail[end..];
        }
        sgr.sort();
        json!({ "sgr_sequences": sgr, "enters_alternate_screen": text.contains("\u{1b}[?1049h") })
    });
    // Go draws with the 256-colour palette tokens of `internal/ui/theme`
    // (212 title, 240 muted, 220 warning) and the alternate screen.
    let sequences = go["sgr_sequences"].as_array().unwrap();
    for expected in [
        "ESC[1;38;5;212m",
        "ESC[38;5;240m",
        "ESC[38;5;220m",
        "ESC[0m",
    ] {
        assert!(
            sequences.iter().any(|s| s == expected),
            "recorded Go TUI lacks {expected}: {sequences:?}"
        );
    }
    assert_eq!(go["enters_alternate_screen"], json!(true));
}

/// Open `ui` on a terminal, let it draw, press `q`, return everything written.
fn tui_session(binary: &Path, sandbox: &Sandbox) -> Vec<u8> {
    use std::io::Write;
    let (master, slave) = openpty();
    let mut cmd = command(
        binary,
        sandbox,
        &[
            ("TERM", "xterm-256color"),
            ("FORCE_COLOR", "3"),
            ("SYMVAULT_PASSPHRASE", "synthetic-r6-passphrase"),
            ("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1"),
        ],
    );
    cmd.arg("ui")
        .stdin(Stdio::from(slave.try_clone().expect("dup")))
        .stdout(Stdio::from(slave.try_clone().expect("dup")))
        .stderr(Stdio::from(slave.try_clone().expect("dup")));
    let mut child = cmd.spawn().expect("spawn ui");
    drop(cmd);
    drop(slave);
    let mut writer = fs::File::from(master.try_clone().expect("dup master"));
    let collected = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    let reader = thread::spawn(move || {
        let mut file = fs::File::from(master);
        let mut buffer = [0u8; 4096];
        while let Ok(read) = file.read(&mut buffer) {
            if read == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&buffer[..read]);
        }
    });
    thread::sleep(Duration::from_secs(2));
    let _ = writer.write_all(b"q");
    let started = Instant::now();
    while child.try_wait().expect("wait").is_none() {
        if started.elapsed() > Duration::from_secs(10) {
            child.kill().expect("kill");
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();
    let _ = reader.join();
    collected.lock().unwrap().clone()
}
