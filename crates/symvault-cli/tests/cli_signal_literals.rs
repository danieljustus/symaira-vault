#![cfg(unix)]
//! ADR 0037 R14 (CLI-003): the text `broker --passthrough` and `intake watch
//! --interval/--debounce` print for unusual literals, from runs that end by
//! signal.
//!
//! Both commands run until SIGINT/SIGTERM, so a plain `Command::output()`
//! transcript cannot hold them. Each case starts the real binary, waits until
//! the startup banner is complete, sends the signal and records stdout, stderr,
//! exit code and terminating signal. A literal the flag parser refuses never
//! reaches the banner; the run then ends by itself and no signal is sent.
//!
//! Recorded from the Go oracle (`legacy/go-oracle`, `ce2390d7`) into
//! `testdata/port/cli-observations/cli_signal_literals.json`; the closure of
//! each `observe` documents how. Recapture: see
//! docs/rust-port/go-oracle-archive.md ("Recapture").
//!
//! Normalisation (all in [`normalise`], applied to both sides): the sandbox
//! directory becomes `<HOME>`, the ephemeral loopback port `<PORT>` and the
//! CA bundle path `<CA>` (Go writes `<vault>/broker-ca.pem`, Rust a private
//! `.broker-ca-*` directory per broker: ADR 0037 item 10).

#[path = "common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::{
    io::Read,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use go_oracle_ext::Observations;
use serde_json::{Value, json};

const ORACLE: &str = "ce2390d748818a4beb413e97183b7795efa99411";
const PASSPHRASE: &str = "synthetic-r14-passphrase";
/// Time between the last expected banner byte and the signal: the banner is
/// printed in one burst, this only guards a split write.
const SETTLE: Duration = Duration::from_millis(300);
const DEADLINE: Duration = Duration::from_secs(20);

fn replace_all(text: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        text.to_owned()
    } else {
        text.replace(from, to)
    }
}

/// Everything a run prints that depends on the sandbox.
fn normalise(text: &[u8], home: &Path) -> String {
    let mut text = String::from_utf8_lossy(text).into_owned();
    let home_text = home.to_string_lossy().into_owned();
    if let Ok(real) = std::fs::canonicalize(home) {
        text = replace_all(&text, &real.to_string_lossy(), "<HOME>");
    }
    text = replace_all(&text, &home_text, "<HOME>");
    // CA bundle: `<HOME>/vault/broker-ca.pem` or `<HOME>/vault/.broker-ca-XXXXXX/broker-ca.pem`.
    let mut out = String::new();
    let mut rest = text.as_str();
    while let Some(start) = rest.find("<HOME>/vault/") {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .find("broker-ca.pem")
            .map(|i| i + "broker-ca.pem".len());
        match end {
            Some(end) if !tail[..end].contains('\n') => {
                out.push_str("<CA>");
                rest = &tail[end..];
            }
            _ => {
                out.push_str("<HOME>/vault/");
                rest = &tail["<HOME>/vault/".len()..];
            }
        }
    }
    out.push_str(rest);
    // Ephemeral loopback port.
    let mut result = String::new();
    let mut chars = out.as_str();
    while let Some(index) = chars.find("127.0.0.1:") {
        let (head, tail) = chars.split_at(index + "127.0.0.1:".len());
        result.push_str(head);
        let digits = tail.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 {
            result.push_str("<PORT>");
        }
        chars = &tail[digits..];
    }
    result.push_str(chars);
    result
}

struct Sandbox {
    _guard: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
}

fn sandbox(rust: &Path) -> Sandbox {
    let guard = tempfile::Builder::new()
        .prefix("symvault-r14-")
        .tempdir()
        .expect("sandbox");
    let home = guard.path().join("home");
    std::fs::create_dir_all(home.join("watched")).expect("home");
    let vault = home.join("vault");
    let init = command(rust, &home, &vault)
        .args(["init", "--auth", "passphrase"])
        .output()
        .expect("init");
    assert!(init.status.success(), "init: {:?}", init.stderr);
    Sandbox {
        _guard: guard,
        home,
        vault,
    }
}

fn command(binary: &Path, home: &Path, vault: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .arg("--vault")
        .arg(vault)
        .current_dir(home)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env("CI", "1");
    command
}

/// Start `binary args`, wait until `ready` is complete in stdout (or the run
/// ends), send `signal`, and describe the outcome.
fn drive(binary: &Path, sandbox: &Sandbox, args: &[&str], ready: &str, signal: i32) -> Value {
    let mut child = command(binary, &sandbox.home, &sandbox.vault)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let out = Arc::new(Mutex::new(Vec::new()));
    let err = Arc::new(Mutex::new(Vec::new()));
    let readers: Vec<_> = [
        (
            Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
            out.clone(),
        ),
        (
            Box::new(child.stderr.take().unwrap()) as Box<dyn Read + Send>,
            err.clone(),
        ),
    ]
    .into_iter()
    .map(|(mut pipe, sink)| {
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = pipe.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        })
    })
    .collect();
    let started = Instant::now();
    let mut signalled = false;
    let mut ready_at = None;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        let seen = String::from_utf8_lossy(&out.lock().unwrap()).contains(ready);
        if seen && ready_at.is_none() {
            ready_at = Some(Instant::now());
        }
        if let Some(at) = ready_at
            && !signalled
            && at.elapsed() >= SETTLE
        {
            // SAFETY: plain kill(2) on the pid of our own child.
            unsafe { libc::kill(child.id() as libc::pid_t, signal) };
            signalled = true;
        }
        if started.elapsed() > DEADLINE {
            child.kill().expect("kill");
            let status = child.wait().expect("reap");
            for reader in readers {
                let _ = reader.join();
            }
            panic!(
                "{binary:?} {args:?} did not end ({status:?}); stdout {:?}",
                String::from_utf8_lossy(&out.lock().unwrap())
            );
        }
        thread::sleep(Duration::from_millis(25));
    };
    for reader in readers {
        let _ = reader.join();
    }
    json!({
        "signalled": signalled,
        "exit_code": status.code(),
        "terminated_by_signal": status.signal(),
        "stdout": normalise(&out.lock().unwrap(), &sandbox.home),
        "stderr": normalise(&err.lock().unwrap(), &sandbox.home),
    })
}

/// `--passthrough` literals (the flag is a CSV string slice) and the banner
/// line that closes the broker startup output.
const BROKER_CASES: &[(&str, &[&str], libc::c_int)] = &[
    (
        "plain",
        &["--passthrough", "a.example,b.example"],
        libc::SIGINT,
    ),
    ("sigterm", &["--passthrough", "a.example"], libc::SIGTERM),
    ("empty", &["--passthrough", ""], libc::SIGINT),
    ("equals-empty", &["--passthrough="], libc::SIGINT),
    ("only-commas", &["--passthrough", ",,"], libc::SIGINT),
    ("one-comma", &["--passthrough", ","], libc::SIGINT),
    (
        "quoted-comma",
        &["--passthrough", "a,\"b,c\""],
        libc::SIGINT,
    ),
    (
        "doubled-quote",
        &["--passthrough", "\"a\"\"b\""],
        libc::SIGINT,
    ),
    (
        "unterminated-quote",
        &["--passthrough", "\"un"],
        libc::SIGINT,
    ),
    (
        "bare-quote-in-field",
        &["--passthrough", "a\"b"],
        libc::SIGINT,
    ),
    ("spaces", &["--passthrough", " a , b "], libc::SIGINT),
    (
        "repeated",
        &["--passthrough", "a", "--passthrough", "b,c"],
        libc::SIGINT,
    ),
    ("equals-form", &["--passthrough=a.example"], libc::SIGINT),
    (
        "wildcard-and-case",
        &["--passthrough", "*.Example.COM,EXAMPLE.com"],
        libc::SIGINT,
    ),
    (
        "unicode",
        &["--passthrough", "bücher.example,例え.jp"],
        libc::SIGINT,
    ),
    (
        "with-port-and-path",
        &["--passthrough", "host:443,host/path"],
        libc::SIGINT,
    ),
    (
        "strict-and-list",
        &["--strict", "--passthrough", "a.example"],
        libc::SIGINT,
    ),
    (
        "many",
        &["--passthrough", "h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11"],
        libc::SIGINT,
    ),
    (
        "backslash-and-tab",
        &["--passthrough", "a\\b,c\td"],
        libc::SIGINT,
    ),
];

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn broker_passthrough_literals_match_go() {
    let obs = Observations::begin(
        "cli_signal_literals",
        "broker_passthrough_literals_match_go",
        Some(ORACLE),
    );
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let sandbox = sandbox(&rust);
    for (name, flags, signal) in BROKER_CASES {
        let mut args = vec!["broker"];
        args.extend_from_slice(flags);
        // The refusal of a malformed literal ends the run; every other run
        // is complete once the environment block is printed.
        let ready = "NO_PROXY=127.0.0.1,localhost\n";
        let go = obs.observe(name, |go_binary| {
            drive(go_binary, &sandbox, &args, ready, *signal)
        });
        if !obs.capturing() {
            let native = drive(&rust, &sandbox, &args, ready, *signal);
            assert_eq!(native, go, "broker {name}: {flags:?}");
        }
    }
    assert_eq!(obs.count(), BROKER_CASES.len());
}

const INTERVAL_CASES: &[(&str, &[&str], libc::c_int)] = &[
    ("default", &[], libc::SIGINT),
    ("default-sigterm", &[], libc::SIGTERM),
    ("zero-bare", &["--interval", "0"], libc::SIGINT),
    ("zero-seconds", &["--interval", "0s"], libc::SIGINT),
    ("negative", &["--interval", "-5s"], libc::SIGINT),
    ("negative-nano", &["--interval", "-1ns"], libc::SIGTERM),
    ("negative-zero", &["--interval", "-0"], libc::SIGINT),
    ("fraction", &["--interval", "1.5s"], libc::SIGINT),
    ("fraction-leading-dot", &["--interval", ".5s"], libc::SIGINT),
    (
        "fraction-trailing-dot",
        &["--interval", "5.s"],
        libc::SIGINT,
    ),
    ("explicit-plus", &["--interval", "+5s"], libc::SIGINT),
    ("unitless", &["--interval", "5"], libc::SIGINT),
    ("empty", &["--interval", ""], libc::SIGINT),
    ("huge-hours", &["--interval", "100000h"], libc::SIGINT),
    ("compound", &["--interval", "1h2m3.5s"], libc::SIGINT),
    ("micro-ascii", &["--interval", "1us"], libc::SIGINT),
    ("micro-greek", &["--interval", "1µs"], libc::SIGINT),
    ("milli", &["--interval", "1ms"], libc::SIGINT),
    ("sub-nano", &["--interval", "0.000000001s"], libc::SIGINT),
    ("sub-nano-truncated", &["--interval", "0.9ns"], libc::SIGINT),
    (
        "max-nanos",
        &["--interval", "9223372036854775807ns"],
        libc::SIGINT,
    ),
    (
        "max-text",
        &["--interval", "2562047h47m16.854775807s"],
        libc::SIGTERM,
    ),
    (
        "overflow-nanos",
        &["--interval", "9223372036854775808ns"],
        libc::SIGINT,
    ),
    ("overflow-hours", &["--interval", "9999999h"], libc::SIGINT),
    ("exponent", &["--interval", "1e3s"], libc::SIGINT),
    ("inner-space", &["--interval", "1m 5s"], libc::SIGINT),
    ("outer-space", &["--interval", " 5s"], libc::SIGINT),
    ("equals-form", &["--interval=7s"], libc::SIGINT),
    ("days-unit", &["--interval", "1d"], libc::SIGINT),
    ("debounce-zero", &["--debounce", "0"], libc::SIGINT),
    ("debounce-negative", &["--debounce", "-1s"], libc::SIGINT),
    ("debounce-fraction", &["--debounce", "0.25h"], libc::SIGINT),
    ("debounce-unitless", &["--debounce", "3"], libc::SIGINT),
    (
        "both",
        &["--interval", "1.5ms", "--debounce", "2m30s"],
        libc::SIGTERM,
    ),
    (
        "last-wins",
        &["--interval", "1s", "--interval", "2s"],
        libc::SIGINT,
    ),
];

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn intake_watch_interval_literals_match_go() {
    let obs = Observations::begin(
        "cli_signal_literals",
        "intake_watch_interval_literals_match_go",
        Some(ORACLE),
    );
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let sandbox = sandbox(&rust);
    let watched = sandbox.home.join("watched");
    let watched_text = watched.to_str().unwrap().to_owned();
    for (name, flags, signal) in INTERVAL_CASES {
        let mut args = vec!["intake", "watch", watched_text.as_str()];
        args.extend_from_slice(flags);
        let ready = "Ctrl-C to stop.\n";
        let go = obs.observe(name, |go_binary| {
            drive(go_binary, &sandbox, &args, ready, *signal)
        });
        if !obs.capturing() {
            let native = drive(&rust, &sandbox, &args, ready, *signal);
            assert_eq!(native, go, "intake watch {name}: {flags:?}");
        }
    }
    assert_eq!(obs.count(), INTERVAL_CASES.len());
}
