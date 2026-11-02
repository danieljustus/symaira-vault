//! `symvault setup` against the Go wizard, driven through a real PTY.
//!
//! Every scenario scripts keystrokes for the interactive wizard (bubbletea in
//! Go, ratatui here), runs it in a disposable `HOME`/`XDG_*` root and compares
//! what is observable *outside* the TUI:
//!
//! * exit code (and terminating signal) of every run of the scenario,
//! * whether every scripted screen was reached (`ok`) and which was not,
//! * the text the process prints after it leaves the alternate screen
//!   (`ESC[?1049l`): Go and Rust share one PTY for stdout and stderr, so this
//!   is the combined stdout/stderr tail (`Error: ...` lines, the pause notice,
//!   the panic banner), ANSI-stripped, CRLF-normalized,
//! * the recursive file manifest of the sandbox: path, kind, mode and, for
//!   text files, the normalized contents (size for binary files and age files),
//! * that the Go binary can open every vault the wizard left behind
//!   (`symvault --vault <copy> list`), which proves `identity.age` interop.
//!
//! Not compared (out of scope on purpose):
//!
//! * the TUI's own bytes: frames, colors, cursor movement, spinner glyphs and
//!   anything written while the alternate screen is active (bubbletea and
//!   ratatui render differently by design). Visible *behavior* is covered by the
//!   scripted `expect` screens, not by their pixels;
//! * Go's panic stack trace (goroutine dump with addresses): it is cut from the
//!   Go side, Rust prints none;
//! * Touch ID. A no-cgo Go oracle can never see biometrics, so the Auth step,
//!   `SaveBiometricPassphrase` and `authMethod: touchid` are **unverified**
//!   against Go; Rust runs with `SYMVAULT_TEST_TOUCH_ID=unavailable` to match;
//! * `.git` internals except `HEAD` and `config`, the `cwd` and `tmp` sandbox
//!   directories, and timestamps, token ids/hashes/prefixes, age public keys,
//!   resume-file name hashes and `tool_registry_hash` (normalized to
//!   placeholders; the Rust port pins a registry hash from an older oracle, see
//!   `docs/rust-port/cli-gap-inventory.md`).
//!
//! Modes
//!
//! * `native_matches_live_go_oracle` (needs `SYMVAULT_GO_BINARY`): runs every
//!   scenario against Go and Rust and compares; it also compares the live Go
//!   result with `testdata/port/cli/setup-wizard/go-results.json`. When the
//!   variable is set nothing is skipped: a missing binary, a short scenario
//!   count or an unreached screen fails.
//! * `native_matches_recorded_go_results` (no Go needed, macOS): replays Rust
//!   against the recorded normalized Go results; Go-initialized vaults come
//!   from the recorded `vault_seed`.
//! * `record_go_results` (ignored): rewrites the recording from the live Go
//!   oracle. Needs `SYMVAULT_GO_ORACLE_COMMIT` and `SYMVAULT_GO_ORACLE_BUILD`.
//! * driver and comparator self-tests (no Go): PTY capture, signals, timeouts,
//!   alternate-screen extraction, normalizers and mutation negative controls.
#![cfg(unix)]
// A PTY needs `openpty(3)`, `setsid(2)` and `ioctl(TIOCSCTTY)` between fork
// and exec; there is no safe std API for it.
#![allow(unsafe_code)]

use std::{
    collections::BTreeMap,
    env, fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{fs::PermissionsExt, process::CommandExt, process::ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECORDING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/port/cli/setup-wizard/go-results.json"
);
const PASS: &[u8] = b"correct horse battery staple";
const ENTER: &[u8] = b"\r";
const DOWN: &[u8] = b"\x1b[B";
const UP: &[u8] = b"\x1b[A";
const ESC: &[u8] = b"\x1b";
const TAB: &[u8] = b"\t";
const CTRL_C: &[u8] = b"\x03";
const CTRL_S: &[u8] = b"\x13";
const CTRL_U: &[u8] = b"\x15";
const ALT_SCREEN_EXIT: &[u8] = b"\x1b[?1049l";
const RECIPIENT: &str = "age10jtjwy0k55eajndnwtvujmy4rhdfa7rt88r6v98ltefw0sdvddksrruz0j";
/// Fewer scenarios than this means the corpus was cut, not that it passed.
const MIN_SCENARIOS: usize = 27;
const PARALLEL: usize = 4;

// ------------------------------------------------------------------ PTY ----

#[derive(Clone, Debug)]
enum Step {
    /// Wait until the ANSI-stripped output since the last send contains this.
    Expect(&'static str),
    Send(Vec<u8>),
    Sleep(Duration),
    /// The first listed text that shows up decides which sub-steps run.
    Either(Vec<(&'static str, Vec<Step>)>),
    /// Wait for the process to exit by itself.
    Exit,
}

fn expect(text: &'static str) -> Step {
    Step::Expect(text)
}

fn send(bytes: &[u8]) -> Step {
    Step::Send(bytes.to_vec())
}

fn sleep(ms: u64) -> Step {
    Step::Sleep(Duration::from_millis(ms))
}

#[derive(Debug)]
struct RunResult {
    ok: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    raw: Vec<u8>,
    failed: Vec<String>,
}

struct Session {
    master: OwnedFd,
    child: Child,
    raw: Vec<u8>,
    closed: bool,
    status: Option<std::process::ExitStatus>,
}

fn set_cloexec(fd: RawFd) {
    // SAFETY: fcntl on a descriptor this process owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }
}

fn open_pty(rows: u16, cols: u16) -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: out-pointers are valid; the descriptors are wrapped right away.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    assert_eq!(rc, 0, "openpty: {}", io::Error::last_os_error());
    set_cloexec(master);
    set_cloexec(slave);
    // SAFETY: openpty returned two fresh descriptors nobody else owns.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

impl Session {
    fn start(binary: &Path, args: &[String], env: &[(String, String)], cwd: &Path) -> Self {
        let (master, slave) = open_pty(40, 120);
        let mut command = Command::new(binary);
        command
            .args(args)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .current_dir(cwd)
            .stdin(Stdio::from(slave.try_clone().expect("dup slave")))
            .stdout(Stdio::from(slave.try_clone().expect("dup slave")))
            .stderr(Stdio::from(slave));
        // SAFETY: only async-signal-safe calls (setsid, ioctl) between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {}: {error}", binary.display()));
        // SAFETY: plain flag update on the master descriptor.
        unsafe {
            let fd = master.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Self {
            master,
            child,
            raw: Vec::new(),
            closed: false,
            status: None,
        }
    }

    /// Reads what the child printed; answers the terminal queries a
    /// bubbletea/lipgloss program (and crossterm) emits.
    fn pump(&mut self, millis: i32) -> bool {
        if self.closed {
            thread::sleep(Duration::from_millis(millis.max(0) as u64));
            return false;
        }
        let fd = self.master.as_raw_fd();
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready <= 0 {
            return false;
        }
        let mut buffer = [0u8; 65536];
        // SAFETY: the buffer is valid for its whole length.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock
                && error.kind() != io::ErrorKind::Interrupted
            {
                self.closed = true;
            }
            return false;
        }
        if count == 0 {
            self.closed = true;
            return false;
        }
        let chunk = &buffer[..count as usize];
        self.raw.extend_from_slice(chunk);
        self.answer_queries(chunk);
        true
    }

    fn answer_queries(&mut self, chunk: &[u8]) {
        let has = |needle: &[u8]| chunk.windows(needle.len()).any(|window| window == needle);
        if has(b"\x1b]11;?") || has(b"\x1b]10;?") {
            self.write(b"\x1b]11;rgb:0000/0000/0000\x1b\\");
        }
        if has(b"\x1b[6n") {
            self.write(b"\x1b[1;1R");
        }
        if has(b"\x1b[c") || has(b"\x1b[0c") {
            self.write(b"\x1b[?1;2c");
        }
    }

    fn write(&self, bytes: &[u8]) {
        let fd = self.master.as_raw_fd();
        let mut written = 0;
        let mut spins = 0;
        while written < bytes.len() && spins < 200 {
            // SAFETY: the slice is valid for the length passed.
            let count =
                unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
            if count > 0 {
                written += count as usize;
            } else {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    spins += 1;
                    thread::sleep(Duration::from_millis(5));
                } else {
                    return; // child gone (EIO)
                }
            }
        }
    }

    fn reap(&mut self) -> bool {
        if self.status.is_some() {
            return true;
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.status = Some(status);
                true
            }
            _ => false,
        }
    }

    fn screen_since(&self, since: usize) -> String {
        strip_ansi(&self.raw[since.min(self.raw.len())..])
    }

    fn do_send(&mut self, bytes: &[u8], since: &mut usize) {
        thread::sleep(Duration::from_millis(120));
        while self.pump(50) {}
        *since = self.raw.len();
        self.write(bytes);
    }

    /// Runs `steps`; false stops the script (an expectation was missed).
    fn run_steps(
        &mut self,
        steps: &[Step],
        since: &mut usize,
        deadline: Instant,
        step_timeout: Duration,
        failed: &mut Vec<String>,
    ) -> bool {
        for step in steps {
            match step {
                Step::Send(bytes) => self.do_send(bytes, since),
                Step::Sleep(duration) => {
                    let end = Instant::now() + *duration;
                    while Instant::now() < end {
                        self.pump(50);
                    }
                }
                Step::Expect(want) => {
                    let end = (Instant::now() + step_timeout).min(deadline);
                    let mut found = false;
                    while Instant::now() < end {
                        if self.screen_since(*since).contains(want) {
                            found = true;
                            break;
                        }
                        if self.reap() {
                            self.pump(50);
                            found = self.screen_since(*since).contains(want);
                            break;
                        }
                        self.pump(50);
                    }
                    if !found {
                        failed.push(format!("expect {want:?}"));
                        return false;
                    }
                }
                Step::Either(options) => {
                    let end = (Instant::now() + step_timeout).min(deadline);
                    let mut chosen: Option<&Vec<Step>> = None;
                    while chosen.is_none() && Instant::now() < end {
                        let screen = self.screen_since(*since);
                        chosen = options
                            .iter()
                            .find(|(text, _)| screen.contains(text))
                            .map(|(_, sub)| sub);
                        if chosen.is_none() {
                            if self.reap() {
                                self.pump(50);
                                break;
                            }
                            self.pump(50);
                        }
                    }
                    let Some(sub) = chosen else {
                        let names: Vec<&str> = options.iter().map(|(text, _)| *text).collect();
                        failed.push(format!("either {names:?}"));
                        return false;
                    };
                    if !self.run_steps(sub, since, deadline, step_timeout, failed) {
                        return false;
                    }
                }
                Step::Exit => {
                    let end = (Instant::now() + step_timeout).min(deadline);
                    while Instant::now() < end {
                        if self.reap() {
                            break;
                        }
                        self.pump(50);
                    }
                    if self.status.is_none() {
                        failed.push("exit".to_owned());
                        return false;
                    }
                }
            }
        }
        true
    }
}

fn run_pty(
    binary: &Path,
    args: &[String],
    env: &[(String, String)],
    cwd: &Path,
    steps: &[Step],
    step_timeout: Duration,
) -> RunResult {
    let mut session = Session::start(binary, args, env, cwd);
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut failed = Vec::new();
    let mut since = 0;
    let mut ok = session.run_steps(steps, &mut since, deadline, step_timeout, &mut failed);
    let end = Instant::now() + Duration::from_secs(3);
    while session.status.is_none() && Instant::now() < end {
        if session.reap() {
            break;
        }
        session.pump(50);
    }
    while session.pump(100) {}
    if session.status.is_none() {
        let _ = session.child.kill();
        session.status = session.child.wait().ok();
        ok = false;
        failed.push("process had to be killed".to_owned());
    }
    let status = session.status.expect("status");
    RunResult {
        ok,
        exit_code: status.code(),
        signal: status.signal(),
        raw: session.raw,
        failed,
    }
}

/// Removes CSI, OSC and charset escapes.
fn strip_ansi(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] != 0x1b {
            out.push(data[i]);
            i += 1;
            continue;
        }
        i += 1;
        match data.get(i) {
            Some(b'[') => {
                i += 1;
                while i < data.len() && (0x30..=0x3f).contains(&data[i]) {
                    i += 1;
                }
                while i < data.len() && (0x20..=0x2f).contains(&data[i]) {
                    i += 1;
                }
                i += 1;
            }
            Some(b']') => {
                i += 1;
                while i < data.len() {
                    if data[i] == 0x07 {
                        i += 1;
                        break;
                    }
                    if data[i] == 0x1b && data.get(i + 1) == Some(&b'\\') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            Some(b'(' | b')') => i += 2,
            Some(_) => i += 1,
            None => {}
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// -------------------------------------------------------- normalization ----

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// `tok-YYYYMMDD-xxxxxxxx` -> `<TOKID>`.
fn replace_token_ids(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"tok-")
            && bytes.len() >= i + 21
            && bytes[i + 4..i + 12].iter().all(u8::is_ascii_digit)
            && bytes[i + 12] == b'-'
            && bytes[i + 13..i + 21].iter().all(|b| is_hex(*b))
        {
            out.push_str("<TOKID>");
            i += 21;
        } else {
            let ch = text[i..].chars().next().expect("char");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// `"key": "<hex of exactly len>"` -> `"key": "<placeholder>"`.
fn replace_json_hex(text: &str, key: &str, len: usize, placeholder: &str) -> String {
    let needle = format!("\"{key}\": \"");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(&needle) {
        let value_start = at + needle.len();
        out.push_str(&rest[..value_start]);
        let tail = &rest[value_start..];
        let hex = tail.bytes().take_while(|b| is_hex(*b)).count();
        if hex == len && tail.as_bytes().get(len) == Some(&b'"') {
            out.push_str(placeholder);
            rest = &tail[len..];
        } else {
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// `2026-11-01T23:46:25.542275Z` and `...+01:00` -> `<TS>`.
fn replace_timestamps(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let date = bytes.len() >= i + 11
            && bytes[i..i + 4].iter().all(u8::is_ascii_digit)
            && bytes[i + 4] == b'-'
            && bytes[i + 5..i + 7].iter().all(u8::is_ascii_digit)
            && bytes[i + 7] == b'-'
            && bytes[i + 8..i + 10].iter().all(u8::is_ascii_digit)
            && bytes[i + 10] == b'T';
        if date {
            let mut j = i + 11;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit() || bytes[j] == b':' || bytes[j] == b'.')
            {
                j += 1;
            }
            let zone = if bytes.get(j) == Some(&b'Z') {
                Some(j + 1)
            } else if matches!(bytes.get(j), Some(b'+' | b'-'))
                && bytes.len() >= j + 6
                && bytes[j + 1..j + 3].iter().all(u8::is_ascii_digit)
                && bytes[j + 3] == b':'
                && bytes[j + 4..j + 6].iter().all(u8::is_ascii_digit)
            {
                Some(j + 6)
            } else {
                None
            };
            if let Some(end) = zone {
                out.push_str("<TS>");
                i = end;
                continue;
            }
        }
        let ch = text[i..].chars().next().expect("char");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `age1` followed by 50 or more bech32 characters -> `<AGE1>`.
fn replace_age_keys(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("age1") {
        let run = rest[at + 4..]
            .bytes()
            .take_while(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
            .count();
        out.push_str(&rest[..at]);
        if run >= 50 {
            out.push_str("<AGE1>");
            rest = &rest[at + 4 + run..];
        } else {
            out.push_str("age1");
            rest = &rest[at + 4..];
        }
    }
    out.push_str(rest);
    out
}

struct Roots(Vec<String>);

impl Roots {
    fn of(root: &Path) -> Self {
        let mut roots = vec![root.to_string_lossy().into_owned()];
        if let Ok(canonical) = root.canonicalize() {
            let canonical = canonical.to_string_lossy().into_owned();
            if !roots.contains(&canonical) {
                roots.push(canonical);
            }
        }
        // Longest first so a canonical /private/var path wins over /var.
        roots.sort_by_key(|root| std::cmp::Reverse(root.len()));
        Self(roots)
    }

    fn text(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for root in &self.0 {
            text = text.replace(root.as_str(), "<ROOT>");
        }
        let text = replace_token_ids(&text);
        let text = replace_json_hex(&text, "hash", 64, "<HASH>");
        let text = replace_json_hex(&text, "tool_registry_hash", 64, "<REGISTRY-HASH>");
        let text = replace_json_hex(&text, "prefix", 4, "<PFX>");
        let text = replace_timestamps(&text);
        replace_age_keys(&text)
    }
}

/// The text after the last alternate-screen exit: the process's stdout/stderr
/// once the TUI is gone. Go's panic goroutine dump is cut.
fn post_tui_text(raw: &[u8], roots: &Roots) -> String {
    let Some(at) = raw
        .windows(ALT_SCREEN_EXIT.len())
        .rposition(|window| window == ALT_SCREEN_EXIT)
    else {
        return "<no alternate-screen exit>".to_owned();
    };
    let mut text = strip_ansi(&raw[at + ALT_SCREEN_EXIT.len()..]).replace("\r\n", "\n");
    if let Some(trace) = text.find("goroutine ")
        && let Some(error) = text[trace..].find("\nError: ")
    {
        text = format!("{}{}", &text[..trace], &text[trace + error + 1..]);
    }
    roots.text(&text)
}

// ------------------------------------------------------------- results ----

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RunOutcome {
    label: String,
    ok: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    failed: Vec<String>,
    post_tui: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManifestEntry {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ScenarioResult {
    name: String,
    runs: Vec<RunOutcome>,
    manifest: BTreeMap<String, ManifestEntry>,
    /// `symvault --vault <copy> list` of the Go binary on each vault left
    /// behind (`exit code`), empty when no live Go binary is available.
    go_opens_vault: BTreeMap<String, String>,
}

fn top_level_skipped(rel: &str) -> bool {
    matches!(rel.split('/').next(), Some("cwd" | "tmp"))
}

/// Inside a `.git` directory only `HEAD` and `config` are recorded; the rest
/// (objects, hooks, logs, index) is volatile.
fn git_internal_skipped(rel: &str, is_file: bool) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    let Some(git) = parts.iter().position(|part| *part == ".git") else {
        return false;
    };
    let inside = &parts[git + 1..];
    match inside {
        [] => false,
        [name] => !(is_file && matches!(*name, "HEAD" | "config")),
        _ => true,
    }
}

fn normalized_name(rel: &str) -> String {
    // Resume files are named after a hash of the vault directory.
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.len() >= 2 && parts[parts.len() - 2] == "wizard" {
        let last = parts[parts.len() - 1];
        if let Some(stem) = last.strip_suffix(".yaml")
            && stem.len() == 16
            && stem.bytes().all(is_hex)
        {
            let mut parts = parts;
            let n = parts.len();
            parts[n - 1] = "<RESUME>.yaml";
            return parts.join("/");
        }
    }
    rel.to_owned()
}

fn manifest(root: &Path, roots: &Roots) -> BTreeMap<String, ManifestEntry> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut names: Vec<_> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .map(|entry| entry.expect("entry").path())
            .collect();
        names.sort();
        for path in names {
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .into_owned();
            if top_level_skipped(&rel) {
                continue;
            }
            let meta = fs::symlink_metadata(&path).expect("lstat");
            let mode = Some(format!("{:o}", meta.permissions().mode() & 0o777));
            let kind = meta.file_type();
            if git_internal_skipped(&rel, kind.is_file()) {
                continue;
            }
            if kind.is_dir() {
                out.insert(
                    normalized_name(&rel),
                    ManifestEntry {
                        kind: "dir".into(),
                        mode,
                        size: None,
                        text: None,
                        link: None,
                    },
                );
                stack.push(path.clone());
                continue;
            }
            if kind.is_symlink() {
                let target = fs::read_link(&path).expect("readlink");
                out.insert(
                    normalized_name(&rel),
                    ManifestEntry {
                        kind: "link".into(),
                        mode: None,
                        size: None,
                        text: None,
                        link: Some(roots.text(&target.to_string_lossy())),
                    },
                );
                continue;
            }
            let data = fs::read(&path).expect("read");
            let mut entry = ManifestEntry {
                kind: "file".into(),
                mode,
                size: Some(data.len() as u64),
                text: None,
                link: None,
            };
            if data.len() < 40_000
                && !data.starts_with(b"age-encryption.org")
                && let Ok(text) = String::from_utf8(data)
            {
                entry.size = None;
                let text = if rel.ends_with("mcp-tokens.json") {
                    order_tokens(&text)
                } else {
                    text
                };
                entry.text = Some(roots.text(&text));
            }
            out.insert(normalized_name(&rel), entry);
        }
    }
    out
}

/// `mcp-tokens.json` is an object keyed by random token ids, so its entry order
/// is random in Go and Rust alike. The tokens are listed sorted by label.
fn order_tokens(text: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) else {
        return text.to_owned();
    };
    if let Some(tokens) = value
        .get_mut("tokens")
        .and_then(|tokens| tokens.as_object())
    {
        let mut list: Vec<serde_json::Value> = tokens.values().cloned().collect();
        list.sort_by_key(|token| token["label"].as_str().unwrap_or_default().to_owned());
        value["tokens"] = serde_json::Value::Array(list);
    }
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_owned())
}

/// The one accepted difference, and only in this exact form: a new vault with
/// git sync gets its repository from `symvault_sync::GitRepository::init`
/// (`git init`, `symbolic-ref HEAD refs/heads/master`, `config user.name` and
/// `user.email`), where Go uses go-git's `PlainInit`, whose config holds only
/// `bare = false`. The extra keys below are exactly what the git CLI adds; with
/// them removed the Rust file must equal Go's byte for byte. The behavior is
/// shared with `symvault init` and is not specific to the wizard.
fn accepted_git_config_divergence(go: &str, rust: &str) -> bool {
    const CLI_DEFAULTS: [&str; 5] = [
        "\trepositoryformatversion = 0\n",
        "\tfilemode = true\n",
        "\tlogallrefupdates = true\n",
        "\tignorecase = true\n",
        "\tprecomposeunicode = true\n",
    ];
    const USER_BLOCK: &str = "[user]\n\tname = Symaira Vault\n\temail = symvault@example.com\n";
    if go == rust {
        return false;
    }
    let mut stripped = rust.replace(USER_BLOCK, "");
    for line in CLI_DEFAULTS {
        stripped = stripped.replace(line, "");
    }
    stripped == go
}

/// Scenarios that end with that git-config difference (a new vault with git
/// sync). Each must still show it: a fixed port has to drop its entry.
const KNOWN_GIT_CONFIG_DIVERGENCES: [&str; 2] = ["git_sync", "git_multidevice"];

/// Makes the accepted difference equal on the Rust side and reports which
/// scenarios showed it. Any other difference stays.
fn apply_known_divergences(go: &[ScenarioResult], rust: &mut [ScenarioResult]) -> Vec<String> {
    let mut seen = Vec::new();
    for (go, rust) in go.iter().zip(rust.iter_mut()) {
        if !KNOWN_GIT_CONFIG_DIVERGENCES.contains(&rust.name.as_str()) {
            continue;
        }
        let key = "xdg/data/symaira-vault/.git/config";
        let (Some(go_entry), Some(rust_entry)) = (go.manifest.get(key), rust.manifest.get(key))
        else {
            continue;
        };
        if let (Some(go_text), Some(rust_text)) = (&go_entry.text, &rust_entry.text)
            && accepted_git_config_divergence(go_text, rust_text)
        {
            rust.manifest.insert(key.to_owned(), go_entry.clone());
            seen.push(rust.name.clone());
        }
    }
    seen
}

fn assert_known_divergences_observed(seen: &[String]) {
    let mut expected: Vec<&str> = KNOWN_GIT_CONFIG_DIVERGENCES.to_vec();
    expected.sort_unstable();
    let mut seen: Vec<&str> = seen.iter().map(String::as_str).collect();
    seen.sort_unstable();
    assert_eq!(
        seen, expected,
        "the known git-config divergence must show in exactly its scenarios; drop the entry once Rust matches Go"
    );
}

/// Field-by-field comparison; every difference names scenario, run and field.
fn diff_results(
    left_name: &str,
    left: &ScenarioResult,
    right_name: &str,
    right: &ScenarioResult,
) -> Vec<String> {
    let mut diffs = Vec::new();
    let name = &left.name;
    if left.runs.len() != right.runs.len() {
        diffs.push(format!(
            "{name}: run count {left_name}={} {right_name}={}",
            left.runs.len(),
            right.runs.len()
        ));
    }
    for (a, b) in left.runs.iter().zip(&right.runs) {
        let at = format!("{name}/{}", a.label);
        macro_rules! field {
            ($field:ident) => {
                if a.$field != b.$field {
                    diffs.push(format!(
                        "{at}.{}: {left_name}={:?} {right_name}={:?}",
                        stringify!($field),
                        a.$field,
                        b.$field
                    ));
                }
            };
        }
        field!(label);
        field!(ok);
        field!(exit_code);
        field!(signal);
        field!(failed);
        field!(post_tui);
    }
    let keys: std::collections::BTreeSet<&String> =
        left.manifest.keys().chain(right.manifest.keys()).collect();
    for key in keys {
        match (left.manifest.get(key), right.manifest.get(key)) {
            (Some(a), Some(b)) if a != b => diffs.push(format!(
                "{name}: manifest {key}\n  {left_name}={a:?}\n  {right_name}={b:?}"
            )),
            (Some(a), None) => diffs.push(format!("{name}: only in {left_name}: {key} {a:?}")),
            (None, Some(b)) => diffs.push(format!("{name}: only in {right_name}: {key} {b:?}")),
            _ => {}
        }
    }
    if left.go_opens_vault != right.go_opens_vault {
        diffs.push(format!(
            "{name}: go_opens_vault {left_name}={:?} {right_name}={:?}",
            left.go_opens_vault, right.go_opens_vault
        ));
    }
    diffs
}

// ------------------------------------------------------------ scenarios ----

struct Ctx<'a> {
    /// The binary under test.
    binary: &'a Path,
    /// Go oracle, used for `init` and the open check; `None` replays a seed.
    go: Option<&'a Path>,
    seed: &'a [SeedFile],
    root: PathBuf,
}

impl Ctx<'_> {
    fn env(&self) -> Vec<(String, String)> {
        let root = self.root.to_string_lossy();
        let pairs = [
            ("HOME", format!("{root}/home")),
            ("TMPDIR", format!("{root}/tmp")),
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("TERM", "xterm-256color".to_owned()),
            ("CI", "1".to_owned()),
            ("LANG", "en_US.UTF-8".to_owned()),
            ("LC_ALL", "en_US.UTF-8".to_owned()),
            ("XDG_CONFIG_HOME", format!("{root}/xdg/config")),
            ("XDG_DATA_HOME", format!("{root}/xdg/data")),
            ("XDG_CACHE_HOME", format!("{root}/xdg/cache")),
            // No-cgo Go cannot see Touch ID; see the module header.
            ("SYMVAULT_TEST_TOUCH_ID", "unavailable".to_owned()),
        ];
        pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
    }

    fn make_dirs(&self) {
        for dir in ["home", "tmp", "cwd", "xdg/config", "xdg/data", "xdg/cache"] {
            fs::create_dir_all(self.root.join(dir)).expect("sandbox dir");
        }
    }

    fn setup(&self, label: &str, args: &[&str], steps: Vec<Step>) -> RunOutcome {
        let mut argv = vec!["setup".to_owned()];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        let result = run_pty(
            self.binary,
            &argv,
            &self.env(),
            &self.root.join("cwd"),
            &steps,
            Duration::from_secs(120),
        );
        let roots = Roots::of(&self.root);
        RunOutcome {
            label: label.to_owned(),
            ok: result.ok,
            exit_code: result.exit_code,
            signal: result.signal,
            failed: result.failed.clone(),
            post_tui: post_tui_text(&result.raw, &roots),
        }
    }

    fn vault_dir(&self) -> PathBuf {
        self.root.join("xdg/data/symaira-vault")
    }

    /// A vault initialized by the Go binary (or its recorded seed).
    fn go_init(&self) {
        match self.go {
            Some(go) => {
                let mut env = self.env();
                env.push((
                    "SYMVAULT_PASSPHRASE".into(),
                    String::from_utf8_lossy(PASS).into_owned(),
                ));
                env.push(("SYMVAULT_ALLOW_ENV_PASSPHRASE".into(), "1".into()));
                let output = Command::new(go)
                    .arg("init")
                    .env_clear()
                    .envs(env.iter().map(|(k, v)| (k, v)))
                    .current_dir(self.root.join("cwd"))
                    .stdin(Stdio::null())
                    .output()
                    .expect("run go init");
                assert!(
                    output.status.success(),
                    "go init failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => {
                assert!(!self.seed.is_empty(), "no recorded vault seed");
                let roots = self.root.to_string_lossy().into_owned();
                for file in self.seed {
                    let path = self.vault_dir().join(&file.path);
                    if file.kind == "dir" {
                        fs::create_dir_all(&path).expect("seed dir");
                    } else {
                        fs::create_dir_all(path.parent().expect("parent")).expect("seed parent");
                        let data = match (&file.text, &file.base64) {
                            (Some(text), _) => text.replace("<ROOT>", &roots).into_bytes(),
                            (None, Some(encoded)) => decode_base64(encoded),
                            _ => Vec::new(),
                        };
                        fs::write(&path, data).expect("seed file");
                    }
                    let mode = u32::from_str_radix(&file.mode, 8).expect("seed mode");
                    fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                        .expect("seed mode");
                }
            }
        }
    }

    fn resume_files(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "yaml")
                    && path
                        .parent()
                        .and_then(Path::file_name)
                        .is_some_and(|name| name == "wizard")
                {
                    found.push(path);
                }
            }
        }
        found.sort();
        found
    }

    fn the_resume_file(&self) -> PathBuf {
        let files = self.resume_files();
        assert_eq!(
            files.len(),
            1,
            "expected exactly one resume file: {files:?}"
        );
        files.into_iter().next().expect("one")
    }
}

type Scenario = fn(&Ctx) -> Vec<RunOutcome>;

fn skip_auth() -> Step {
    Step::Either(vec![
        (
            "Authentication method",
            vec![send(DOWN), send(ENTER), expect("Sync strategy")],
        ),
        ("Sync strategy", vec![]),
    ])
}

/// Welcome through the passphrase pair, then the optional Auth step.
fn to_sync() -> Vec<Step> {
    vec![
        expect("Welcome to Symaira Vault"),
        send(ENTER),
        expect("Vault directory"),
        send(ENTER),
        expect("Set vault passphrase"),
        send(PASS),
        send(ENTER),
        send(PASS),
        send(ENTER),
        skip_auth(),
    ]
}

fn tail_apply() -> Vec<Step> {
    vec![
        expect("review your choices"),
        send(ENTER),
        expect("is ready"),
        send(ENTER),
        Step::Exit,
    ]
}

/// The apply of a new git-synced vault ends in Go's nil-pointer panic.
fn tail_apply_panics() -> Vec<Step> {
    vec![
        expect("review your choices"),
        send(ENTER),
        expect("Caught panic"),
        Step::Exit,
    ]
}

fn from_agents(profile: Vec<Step>) -> Vec<Step> {
    let mut steps = vec![
        expect("AI agent configuration"),
        send(ENTER),
        expect("Backup plan"),
        send(ENTER),
        expect("Vault profile name"),
    ];
    steps.extend(profile);
    steps
}

fn happy_steps() -> Vec<Step> {
    let mut steps = to_sync();
    steps.push(send(ENTER)); // sync: local
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply());
    steps
}

fn abort_at_agents(prefix: Vec<Step>) -> Vec<Step> {
    let mut steps = prefix;
    steps.extend([
        send(ENTER),
        expect("AI agent configuration"),
        send(ESC),
        expect("Cancel setup?"),
        send(b"y"),
        Step::Exit,
    ]);
    steps
}

fn toggle_all_agents() -> Vec<Step> {
    let mut steps = Vec::new();
    for _ in 0..5 {
        steps.push(send(b" "));
        steps.push(send(DOWN));
    }
    steps
}

fn agents_with(toggle: Vec<Step>, profile: Vec<Step>) -> Vec<Step> {
    let mut steps = to_sync();
    steps.extend([send(ENTER), expect("AI agent configuration")]);
    steps.extend(toggle);
    steps.extend([
        send(ENTER),
        expect("Backup plan"),
        send(ENTER),
        expect("Vault profile name"),
    ]);
    steps.extend(profile);
    steps.extend(tail_apply());
    steps
}

fn reconfigure_prefix() -> Vec<Step> {
    vec![
        expect("Re-configuring Symaira Vault"),
        send(ENTER),
        expect("Sync strategy"),
    ]
}

fn resume_then(extra: Vec<Step>) -> Vec<Step> {
    let mut steps = vec![expect("Resume Previous Setup"), send(b"y")];
    steps.extend(extra);
    steps
}

fn happy(ctx: &Ctx) -> Vec<RunOutcome> {
    vec![ctx.setup("run1", &[], happy_steps())]
}

fn no_resume(ctx: &Ctx) -> Vec<RunOutcome> {
    // An aborted run leaves a resume file; --no-resume must ignore it.
    let aborted = ctx.setup("abort", &[], abort_at_agents(to_sync()));
    let fresh = ctx.setup("no_resume", &["--no-resume"], happy_steps());
    vec![aborted, fresh]
}

fn abort_resume(ctx: &Ctx) -> Vec<RunOutcome> {
    let aborted = ctx.setup("abort", &[], abort_at_agents(to_sync()));
    let mut steps = resume_then(vec![
        expect("Set vault passphrase"),
        send(PASS),
        send(ENTER),
        send(PASS),
        send(ENTER),
        skip_auth(),
        send(ENTER),
    ]);
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply());
    vec![aborted, ctx.setup("resume", &[], steps)]
}

fn abort_ctrlc(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = to_sync();
    steps.extend([
        send(ENTER),
        expect("AI agent configuration"),
        send(CTRL_C),
        Step::Exit,
    ]);
    vec![ctx.setup("ctrlc", &[], steps)]
}

fn abort_no_resume_flag(ctx: &Ctx) -> Vec<RunOutcome> {
    vec![ctx.setup(
        "abort_noresume",
        &["--no-resume"],
        abort_at_agents(to_sync()),
    )]
}

fn esc_then_no(ctx: &Ctx) -> Vec<RunOutcome> {
    let steps = vec![
        expect("Welcome to Symaira Vault"),
        send(ESC),
        expect("Cancel setup?"),
        send(b"n"),
        expect("Welcome to Symaira Vault"),
        send(ESC),
        expect("Cancel setup?"),
        send(b"x"),
        send(ESC),
        expect("Welcome"),
        send(ESC),
        send(b"Y"),
        Step::Exit,
    ];
    vec![ctx.setup("esc", &[], steps)]
}

fn bad_passphrase(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = vec![
        expect("Welcome to Symaira Vault"),
        send(ENTER),
        expect("Vault directory"),
        send(ENTER),
        expect("Set vault passphrase"),
        send(b"short"),
        send(ENTER),
        send(b"short"),
        send(ENTER),
        expect("passphrase must be at least 12 characters"),
        send(TAB),
        send(b" and more"),
        send(ENTER),
        send(ENTER),
        expect("passphrases do not match"),
        send(CTRL_U),
        send(b"short and more"),
        send(ENTER),
        skip_auth(),
        send(ENTER),
    ];
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply());
    vec![ctx.setup("badpass", &[], steps)]
}

fn agent_fail(ctx: &Ctx) -> Vec<RunOutcome> {
    vec![ctx.setup(
        "agent_fail",
        &[],
        agents_with(toggle_all_agents(), vec![send(ENTER)]),
    )]
}

fn agent_fail_keep(ctx: &Ctx) -> Vec<RunOutcome> {
    vec![ctx.setup(
        "agent_fail_keep",
        &["--keep-on-error"],
        agents_with(toggle_all_agents(), vec![send(ENTER)]),
    )]
}

fn profile_custom(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = to_sync();
    steps.push(send(ENTER));
    steps.extend(from_agents(vec![send(CTRL_U), send(b"work"), send(ENTER)]));
    steps.extend(tail_apply());
    vec![ctx.setup("profile", &[], steps)]
}

fn profile_invalid(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = to_sync();
    steps.push(send(ENTER));
    steps.extend(from_agents(vec![
        send(CTRL_U),
        send(ENTER),
        expect("profile name must not be empty"),
        send(b"a b"),
        send(ENTER),
        expect("profile name must not contain spaces or slashes"),
        send(CTRL_U),
        send(b"p/q"),
        send(ENTER),
        expect("profile name must not contain spaces or slashes"),
        send(CTRL_U),
        send(b"ok"),
        send(ENTER),
    ]));
    steps.extend(tail_apply());
    vec![ctx.setup("profile_invalid", &[], steps)]
}

fn git_sync(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = to_sync();
    steps.extend([
        send(DOWN),
        send(ENTER),
        expect("Git remote URL"),
        send(b"nonsense"),
        send(ENTER),
        expect("please enter a valid git URL"),
        send(CTRL_U),
        send(b"https://example.invalid/v.git"),
        send(ENTER),
        expect("Auto-push on change?"),
        send(ENTER),
        expect("Multi-device setup"),
        send(ENTER),
    ]);
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply_panics());
    vec![ctx.setup("git_sync", &[], steps)]
}

fn git_multidevice(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = to_sync();
    steps.extend([
        send(DOWN),
        send(ENTER),
        expect("Git remote URL"),
        send(b"git@example.invalid:me/v.git"),
        send(ENTER),
        expect("Auto-push on change?"),
        send(b"n"),
        expect("Multi-device setup"),
        send(UP),
        send(ENTER),
        expect("Additional recipients"),
        send(ENTER),
    ]);
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply_panics());
    vec![ctx.setup("git_md", &[], steps)]
}

fn go_back(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = to_sync();
    steps.push(send(ENTER));
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend([
        expect("review your choices"),
        send(DOWN),
        send(ENTER),
        expect("Backup plan"),
        send(ENTER),
        expect("Vault profile name"),
        send(ENTER),
        expect("review your choices"),
        send(UP),
        send(ENTER),
        expect("is ready"),
        send(ENTER),
        Step::Exit,
    ]);
    vec![ctx.setup("go_back", &[], steps)]
}

fn summary_cancel(ctx: &Ctx) -> Vec<RunOutcome> {
    let mut steps = to_sync();
    steps.push(send(ENTER));
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend([
        expect("review your choices"),
        send(DOWN),
        send(DOWN),
        send(ENTER),
        Step::Exit,
    ]);
    vec![ctx.setup("summary_cancel", &[], steps)]
}

fn existing_vault(ctx: &Ctx) -> Vec<RunOutcome> {
    let first = ctx.setup("first", &[], happy_steps());
    let mut steps = reconfigure_prefix();
    steps.push(send(ENTER));
    steps.extend(from_agents(vec![
        send(CTRL_U),
        send(b"second"),
        send(ENTER),
    ]));
    steps.extend(tail_apply());
    vec![first, ctx.setup("reconfigure", &[], steps)]
}

fn existing_agent_fail(ctx: &Ctx) -> Vec<RunOutcome> {
    let first = ctx.setup("first", &[], happy_steps());
    let mut steps = reconfigure_prefix();
    steps.extend([send(ENTER), expect("AI agent configuration")]);
    steps.extend(toggle_all_agents());
    steps.extend([
        send(ENTER),
        expect("Backup plan"),
        send(ENTER),
        expect("Vault profile name"),
        send(ENTER),
    ]);
    steps.extend(tail_apply());
    vec![first, ctx.setup("reconfigure_agentfail", &[], steps)]
}

fn vault_path_custom(ctx: &Ctx) -> Vec<RunOutcome> {
    let custom = format!("{}/home/my vault/v1", ctx.root.display());
    let mut steps = vec![
        expect("Welcome to Symaira Vault"),
        send(ENTER),
        expect("Vault directory"),
        send(CTRL_U),
        send(b""),
        send(ENTER),
        expect("vault path must not be empty"),
        send(b"/a/../b"),
        send(ENTER),
        expect("invalid path (traversal detected)"),
        send(CTRL_U),
        send(custom.as_bytes()),
        send(ENTER),
        expect("Set vault passphrase"),
        send(PASS),
        send(ENTER),
        send(PASS),
        send(ENTER),
        skip_auth(),
        send(ENTER),
    ];
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply());
    vec![ctx.setup("vpath", &[], steps)]
}

/// Reconfigure a Go-initialized vault with git sync and multi-device, typing a
/// valid age recipient into the recipients step. Go's textarea is never
/// focused, so the text is dropped and no `recipients.txt` appears.
fn recipients_flow(ctx: &Ctx, label: &str, save: &[u8]) -> Vec<RunOutcome> {
    ctx.go_init();
    let mut steps = reconfigure_prefix();
    steps.extend([
        send(DOWN),
        send(ENTER),
        expect("Git remote URL"),
        send(b"https://example.invalid/v.git"),
        send(ENTER),
        expect("Auto-push on change?"),
        send(b"n"),
        expect("Multi-device setup"),
        send(UP),
        send(ENTER),
        expect("Additional recipients"),
        send(RECIPIENT.as_bytes()),
        send(save),
    ]);
    steps.extend(from_agents(vec![send(CTRL_U), send(b"work"), send(ENTER)]));
    steps.extend(tail_apply());
    vec![ctx.setup(label, &[], steps)]
}

fn existing_git_recipients_ctrl_s(ctx: &Ctx) -> Vec<RunOutcome> {
    recipients_flow(ctx, "existing_git_ctrl_s", CTRL_S)
}

fn existing_git_recipients_enter(ctx: &Ctx) -> Vec<RunOutcome> {
    // Enter on an unfocused (so blank) area saves immediately, like Go.
    recipients_flow(ctx, "existing_git_enter", ENTER)
}

fn existing_git_default(ctx: &Ctx) -> Vec<RunOutcome> {
    ctx.go_init();
    let mut steps = reconfigure_prefix();
    steps.extend([
        send(DOWN),
        send(ENTER),
        expect("Git remote URL"),
        send(b"ssh://git@example.invalid/v.git"),
        send(ENTER),
        expect("Auto-push on change?"),
        send(ENTER),
        expect("Multi-device setup"),
        send(ENTER),
    ]);
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply());
    vec![ctx.setup("existing_git_default", &[], steps)]
}

/// An aborted reconfigure leaves a resume file at the agents step.
fn abort_reconfigure(ctx: &Ctx) -> RunOutcome {
    let mut steps = reconfigure_prefix();
    steps.extend([
        send(ENTER),
        expect("AI agent configuration"),
        send(ESC),
        expect("Cancel setup?"),
        send(b"y"),
        Step::Exit,
    ]);
    ctx.setup("abort", &[], steps)
}

fn edit_resume(ctx: &Ctx, edit: impl FnOnce(String) -> String) {
    let path = ctx.the_resume_file();
    let text = fs::read_to_string(&path).expect("read resume file");
    fs::write(&path, edit(text)).expect("write resume file");
}

/// The wizard UI only ever picks the stdio transport; an HTTP agent can only
/// come from a saved resume file. Both sides then create the same scoped
/// token before the (always failing) installer is reached.
fn http_agent_resume(ctx: &Ctx) -> Vec<RunOutcome> {
    ctx.go_init();
    let aborted = abort_reconfigure(ctx);
    edit_resume(ctx, |text| {
        let mut text = text.replace("last_step: Sync Strategy", "last_step: Backup Plan");
        text.push_str(
            "selected_agents:\n    - agenttype: claude-code\n      transport: http\n      scope: '*'\n      readonly: true\n",
        );
        text
    });
    let mut steps = resume_then(vec![
        expect("Backup plan"),
        send(ENTER),
        expect("Vault profile name"),
        send(ENTER),
    ]);
    steps.extend(tail_apply());
    vec![aborted, ctx.setup("resume_http_agent", &[], steps)]
}

fn stale_resume(ctx: &Ctx) -> Vec<RunOutcome> {
    let aborted = ctx.setup("abort", &[], abort_at_agents(to_sync()));
    let file = fs::File::options()
        .write(true)
        .open(ctx.the_resume_file())
        .expect("open resume file");
    file.set_modified(SystemTime::now() - Duration::from_secs(25 * 3600))
        .expect("age the resume file");
    drop(file);
    vec![aborted, ctx.setup("stale_then_fresh", &[], happy_steps())]
}

fn corrupt_resume(ctx: &Ctx) -> Vec<RunOutcome> {
    let aborted = ctx.setup("abort", &[], abort_at_agents(to_sync()));
    fs::write(ctx.the_resume_file(), "vault_dir: [unterminated\n  : : :\n")
        .expect("corrupt the resume file");
    vec![aborted, ctx.setup("corrupt_then_fresh", &[], happy_steps())]
}

fn resume_no(ctx: &Ctx) -> Vec<RunOutcome> {
    let aborted = ctx.setup("abort", &[], abort_at_agents(to_sync()));
    let mut steps = vec![expect("Resume Previous Setup"), send(b"n")];
    // happy_steps minus its first screen (Welcome is consumed by the prompt)
    steps.extend(happy_steps().into_iter().skip(2));
    vec![aborted, ctx.setup("resume_no", &[], steps)]
}

/// A resume file carrying an invalid recipient: the pre-flight check fails,
/// the wizard stays on the summary and shows no error (Go quirk), and Go
/// reports the pre-flight error only when the user cancels.
fn preflight_failure(ctx: &Ctx) -> Vec<RunOutcome> {
    ctx.go_init();
    let aborted = abort_reconfigure(ctx);
    edit_resume(ctx, |text| {
        let mut text = text
            .replace("last_step: Sync Strategy", "last_step: Backup Plan")
            .replace("sync_mode: local", "sync_mode: git")
            .replace("multi_device: false", "multi_device: true");
        text.push_str("recipients:\n    - age1short\n");
        text
    });
    let steps = resume_then(vec![
        expect("Backup plan"),
        send(ENTER),
        expect("Vault profile name"),
        send(ENTER),
        expect("review your choices"),
        send(ENTER), // Apply -> pre-flight rejects age1short
        sleep(2000),
        send(ESC),
        expect("Cancel setup?"),
        send(b"y"),
        Step::Exit,
    ]);
    vec![aborted, ctx.setup("preflight", &[], steps)]
}

/// `vault.InitWithPassphrase` fails (`entries` is a regular file); Go ignores
/// the error of that apply step and reports success.
fn vault_init_failure(ctx: &Ctx) -> Vec<RunOutcome> {
    let vault = ctx.root.join("home/vv");
    fs::create_dir_all(&vault).expect("vault dir");
    fs::write(vault.join("entries"), "x").expect("blocking file");
    let mut steps = vec![
        expect("Welcome to Symaira Vault"),
        send(ENTER),
        expect("Vault directory"),
        send(CTRL_U),
        send(vault.to_string_lossy().as_bytes()),
        send(ENTER),
        expect("Set vault passphrase"),
        send(PASS),
        send(ENTER),
        send(PASS),
        send(ENTER),
        skip_auth(),
        send(ENTER),
    ];
    steps.extend(from_agents(vec![send(ENTER)]));
    steps.extend(tail_apply());
    vec![ctx.setup("init_failure", &[], steps)]
}

struct ScenarioDef {
    name: &'static str,
    run: Scenario,
    /// The scenario types a recipient that Go drops: no `recipients.txt`.
    no_recipients_file: bool,
}

const fn def(name: &'static str, run: Scenario) -> ScenarioDef {
    ScenarioDef {
        name,
        run,
        no_recipients_file: false,
    }
}

fn scenarios() -> Vec<ScenarioDef> {
    vec![
        def("happy", happy),
        def("no_resume", no_resume),
        def("abort_resume", abort_resume),
        def("abort_ctrlc", abort_ctrlc),
        def("abort_no_resume_flag", abort_no_resume_flag),
        def("esc_then_no", esc_then_no),
        def("bad_passphrase", bad_passphrase),
        def("agent_fail", agent_fail),
        def("agent_fail_keep", agent_fail_keep),
        def("profile_custom", profile_custom),
        def("profile_invalid", profile_invalid),
        def("git_sync", git_sync),
        def("git_multidevice", git_multidevice),
        def("go_back", go_back),
        def("summary_cancel", summary_cancel),
        def("existing_vault", existing_vault),
        def("existing_agent_fail", existing_agent_fail),
        def("vault_path_custom", vault_path_custom),
        ScenarioDef {
            no_recipients_file: true,
            ..def(
                "existing_git_recipients_ctrl_s",
                existing_git_recipients_ctrl_s,
            )
        },
        ScenarioDef {
            no_recipients_file: true,
            ..def(
                "existing_git_recipients_enter",
                existing_git_recipients_enter,
            )
        },
        def("existing_git_default", existing_git_default),
        def("http_agent_resume", http_agent_resume),
        def("stale_resume", stale_resume),
        def("corrupt_resume", corrupt_resume),
        def("resume_no", resume_no),
        def("preflight_failure", preflight_failure),
        def("vault_init_failure", vault_init_failure),
    ]
}

// ----------------------------------------------------------- recording ----

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SeedFile {
    path: String,
    kind: String,
    mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base64: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Recording {
    schema_version: u32,
    provenance: Provenance,
    /// The vault `go init` writes, so the replay needs no Go binary.
    vault_seed: Vec<SeedFile>,
    scenarios: Vec<ScenarioResult>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Provenance {
    oracle_commit: String,
    oracle_build: String,
    oracle_binary_sha256: String,
    generated_on: String,
    generator: String,
    comparison: Vec<String>,
    excluded: Vec<String>,
}

const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(BASE64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn decode_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for byte in text.bytes().filter(|b| *b != b'=') {
        let value = BASE64.iter().position(|c| *c == byte).expect("base64") as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// What `go init` leaves in the vault directory, with the sandbox root
/// replaced by a placeholder.
fn capture_seed(vault: &Path, roots: &Roots) -> Vec<SeedFile> {
    let mut files = vec![SeedFile {
        path: String::new(),
        kind: "dir".into(),
        mode: format!(
            "{:o}",
            fs::metadata(vault).expect("vault dir").permissions().mode() & 0o777
        ),
        text: None,
        base64: None,
    }];
    let mut stack = vec![vault.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .expect("read seed dir")
            .flatten()
            .collect();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            let rel = path
                .strip_prefix(vault)
                .expect("under vault")
                .to_string_lossy()
                .into_owned();
            let meta = fs::symlink_metadata(&path).expect("lstat");
            let mode = format!("{:o}", meta.permissions().mode() & 0o777);
            if meta.is_dir() {
                files.push(SeedFile {
                    path: rel,
                    kind: "dir".into(),
                    mode,
                    text: None,
                    base64: None,
                });
                stack.push(path);
            } else {
                let data = fs::read(&path).expect("read seed file");
                let (text, base64) = match String::from_utf8(data.clone()) {
                    Ok(text) if !data.starts_with(b"age-encryption.org") => {
                        let mut text = text;
                        for root in &roots.0 {
                            text = text.replace(root.as_str(), "<ROOT>");
                        }
                        (Some(text), None)
                    }
                    _ => (None, Some(encode_base64(&data))),
                };
                files.push(SeedFile {
                    path: rel,
                    kind: "file".into(),
                    mode,
                    text,
                    base64,
                });
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

// -------------------------------------------------------------- driver ----

fn oracle_path() -> Option<PathBuf> {
    let go = PathBuf::from(env::var_os("SYMVAULT_GO_BINARY")?);
    assert!(
        go.is_file(),
        "SYMVAULT_GO_BINARY is set but {} is not a file",
        go.display()
    );
    Some(go)
}

fn rust_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_symvault"))
}

/// Runs the Go binary on a copy of the left-behind vault to prove interop.
fn go_open_check(go: &Path, ctx: &Ctx) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let roots = Roots::of(&ctx.root);
    let mut vaults = Vec::new();
    let mut stack = vec![ctx.root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(&ctx.root).expect("under root").to_owned();
            if top_level_skipped(&rel.to_string_lossy()) {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|name| name == "identity.age")
                && path.with_file_name("config.yaml").is_file()
            {
                vaults.push(path.parent().expect("parent").to_owned());
            }
        }
    }
    vaults.sort();
    for vault in vaults {
        let copy = tempfile::tempdir().expect("copy dir");
        copy_tree(&vault, &copy.path().join("vault"));
        let home = copy.path().join("home");
        fs::create_dir_all(&home).expect("home");
        let output = Command::new(go)
            .args(["--vault"])
            .arg(copy.path().join("vault"))
            .arg("list")
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("CI", "1")
            .env(
                "SYMVAULT_PASSPHRASE",
                String::from_utf8_lossy(PASS).as_ref(),
            )
            .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
            .stdin(Stdio::null())
            .output()
            .expect("run go list");
        let key = vault
            .strip_prefix(&ctx.root)
            .expect("under root")
            .to_string_lossy()
            .into_owned();
        out.insert(
            key,
            format!(
                "exit={:?} stdout={:?}",
                output.status.code(),
                roots.text(&String::from_utf8_lossy(&output.stdout))
            ),
        );
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("copy dir");
    for entry in fs::read_dir(from).expect("read dir").flatten() {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

fn run_scenario(
    def: &ScenarioDef,
    binary: &Path,
    go: Option<&Path>,
    open_check_with: Option<&Path>,
    seed: &[SeedFile],
) -> ScenarioResult {
    let dir = tempfile::Builder::new()
        .prefix("symvault-setup-diff-")
        .tempdir()
        .expect("sandbox");
    let ctx = Ctx {
        binary,
        go,
        seed,
        root: dir.path().to_owned(),
    };
    ctx.make_dirs();
    let runs = (def.run)(&ctx);
    let roots = Roots::of(&ctx.root);
    let manifest = manifest(&ctx.root, &roots);
    let go_opens_vault = open_check_with
        .map(|go| go_open_check(go, &ctx))
        .unwrap_or_default();
    if def.no_recipients_file {
        assert!(
            !manifest.keys().any(|key| key.ends_with("recipients.txt")),
            "{}: a typed recipient reached recipients.txt",
            def.name
        );
    }
    ScenarioResult {
        name: def.name.to_owned(),
        runs,
        manifest,
        go_opens_vault,
    }
}

/// Runs every scenario with `PARALLEL` worker threads, in definition order.
fn run_all(
    binary: &Path,
    go: Option<&Path>,
    open_check_with: Option<&Path>,
    seed: &[SeedFile],
) -> Vec<ScenarioResult> {
    let defs = scenarios();
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<ScenarioResult>>> = Mutex::new(vec![None; defs.len()]);
    thread::scope(|scope| {
        for _ in 0..PARALLEL {
            scope.spawn(|| {
                loop {
                    let index = {
                        let mut next = next.lock().expect("lock");
                        let index = *next;
                        *next += 1;
                        index
                    };
                    let Some(def) = defs.get(index) else { break };
                    let result = run_scenario(def, binary, go, open_check_with, seed);
                    results.lock().expect("lock")[index] = Some(result);
                }
            });
        }
    });
    results
        .into_inner()
        .expect("lock")
        .into_iter()
        .map(|result| result.expect("every scenario ran"))
        .collect()
}

/// Every run must have reached every scripted screen and exited on its own.
fn unreached(results: &[ScenarioResult], label: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for result in results {
        for run in &result.runs {
            if !run.ok || (run.exit_code.is_none() && run.signal.is_none()) {
                problems.push(format!(
                    "{label} {}/{}: ok={} failed={:?} exit={:?} signal={:?} post_tui={:?}",
                    result.name,
                    run.label,
                    run.ok,
                    run.failed,
                    run.exit_code,
                    run.signal,
                    run.post_tui
                ));
            }
        }
    }
    problems
}

fn load_recording() -> Recording {
    let raw = fs::read_to_string(RECORDING).expect("read setup-wizard recording");
    let recording: Recording = serde_json::from_str(&raw).expect("parse setup-wizard recording");
    assert_eq!(recording.schema_version, 1);
    recording
}

fn assert_recording_shape(recording: &Recording) {
    assert!(
        recording.scenarios.len() >= MIN_SCENARIOS,
        "recording holds only {} scenarios",
        recording.scenarios.len()
    );
    let defs = scenarios();
    assert_eq!(
        recording
            .scenarios
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        defs.iter().map(|d| d.name).collect::<Vec<_>>(),
        "the recording and the scenario list differ; re-record"
    );
    assert_eq!(recording.provenance.oracle_commit.len(), 40);
    assert!(recording.provenance.oracle_build.contains("CGO_ENABLED=0"));
}

fn report(label: &str, diffs: &[String], executed: usize) {
    eprintln!(
        "setup wizard differential ({label}): {executed} scenarios executed, {} differences",
        diffs.len()
    );
    for diff in diffs {
        eprintln!("  DIFF {diff}");
    }
}

// --------------------------------------------------------------- tests ----

#[test]
fn native_matches_live_go_oracle() {
    let Some(go) = oracle_path() else {
        eprintln!("skipping live Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust = rust_binary();
    let go_results = run_all(&go, Some(&go), Some(&go), &[]);
    let rust_results = run_all(&rust, Some(&go), Some(&go), &[]);

    assert!(
        go_results.len() >= MIN_SCENARIOS && go_results.len() == rust_results.len(),
        "executed {} Go and {} Rust scenarios, need at least {MIN_SCENARIOS}",
        go_results.len(),
        rust_results.len()
    );
    let mut problems = unreached(&go_results, "go");
    problems.extend(unreached(&rust_results, "rust"));
    let mut rust_results = rust_results;
    assert_known_divergences_observed(&apply_known_divergences(&go_results, &mut rust_results));
    let mut diffs = Vec::new();
    for (g, r) in go_results.iter().zip(&rust_results) {
        diffs.extend(diff_results("go", g, "rust", r));
    }
    // The vault the wizard leaves must open with Go in at least one scenario.
    let opened = go_results
        .iter()
        .flat_map(|result| result.go_opens_vault.values())
        .filter(|outcome| outcome.starts_with("exit=Some(0)"))
        .count();
    assert!(
        opened >= 8,
        "only {opened} left-behind vaults opened with Go"
    );

    if cfg!(target_os = "macos") && Path::new(RECORDING).is_file() {
        // The recording must not be stale against the live oracle.
        let recording = load_recording();
        assert_recording_shape(&recording);
        for (live, recorded) in go_results.iter().zip(&recording.scenarios) {
            let mut recorded = recorded.clone();
            // The recording is made without the open check's live Go binary
            // only when absent; compare the rest verbatim.
            recorded.go_opens_vault = live.go_opens_vault.clone();
            diffs.extend(diff_results("live-go", live, "recorded-go", &recorded));
        }
    }
    report("live", &diffs, go_results.len());
    for problem in &problems {
        eprintln!("  UNREACHED {problem}");
    }
    assert!(
        problems.is_empty(),
        "scripted screens not reached:\n{}",
        problems.join("\n")
    );
    assert!(
        diffs.is_empty(),
        "{} differences:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

#[test]
fn native_matches_recorded_go_results() {
    if !cfg!(target_os = "macos") {
        eprintln!("skipping recorded replay: the recording was made on darwin");
        return;
    }
    let recording = load_recording();
    assert_recording_shape(&recording);
    let rust = rust_binary();
    let results = run_all(&rust, None, None, &recording.vault_seed);
    assert_eq!(results.len(), recording.scenarios.len());
    let problems = unreached(&results, "rust");
    let mut recorded: Vec<ScenarioResult> = recording.scenarios.clone();
    // The open check needs the Go binary; the replay has none.
    recorded.iter_mut().for_each(|r| r.go_opens_vault.clear());
    let mut results = results;
    assert_known_divergences_observed(&apply_known_divergences(&recorded, &mut results));
    let mut diffs = Vec::new();
    for (rust, recorded) in results.iter().zip(&recorded) {
        diffs.extend(diff_results("recorded-go", recorded, "rust", rust));
    }
    report("replay", &diffs, results.len());
    assert!(
        problems.is_empty(),
        "scripted screens not reached:\n{}",
        problems.join("\n")
    );
    assert!(
        diffs.is_empty(),
        "{} differences:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// Rewrites the recording from the live Go oracle:
/// `SYMVAULT_GO_BINARY=... SYMVAULT_GO_ORACLE_COMMIT=<40 hex> \
///  SYMVAULT_GO_ORACLE_BUILD='go1.26.10 CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 -trimpath' \
///  cargo test -p symvault-cli --test setup_wizard_differential -- --ignored record_go_results`
#[test]
#[ignore = "rewrites testdata/port/cli/setup-wizard/go-results.json"]
fn record_go_results() {
    let go = oracle_path().expect("SYMVAULT_GO_BINARY");
    let commit = env::var("SYMVAULT_GO_ORACLE_COMMIT").expect("SYMVAULT_GO_ORACLE_COMMIT");
    assert!(
        commit.len() == 40 && commit.bytes().all(is_hex),
        "oracle commit must be 40 hex digits"
    );
    let build = env::var("SYMVAULT_GO_ORACLE_BUILD").expect("SYMVAULT_GO_ORACLE_BUILD");
    assert!(
        build.contains("CGO_ENABLED=0"),
        "the oracle must be a no-cgo build"
    );

    // A Go-initialized vault, captured once.
    let seed_dir = tempfile::tempdir().expect("seed dir");
    let seed_ctx = Ctx {
        binary: &go,
        go: Some(&go),
        seed: &[],
        root: seed_dir.path().to_owned(),
    };
    seed_ctx.make_dirs();
    seed_ctx.go_init();
    let seed = capture_seed(&seed_ctx.vault_dir(), &Roots::of(&seed_ctx.root));

    let mut scenarios = run_all(&go, Some(&go), Some(&go), &[]);
    let problems = unreached(&scenarios, "go");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    for scenario in &mut scenarios {
        scenario.go_opens_vault.clear();
    }
    let recording = Recording {
        schema_version: 1,
        provenance: Provenance {
            oracle_commit: commit,
            oracle_build: build,
            oracle_binary_sha256: hex::encode(Sha256::digest(fs::read(&go).expect("read oracle"))),
            generated_on: "darwin".to_owned(),
            generator: "crates/symvault-cli/tests/setup_wizard_differential.rs record_go_results".to_owned(),
            comparison: vec![
                "exit code and signal of every run".into(),
                "every scripted screen reached (ok) and the screens that were not".into(),
                "text printed after the alternate-screen exit (stdout and stderr share the PTY), ANSI-stripped".into(),
                "sandbox file manifest: path, kind, mode, normalized text or size".into(),
            ],
            excluded: vec![
                "TUI frames and every byte written inside the alternate screen".into(),
                "Go panic goroutine dump".into(),
                "Touch ID (no-cgo oracle cannot see biometrics)".into(),
                "git internals except HEAD and config; cwd and tmp".into(),
                "normalized: timestamps, token ids, hashes, prefixes, tool_registry_hash, age public keys, resume file name hashes, sandbox root".into(),
            ],
        },
        vault_seed: seed,
        scenarios,
    };
    let mut text = serde_json::to_string_pretty(&recording).expect("serialize");
    text.push('\n');
    fs::create_dir_all(Path::new(RECORDING).parent().expect("dir")).expect("create dir");
    fs::write(RECORDING, text).expect("write recording");
}

// ---------------------------------------------- self-tests (no Go needed) --

fn sh(script: &str, steps: &[Step], timeout: Duration) -> RunResult {
    let dir = tempfile::tempdir().expect("cwd");
    run_pty(
        Path::new("/bin/sh"),
        &["-c".to_owned(), script.to_owned()],
        &[("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        dir.path(),
        steps,
        timeout,
    )
}

#[test]
fn pty_driver_sends_keys_and_captures_exit_code_and_output() {
    let result = sh(
        "printf 'name? '; read x; printf 'got:%s\\n' \"$x\"; exit 3",
        &[expect("name?"), send(b"hi\r"), expect("got:hi"), Step::Exit],
        Duration::from_secs(20),
    );
    assert!(result.ok, "{:?}", result.failed);
    assert_eq!(result.exit_code, Some(3));
    assert_eq!(result.signal, None);
    assert!(strip_ansi(&result.raw).contains("got:hi"));
}

#[test]
fn pty_driver_reports_signals_and_missed_screens() {
    let result = sh("kill -9 $$", &[Step::Exit], Duration::from_secs(20));
    assert!(result.ok);
    assert_eq!(result.exit_code, None);
    assert_eq!(result.signal, Some(9));

    // A missed screen is reported and the runaway child is killed.
    let result = sh(
        "sleep 30",
        &[expect("never printed")],
        Duration::from_millis(600),
    );
    assert!(!result.ok);
    assert!(result.failed.iter().any(|f| f.contains("never printed")));
    assert!(result.failed.iter().any(|f| f.contains("killed")));
}

#[test]
fn pty_driver_either_takes_the_first_screen_that_shows_up() {
    let result = sh(
        "printf 'second\\n'; read x; printf 'saw:%s\\n' \"$x\"",
        &[
            Step::Either(vec![
                ("first", vec![send(b"1\r")]),
                ("second", vec![send(b"2\r"), expect("saw:2")]),
            ]),
            Step::Exit,
        ],
        Duration::from_secs(20),
    );
    assert!(result.ok, "{:?}", result.failed);
    assert_eq!(result.exit_code, Some(0));
}

#[test]
fn post_tui_text_is_what_follows_the_last_alternate_screen_exit() {
    let roots = Roots(vec!["/tmp/sandbox".to_owned()]);
    let raw = b"\x1b[?1049hframe\x1b[?1049l\x1b[?25hError: x /tmp/sandbox/v\r\nError: x\r\n";
    assert_eq!(post_tui_text(raw, &roots), "Error: x <ROOT>/v\nError: x\n");
    assert_eq!(
        post_tui_text(b"no tui", &roots),
        "<no alternate-screen exit>"
    );
    // Go's panic goroutine dump is cut up to the final error lines.
    let panic = b"\x1b[?1049lCaught panic:\r\n\r\ngoroutine 1 [running]:\r\n\tframe +0x1\r\nError: wizard: killed\r\n";
    assert_eq!(
        post_tui_text(panic, &roots),
        "Caught panic:\n\nError: wizard: killed\n"
    );
}

#[test]
fn normalizers_replace_only_the_volatile_parts() {
    let roots = Roots(vec!["/r".to_owned()]);
    let text = r#"{"id": "tok-20261101-0cd66290", "hash": "72f4989567d175c93b7a21d0cb2ef5d753135ed181656a6d1204cee6c34fc75f", "prefix": "e572", "tool_registry_hash": "bccf8c7e8660328030bc4e9bbc0c0d43a650278bae4b8ef60d5543d64c46455d", "at": "2026-11-01T23:46:25.542275Z", "p": "/r/v", "k": "age10jtjwy0k55eajndnwtvujmy4rhdfa7rt88r6v98ltefw0sdvddksrruz0j", "short": "age1abc", "keep": "hash"}"#;
    let out = roots.text(text);
    assert_eq!(
        out,
        r#"{"id": "<TOKID>", "hash": "<HASH>", "prefix": "<PFX>", "tool_registry_hash": "<REGISTRY-HASH>", "at": "<TS>", "p": "<ROOT>/v", "k": "<AGE1>", "short": "age1abc", "keep": "hash"}"#
    );
    // A 63-digit hash is not a hash and stays visible.
    let odd = r#""hash": "72f4989567d175c93b7a21d0cb2ef5d753135ed181656a6d1204cee6c34fc75""#;
    assert_eq!(roots.text(odd), odd);
    assert_eq!(
        normalized_name("home/Library/Caches/symaira/wizard/dd0c9b994e60f5e0.yaml"),
        "home/Library/Caches/symaira/wizard/<RESUME>.yaml"
    );
    assert_eq!(
        normalized_name("xdg/data/x/dd0c9b994e60f5e0.yaml"),
        "xdg/data/x/dd0c9b994e60f5e0.yaml"
    );
    assert_eq!(
        decode_base64(&encode_base64(b"\x00\x01age\xff\xfe!")),
        b"\x00\x01age\xff\xfe!"
    );
}

fn sample_result() -> ScenarioResult {
    let mut manifest = BTreeMap::new();
    manifest.insert(
        "xdg/data/symaira-vault/config.yaml".to_owned(),
        ManifestEntry {
            kind: "file".into(),
            mode: Some("600".into()),
            size: None,
            text: Some("vaultDir: <ROOT>/v\n".into()),
            link: None,
        },
    );
    ScenarioResult {
        name: "sample".into(),
        runs: vec![RunOutcome {
            label: "run1".into(),
            ok: true,
            exit_code: Some(0),
            signal: None,
            failed: vec![],
            post_tui: "Error: x\n".into(),
        }],
        manifest,
        go_opens_vault: BTreeMap::from([("v".to_owned(), "exit=Some(0) stdout=\"\"".to_owned())]),
    }
}

/// Negative controls: the comparator must flag a change in every field it
/// claims to compare, and nothing when nothing changed.
#[test]
fn comparator_flags_every_compared_field() {
    let base = sample_result();
    assert!(diff_results("a", &base, "b", &base.clone()).is_empty());

    type Mutation = Box<dyn Fn(&mut ScenarioResult)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        ("exit code", Box::new(|r| r.runs[0].exit_code = Some(1))),
        ("signal", Box::new(|r| r.runs[0].signal = Some(9))),
        ("ok", Box::new(|r| r.runs[0].ok = false)),
        (
            "failed screens",
            Box::new(|r| r.runs[0].failed.push("expect x".into())),
        ),
        (
            "post-TUI text",
            Box::new(|r| r.runs[0].post_tui.push_str("Error: y\n")),
        ),
        ("run label", Box::new(|r| r.runs[0].label = "other".into())),
        ("run count", Box::new(|r| r.runs.push(r.runs[0].clone()))),
        (
            "file mode",
            Box::new(|r| {
                r.manifest
                    .values_mut()
                    .for_each(|e| e.mode = Some("644".into()))
            }),
        ),
        (
            "file text",
            Box::new(|r| {
                r.manifest
                    .values_mut()
                    .for_each(|e| e.text = Some("vaultDir: x\n".into()))
            }),
        ),
        (
            "extra file",
            Box::new(|r| {
                r.manifest.insert(
                    "xdg/data/symaira-vault/recipients.txt".into(),
                    ManifestEntry {
                        kind: "file".into(),
                        mode: Some("600".into()),
                        size: None,
                        text: Some("age1x\n".into()),
                        link: None,
                    },
                );
            }),
        ),
        ("missing file", Box::new(|r| r.manifest.clear())),
        ("go open check", Box::new(|r| r.go_opens_vault.clear())),
    ];
    for (label, mutate) in mutations {
        let mut other = base.clone();
        mutate(&mut other);
        assert!(
            !diff_results("go", &base, "rust", &other).is_empty(),
            "a changed {label} was not detected"
        );
    }
}

#[test]
fn scenario_list_meets_the_minimum_and_names_are_unique() {
    let defs = scenarios();
    assert!(defs.len() >= MIN_SCENARIOS, "{} scenarios", defs.len());
    let names: std::collections::BTreeSet<&str> = defs.iter().map(|d| d.name).collect();
    assert_eq!(names.len(), defs.len());
    for required in [
        "existing_git_recipients_ctrl_s",
        "http_agent_resume",
        "stale_resume",
        "corrupt_resume",
        "resume_no",
        "preflight_failure",
        "vault_init_failure",
    ] {
        assert!(names.contains(required), "{required} is missing");
    }
}

#[test]
fn only_the_git_cli_defaults_are_accepted_in_the_git_config() {
    let go = "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = u\n";
    let rust = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n\tignorecase = true\n\tprecomposeunicode = true\n[user]\n\tname = Symaira Vault\n\temail = symvault@example.com\n[remote \"origin\"]\n\turl = u\n";
    assert!(accepted_git_config_divergence(go, rust));
    // equal files are no divergence; any other change is not accepted
    assert!(!accepted_git_config_divergence(go, go));
    assert!(!accepted_git_config_divergence(
        go,
        &rust.replace("url = u", "url = other")
    ));
    assert!(!accepted_git_config_divergence(
        go,
        &rust.replace("Symaira Vault", "Someone")
    ));
    assert!(!accepted_git_config_divergence(
        go,
        &format!("{rust}[extra]\n\tk = v\n")
    ));
}

#[test]
fn token_files_compare_independent_of_random_key_order() {
    let a = r#"{"version":2,"tokens":{"tok-20261101-0000000a":{"id":"tok-20261101-0000000a","label":"b"},"tok-20261101-0000000b":{"id":"tok-20261101-0000000b","label":"a"}}}"#;
    let b = r#"{"version":2,"tokens":{"tok-20261101-0000000c":{"id":"tok-20261101-0000000c","label":"a"},"tok-20261101-0000000d":{"id":"tok-20261101-0000000d","label":"b"}}}"#;
    let roots = Roots(vec![]);
    let na = roots.text(&order_tokens(a));
    assert_eq!(na, roots.text(&order_tokens(b)));
    // a changed label or scope still differs
    assert_ne!(na, roots.text(&order_tokens(&a.replace("\"b\"", "\"c\""))));
}
