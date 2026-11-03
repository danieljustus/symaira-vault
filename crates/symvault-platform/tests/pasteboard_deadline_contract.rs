#![cfg(unix)]

//! PLATFORM-001-FIDELITY review fix: the macOS pasteboard tools run under a
//! deadline again. Real fake `pbcopy`/`pbpaste` processes (POSIX shell scripts
//! on a disposable PATH) that sleep, never read or never exit are driven
//! through the production `PasteboardClipboard` over a `SystemHost` with a
//! short injected timeout (the real host uses `PASTEBOARD_TIMEOUT`, 30 s).
//! Every call must return within a bound, kill the tool's whole process group,
//! reap it (no zombie: `kill(pid, 0)` says `ESRCH`) and keep the secret off
//! argv and out of the tool's environment. Normal paths keep Go's texts.
//!
//! Each call runs on a helper thread behind a guard, so a missing deadline
//! fails the test by the guard instead of hanging the test run.

use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use symvault_platform::Clipboard;
use symvault_platform::desktop_commands::{PASTEBOARD_TIMEOUT, PasteboardClipboard, SystemHost};

const TIMEOUT: Duration = Duration::from_millis(400);
/// A bounded call must come back long before this; the guard fails the test
/// (instead of hanging it) when it does not.
const GUARD: Duration = Duration::from_secs(8);
const SECRET: &str = "pb-deadline-secret-9d41";

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "symvault-pb-deadline-{name}-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        let dir = PathBuf::from(dir.to_string_lossy().replace(['(', ')', ' '], ""));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        Self(dir)
    }

    fn bin(&self) -> PathBuf {
        self.0.join("bin")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn tool(&self, name: &str, body: &str) {
        let path = self.bin().join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn clipboard(
        &self,
        timeout: Option<Duration>,
        extra_env: &[(&str, &str)],
    ) -> PasteboardClipboard {
        let mut env = HashMap::from([
            // The scripts need the system tools; only `bin` is searched for
            // `pbcopy`/`pbpaste`.
            (
                "PATH".to_owned(),
                format!("{}:/usr/bin:/bin", self.bin().to_str().unwrap()),
            ),
            ("HOME".to_owned(), self.0.to_str().unwrap().to_owned()),
        ]);
        for (key, value) in extra_env {
            env.insert((*key).to_owned(), (*value).to_owned());
        }
        let host = SystemHost::isolated(vec![self.bin()], env);
        let host = match timeout {
            Some(timeout) => host.with_timeout(timeout),
            None => host,
        };
        PasteboardClipboard::new(Arc::new(host))
    }

    fn pid(&self, name: &str) -> i32 {
        // The tool writes its pid before it blocks; wait for it.
        let path = self.file(name);
        let start = Instant::now();
        loop {
            if let Ok(text) = fs::read_to_string(&path)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            assert!(start.elapsed() < GUARD, "tool never wrote {name}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Safety net: never leave a sleeping fake tool behind.
        for name in ["pid", "grandchild"] {
            if let Ok(text) = fs::read_to_string(self.file(name))
                && let Ok(pid) = text.trim().parse::<i32>()
                && let Some(pid) = rustix::process::Pid::from_raw(pid)
            {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn gone(pid: i32) -> bool {
    let pid = rustix::process::Pid::from_raw(pid).expect("positive pid");
    matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

/// `kill(pid, 0)` is `ESRCH` only once the process is reaped (a zombie still
/// answers), so this is the no-zombie check.
fn assert_reaped(pid: i32, what: &str) {
    let start = Instant::now();
    while !gone(pid) {
        assert!(
            start.elapsed() < GUARD,
            "{what} (pid {pid}) is still there: not killed or not reaped"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Runs `call` on a helper thread; fails (rather than hangs) after `GUARD`.
fn guarded<T: Send + 'static>(
    sandbox: &Sandbox,
    call: impl FnOnce() -> T + Send + 'static,
) -> (T, Duration) {
    let (tx, rx) = mpsc::channel();
    let start = Instant::now();
    std::thread::spawn(move || {
        let _ = tx.send(call());
    });
    match rx.recv_timeout(GUARD) {
        Ok(value) => (value, start.elapsed()),
        Err(_) => {
            // Do not leave the hung tool behind before failing.
            drop(Sandbox(sandbox.0.clone()));
            panic!("DEADLINE GUARD: the pasteboard call did not return within {GUARD:?}");
        }
    }
}

fn copy_error(clipboard: PasteboardClipboard, payload: Vec<u8>) -> String {
    clipboard.set(&payload).expect_err("must fail").message
}

#[test]
fn real_host_is_bounded_by_the_documented_default() {
    assert_eq!(PASTEBOARD_TIMEOUT, Duration::from_secs(30));
}

#[test]
fn pbcopy_that_never_reads_a_large_payload_is_killed_and_reaped() {
    let sandbox = Sandbox::new("noread");
    sandbox.tool(
        "pbcopy",
        &format!(
            "echo $$ > '{}'\nexec sleep 120",
            sandbox.file("pid").display()
        ),
    );
    let clipboard = sandbox.clipboard(Some(TIMEOUT), &[]);
    // Far above any pipe buffer: the write blocks for ever without a deadline.
    let payload = vec![b'x'; 8 * 1024 * 1024];
    let (error, took) = guarded(&sandbox, move || copy_error(clipboard, payload));
    assert_eq!(error, "signal: killed");
    assert!(took >= TIMEOUT, "returned before the deadline: {took:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
    assert_reaped(sandbox.pid("pid"), "pbcopy");
}

#[test]
fn pbcopy_that_reads_everything_but_never_exits_is_killed_and_reaped() {
    let sandbox = Sandbox::new("noexit");
    sandbox.tool(
        "pbcopy",
        &format!(
            "echo $$ > '{}'\ncat > /dev/null\nexec sleep 120",
            sandbox.file("pid").display()
        ),
    );
    let clipboard = sandbox.clipboard(Some(TIMEOUT), &[]);
    let (error, took) = guarded(&sandbox, move || {
        copy_error(clipboard, SECRET.as_bytes().to_vec())
    });
    assert_eq!(error, "signal: killed");
    assert!(
        took >= TIMEOUT && took < Duration::from_secs(5),
        "took {took:?}"
    );
    assert_reaped(sandbox.pid("pid"), "pbcopy");
}

#[test]
fn pbcopy_that_sleeps_before_reading_is_killed_and_the_whole_group_dies() {
    let sandbox = Sandbox::new("group");
    // The shell forks a grandchild that holds stdin; only a group kill ends it.
    sandbox.tool(
        "pbcopy",
        &format!(
            "echo $$ > '{pid}'\nsleep 120 &\necho $! > '{gc}'\nwait",
            pid = sandbox.file("pid").display(),
            gc = sandbox.file("grandchild").display()
        ),
    );
    let clipboard = sandbox.clipboard(Some(TIMEOUT), &[]);
    let (error, _) = guarded(&sandbox, move || {
        copy_error(clipboard, vec![b'y'; 4 * 1024 * 1024])
    });
    assert_eq!(error, "signal: killed");
    assert_reaped(sandbox.pid("pid"), "pbcopy");
    assert_reaped(sandbox.pid("grandchild"), "pbcopy's child process");
}

#[test]
fn clear_with_a_hung_pbcopy_returns_too() {
    // Auto-clear is `set(b"")`; the empty write must not skip the deadline.
    let sandbox = Sandbox::new("clear");
    sandbox.tool(
        "pbcopy",
        &format!(
            "echo $$ > '{}'\nexec sleep 120",
            sandbox.file("pid").display()
        ),
    );
    let clipboard = sandbox.clipboard(Some(TIMEOUT), &[]);
    let (error, took) = guarded(&sandbox, move || {
        clipboard.clear().expect_err("must fail").message
    });
    assert_eq!(error, "signal: killed");
    assert!(took < Duration::from_secs(5), "took {took:?}");
    assert_reaped(sandbox.pid("pid"), "pbcopy");
}

#[test]
fn pbpaste_that_never_exits_is_killed_and_reaped() {
    let sandbox = Sandbox::new("paste");
    sandbox.tool(
        "pbpaste",
        &format!(
            "echo $$ > '{}'\nprintf partial\nexec sleep 120",
            sandbox.file("pid").display()
        ),
    );
    let clipboard = sandbox.clipboard(Some(TIMEOUT), &[]);
    let (error, took) = guarded(&sandbox, move || {
        clipboard.read().expect_err("must fail").message
    });
    assert_eq!(error, "signal: killed");
    assert!(
        took >= TIMEOUT && took < Duration::from_secs(5),
        "took {took:?}"
    );
    assert_reaped(sandbox.pid("pid"), "pbpaste");
}

#[test]
fn a_stdout_holder_that_outlives_pbpaste_is_bounded() {
    // pbpaste exits, a background child keeps the pipe open: Go's `Output`
    // would wait for it; the deadline ends it and kills the group.
    let sandbox = Sandbox::new("holder");
    sandbox.tool(
        "pbpaste",
        &format!(
            "sleep 120 &\necho $! > '{}'\necho $$ > '{}'\nprintf text",
            sandbox.file("grandchild").display(),
            sandbox.file("pid").display()
        ),
    );
    let clipboard = sandbox.clipboard(Some(TIMEOUT), &[]);
    let (error, took) = guarded(&sandbox, move || {
        clipboard.read().expect_err("must fail").message
    });
    assert_eq!(error, "signal: killed");
    assert!(took < Duration::from_secs(5), "took {took:?}");
    assert_reaped(sandbox.pid("pid"), "pbpaste");
    assert_reaped(sandbox.pid("grandchild"), "pbpaste's child process");
}

#[test]
fn a_failed_stdin_write_keeps_go_text_and_the_lingering_tool_is_reaped() {
    let sandbox = Sandbox::new("epipe");
    // Closes stdin without reading, then lives on: Go returns the write error
    // and leaks the process; Rust returns the same text and reaps at the
    // deadline.
    sandbox.tool(
        "pbcopy",
        &format!(
            "echo $$ > '{}'\nexec 0<&-\nexec sleep 120",
            sandbox.file("pid").display()
        ),
    );
    let clipboard = sandbox.clipboard(Some(TIMEOUT), &[]);
    let (error, took) = guarded(&sandbox, move || {
        copy_error(clipboard, vec![b'z'; 4 * 1024 * 1024])
    });
    assert_eq!(error, "write |1: broken pipe");
    assert!(took < TIMEOUT, "must not wait for the tool: {took:?}");
    assert_reaped(sandbox.pid("pid"), "pbcopy after a write failure");
}

#[test]
fn normal_paths_keep_go_texts_under_a_deadline() {
    let sandbox = Sandbox::new("normal");
    sandbox.tool("pbcopy", "cat > /dev/null\nexit 3");
    sandbox.tool("pbpaste", "printf 'clip text'");
    let clipboard = sandbox.clipboard(Some(Duration::from_secs(20)), &[]);
    assert_eq!(
        clipboard.set(SECRET.as_bytes()).unwrap_err().message,
        "exit status 3"
    );
    assert_eq!(clipboard.read().unwrap(), b"clip text");

    sandbox.tool("pbcopy", "cat > /dev/null");
    clipboard.set(SECRET.as_bytes()).unwrap();
    clipboard.clear().unwrap();

    sandbox.tool("pbcopy", "kill -TERM $$");
    assert_eq!(
        clipboard.set(b"x").unwrap_err().message,
        "signal: terminated"
    );

    fs::remove_file(sandbox.bin().join("pbcopy")).unwrap();
    assert_eq!(
        clipboard.set(b"x").unwrap_err().message,
        "exec: \"pbcopy\": executable file not found in $PATH"
    );

    // A closed stdin on a payload above the pipe buffer, tool exits 0.
    sandbox.tool("pbcopy", "exec 0<&-\nexit 0");
    assert_eq!(
        clipboard
            .set(&vec![b'x'; 4 * 1024 * 1024])
            .unwrap_err()
            .message,
        "write |1: broken pipe"
    );
}

#[test]
fn the_secret_reaches_the_tool_on_stdin_only() {
    let sandbox = Sandbox::new("leak");
    sandbox.tool(
        "pbcopy",
        &format!(
            "printf '%s\\n' \"$@\" > '{argv}'\nenv > '{env}'\ncat > '{stdin}'",
            argv = sandbox.file("argv").display(),
            env = sandbox.file("env").display(),
            stdin = sandbox.file("stdin").display()
        ),
    );
    // Decoys stand for the credential-bearing environment of the CLI process.
    let clipboard = sandbox.clipboard(
        Some(Duration::from_secs(20)),
        &[
            ("LANG", "en_US.UTF-8"),
            ("LC_ALL", "en_US.UTF-8"),
            ("SYMVAULT_PASSWORD", "decoy-password"),
            ("AWS_SECRET_ACCESS_KEY", "decoy-aws"),
            ("SSH_AUTH_SOCK", "/tmp/decoy-agent"),
        ],
    );
    clipboard.set(SECRET.as_bytes()).unwrap();
    assert_eq!(fs::read_to_string(sandbox.file("stdin")).unwrap(), SECRET);
    assert!(
        fs::read_to_string(sandbox.file("argv"))
            .unwrap()
            .trim()
            .is_empty(),
        "argv must be empty"
    );
    let env = fs::read_to_string(sandbox.file("env")).unwrap();
    assert!(!env.contains(SECRET), "secret in the tool environment");
    for decoy in [
        "SYMVAULT_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "decoy",
    ] {
        assert!(!env.contains(decoy), "{decoy} reached pbcopy:\n{env}");
    }
    for kept in ["PATH=", "HOME=", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"] {
        assert!(env.contains(kept), "{kept} missing:\n{env}");
    }
}
