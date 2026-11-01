//! Drives the real `symvault add` binary through a pseudo-terminal, so the
//! interactive form runs exactly as it does for a person. Expected entries come
//! from the Go oracle (see the PTY differential recorded with this port).
//!
//! The only `unsafe` here is the libc plumbing that creates the pty pair and
//! makes it the child's controlling terminal; every call is checked.
#![cfg(unix)]
#![allow(unsafe_code)]

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_symvault");
const PASSPHRASE: &str = "Tr0ub4dor&3-xyz-correct";
const STRONG: &str = "Xk9#mP2$vL7qZ!aaBB";
const TOTP: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEH";
const TAB: &str = "\t";
const ENTER: &str = "\r";
const CTRL_C: &str = "\x03";

fn command(root: &Path) -> Command {
    let home = root.join("h");
    let mut command = Command::new(BIN);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".data"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .env("TMPDIR", root)
        .env("TERM", "xterm-256color")
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_NO_ENV_WARNING", "1")
        .current_dir(root);
    command
}

fn init_vault() -> test_temp_root::TempRoot {
    let root = test_temp_root::TempRoot::existing("symvault-addform-");
    std::fs::create_dir_all(root.join("h")).unwrap();
    let output = command(&root).arg("init").output().unwrap();
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    root
}

fn strip_ansi(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.next() {
                Some('[') => {
                    for n in chars.by_ref() {
                        if ('@'..='~').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(n) = chars.next() {
                        if n == '\x07' || (n == '\x1b' && chars.next() == Some('\\')) {
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

struct Pty {
    child: Child,
    master: File,
    output: Receiver<Vec<u8>>,
    seen: Vec<u8>,
}

impl Pty {
    fn spawn(root: &Path, args: &[&str]) -> Self {
        let mut master_fd = -1;
        let mut slave_fd = -1;
        let mut size = libc::winsize {
            ws_row: 40,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: every pointer is valid for the call (`size` and the two
        // descriptors are locals); a null name and termios are allowed.
        let rc = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        // SAFETY: openpty returned two fresh descriptors we now own.
        let (master, slave) = unsafe {
            (
                OwnedFd::from_raw_fd(master_fd),
                OwnedFd::from_raw_fd(slave_fd),
            )
        };

        let mut command = command(root);
        command
            .args(args)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: runs between fork and exec in the child; only async-signal-safe
        // libc calls (setsid, ioctl) and no allocation.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        drop(slave);
        drop(command);

        let master = File::from(master);
        let mut reader = master.try_clone().unwrap();
        let (sender, output) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 || sender.send(buffer[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            master,
            output,
            seen: Vec::new(),
        }
    }

    fn drain(&mut self, wait: Duration) {
        if let Ok(chunk) = self.output.recv_timeout(wait) {
            self.seen.extend(chunk);
            while let Ok(chunk) = self.output.try_recv() {
                self.seen.extend(chunk);
            }
        }
    }

    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !strip_ansi(&self.seen).contains(needle) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; saw {:?}",
                strip_ansi(&self.seen)
            );
            self.drain(Duration::from_millis(50));
        }
    }

    fn send(&mut self, keys: &str) {
        self.master.write_all(keys.as_bytes()).unwrap();
        self.master.flush().unwrap();
        thread::sleep(Duration::from_millis(80));
        self.drain(Duration::from_millis(1));
    }

    /// Waits for the child and returns (exit code, terminal text).
    fn finish(mut self) -> (i32, String) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            self.drain(Duration::from_millis(20));
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("child did not exit; saw {:?}", strip_ansi(&self.seen));
            }
        };
        self.drain(Duration::from_millis(100));
        (
            status
                .code()
                .unwrap_or_else(|| -status.signal().unwrap_or(0)),
            strip_ansi(&self.seen),
        )
    }
}

fn get_json(root: &Path, name: &str) -> Option<Value> {
    let output = command(root)
        .args(["get", name, "--json"])
        .output()
        .unwrap();
    output
        .status
        .success()
        .then(|| serde_json::from_slice(&output.stdout).unwrap())
}

fn list_json(root: &Path) -> Value {
    let output = command(root).args(["list", "--json"]).output().unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Types every key press with a short pause, the way a person would.
fn run_form(root: &Path, args: &[&str], keys: &[&str]) -> (i32, String) {
    let mut pty = Pty::spawn(root, args);
    pty.wait_for("Add New Entry");
    for key in keys {
        pty.send(key);
    }
    pty.finish()
}

#[test]
fn ctrl_c_cancels_with_go_error_and_creates_nothing() {
    let root = init_vault();
    let (code, text) = run_form(&root, &["add", "e1"], &[CTRL_C]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("Error: canceled"), "{text}");
    assert!(get_json(&root, "e1").is_none());
}

#[test]
fn escape_does_nothing_and_cancel_after_typing_stores_nothing() {
    let root = init_vault();
    let (code, text) = run_form(&root, &["add", "e1"], &["\x1b", "bob", TAB, STRONG, CTRL_C]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("Error: canceled"));
    assert!(get_json(&root, "e1").is_none());
}

#[test]
fn fully_filled_form_stores_the_go_shaped_entry() {
    let root = init_vault();
    let keys = [
        "alice",
        TAB,
        STRONG,
        TAB,
        TAB,
        TAB,
        "\x15yes",
        TAB,
        "https://x.example",
        TAB,
        "n1\rn2",
        TAB,
        TOTP,
        TAB,
        "Iss",
        TAB,
        "acct",
        ENTER,
        "\x1b[D",
    ];
    let (code, text) = run_form(&root, &["add", "e1"], &keys);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("Entry created: e1"), "{text}");
    let entry = get_json(&root, "e1").expect("entry stored");
    let fields = &entry["Fields"];
    assert_eq!(fields["username"], "alice");
    assert_eq!(fields["password"], "***");
    assert_eq!(fields["url"], "https://x.example");
    assert_eq!(fields["notes"], "n1\nn2");
    assert_eq!(fields["totp"]["secret"], TOTP);
    assert_eq!(fields["totp"]["issuer"], "Iss");
    assert_eq!(fields["totp"]["account_name"], "acct");
    let list = list_json(&root);
    assert_eq!(list[0]["type"], "password");
    assert_eq!(
        list[0]["usage_hint"],
        "Use for authentication. Consider using a password manager or secret injection."
    );
    assert_eq!(list[0]["auto_rotate"], true);
}

#[test]
fn flags_seed_the_form_and_win_over_form_answers_for_url_notes_and_totp() {
    let root = init_vault();
    let keys = [
        "formuser",
        TAB,
        STRONG,
        TAB,
        TAB,
        TAB,
        TAB,
        "https://form.example",
        TAB,
        "formnotes",
        TAB,
        TAB,
        TAB,
        ENTER,
        "\x1b[D",
    ];
    let args = [
        "add",
        "e1",
        "--url",
        "https://f.example",
        "--notes",
        "flagnote",
        "--username",
        "flaguser",
    ];
    let (code, text) = run_form(&root, &args, &keys);
    assert_eq!(code, 0, "{text}");
    let entry = get_json(&root, "e1").unwrap();
    // Typing appends to the flag-provided default (the form is pre-filled), the
    // form answer wins for username, and flags win for url/notes.
    assert_eq!(entry["Fields"]["username"], "flaguserformuser");
    assert_eq!(entry["Fields"]["url"], "https://f.example");
    assert_eq!(entry["Fields"]["notes"], "flagnote");
}

#[test]
fn flag_defaults_type_and_hint_apply_when_the_form_leaves_them_blank() {
    let root = init_vault();
    let args = [
        "add",
        "e1",
        "--type",
        "ssh_key",
        "--usage-hint",
        "FLAGHINT",
        "--auto-rotate",
    ];
    let keys = [TAB, TAB, TAB, TAB, TAB, TAB, TAB, TAB, TAB, ENTER];
    let (code, text) = run_form(&root, &args, &keys);
    assert_eq!(code, 0, "{text}");
    let list = list_json(&root);
    assert_eq!(list[0]["type"], "ssh_key");
    assert_eq!(list[0]["usage_hint"], "FLAGHINT");
    assert_eq!(list[0]["auto_rotate"], true);
    // No password was entered, so the entry has no secret value.
    assert_ne!(list[0]["has_value"], true);
}

#[test]
fn invalid_totp_secret_is_rejected_after_the_form_without_writing() {
    let root = init_vault();
    let keys = [
        TAB, STRONG, TAB, TAB, TAB, TAB, TAB, TAB, "JBSWY3DP", TAB, TAB, ENTER,
    ];
    let (code, text) = run_form(&root, &["add", "e1"], &keys);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("Error: TOTP secret too short: minimum 16 bytes required"),
        "{text}"
    );
    assert!(get_json(&root, "e1").is_none());
}

#[test]
fn existing_entry_fails_before_the_form_even_with_force() {
    let root = init_vault();
    let created = command(&root)
        .args(["add", "e1", "--value", STRONG])
        .output()
        .unwrap();
    assert!(created.status.success());
    for args in [&["add", "e1"][..], &["add", "e1", "--force"][..]] {
        let mut pty = Pty::spawn(&root, args);
        let (code, text) = {
            // No form is shown: the process exits on its own.
            pty.drain(Duration::from_millis(10));
            pty.finish()
        };
        assert_eq!(code, 1, "{text}");
        assert!(
            text.contains(
                "Error: entry \"e1\" already exists (use 'set' to update or 'edit' to modify)"
            ),
            "{text}"
        );
        assert!(!text.contains("Add New Entry"), "{text}");
    }
}

#[test]
fn value_flag_on_a_terminal_warns_about_process_listings() {
    let root = init_vault();
    let (code, text) = {
        let pty = Pty::spawn(&root, &["add", "e1", "--value", STRONG]);
        pty.finish()
    };
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(
            "Warning: --value is visible in process listings (ps aux). Use --stdin-value for secure input."
        ),
        "{text}"
    );
    // Go prints the warning even under --quiet (only "Entry created" is silenced).
    let quiet = {
        let pty = Pty::spawn(&root, &["add", "e2", "--quiet", "--value", STRONG]);
        pty.finish()
    };
    assert_eq!(quiet.0, 0, "{}", quiet.1);
    assert!(
        quiet.1.contains("Warning: --value is visible"),
        "{}",
        quiet.1
    );
    assert!(!quiet.1.contains("Entry created"), "{}", quiet.1);
}
