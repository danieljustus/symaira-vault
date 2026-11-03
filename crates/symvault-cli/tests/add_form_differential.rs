#![cfg(unix)]
#![deny(unsafe_code)]

//! Go↔Rust differential for the interactive `symvault add` form.
//!
//! `add_form_pty.rs` pins the Rust side alone; this file is the oracle-bound
//! half. Each scenario runs the Go oracle (`SYMVAULT_GO_BINARY`) and the Rust
//! binary under a real pseudo-terminal in separate disposable HOME/XDG roots,
//! typing the same keystrokes, and compares
//!
//! - the exit status (signals as negative numbers),
//! - stderr, line by line with **no** de-duplication (Go prints every `add`
//!   error twice, once from cobra and once from `ExecuteRoot`),
//! - the stdout lines that are not form frames (`Entry created`, ...),
//! - whether the form appeared at all,
//! - `symvault list --json` of the resulting vault, and
//! - the entry the vault ends up holding, decrypted with the repository's own
//!   crypto/store path (data, secret metadata, version, tags, write history).
//!
//! stdin/stdout are the pty, stderr is a pipe so it can be compared on its
//! own. A small embedded `python3 -I` driver owns the pty; it answers the Go
//! TUI's startup terminal queries (OSC 11 background colour, CSI 6n cursor
//! position). The Go side of every scenario was recorded once from the pinned
//! oracle (`testdata/port/cli-observations/add_form_differential.json`) and is
//! replayed; a missing recording fails the test.

#[path = "common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use symvault_crypto::{SecretBytes, decrypt_identity};
use symvault_store::Store;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");
const PASSPHRASE: &str = "Tr0ub4dor&3-xyz-correct";
const ENTRY: &str = "e1";
const MIN_SCENARIOS: usize = 37;
/// Pinned Go oracle (a `CGO_ENABLED=0` build of this commit).
const ORACLE_COMMIT: &str = "fca3f89401833b5e14ec4ec74ef736b0f63bca74";

/// Pty driver: spawns the binary on a pty (stdin/stdout) with stderr on a pipe,
/// plays the keystroke script and prints one JSON result object.
const DRIVER: &str = r####"import fcntl, json, os, re, select, signal, struct, sys, termios, time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def strip(raw):
    return ANSI.sub(b"", bytes(raw)).replace(b"\r", b"")


def main():
    spec = json.load(open(sys.argv[1]))
    master, slave = os.openpty()
    # Size the terminal before the child starts so its first size query is final.
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    err_r, err_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(err_w, 2)
            for fd in (master, slave, err_r, err_w):
                if fd > 2:
                    os.close(fd)
            os.chdir(spec["cwd"])
            os.execve(spec["binary"], [spec["binary"]] + spec["args"], spec["env"])
        finally:
            os._exit(127)
    os.close(slave)
    os.close(err_w)

    out = bytearray()
    err = bytearray()
    st = {"master_open": True, "err_open": True, "status": None, "answered": [0, 0]}

    def reap():
        if st["status"] is None:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                st["status"] = status
        return st["status"] is not None

    def answer_queries():
        # The Go TUI asks the terminal for its background colour (OSC 11) and the
        # cursor position (CSI 6n) at startup and stalls until it gets answers.
        osc = out.count(b"\x1b]11;?")
        while st["answered"][0] < osc:
            st["answered"][0] += 1
            os.write(master, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
        csi = out.count(b"\x1b[6n")
        while st["answered"][1] < csi:
            st["answered"][1] += 1
            os.write(master, b"\x1b[1;1R")

    def pump(duration):
        end = time.time() + duration
        while True:
            left = end - time.time()
            if left <= 0:
                return
            fds = []
            if st["master_open"]:
                fds.append(master)
            if st["err_open"]:
                fds.append(err_r)
            if not fds:
                time.sleep(min(left, 0.02))
                continue
            ready, _, _ = select.select(fds, [], [], min(left, 0.02))
            for fd in ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b""
                if fd == master:
                    if data:
                        out.extend(data)
                        try:
                            answer_queries()
                        except OSError:
                            pass
                    else:
                        st["master_open"] = False
                else:
                    if data:
                        err.extend(data)
                    else:
                        st["err_open"] = False

    def send(data):
        try:
            for off in range(0, len(data), 128):
                os.write(master, data[off:off + 128])
                if len(data) > 128:
                    pump(0.03)  # keep the output side drained during big pastes
        except OSError:
            pass

    deadline = time.time() + spec["timeout"]
    form_seen = False
    if spec["wait_form"]:
        while time.time() < deadline and not reap() and b"Add New Entry" not in strip(out):
            pump(0.02)
        form_seen = b"Add New Entry" in strip(out)
    for step in spec["steps"]:
        if reap():
            break
        pump(step["delay"])
        if reap():
            break
        send(bytes.fromhex(step["hex"]))
    if spec["nudge"] and not reap():
        # One trailing message wakes the oracle's event loop after the last key.
        end = time.time() + 1.3
        while time.time() < end and not reap():
            pump(0.02)
        if not reap():
            send(b"\x1b[D")
    timed_out = False
    while not reap():
        if time.time() > deadline:
            timed_out = True
            os.kill(pid, signal.SIGKILL)
            while not reap():
                pump(0.05)
            break
        pump(0.02)
    for _ in range(20):
        pump(0.02)
        if not st["master_open"] and not st["err_open"]:
            break
    status = st["status"]
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
    if not form_seen:
        form_seen = b"Add New Entry" in strip(out)
    stderr_lines = err.decode("utf-8", "replace").replace("\r", "").split("\n")
    if stderr_lines and stderr_lines[-1] == "":
        stderr_lines.pop()
    result = {
        "rc": rc,
        "timeout": timed_out,
        "form_seen": form_seen,
        "stdout_lines": [l.decode("utf-8", "replace").strip() for l in strip(out).split(b"\n") if l.strip()],
        "stderr_lines": stderr_lines,
    }
    sys.stdout.write(json.dumps(result))


main()"####;

/// One keystroke write, preceded by a delay in milliseconds.
struct Step {
    delay_ms: u64,
    bytes: &'static [u8],
}

const fn st(delay_ms: u64, bytes: &'static [u8]) -> Step {
    Step { delay_ms, bytes }
}

struct Scenario {
    name: &'static str,
    args: &'static [&'static str],
    /// Non-interactive `symvault` invocations run first on the same vault.
    pre: &'static [&'static [&'static str]],
    /// Send one trailing key if the program is still alive 1.3 s after the
    /// last step (the oracle's event loop needs one more message to quit).
    nudge: bool,
    /// Whether the Go oracle shows the form in this scenario.
    expect_form: bool,
    timeout_secs: u64,
    steps: &'static [Step],
}

const fn sc(
    name: &'static str,
    args: &'static [&'static str],
    pre: &'static [&'static [&'static str]],
    nudge: bool,
    expect_form: bool,
    timeout_secs: u64,
    steps: &'static [Step],
) -> Scenario {
    Scenario {
        name,
        args,
        pre,
        nudge,
        expect_form,
        timeout_secs,
        steps,
    }
}

const SCENARIOS: &[Scenario] = &[
    sc("cancel_ctrlc", &["add", "e1"], &[], false, true, 45, &[st(300, b"\x03")]),
    sc("esc_noop_then_cancel", &["add", "e1"], &[], false, true, 45, &[st(300, b"\x1b"), st(300, b"abc"), st(300, b"\x03")]),
    sc("cancel_after_typing", &["add", "e1"], &[], false, true, 45, &[st(200, b"bob"), st(200, b"\x09"), st(200, b"Xk9#mP2$vL7qZ!aaBB"), st(200, b"\x03")]),
    sc("fill_all", &["add", "e1"], &[], true, true, 45, &[st(120, b"alice"), st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09yes"), st(120, b"\x09https://x.example"), st(120, b"\x09n1\x0dn2"), st(120, b"\x09JBSWY3DPEHPK3PXPJBSWY3DPEH"), st(120, b"\x09Iss"), st(120, b"\x09acct"), st(100, b"\x0d")]),
    sc("fill_pw_only", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("defaults_flags_accept", &["add", "e1", "--username", "u1", "--url", "https://f.example", "--notes", "fn", "--type", "api_key", "--usage-hint", "HH", "--auto-rotate", "--totp-secret", "JBSWY3DPEHPK3PXPJBSWY3DPEH", "--totp-issuer", "FI", "--totp-account", "FA"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("flags_override_form", &["add", "e1", "--url", "https://f.example", "--notes", "flagnote", "--username", "flaguser"], &[], true, true, 45, &[st(120, b"formuser"), st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09https://form.example"), st(120, b"\x09formnotes"), st(120, b"\x09\x09\x09"), st(100, b"\x0d")]),
    sc("weak_pw_noforce", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09weak"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("weak_pw_force", &["add", "e1", "--force"], &[], true, true, 45, &[st(120, b"\x09weak"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("empty_password", &["add", "e1"], &[], true, true, 45, &[st(120, b"nobody"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("all_empty", &["add", "e1"], &[], true, true, 45, &[st(900, b""), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("type_explicit_apikey", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x15API_Key"), st(120, b"\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("type_junk", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x15zzz"), st(120, b"\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("type_detect_github", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("type_cleared_empty", &["add", "e1"], &[], true, true, 45, &[st(900, b""), st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x15\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("hint_custom", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x15my hint\x0dline2"), st(120, b"\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("auto_rotate_variants", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x15yes"), st(120, b"\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("auto_rotate_yesno_case", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x15YES"), st(120, b"\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("totp_invalid", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09\x09\x09JBSWY3DP"), st(120, b"\x09\x09"), st(100, b"\x0d")]),
    sc("totp_whitespace_only", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09\x09\x09   "), st(120, b"\x09iss"), st(120, b"\x09"), st(100, b"\x0d")]),
    sc("trim_fields", &["add", "e1"], &[], true, true, 45, &[st(120, b"  spaced  "), st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09  https://t.example  "), st(120, b"\x09  \x0d  note  \x0d "), st(120, b"\x09JBSWY3DPEHPK3PXPJBSWY3DPEH"), st(120, b"\x09 Iss "), st(120, b"\x09 Acct "), st(100, b"\x0d")]),
    sc("backspace_back_nav", &["add", "e1"], &[], true, true, 45, &[st(900, b""), st(200, b"ab"), st(100, b"\x09"), st(100, b"\x7f"), st(100, b"Z"), st(100, b"\x09"), st(100, b"Xk9#mP2$vL7qZ!aaBB"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x0d")]),
    // Forward, forward, back arrive as one read: the oracle hands stray blink
    // ticks to whichever field is focused, and a blank type field that sees one
    // fills the usage hint, so the form must not dwell on it between writes.
    sc("shift_tab_nav", &["add", "e1"], &[], true, true, 45, &[st(900, b""), st(200, b"\x09\x09\x1b[Z"), st(100, b"Xk9#mP2$vL7qZ!aaBB"), st(100, b"\x1b[Z"), st(100, b"usr"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x0d")]),
    sc("enter_navigation", &["add", "e1"], &[], true, true, 45, &[st(200, b"usr\x0d"), st(100, b"Xk9#mP2$vL7qZ!aaBB\x0d"), st(100, b"\x0d"), st(100, b"\x09"), st(100, b"yes\x0d"), st(100, b"https://e\x0d"), st(100, b"\x09"), st(100, b"\x0d"), st(100, b"\x0d"), st(100, b"\x0d")]),
    sc("exists_noforce", &["add", "e1"], &[&["add", "e1", "--value", "Xk9#mP2$vL7qZ!aaBB"]], false, false, 12, &[]),
    sc("exists_force", &["add", "e1", "--force"], &[&["add", "e1", "--value", "Xk9#mP2$vL7qZ!aaBB"]], false, false, 12, &[]),
    sc("expires_at", &["add", "e1", "--expires-at", "2030-01-02T03:04:05Z"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("value_flag_tty_warning", &["add", "e1", "--value", "Xk9#mP2$vL7qZ!aaBB"], &[], false, false, 12, &[]),
    sc("value_flag_tty_quiet", &["add", "e1", "--quiet", "--value", "Xk9#mP2$vL7qZ!aaBB"], &[], false, false, 12, &[]),
    sc("totp_flag_tty_warning", &["add", "e1", "--totp-secret", "JBSWY3DPEHPK3PXPJBSWY3DPEH"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("type_flag_no_password", &["add", "e1", "--type", "ssh_key"], &[], true, true, 45, &[st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("usage_hint_flag_only", &["add", "e1", "--usage-hint", "FLAGHINT"], &[], true, true, 45, &[st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("hint_tick_idle_on_type", &["add", "e1"], &[], true, true, 45, &[st(50, b"\x09\x09"), st(1200, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x09"), st(100, b"\x0d")]),
    sc("long_fields", &["add", "e1"], &[], true, true, 45, &[st(120, b"uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"), st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x09\x09hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"), st(120, b"\x09nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"), st(120, b"\x09\x09\x09"), st(100, b"\x0d")]),
    sc("unicode_pw", &["add", "e1"], &[], true, true, 45, &[st(120, b"\xc3\xbc-\xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c-\xe5\xaf\x86\xe7\xa0\x81-\xf0\x9f\x94\x90"), st(120, b"\x09P\xc3\xa4ssw\xc3\xb6rd-\xe5\xaf\x86\xe7\xa0\x81\xf0\x9f\x94\x90aA1!"), st(120, b"\x09\x09\x09\x09\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("word_edits", &["add", "e1"], &[], true, true, 45, &[st(120, b"foo bar baz\x17\x17x"), st(120, b"\x09Xk9#mP2$vL7qZ!aaBB\x01\x0b"), st(120, b"\x09\x09\x09\x09abc def\x1b[D\x1b[D\x1b[D\x04"), st(120, b"\x09\x09\x09\x09"), st(100, b"\x0d")]),
    sc("hint_textarea_edit", &["add", "e1"], &[], true, true, 45, &[st(120, b"\x09Xk9#mP2$vL7qZ!aaBB"), st(120, b"\x09\x09\x15ab\x0dcd\x1b[A\x05\x0b"), st(120, b"\x09\x09\x09l1\x0dl2\x0dl3\x1b[A\x1b[A\x04\x04"), st(120, b"\x09\x09\x09"), st(100, b"\x0d")]),
];

/// What one run produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Run {
    rc: i64,
    timeout: bool,
    form_seen: bool,
    /// Every non-empty, ANSI-stripped pty line (kept for failure reports).
    stdout_lines: Vec<String>,
    stderr_lines: Vec<String>,
    list: Value,
    entry: Value,
}

impl Run {
    /// Result lines in the pty output. The form repaints in place, so after
    /// the ANSI codes are stripped a result can sit at the end of a frame
    /// line; each marker is therefore searched for inside the line and the
    /// text from the marker on is kept.
    fn result_lines(&self) -> Vec<&str> {
        const MARKERS: [&str; 4] = [
            "Entry created: ",
            "Warning: ",
            "Error: ",
            "SYMVAULT_PASSPHRASE",
        ];
        self.stdout_lines
            .iter()
            .filter_map(|line| {
                MARKERS
                    .iter()
                    .filter_map(|marker| line.find(marker))
                    .min()
                    .map(|at| &line[at..])
            })
            .collect()
    }
}

/// Describes every compared facet in which `go` and `rust` differ.
fn differences(go: &Run, rust: &Run) -> Vec<String> {
    let mut out = Vec::new();
    let mut facet = |name: &str, same: bool, go: String, rust: String| {
        if !same {
            out.push(format!("  {name}\n    go:   {go}\n    rust: {rust}"));
        }
    };
    facet(
        "exit code",
        go.rc == rust.rc,
        go.rc.to_string(),
        rust.rc.to_string(),
    );
    facet(
        "form shown",
        go.form_seen == rust.form_seen,
        go.form_seen.to_string(),
        rust.form_seen.to_string(),
    );
    facet(
        "stderr lines",
        go.stderr_lines == rust.stderr_lines,
        format!("{:?}", go.stderr_lines),
        format!("{:?}", rust.stderr_lines),
    );
    facet(
        "stdout result lines",
        go.result_lines() == rust.result_lines(),
        format!("{:?}", go.result_lines()),
        format!("{:?}", rust.result_lines()),
    );
    facet(
        "list --json",
        go.list == rust.list,
        go.list.to_string(),
        rust.list.to_string(),
    );
    facet(
        "stored entry",
        go.entry == rust.entry,
        go.entry.to_string(),
        rust.entry.to_string(),
    );
    out
}

fn env_for(root: &Path) -> BTreeMap<String, String> {
    let home = root.join("h");
    let text = |path: PathBuf| path.to_string_lossy().into_owned();
    [
        ("PATH", "/usr/bin:/bin".to_owned()),
        ("HOME", text(home.clone())),
        ("XDG_CONFIG_HOME", text(home.join(".config"))),
        ("XDG_DATA_HOME", text(home.join(".data"))),
        ("XDG_STATE_HOME", text(home.join(".state"))),
        ("TMPDIR", text(root.to_path_buf())),
        ("SYMVAULT_PASSPHRASE", PASSPHRASE.to_owned()),
        ("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1".to_owned()),
        ("SYMVAULT_NO_ENV_WARNING", "1".to_owned()),
        ("TERM", "xterm-256color".to_owned()),
        ("LANG", "en_US.UTF-8".to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

/// Non-interactive run: no tty, empty stdin.
fn plain(binary: &Path, root: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .env_clear()
        .envs(env_for(root))
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .expect("run binary")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The vault entry, decrypted through the repository's own identity/store path.
fn stored_entry(root: &Path) -> Value {
    let vault = root.join("h/.data/symaira-vault");
    let ciphertext = fs::read(vault.join("identity.age")).expect("identity.age");
    let identity = decrypt_identity(&ciphertext, &SecretBytes::new(PASSPHRASE.as_bytes()))
        .expect("decrypt identity with the scenario passphrase");
    let store = Store::open(
        symvault_store::data_safety::test_support_pre_marked(&vault),
        &identity,
    )
    .expect("open vault");
    if !store
        .entry_exists(ENTRY, &identity)
        .expect("entry_exists on the scenario vault")
    {
        return Value::Null;
    }
    let entry = store.get(ENTRY, &identity).expect("decrypt stored entry");
    assert!(
        entry.metadata.write_history.is_empty(),
        "`add` must store no write history, got {:?}",
        entry.metadata.write_history
    );
    json!({
        "path": entry.path,
        "data": entry.data,
        "secret_meta": serde_json::to_value(&entry.secret_metadata).expect("secret metadata"),
        "version": entry.metadata.version,
        "tags": entry.metadata.tags,
        "write_history": entry.metadata.write_history.len(),
        "classification": entry.classification,
        "canary": entry.canary,
    })
}

fn run_scenario(binary: &Path, tag: &str, scenario: &Scenario) -> Run {
    let tmp = tempfile::Builder::new()
        .prefix(&format!("symvault-add-diff-{}-{tag}-", scenario.name))
        .tempdir()
        .expect("disposable root");
    let root = tmp.path();
    fs::create_dir_all(root.join("h")).expect("home");
    let init = plain(binary, root, &["init"]);
    assert!(
        init.status.success(),
        "{tag} init failed for {}: {}",
        scenario.name,
        String::from_utf8_lossy(&init.stderr)
    );
    for pre in scenario.pre {
        let output = plain(binary, root, pre);
        assert!(
            output.status.success(),
            "{tag} setup {pre:?} failed for {}: {}",
            scenario.name,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let steps: Vec<Value> = scenario
        .steps
        .iter()
        .map(|step| json!({ "delay": step.delay_ms as f64 / 1000.0, "hex": hex(step.bytes) }))
        .collect();
    let spec = json!({
        "binary": binary,
        "args": scenario.args,
        "cwd": root,
        "env": env_for(root),
        "steps": steps,
        "nudge": scenario.nudge,
        "wait_form": scenario.expect_form,
        "timeout": scenario.timeout_secs,
    });
    let spec_path = root.join("spec.json");
    fs::write(&spec_path, spec.to_string()).expect("write spec");
    let driven = Command::new("python3")
        .args(["-I", "-c", DRIVER])
        .arg(&spec_path)
        .output()
        .expect("python3 is required to drive the pty");
    assert!(
        driven.status.success(),
        "{tag} pty driver failed for {}: {}",
        scenario.name,
        String::from_utf8_lossy(&driven.stderr)
    );
    let driven: Value = serde_json::from_slice(&driven.stdout).expect("driver result JSON");

    let lines = |key: &str| -> Vec<String> {
        driven[key]
            .as_array()
            .expect("line array")
            .iter()
            .map(|line| line.as_str().expect("line").to_owned())
            .collect()
    };
    let list = plain(binary, root, &["list", "--json"]);
    let list = serde_json::from_slice(&list.stdout)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&list.stdout).into_owned()));
    Run {
        rc: driven["rc"].as_i64().expect("exit code"),
        timeout: driven["timeout"].as_bool().expect("timeout flag"),
        form_seen: driven["form_seen"].as_bool().expect("form flag"),
        stdout_lines: lines("stdout_lines"),
        stderr_lines: lines("stderr_lines"),
        list,
        entry: stored_entry(root),
    }
}

#[test]
fn add_form_matches_the_go_oracle() {
    let observations = go_oracle_ext::Observations::begin(
        "add_form_differential",
        "add_form_matches_the_go_oracle",
        Some(ORACLE_COMMIT),
    );
    let python = Command::new("python3")
        .args(["-I", "--version"])
        .output()
        .expect("python3 must be installed to drive the pty differential");
    assert!(python.status.success(), "python3 -I --version failed");

    let rust = PathBuf::from(BINARY);
    let mut compared = 0_usize;
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let (go_run, rust_run) = thread::scope(|scope| {
            let go_run = scope.spawn(|| {
                observations.observe(scenario.name, |go| {
                    serde_json::to_value(run_scenario(go, "go", scenario)).expect("go run json")
                })
            });
            let rust_run = scope.spawn(|| run_scenario(&rust, "rust", scenario));
            (
                go_run.join().expect("go scenario"),
                rust_run.join().expect("rust scenario"),
            )
        });
        let go_run: Run = serde_json::from_value(go_run).expect("recorded Go run");
        let mut problems = differences(&go_run, &rust_run);
        for (side, run) in [("go", &go_run), ("rust", &rust_run)] {
            if run.timeout {
                problems.push(format!("  {side} timed out"));
            }
        }
        if go_run.form_seen != scenario.expect_form {
            problems.push(format!(
                "  oracle form shown = {}, scenario expects {}",
                go_run.form_seen, scenario.expect_form
            ));
        }
        compared += 1;
        if !problems.is_empty() {
            failures.push(format!("{}:\n{}", scenario.name, problems.join("\n")));
        }
    }
    assert!(
        compared >= MIN_SCENARIOS,
        "only {compared} add-form scenarios compared, expected at least {MIN_SCENARIOS}"
    );
    assert!(
        failures.is_empty(),
        "{} of {compared} add-form scenarios diverge from the oracle:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(observations.count(), compared);
    println!("add-form differential: {compared} scenarios compared, all equal");
}

#[test]
fn comparator_flags_every_facet() {
    let base = Run {
        rc: 1,
        timeout: false,
        form_seen: true,
        stdout_lines: vec!["Add New Entry".into(), "Error: x".into()],
        stderr_lines: vec!["Error: x".into(), "Error: x".into()],
        list: json!([]),
        entry: Value::Null,
    };
    assert!(differences(&base, &base.clone()).is_empty());

    // The duplicate Go prints must not be collapsed.
    let mut single = base.clone();
    single.stderr_lines.pop();
    assert_eq!(differences(&base, &single).len(), 1);

    let mut other = base.clone();
    other.rc = 0;
    other.form_seen = false;
    other.stdout_lines = vec!["Entry created: e1".into()];
    other.list = json!(["e1"]);
    other.entry = json!({ "version": 2 });
    assert!(differences(&base, &other).len() >= 5);
}
