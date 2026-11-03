#!/usr/bin/env python3
"""CLI-007: real Go/Rust signal behavior of `broker`, `run`, `run --broker`, `intake watch`,
`mcp --stdio --allow-locked` and the `ui` terminal UI (under a pseudo-terminal).

Unix only. Signals are delivered to real child processes in disposable HOME /
XDG / TMPDIR roots with a memory keyring and a synthetic passphrase. Windows
Ctrl-C / Ctrl-Break in a private console is NOT exercised here (it is covered for
`broker` by egress_contract.py and for `intake watch` by intake_watch_contract.py);
running this driver on Windows fails closed instead of passing vacuously.

Each observation records how the process ended (exit status or killing signal),
stdout/stderr, whether a listener or an orphaned child survived, and the
on-disk names left under HOME (including a private TMPDIR). The Go oracle is
built from ORACLE; Rust must produce the same observation. The one documented
difference is Go's persistent <vault>/broker-ca.pem, which Rust replaces with a
per-instance temporary CA directory that must not survive any catchable signal.

Go-only oracle records (`go_only`, not compared against Rust): a stdio `mcp` server and the
`ui` terminal UI (PTY, Enter copies the selected entry) and an HTTP `mcp` server (copy over
HTTP; also with SIGHUP inherited as SIG_IGN) with an armed clipboard auto-clear timer. The Rust leg would need the real macOS pasteboard (`/usr/bin/pbcopy` is the only
lookup), so the Rust side is carried by injected-clipboard process tests:
`approval::tests::stdio_armed_clipboard_signal_clears_and_requests_shutdown` (mcp) and
`tui::tests::ui_signal_with_held_copy_process_contract` (ui) and
`mcp_shutdown::tests::http_sighup_follows_the_armed_clipboard_timer` plus
`http_signal_shutdown_clears_an_armed_clipboard` (HTTP; Makefile target
`signal-process-contract` runs them). Go runs against fake pasteboard tools on a PATH that
cannot reach the real ones. Declared Rust-safer differences: SIGQUIT clears an armed
clipboard (Go has no SIGQUIT in its auto-clear subscription and leaves the secret), in `ui`
and in stdio `mcp`; a `ui` copy kept until quit (duration 0) is cleared before a SIGHUP death.
"""
import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import termios
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "scripts/rust-port/http_process_seed.go.txt"
ORACLE = "45b8577e01ce1826e312ed970d0fc01a3a9b6e17"
PASSPHRASE = "correct horse battery staple"
CA_NAME = "broker-ca.pem"
GRACEFUL = ("SIGINT", "SIGTERM")
KILLING = ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT")
CHILD = '''import os, signal, sys, time
for name in ("SIGINT", "SIGTERM", "SIGHUP"):
    signal.signal(getattr(signal, name), signal.SIG_DFL)
open(sys.argv[1], "w").write(str(os.getpid()))
print("ready", flush=True)
time.sleep(60)
'''

# What the actual Go oracle must do. They guard against a vacuous differential
# (for example everything timing out); the Rust side is compared to the
# observed Go record, not to this table.
GO_EXPECTED = {
    ("broker", "SIGINT"): ("exit", 0), ("broker", "SIGTERM"): ("exit", 0),
    ("broker", "SIGHUP"): ("signal", signal.SIGHUP), ("broker", "SIGQUIT"): ("exit", 2),
    ("intake-watch", "SIGINT"): ("exit", 0), ("intake-watch", "SIGTERM"): ("exit", 0),
    ("intake-watch", "SIGHUP"): ("signal", signal.SIGHUP), ("intake-watch", "SIGQUIT"): ("exit", 2),
    ("run", "SIGINT"): ("signal", signal.SIGINT), ("run", "SIGTERM"): ("signal", signal.SIGTERM),
    ("run", "SIGHUP"): ("signal", signal.SIGHUP), ("run", "SIGQUIT"): ("exit", 2),
    ("run-broker", "SIGINT"): ("signal", signal.SIGINT), ("run-broker", "SIGTERM"): ("signal", signal.SIGTERM),
    ("run-broker", "SIGHUP"): ("signal", signal.SIGHUP), ("run-broker", "SIGQUIT"): ("exit", 2),
    # `mcp --stdio --allow-locked`: `serve` subscribes SIGINT/SIGTERM/SIGQUIT before it branches on the vault.
    ("mcp-locked", "SIGINT"): ("exit", 0), ("mcp-locked", "SIGTERM"): ("exit", 0),
    ("mcp-locked", "SIGHUP"): ("signal", signal.SIGHUP), ("mcp-locked", "SIGQUIT"): ("exit", 0),
    # `ui` (bubbletea): SIGTERM quits, an external SIGINT fails with `program was interrupted`.
    ("ui", "SIGINT"): ("exit", 1), ("ui", "SIGTERM"): ("exit", 0),
    ("ui", "SIGHUP"): ("signal", signal.SIGHUP), ("ui", "SIGQUIT"): ("exit", 2),
}
# Terminal state after `ui` ended: bubbletea restores the terminal and leaves the alternate
# screen on SIGTERM and SIGINT; SIGHUP and SIGQUIT end the Go runtime and leave it raw.
GO_EXPECTED_UI_TERMINAL = {"SIGINT": True, "SIGTERM": True, "SIGHUP": False, "SIGQUIT": False}
UI_INTERRUPTED = "Error: ui failed: program was killed: program was interrupted\n"
LOCKED_WARNING = "Vault is locked; starting MCP server in read-only mode. Run 'symvault unlock' to enable vault tools.\n"
ALT_SCREEN_ON, ALT_SCREEN_OFF = b"\x1b[?1049h", b"\x1b[?1049l"
INITIALIZE = (b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",'
              b'"clientInfo":{"name":"signals","version":"1"},"capabilities":{}}}\n')
# Fake pasteboard tools for the Go-only clipboard observation: every name atotto/clipboard can
# resolve, writing to a file next to the script. `events` records `secret`/`clear` per write.
FAKE_CLIPBOARD = '''#!/bin/sh
d="${0%/*}"
case "${0##*/}" in
 pbpaste|wl-paste) cat "$d/clip.txt" 2>/dev/null; exit 0;;
esac
for a in "$@"; do case "$a" in -out|-o|--output) cat "$d/clip.txt" 2>/dev/null; exit 0;; esac; done
cat > "$d/clip.txt"
if [ -s "$d/clip.txt" ]; then echo secret >> "$d/events"; else echo clear >> "$d/events"; fi
'''
FAKE_CLIPBOARD_TOOLS = ("pbcopy", "pbpaste", "xclip", "xsel", "wl-copy", "wl-paste")
CLIPBOARD_SECRET = "s3cret-value-12345"

# Dispositions inherited as SIG_IGN (a parent such as nohup or a job-control-free
# supervisor). Go 1.26 runtime/signal_unix.go sigInstallGoHandler keeps the
# inherited ignore for SIGHUP and SIGINT only; SIGTERM and SIGQUIT always get the
# Go handler. signal.Notify (broker, intake watch) overrides an ignore, so SIGINT
# and SIGTERM still stop those commands. Key: (command, ignored-and-sent signal);
# value: (survived the signal, ending after the follow-up SIGTERM when it survived).
# They guard against a vacuous differential; Rust is compared to the observed Go record.
GO_EXPECTED_IGNORED = {
    ("broker", "SIGHUP"): (True, ("exit", 0)), ("broker", "SIGINT"): (False, ("exit", 0)),
    ("broker", "SIGTERM"): (False, ("exit", 0)), ("broker", "SIGQUIT"): (False, ("exit", 2)),
    ("intake-watch", "SIGHUP"): (True, ("exit", 0)), ("intake-watch", "SIGINT"): (False, ("exit", 0)),
    ("run", "SIGHUP"): (True, ("signal", signal.SIGTERM)), ("run", "SIGINT"): (True, ("signal", signal.SIGTERM)),
    ("run", "SIGTERM"): (False, ("signal", signal.SIGTERM)), ("run", "SIGQUIT"): (False, ("exit", 2)),
    ("run-broker", "SIGHUP"): (True, ("signal", signal.SIGTERM)), ("run-broker", "SIGINT"): (True, ("signal", signal.SIGTERM)),
}
IGNORED_CASES = tuple(GO_EXPECTED_IGNORED)
SURVIVE_WINDOW = 1.5  # observation window for a process that must survive an ignored signal
DIE_WINDOW = 5.0  # a process that must die gets this long (returns as soon as it exits; loaded runners are slow)


def checked(args, cwd=ROOT, env=None, timeout=300):
    result = subprocess.run([str(x) for x in args], cwd=cwd, env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): " + result.stderr.decode(errors="replace")[-3000:])
    return result.stdout


def isolated(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SYMVAULT_")}
    tmp = home / "tmp"
    tmp.mkdir(exist_ok=True)
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / "config"), XDG_DATA_HOME=str(home / "data"),
               XDG_CACHE_HOME=str(home / "cache"), TMPDIR=str(tmp), SYMVAULT_TEST_KEYRING="memory",
               SYMVAULT_VAULT=str(home / "vault"), SYMVAULT_PASSPHRASE=PASSPHRASE,
               SYMVAULT_ALLOW_ENV_PASSPHRASE="1", SYMVAULT_NO_ENV_WARNING="1", SYMVAULT_SECUREUI="none",
               CI="1", NO_COLOR="1")
    return env


def ignoring(argv, names):
    """Wrap `argv` so it starts with each signal in `names` set to SIG_IGN.

    SIG_IGN survives exec, like `nohup` or a supervisor parent. A POSIX shell sets it
    (`trap "" HUP`) and execs the real binary, so the pid is unchanged and nothing runs
    in the forked child between fork and exec (`preexec_fn` is not fork-safe while the
    pump threads of earlier cases are running).
    """
    names = tuple(names)
    if not names:
        return argv
    if os.name == "nt":
        raise NotImplementedError("inherited SIG_IGN is Unix-only")
    traps = " ".join(signal.Signals[name].name[3:] for name in names)
    return ["sh", "-c", f'trap "" {traps}; exec "$@"', "sh", *argv]


class Proc:
    """A child with pipe readers, so a dead or orphan-holding child never blocks the driver."""

    def __init__(self, args, home, new_session=False, ignore=(), stdin=subprocess.DEVNULL, env=None):
        self.home = home
        ignore = tuple(ignore)
        self.out, self.err = bytearray(), bytearray()
        self.popen = subprocess.Popen(ignoring([str(x) for x in args], ignore), cwd=home, env=env or isolated(home),
                                      stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      start_new_session=new_session)
        self.threads = [threading.Thread(target=self._pump, args=(stream, sink), daemon=True)
                        for stream, sink in ((self.popen.stdout, self.out), (self.popen.stderr, self.err))]
        for thread in self.threads:
            thread.start()

    @staticmethod
    def _pump(stream, sink):
        while chunk := stream.read1(4096):
            sink += chunk

    def wait_for_output(self, marker, timeout=30):
        deadline = time.monotonic() + timeout
        while marker not in bytes(self.out):
            assert self.popen.poll() is None, ("exited before ready", bytes(self.err)[-500:])
            assert time.monotonic() < deadline, ("not ready", bytes(self.out)[-500:])
            time.sleep(0.01)

    def finish(self, timeout=15):
        try:
            self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.popen.kill()
            self.popen.wait()
            raise AssertionError(("process did not stop after the signal", self.popen.args[-3:], bytes(self.err)[-300:]))
        finally:
            for thread in self.threads:
                thread.join(timeout=3)
        return self.popen.returncode

    def kill(self):
        if self.popen.stdin is not None and not self.popen.stdin.closed:
            try:
                self.popen.stdin.close()
            except OSError:
                pass
        if self.popen.poll() is None:
            self.popen.kill()
            self.popen.wait()


def survived_signal(proc, send, sig, should_die=False):
    """Send `sig`; True when the process is still running when the observation window ends.

    A process expected to die is polled for up to DIE_WINDOW and returns as soon as it
    exits, so a slow runner cannot turn a late exit into a false "survived". A process
    expected to survive keeps the short SURVIVE_WINDOW; a real survivor never exits."""
    send(sig)
    try:
        proc.popen.wait(timeout=DIE_WINDOW if should_die else SURVIVE_WINDOW)
    except subprocess.TimeoutExpired:
        return True
    return False


def ending(returncode):
    return ["signal", -returncode] if returncode < 0 else ["exit", returncode]


# Vault-owned names that exist after `init` or a plain vault open in either
# implementation (Go also creates .lock and manifest.age on open). Anything
# else at the vault top level, and every name outside the vault, is
# signal-relevant state: private TMPDIR files, CA directories, staging.
# `.symvault-rust` is the declared D1 artifact (data-safety gate marker): a Rust
# run marks the Go-created vault before its first mutation; Go leaves none.
VAULT_BASELINE = {".git", ".gitignore", ".lock", ".symvault-migrated", ".symvault-rust", "config.yaml",
                  "entries", "identity.age", "manifest.age"}


def snapshot(home):
    """Names (not contents) of signal-relevant state under HOME, excluding the driver's own files."""
    names = set()
    for path in home.rglob("*"):
        parts = path.relative_to(home).parts
        if parts in {("child.py",), ("child.pid",)}:
            continue
        # Declared D1 artifact: the data-safety backup of a Go-created vault lands in
        # $HOME/.local/state/symvault/backups (and the dirs created for it).
        if parts in {(".local",), (".local", "state")} or parts[:3] == (".local", "state", "symvault"):
            continue
        if parts[0] == "vault" and (len(parts) > 2 or (len(parts) == 2 and parts[1] in VAULT_BASELINE)):
            continue
        # Go and Rust name the intake spool differently (random suffix only).
        names.add(re.sub(r"symvault-intake-[A-Za-z0-9]+", "symvault-intake-__ID__", "/".join(parts)))
    return sorted(names)


def listener_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_gone(pid, timeout=5):
    deadline = time.monotonic() + timeout
    while pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    return not pid_alive(pid)


def normal(raw, home):
    text = raw.decode("utf-8", "replace").replace(str(home), "__HOME__")
    text = re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:__PORT__", text)
    # Go overwrites <vault>/broker-ca.pem; Rust writes a per-instance directory.
    text = re.sub(r"__HOME__/vault/(\.broker-ca-[A-Za-z0-9]+/)?broker-ca\.pem", "__CA__", text)
    return text.replace("\r\n", "\n")


def new_home(base, template, name):
    home = base / name
    shutil.copytree(template, home, symlinks=True)
    return home


def case_record(name, command, sig, proc, home, graceful_quit=False, **extra):
    stderr = normal(bytes(proc.err), home)
    record = dict(case=name, command=command, signal=sig, ending=ending(proc.popen.returncode),
                  stdout=normal(bytes(proc.out), home),
                  # Go's SIGQUIT goroutine dump is runtime-specific and unbounded;
                  # the exit status 2 and on-disk state are compared instead. `mcp`
                  # handles SIGQUIT itself and prints one fixed line, which is compared.
                  stderr="<not compared: Go SIGQUIT goroutine dump>" if sig == "SIGQUIT" and not graceful_quit else stderr,
                  state=snapshot(home))
    record.update(extra)
    return record


def foreground_case(binary, base, template, command, sig, ignored=False):
    """broker / intake watch: signal the parent only; `ignored` starts it with `sig` set to SIG_IGN."""
    name = f"{command}-{'ignored-' if ignored else ''}{sig.lower()}"
    home = new_home(base, template, name)
    (home / "inbox").mkdir()
    if command == "broker":
        args, ready = ["broker"], b"NO_PROXY=127.0.0.1,localhost\n"
    else:
        args, ready = ["intake", "watch", "inbox", "--interval", "1h"], b"Ctrl-C to stop.\n"
    proc = Proc([binary, *args], home, ignore=(sig,) if ignored else ())
    try:
        # The readiness marker is printed only after the command has installed its
        # signal handling, so signalling before it would race the install.
        proc.wait_for_output(ready)
        port = None
        if command == "broker":
            found = re.search(rb"127\.0\.0\.1:(\d+)", bytes(proc.out))
            assert found, "broker did not announce its listener"
            port = int(found.group(1))
            assert listener_open(port), "control: listener must be open before the signal"
        assert proc.popen.poll() is None, "control: process must run until signalled"
        send = lambda number: proc.popen.send_signal(getattr(signal, number))  # noqa: E731
        extra = {}
        if ignored:
            survived = survived_signal(proc, send, sig, should_die=not GO_EXPECTED_IGNORED[(command, sig)][0])
            extra["ignored"], extra["survived"] = True, survived
            if survived:
                if port is not None:
                    extra["listener_open_after_ignored_signal"] = listener_open(port)
                send("SIGTERM")
        else:
            send(sig)
        proc.finish()
        if port is not None:
            extra["listener_closed"] = not listener_open(port)
        record = case_record(name, command, sig, proc, home, **extra)
    finally:
        proc.kill()
    return record


def run_case(binary, base, template, command, sig, group, extra=(), label="", ignored=False):
    """run / run --broker with a long-lived child; signal the parent or its whole group.

    `ignored` starts the parent with `sig` set to SIG_IGN (parent only; never combined with `group`)."""
    assert not (ignored and group)
    name = f"{command}{label}-{'ignored-' if ignored else ''}{'group-' if group else ''}{sig.lower()}"
    home = new_home(base, template, name)
    (home / "child.py").write_text(CHILD)
    pidfile = home / "child.pid"
    args = ["run", *(["--broker"] if command == "run-broker" else []), *extra, "--", sys.executable, home / "child.py", pidfile]
    proc = Proc([binary, *args], home, new_session=group, ignore=(sig,) if ignored else ())
    child = None
    survived = None
    try:
        deadline = time.monotonic() + 30
        while not (pidfile.exists() and pidfile.read_text()):
            assert proc.popen.poll() is None, ("run exited early", bytes(proc.err)[-500:])
            assert time.monotonic() < deadline, "child never started"
            time.sleep(0.02)
        child = int(pidfile.read_text())
        assert pid_alive(child), "control: child must run before the signal"
        assert proc.popen.poll() is None, "control: parent must wait for the child"
        send = lambda number: proc.popen.send_signal(getattr(signal, number))  # noqa: E731
        if group:
            os.killpg(proc.popen.pid, getattr(signal, sig))
        elif ignored:
            survived = survived_signal(proc, send, sig, should_die=not GO_EXPECTED_IGNORED[(command, sig)][0])
            if survived:
                assert pid_alive(child), "an ignored signal must not reach the child either"
                send("SIGTERM")
        else:
            send(sig)
        returncode = proc.finish()
        if group:
            orphan_alive = not wait_gone(child)
        else:
            time.sleep(0.2)  # a child that dies with its parent needs a moment
            orphan_alive = pid_alive(child)
        details = dict(ignored=True, survived=survived) if ignored else {}
        record = case_record(name, command + ("-group" if group else ""), sig, proc, home,
                             orphaned_child_alive=orphan_alive, **details)
        assert returncode == proc.popen.returncode
    finally:
        proc.kill()
        # The child was started by this driver's process tree; reap it and prove it is gone.
        if child is not None and pid_alive(child):
            os.kill(child, signal.SIGKILL)
            assert wait_gone(child), "driver could not reap its own child"
    return record


def locked_case(binary, base, template, sig):
    """`mcp --stdio --allow-locked --agent cli` with a locked vault, stdin held open.

    Go subscribes SIGINT/SIGTERM/SIGQUIT in `serve` before it looks at the vault, so the
    locked server shuts down like an unlocked one and clears the runtime records.
    """
    name = f"mcp-locked-{sig.lower()}"
    home = new_home(base, template, name)
    (home / "vault" / ".runtime-port").write_text('{"port":1,"bind":"127.0.0.1"}')
    env = isolated(home)
    for key in ("SYMVAULT_PASSPHRASE", "SYMVAULT_ALLOW_ENV_PASSPHRASE"):
        env.pop(key)
    proc = Proc([binary, "mcp", "--stdio", "--allow-locked", "--agent", "cli"], home, stdin=subprocess.PIPE, env=env)
    try:
        # A reply to `initialize` proves the stdio loop runs, which is after signal installation.
        proc.popen.stdin.write(INITIALIZE)
        proc.popen.stdin.flush()
        proc.wait_for_output(b'"result"')
        assert LOCKED_WARNING.encode() in bytes(proc.err), "control: the vault must be locked"
        assert proc.popen.poll() is None, "control: process must run until signalled"
        proc.popen.send_signal(getattr(signal, sig))
        proc.finish()
        record = case_record(name, "mcp-locked", sig, proc, home, graceful_quit=True)
    finally:
        proc.kill()
    return record


def read_pty(master, sink, seconds):
    """Collect terminal output for up to `seconds`; answer cursor-position queries like a terminal."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                chunk = os.read(master, 65536)
                if not chunk:
                    return
                sink.extend(chunk)
                if b"\x1b[6n" in chunk:
                    os.write(master, b"\x1b[1;1R")
        except OSError:  # the slave side is gone
            return


def ui_case(binary, base, template, sig):
    """`ui` on a pseudo-terminal; records the ending, stderr and whether the terminal was restored."""
    name = f"ui-{sig.lower()}"
    home = new_home(base, template, name)
    env = isolated(home)
    env["TERM"] = "xterm-256color"
    master, slave = pty.openpty()
    screen = bytearray()
    popen = subprocess.Popen([str(binary), "ui"], cwd=home, env=env, stdin=slave, stdout=slave,
                             stderr=subprocess.PIPE, start_new_session=True)
    os.close(slave)
    err = bytearray()
    pump = threading.Thread(target=lambda: err.extend(popen.stderr.read()), daemon=True)
    pump.start()
    try:
        deadline = time.monotonic() + 30
        while ALT_SCREEN_ON not in screen:
            assert popen.poll() is None, ("ui exited before ready", bytes(err)[-500:])
            assert time.monotonic() < deadline, "ui never entered the alternate screen"
            read_pty(master, screen, 0.2)
        read_pty(master, screen, 0.5)  # let the first frame settle; handlers are installed before it
        raw = termios.tcgetattr(master)[3]
        assert not raw & termios.ICANON and not raw & termios.ECHO, "control: ui must run in raw mode"
        assert popen.poll() is None, "control: ui must run until signalled"
        popen.send_signal(getattr(signal, sig))
        deadline = time.monotonic() + 15
        while popen.poll() is None and time.monotonic() < deadline:
            read_pty(master, screen, 0.1)
        assert popen.poll() is not None, "ui did not stop after the signal"
        read_pty(master, screen, 0.3)
        pump.join(timeout=3)
        cooked = termios.tcgetattr(master)[3]
        record = dict(case=name, command="ui", signal=sig, ending=ending(popen.returncode), stdout="",
                      stderr="<not compared: Go SIGQUIT goroutine dump>" if sig == "SIGQUIT" else normal(bytes(err), home),
                      terminal_restored=bool(cooked & termios.ICANON and cooked & termios.ECHO),
                      alt_screen_left=ALT_SCREEN_OFF in screen, state=snapshot(home))
    finally:
        if popen.poll() is None:
            popen.kill()
            popen.wait()
        os.close(master)
    return record


def clipboard_case(go, base, template, sig):
    """Go only: stdio `mcp` with an armed clipboard auto-clear timer receives `sig`.

    Fake pasteboard tools sit first on a PATH that cannot reach the real ones (macOS keeps
    `pbcopy` in /usr/bin), so the real pasteboard is never touched. The record notes
    whether the tool recorded the secret and the clear, how the process ended, and
    whether it kept serving after the clear.
    """
    name = f"mcp-clipboard-armed-{sig.lower()}"
    home = new_home(base, template, name)
    fake = home / "fakebin"
    fake.mkdir()
    for tool in FAKE_CLIPBOARD_TOOLS:
        (fake / tool).write_text(FAKE_CLIPBOARD)
        (fake / tool).chmod(0o755)
    config = home / "vault" / "config.yaml"
    config.write_text(config.read_text().replace("        canWrite: true\n",
                                                 "        canWrite: true\n        canUseClipboard: true\n        approvalMode: none\n"))
    checked([go, "--vault", home / "vault", "set", "github", "--value", CLIPBOARD_SECRET], cwd=home, env=isolated(home))
    env = isolated(home)
    env["PATH"] = f"{fake}:/bin"
    proc = Proc([go, "mcp", "--stdio", "--agent", "cli"], home, stdin=subprocess.PIPE, env=env)
    events = fake / "events"
    try:
        def send(line):
            proc.popen.stdin.write(line + b"\n")
            proc.popen.stdin.flush()
        send(INITIALIZE.strip())
        proc.wait_for_output(b'"id":1')
        send(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
        send(b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"copy_to_clipboard","arguments":{"path":"github"}}}')
        proc.wait_for_output(b'"id":2')
        assert b'"isError":false' in bytes(proc.out), ("copy_to_clipboard failed", bytes(proc.out)[-300:])
        assert events.read_text().split() == ["secret"], "control: the fake tool must hold the secret before the signal"
        proc.popen.send_signal(getattr(signal, sig))
        try:
            proc.popen.wait(timeout=DIE_WINDOW if sig != "SIGHUP" else SURVIVE_WINDOW)
            serving = False
        except subprocess.TimeoutExpired:
            send(b'{"jsonrpc":"2.0","id":3,"method":"ping"}')
            proc.wait_for_output(b'"id":3')
            serving = True
        # The fake tool is a child of the server and may finish after the server exited.
        deadline = time.monotonic() + 5
        while events.read_text().split() != ["secret", "clear"] and time.monotonic() < deadline:
            time.sleep(0.02)
        record = dict(case=name, command="mcp-clipboard-armed", signal=sig, serving_after_signal=serving,
                      ending=None if serving else ending(proc.popen.returncode),
                      clipboard_events=events.read_text().split())
    finally:
        proc.kill()
    return record


def ui_clipboard_case(go, base, template, sig):
    """Go only: `ui` on a pseudo-terminal copies the selected entry (an armed auto-clear), then gets `sig`.

    Same fake-pasteboard PATH as `clipboard_case`: the real pasteboard is never touched. Go's
    `StartAutoClear` subscription takes SIGINT, SIGTERM and SIGHUP: SIGHUP clears and `ui`
    keeps running (a second SIGHUP, with nothing armed, kills it by the signal); SIGQUIT is not
    subscribed, so Go dumps goroutines, exits 2 and leaves the secret on the clipboard.
    """
    name = f"ui-clipboard-armed-{sig.lower()}"
    home = new_home(base, template, name)
    fake = home / "fakebin"
    fake.mkdir()
    for tool in FAKE_CLIPBOARD_TOOLS:
        (fake / tool).write_text(FAKE_CLIPBOARD)
        (fake / tool).chmod(0o755)
    checked([go, "--vault", home / "vault", "set", "github", "--value", CLIPBOARD_SECRET], cwd=home, env=isolated(home))
    env = isolated(home)
    env["PATH"] = f"{fake}:/bin"
    env["TERM"] = "xterm-256color"
    events = fake / "events"

    def logged():
        return events.read_text().split() if events.exists() else []

    master, slave = pty.openpty()
    screen = bytearray()
    popen = subprocess.Popen([str(go), "ui"], cwd=home, env=env, stdin=slave, stdout=slave,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    os.close(slave)

    def wait_until(done, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end and not done():
            read_pty(master, screen, 0.05)
        return done()

    try:
        assert wait_until(lambda: ALT_SCREEN_ON in screen, 30), "ui never entered the alternate screen"
        read_pty(master, screen, 0.5)
        os.write(master, b"\r")  # Enter copies the selected entry's field
        assert wait_until(lambda: logged() == ["secret"], 10), ("control: the copy must reach the fake tool", logged())
        assert CLIPBOARD_SECRET.encode() not in screen, "control: the secret is never drawn"
        popen.send_signal(getattr(signal, sig))
        wait_until(lambda: popen.poll() is not None, SURVIVE_WINDOW if sig == "SIGHUP" else DIE_WINDOW)
        serving = popen.poll() is None
        record = dict(case=name, command="ui-clipboard-armed", signal=sig, serving_after_signal=serving,
                      ending=None if serving else ending(popen.returncode), second_ending=None)
        if serving:
            assert wait_until(lambda: logged() == ["secret", "clear"], 5), ("clear after signal", logged())
            popen.send_signal(signal.SIGHUP)  # nothing armed any more
            assert wait_until(lambda: popen.poll() is not None, DIE_WINDOW), "second SIGHUP must end ui"
            record["second_ending"] = ending(popen.returncode)
        # The fake tool is a child of the UI and may finish after it exited.
        wait_until(lambda: logged() == ["secret", "clear"], 3)
        record["clipboard_events"] = logged()
    finally:
        if popen.poll() is None:
            popen.kill()
            popen.wait()
        os.close(master)
    return record


HTTP_BINDING_MARKER = b"without TLS; bearer tokens travel in cleartext"
HTTP_CLIPBOARD_CASES = (  # (armed copy, signal, SIGHUP inherited as SIG_IGN)
    (True, "SIGINT", False), (True, "SIGTERM", False), (True, "SIGHUP", False),
    (False, "SIGHUP", False), (True, "SIGHUP", True), (False, "SIGHUP", True),
)


def free_loopback_port():
    with socket.socket() as selection:
        selection.bind(("127.0.0.1", 0))
        return selection.getsockname()[1]


def http_post(port, token, body):
    """One JSON-RPC POST to /mcp; returns (status, body bytes)."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request("POST", "/mcp", body=body, headers={
            "Authorization": f"Bearer {token}", "X-Symaira-Agent": "fixture", "Origin": f"http://127.0.0.1:{port}",
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def http_clipboard_case(go, base, seed_home, token, armed, sig, ignored=False):
    """Go only: HTTP `mcp` receives `sig`, with or without an armed clipboard auto-clear timer.

    Go arms `StartAutoClear` for `copy_to_clipboard` over HTTP too, and that timer (not `serve`)
    is the only subscriber of SIGHUP. Fake pasteboard tools sit first on a PATH that cannot reach
    the real ones, so the real pasteboard is never touched. `ignored` starts the server with SIGHUP
    inherited as SIG_IGN (`nohup`). The record notes whether the server kept serving after the
    signal (answered a ping), how each further signal ended it, and what the fake tool saw.
    """
    name = f"mcp-http-clipboard-{'armed' if armed else 'idle'}-{'ignored-' if ignored else ''}{sig.lower()}"
    home = new_home(base, seed_home, name)
    fake = home / "fakebin"
    fake.mkdir()
    for tool in FAKE_CLIPBOARD_TOOLS:
        (fake / tool).write_text(FAKE_CLIPBOARD)
        (fake / tool).chmod(0o755)
    config = home / "vault" / "config.yaml"
    text = config.read_text()
    patched = text.replace("        canReadValues: true\n", "        canReadValues: true\n        canUseClipboard: true\n", 2)
    assert patched.count("canUseClipboard: true") == 2, ("the fixture config changed", text)
    config.write_text(patched)
    port = free_loopback_port()
    env = isolated(home)
    env["PATH"] = f"{fake}:/bin"
    proc = Proc([go, "--quiet", "mcp", "--bind", "127.0.0.1", "--port", str(port)], home, stdin=subprocess.PIPE,
                env=env, ignore=("SIGHUP",) if ignored else ())
    events = fake / "events"

    def logged():
        return events.read_text().split() if events.exists() else []

    def ping_answered():
        status, body = http_post(port, token, '{"jsonrpc":"2.0","id":9,"method":"ping"}')
        return status == 200 and b'"id":9' in body

    try:
        proc.popen.stdin.write(b"y\n")  # the cleartext-bind confirmation is part of the CLI contract
        proc.popen.stdin.close()
        deadline = time.monotonic() + 30
        while HTTP_BINDING_MARKER not in bytes(proc.err) or not listener_open(port):
            assert proc.popen.poll() is None, ("server exited before serving", bytes(proc.err)[-500:])
            assert time.monotonic() < deadline, "server never listened"
            time.sleep(0.02)
        initialize = INITIALIZE.decode().strip()
        assert http_post(port, token, initialize)[0] == 200, "initialize must succeed"
        if armed:
            status, body = http_post(port, token, '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'
                                     '{"name":"copy_to_clipboard","arguments":{"path":"public/fixture"}}}')
            assert status == 200 and b'"isError":false' in body, ("copy_to_clipboard failed", status, body[-300:])
            assert logged() == ["secret"], ("control: the fake tool must hold the secret before the signal", logged())
        else:
            assert logged() == [], ("control: nothing may touch the clipboard before the signal", logged())
        proc.popen.send_signal(getattr(signal, sig))
        try:
            proc.popen.wait(timeout=SURVIVE_WINDOW if sig == "SIGHUP" else DIE_WINDOW)
            serving = False
        except subprocess.TimeoutExpired:
            serving = ping_answered()
        record = dict(case=name, command="mcp-http-clipboard", armed=armed, signal=sig, ignored=ignored,
                      serving_after_signal=serving, ending=None if serving else ending(proc.popen.returncode),
                      second_ending=None, final_ending=None)
        if serving:
            # A second SIGHUP finds no armed timer. Inherited SIG_IGN is then back in force.
            if not survived_signal(proc, proc.popen.send_signal, signal.SIGHUP, should_die=not ignored):
                record["second_ending"] = ending(proc.popen.returncode)
            else:
                proc.popen.send_signal(signal.SIGTERM)
                record["final_ending"] = ending(proc.finish())
        # The fake tool is a child of the server and may finish after the server exited.
        deadline = time.monotonic() + 3
        while armed and logged() != ["secret", "clear"] and time.monotonic() < deadline:
            time.sleep(0.02)
        record["clipboard_events"] = logged()
    finally:
        proc.kill()
    return record


def exercise_go_only(go, base, template, seed_home, token):
    return ([clipboard_case(go, base, template, sig) for sig in ("SIGINT", "SIGTERM", "SIGHUP")]
            + [ui_clipboard_case(go, base, template, sig) for sig in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT")]
            + [http_clipboard_case(go, base, seed_home, token, armed, sig, ignored)
               for armed, sig, ignored in HTTP_CLIPBOARD_CASES])


GO_EXPECTED_CLIPBOARD = {  # (serving after the signal, ending when it stopped)
    "SIGINT": (False, ["exit", 0]), "SIGTERM": (False, ["exit", 0]), "SIGHUP": (True, None),
}
# `ui` with an armed copy: (serving after the signal, ending, ending after a second SIGHUP, events).
# SIGQUIT is not part of Go's auto-clear subscription, so Go leaves the secret on the clipboard.
GO_EXPECTED_UI_CLIPBOARD = {
    "SIGINT": (False, ["exit", 1], None, ["secret", "clear"]),
    "SIGTERM": (False, ["exit", 0], None, ["secret", "clear"]),
    "SIGHUP": (True, None, ["signal", signal.SIGHUP], ["secret", "clear"]),
    "SIGQUIT": (False, ["exit", 2], None, ["secret"]),
}
# HTTP `mcp` (real Go process): (armed copy, signal, SIGHUP inherited as SIG_IGN) ->
# (serving after the signal, ending when it stopped, ending after a second SIGHUP, ending after the
# follow-up SIGTERM, fake-tool event logs that are acceptable). Go exits 0 on SIGINT/SIGTERM
# usually before its timer's clear reaches the tool (13 of 14 measured runs), so both logs are
# acceptable there; Rust always clears (declared Rust-safer difference). SIGHUP is subscribed by
# the armed timer only: it clears and the server keeps serving, nothing armed it kills the process
# by the signal, and an inherited SIG_IGN is overridden while armed and back in force afterwards.
SECRET, SECRET_CLEAR = ["secret"], ["secret", "clear"]
GO_EXPECTED_HTTP_CLIPBOARD = {
    (True, "SIGINT", False): (False, ["exit", 0], None, None, (SECRET, SECRET_CLEAR)),
    (True, "SIGTERM", False): (False, ["exit", 0], None, None, (SECRET, SECRET_CLEAR)),
    (True, "SIGHUP", False): (True, None, ["signal", signal.SIGHUP], None, (SECRET_CLEAR,)),
    (False, "SIGHUP", False): (False, ["signal", signal.SIGHUP], None, None, ([],)),
    (True, "SIGHUP", True): (True, None, None, ["exit", 0], (SECRET_CLEAR,)),
    (False, "SIGHUP", True): (True, None, None, ["exit", 0], ([],)),
}


def check_go_only(records):
    """The Go clipboard records must show clear-then-shutdown (SIGINT/SIGTERM) or clear-and-serve (SIGHUP)."""
    mcp = [r for r in records if r["command"] == "mcp-clipboard-armed"]
    ui = [r for r in records if r["command"] == "ui-clipboard-armed"]
    http = [r for r in records if r["command"] == "mcp-http-clipboard"]
    assert len(mcp) + len(ui) + len(http) == len(records), ("go_only commands", [r["case"] for r in records])
    assert [(r["armed"], r["signal"], r["ignored"]) for r in http] == list(GO_EXPECTED_HTTP_CLIPBOARD), \
        ("go_only http cases", [r["case"] for r in http])
    assert [r["signal"] for r in mcp] == list(GO_EXPECTED_CLIPBOARD), ("go_only mcp cases", [r["case"] for r in mcp])
    assert [r["signal"] for r in ui] == list(GO_EXPECTED_UI_CLIPBOARD), ("go_only ui cases", [r["case"] for r in ui])
    for record in mcp:
        serving, final = GO_EXPECTED_CLIPBOARD[record["signal"]]
        assert record["serving_after_signal"] is serving, ("oracle drifted: clipboard signal", record)
        assert record["ending"] == final, ("oracle drifted: clipboard signal", record)
        assert record["clipboard_events"] == ["secret", "clear"], ("oracle drifted: clipboard clear", record)
    for record in ui:
        serving, final, second, events = GO_EXPECTED_UI_CLIPBOARD[record["signal"]]
        assert record["serving_after_signal"] is serving, ("oracle drifted: ui clipboard signal", record)
        assert record["ending"] == final, ("oracle drifted: ui clipboard signal", record)
        assert record["second_ending"] == second, ("oracle drifted: ui second SIGHUP", record)
        assert record["clipboard_events"] == events, ("oracle drifted: ui clipboard clear", record)
    for record in http:
        serving, final, second, after, events = GO_EXPECTED_HTTP_CLIPBOARD[(record["armed"], record["signal"], record["ignored"])]
        assert record["serving_after_signal"] is serving, ("oracle drifted: http clipboard signal", record)
        assert record["ending"] == final, ("oracle drifted: http clipboard signal", record)
        assert record["second_ending"] == second, ("oracle drifted: http second SIGHUP", record)
        assert record["final_ending"] == after, ("oracle drifted: http follow-up SIGTERM", record)
        assert record["clipboard_events"] in events, ("oracle drifted: http clipboard clear", record)


def exercise(binary, base, template):
    binary = Path(binary)
    records = []
    for command in ("broker", "intake-watch"):
        for sig in KILLING:
            records.append(foreground_case(binary, base, template, command, sig))
    for command in ("run", "run-broker"):
        for sig in KILLING:
            records.append(run_case(binary, base, template, command, sig, False))
        for sig in ("SIGINT", "SIGTERM"):
            records.append(run_case(binary, base, template, command, sig, True))
    records.append(run_case(binary, base, template, "run", "SIGINT", True, ("--timeout", "60s"), "-timeout"))
    for command, sig in IGNORED_CASES:
        if command in ("broker", "intake-watch"):
            records.append(foreground_case(binary, base, template, command, sig, ignored=True))
        else:
            records.append(run_case(binary, base, template, command, sig, False, ignored=True))
    for sig in KILLING:
        records.append(locked_case(binary, base, template, sig))
    for sig in KILLING:
        records.append(ui_case(binary, base, template, sig))
    return records


def compare(go, rust):
    """Raise AssertionError on the first observable difference."""
    assert [r["case"] for r in go] == [r["case"] for r in rust], "different case lists"
    for left, right in zip(go, rust):
        name = left["case"]
        keys = ["ending", "stdout", "stderr", "listener_closed", "orphaned_child_alive",
                "ignored", "survived", "listener_open_after_ignored_signal",
                "terminal_restored", "alt_screen_left"]
        for key in keys:
            assert left.get(key) == right.get(key), (name, key, left.get(key), right.get(key))
        go_state, rust_state = list(left["state"]), list(right["state"])
        if left["command"].startswith(("broker", "run-broker")):
            # Documented difference: Go leaves its persistent public CA file in the vault.
            go_state = [n for n in go_state if n != f"vault/{CA_NAME}"]
        assert go_state == rust_state, (name, "on-disk state", go_state, rust_state)
        assert not any(".broker-ca-" in n for n in right["state"]), (name, "temporary CA left behind", right["state"])


def check_oracle_expectations(go):
    for record in go:
        key = (record["command"], record["signal"])
        if record.get("ignored"):
            assert key in GO_EXPECTED_IGNORED, ("unexpected ignored-disposition case", key)
            survived, final = GO_EXPECTED_IGNORED[key]
            assert record["survived"] is survived, ("oracle drifted: ignored disposition", key, record["survived"])
            assert record["ending"] == list(final), ("oracle drifted: ignored disposition", key, record["ending"])
            if survived and record["command"] == "broker":
                assert record["listener_open_after_ignored_signal"] is True, ("listener must survive", key)
        elif key in GO_EXPECTED:
            assert record["ending"] == list(GO_EXPECTED[key]), ("oracle drifted", key, record["ending"])
        if record["command"] == "mcp-locked":
            assert record["state"].count("vault/.runtime-port") == (record["signal"] == "SIGHUP"), \
                ("Go clears the runtime port record on a handled signal only", record["case"], record["state"])
            quit_line = "Received SIGQUIT, shutting down gracefully...\n"
            assert record["stderr"] == LOCKED_WARNING + (quit_line if record["signal"] == "SIGQUIT" else ""), \
                ("oracle drifted: locked stderr", record["case"], record["stderr"])
        if record["command"] == "ui":
            assert record["terminal_restored"] is GO_EXPECTED_UI_TERMINAL[record["signal"]], ("oracle drifted: terminal", record["case"])
            assert record["alt_screen_left"] is GO_EXPECTED_UI_TERMINAL[record["signal"]], ("oracle drifted: alt screen", record["case"])
            if record["signal"] == "SIGINT":
                assert record["stderr"] == UI_INTERRUPTED * 2, ("oracle drifted: ui interrupt message", record["stderr"])
            elif record["signal"] != "SIGQUIT":
                assert record["stderr"] == "", ("oracle drifted: ui stderr", record["case"], record["stderr"])
        if record["command"] in ("broker", "run-broker") and "group" not in record["case"]:
            assert record["state"].count(f"vault/{CA_NAME}") == 1, ("Go keeps its persistent CA file", record["case"])
        if record["command"] in ("run", "run-broker"):
            assert record["orphaned_child_alive"] is True, ("Go leaves the child running", record["case"])
        if record["command"].endswith("-group"):
            assert record["ending"] == ["signal", getattr(signal, record["signal"])]
            assert record["orphaned_child_alive"] is False


def build_oracle(destination):
    archive = checked(["git", "archive", ORACLE])
    source = destination / "src"
    source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter="data")
    helper = source / "scripts/rust-port/cmd/httpprocessseed"
    helper.mkdir(parents=True)
    (helper / "main.go").write_bytes(SEED.read_bytes())
    env = dict(os.environ, GOWORK="off")
    binary, seed = destination / "symvault-go", destination / "symvault-seed"
    for output, package in ((binary, "."), (seed, "./scripts/rust-port/cmd/httpprocessseed")):
        checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", output, package], cwd=source, env=env, timeout=600)
    return binary, seed


def make_template(go, base):
    template = base / "template"
    template.mkdir()
    checked([go, "init", "--auth", "passphrase"], cwd=template, env=isolated(template))
    shutil.rmtree(template / "tmp")
    return template


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--go", type=Path, help="prebuilt oracle (development only; default builds ORACLE; needs --go-seed)")
    parser.add_argument("--go-seed", type=Path, help="prebuilt HTTP fixture seed helper (development only)")
    parser.add_argument("--expect-mismatch", action="store_true",
                        help="negative control: PASS only if the Rust binary differs from Go")
    parser.add_argument("--allow-dirty-for-development", action="store_true")
    args = parser.parse_args()
    if os.name == "nt":
        sys.exit("signal_process_contract.py is Unix-only; Windows Ctrl-Break evidence lives in "
                 "egress_contract.py and intake_watch_contract.py. Refusing to report a vacuous pass.")
    rust = args.rust.resolve()
    assert rust.is_file(), "a real Rust CLI binary is required"
    clean = not checked(["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    assert clean or args.allow_dirty_for_development or args.expect_mismatch, "commit the candidate first"
    receipt = dict(oracle_commit=ORACLE, candidate_commit=checked(["git", "rev-parse", "HEAD"]).decode().strip(),
                   candidate_worktree_clean=clean, native_os=platform.system(), architecture=platform.machine(),
                   rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(),
                   driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   seed_sha256=hashlib.sha256(SEED.read_bytes()).hexdigest(),
                   keyring="memory", expect_mismatch=args.expect_mismatch, go=[], rust=[], go_only=[], passed=False)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="symvault-signals-") as raw:
        base = Path(raw)
        go, seed = (args.go.resolve(), args.go_seed.resolve()) if args.go else build_oracle(base)
        receipt["go_binary_sha256"] = hashlib.sha256(go.read_bytes()).hexdigest()
        template = make_template(go, base)
        go_root, rust_root = base / "go", base / "rust"
        go_root.mkdir()
        rust_root.mkdir()
        receipt["go"] = exercise(go, go_root, template)
        check_oracle_expectations(receipt["go"])
        seed_home = base / "http-seed"
        seed_home.mkdir()
        tokens = json.loads(checked([seed, "--root", seed_home / "vault"], cwd=seed_home, env=isolated(seed_home)))
        receipt["go_only"] = exercise_go_only(go, go_root, template, seed_home, tokens["full"])
        check_go_only(receipt["go_only"])
        receipt["rust"] = exercise(rust, rust_root, template)
        try:
            compare(receipt["go"], receipt["rust"])
            mismatch = None
        except AssertionError as error:
            mismatch = repr(error)[:2000]
        receipt["mismatch"] = mismatch or ""
        receipt["passed"] = (mismatch is not None) if args.expect_mismatch else (mismatch is None)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    if not receipt["passed"]:
        sys.exit(f"FAIL: {mismatch or 'negative control was NOT rejected'}")
    if args.expect_mismatch:
        print(f"PASS (negative control): mutant rejected: {mismatch}")
    else:
        print(f"PASS: {len(receipt['go'])} actual Go/Rust signal observations and {len(receipt['go_only'])} "
              f"Go-only clipboard observations on {platform.system()}")


if __name__ == "__main__":
    main()
