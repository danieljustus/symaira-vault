#!/usr/bin/env python3
"""CLI-007: real Go/Rust signal behavior of `broker`, `run`, `run --broker`, `intake watch`.

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
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
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
}


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


class Proc:
    """A child with pipe readers, so a dead or orphan-holding child never blocks the driver."""

    def __init__(self, args, home, new_session=False):
        self.home = home
        self.out, self.err = bytearray(), bytearray()
        self.popen = subprocess.Popen([str(x) for x in args], cwd=home, env=isolated(home),
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
            raise AssertionError("process did not stop after the signal")
        finally:
            for thread in self.threads:
                thread.join(timeout=3)
        return self.popen.returncode

    def kill(self):
        if self.popen.poll() is None:
            self.popen.kill()
            self.popen.wait()


def ending(returncode):
    return ["signal", -returncode] if returncode < 0 else ["exit", returncode]


# Vault-owned names that exist after `init` or a plain vault open in either
# implementation (Go also creates .lock and manifest.age on open). Anything
# else at the vault top level, and every name outside the vault, is
# signal-relevant state: private TMPDIR files, CA directories, staging.
VAULT_BASELINE = {".git", ".gitignore", ".lock", ".symvault-migrated", "config.yaml", "entries",
                  "identity.age", "manifest.age"}


def snapshot(home):
    """Names (not contents) of signal-relevant state under HOME, excluding the driver's own files."""
    names = set()
    for path in home.rglob("*"):
        parts = path.relative_to(home).parts
        if parts in {("child.py",), ("child.pid",)}:
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


def case_record(name, command, sig, proc, home, **extra):
    stderr = normal(bytes(proc.err), home)
    record = dict(case=name, command=command, signal=sig, ending=ending(proc.popen.returncode),
                  stdout=normal(bytes(proc.out), home),
                  # Go's SIGQUIT goroutine dump is runtime-specific and unbounded;
                  # the exit status 2 and on-disk state are compared instead.
                  stderr="<not compared: Go SIGQUIT goroutine dump>" if sig == "SIGQUIT" else stderr,
                  state=snapshot(home))
    record.update(extra)
    return record


def foreground_case(binary, base, template, command, sig):
    """broker / intake watch: signal the parent only."""
    name = f"{command}-{sig.lower()}"
    home = new_home(base, template, name)
    (home / "inbox").mkdir()
    if command == "broker":
        args, ready = ["broker"], b"NO_PROXY=127.0.0.1,localhost\n"
    else:
        args, ready = ["intake", "watch", "inbox", "--interval", "1h"], b"Ctrl-C to stop.\n"
    proc = Proc([binary, *args], home)
    try:
        proc.wait_for_output(ready)
        port = None
        if command == "broker":
            found = re.search(rb"127\.0\.0\.1:(\d+)", bytes(proc.out))
            assert found, "broker did not announce its listener"
            port = int(found.group(1))
            assert listener_open(port), "control: listener must be open before the signal"
        assert proc.popen.poll() is None, "control: process must run until signalled"
        proc.popen.send_signal(getattr(signal, sig))
        proc.finish()
        extra = {} if port is None else dict(listener_closed=not listener_open(port))
        record = case_record(name, command, sig, proc, home, **extra)
    finally:
        proc.kill()
    return record


# A bounded run (--timeout) keeps the child in its own process group so a
# timeout can kill the tree (#1199); a terminal Ctrl-C therefore does not reach
# that child, unlike Go. Recorded and asserted so the exemption cannot go stale.
KNOWN_DIVERGENCES = {"run-timeout-group-sigint": "Rust bounded run isolates the child in its own process group"}


def run_case(binary, base, template, command, sig, group, extra=(), label=""):
    """run / run --broker with a long-lived child; signal the parent or its whole group."""
    name = f"{command}{label}-{'group-' if group else ''}{sig.lower()}"
    home = new_home(base, template, name)
    (home / "child.py").write_text(CHILD)
    pidfile = home / "child.pid"
    args = ["run", *(["--broker"] if command == "run-broker" else []), *extra, "--", sys.executable, home / "child.py", pidfile]
    proc = Proc([binary, *args], home, new_session=group)
    child = None
    try:
        deadline = time.monotonic() + 30
        while not (pidfile.exists() and pidfile.read_text()):
            assert proc.popen.poll() is None, ("run exited early", bytes(proc.err)[-500:])
            assert time.monotonic() < deadline, "child never started"
            time.sleep(0.02)
        child = int(pidfile.read_text())
        assert pid_alive(child), "control: child must run before the signal"
        assert proc.popen.poll() is None, "control: parent must wait for the child"
        if group:
            os.killpg(proc.popen.pid, getattr(signal, sig))
        else:
            proc.popen.send_signal(getattr(signal, sig))
        returncode = proc.finish()
        if group:
            orphan_alive = not wait_gone(child)
        else:
            time.sleep(0.2)  # a child that dies with its parent needs a moment
            orphan_alive = pid_alive(child)
        record = case_record(name, command + ("-group" if group else ""), sig, proc, home,
                             orphaned_child_alive=orphan_alive)
        assert returncode == proc.popen.returncode
    finally:
        proc.kill()
        # The child was started by this driver's process tree; reap it and prove it is gone.
        if child is not None and pid_alive(child):
            os.kill(child, signal.SIGKILL)
            assert wait_gone(child), "driver could not reap its own child"
    return record


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
    return records


def compare(go, rust):
    """Raise AssertionError on the first observable difference."""
    assert [r["case"] for r in go] == [r["case"] for r in rust], "different case lists"
    for left, right in zip(go, rust):
        name = left["case"]
        keys = ["ending", "stdout", "stderr", "listener_closed", "orphaned_child_alive"]
        if name in KNOWN_DIVERGENCES:
            assert (left["orphaned_child_alive"], right["orphaned_child_alive"]) == (False, True), \
                (name, "known divergence changed; remove the exemption", left["orphaned_child_alive"], right["orphaned_child_alive"])
            keys.remove("orphaned_child_alive")
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
        if key in GO_EXPECTED:
            assert record["ending"] == list(GO_EXPECTED[key]), ("oracle drifted", key, record["ending"])
        if record["command"] in ("broker", "run-broker") and "group" not in record["case"]:
            assert record["state"].count(f"vault/{CA_NAME}") == 1, ("Go keeps its persistent CA file", record["case"])
        if record["command"] in ("run", "run-broker"):
            assert record["orphaned_child_alive"] is True, ("Go leaves the child running", record["case"])
        if record["command"].endswith("-group") and record["case"] not in KNOWN_DIVERGENCES:
            assert record["ending"] == ["signal", getattr(signal, record["signal"])]
            assert record["orphaned_child_alive"] is False


def build_oracle(destination):
    archive = checked(["git", "archive", ORACLE])
    source = destination / "src"
    source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter="data")
    binary = destination / "symvault-go"
    env = dict(os.environ, GOWORK="off")
    checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "."], cwd=source, env=env, timeout=600)
    return binary


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
    parser.add_argument("--go", type=Path, help="prebuilt oracle (development only; default builds ORACLE)")
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
                   keyring="memory", expect_mismatch=args.expect_mismatch, go=[], rust=[], passed=False)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="symvault-signals-") as raw:
        base = Path(raw)
        go = args.go.resolve() if args.go else build_oracle(base)
        receipt["go_binary_sha256"] = hashlib.sha256(go.read_bytes()).hexdigest()
        template = make_template(go, base)
        go_root, rust_root = base / "go", base / "rust"
        go_root.mkdir()
        rust_root.mkdir()
        receipt["go"] = exercise(go, go_root, template)
        check_oracle_expectations(receipt["go"])
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
        print(f"PASS: {len(receipt['go'])} actual Go/Rust signal observations on {platform.system()}")


if __name__ == "__main__":
    main()
