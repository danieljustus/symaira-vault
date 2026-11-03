#!/usr/bin/env python3
"""MCP-003/HTTP-004/CLI-007: real Go/Rust graceful drain of `mcp` over HTTP.

Unix only. A disposable vault is seeded by the Go fixture helper; the Go oracle
and the Rust binary then serve it in separate disposable HOMEs. Each case
signals the real server while a real request is in flight and records what the
peer saw (status, headers, body, close, timing class), the exit status, the
stdout/stderr bytes and the on-disk effect (runtime port/TLS records).

Go's order (cmd/mcp/serve_deps.go + serverbootstrap http_lifecycle.go): the
first SIGINT/SIGTERM/SIGQUIT cancels the serving context; the listener closes,
idle keep-alive transports close, requests in flight run for up to
MCP.shutdown_timeout (5 s); what is still open is force-closed; the runtime
records are cleared; the process exits 0 without output (SIGQUIT first prints
one warning). A request that reaches /mcp after the cancel gets 403 `context
canceled`. A second signal is swallowed.
"""
import argparse
import base64
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

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_timeout import oracle_build_timeout  # noqa: E402
from mcp_process_contract import (HTTP_BINDING_MARKER, ORACLE, PipeCapture, checked, free_loopback_port,  # noqa: E402
                                  isolated, normalise_process_text, settled_snapshot,
                                  snapshot_delta, stop_group, tree_snapshot)

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "scripts/rust-port/http_process_seed.go.txt"
DRAIN_SECONDS = 5.0  # MCP.shutdown_timeout default
INIT = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",'
        '"clientInfo":{"name":"drain","version":"1"},"capabilities":{}}}')
PING = '{"jsonrpc":"2.0","id":2,"method":"ping"}'
SIGNALS = {"SIGINT": signal.SIGINT, "SIGTERM": signal.SIGTERM, "SIGQUIT": signal.SIGQUIT}

# case -> (command seconds or None, exit window in seconds after the signal)
# A window must hold for BOTH implementations; it guards against a vacuous
# differential (an immediate exit or a hang), the comparison does the rest.
CASES = {
    "idle-keepalive": (None, (0.0, 3.0)),
    "inflight-within": (2, (1.0, 4.5)),
    "inflight-keepalive": (2, (1.0, 4.5)),
    "inflight-exceeds": (9, (4.5, 8.0)),
    "slowbody-within": (None, (0.8, 3.5)),
    "slowbody-exceeds": (None, (4.5, 8.0)),
    "second-signal": (3, (2.0, 4.8)),
}
RUNS = [(case, name) for case in CASES for name in ("SIGINT", "SIGTERM")] + [("inflight-within", "SIGQUIT")]
GO_EXPECTED = {
    # case -> (peer outcome, status the peer saw)
    "idle-keepalive": ("closed-at-once", 200),
    "inflight-within": ("completed", 200),
    "inflight-keepalive": ("completed", 200),
    "inflight-exceeds": ("force-closed-empty", None),
    "slowbody-within": ("completed", 403),
    "slowbody-exceeds": ("force-closed-empty", None),
    "second-signal": ("completed", 200),
}


def request_head(port, token, length, keep_alive=False):
    connection = "keep-alive" if keep_alive else "close"
    return (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: {connection}\r\n"
            f"Authorization: Bearer {token}\r\nX-Symaira-Agent: fixture\r\nOrigin: http://127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"
            f"Content-Length: {length}\r\n\r\n").encode()


def full_request(port, token, body, keep_alive=False):
    body = body.encode()
    return request_head(port, token, len(body), keep_alive) + body


def run_call(seconds, marker):
    """A real tool call that signals readiness, then stays in flight."""
    # `exec` keeps the shell's pid for the sleeper, so the marker names the process to reap.
    script = f"echo $$ > '{marker}'; exec sleep {seconds}"
    return json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "run_command", "arguments": {"command": ["sh", "-c", script]}}})


def parse_response(raw):
    """Status, headers without Date and a normalized body; None when nothing arrived."""
    if not raw:
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    headers = sorted((k.lower(), v.strip()) for k, v in (line.split(":", 1) for line in lines[1:]))
    headers = [h for h in headers if h[0] != "date"]
    text = body.decode("utf-8", "replace")
    # Per-run randomness only: elapsed time and the data-marker ids.
    text = re.sub(r'duration_ms\\*"?:\d+', "duration_ms:N", text)
    text = re.sub(r"DATA_[0-9a-f]{16}", "DATA_ID", text)
    return {"status_line": lines[0], "headers": headers, "body": text}


class Peer(threading.Thread):
    """One real client connection that sends `parts` and reads until the server closes it.

    A part is `(gate, data)`; `gate` is None or an Event the part waits for."""

    def __init__(self, port, parts):
        super().__init__(daemon=True)
        self.port, self.parts = port, parts
        self.raw = bytearray()
        self.end = None  # how the connection ended
        self.ended_at = None
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=30)

    def run(self):
        try:
            for gate, data in self.parts:
                if gate is not None:
                    assert gate.wait(30), "the driver never released the next part"
                self.sock.sendall(data)
        except OSError as error:
            self.send_error = type(error).__name__
        while True:
            try:
                chunk = self.sock.recv(65536)
            except OSError as error:
                self.end = type(error).__name__
                break
            if not chunk:
                self.end = "eof"
                break
            self.raw += chunk
        self.ended_at = time.monotonic()
        self.sock.close()

    send_error = None


def wait_until(predicate, timeout, what):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, what
        time.sleep(0.01)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def listener_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


def run_case(binary, home, tokens, case, sig_name):
    seconds, window = CASES[case]
    port = free_loopback_port()
    marker = home.parent / f"{home.name}.started"
    process = subprocess.Popen([str(binary), "--quiet", "mcp", "--bind", "127.0.0.1", "--port", str(port)],
                               cwd=home, env=isolated(home), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    capture = PipeCapture(process)
    row = {"case": case, "signal": sig_name}
    token = tokens["full"]
    command_pid = None
    try:
        process.stdin.write(b"y\n")  # the cleartext-bind confirmation is part of the CLI contract
        process.stdin.close()
        process.stdin = None
        deadline = time.monotonic() + 30
        assert capture.wait_for("stderr", lambda data: HTTP_BINDING_MARKER in data, deadline), "server never announced"
        wait_until(lambda: process.poll() is not None or listener_open(port), 30, "server never listened")
        assert process.poll() is None, "server exited before serving"
        # One real initialize creates the agent session the tool call needs.
        first = Peer(port, [(None, full_request(port, token, INIT))])
        first.start()
        first.join(30)
        assert parse_response(bytes(first.raw))["status_line"] == "HTTP/1.1 200 OK", "initialize must succeed"
        ready = settled_snapshot(home, time.monotonic() + 5)

        peer, keep_first, release, command_pid = None, None, threading.Event(), None
        if case == "idle-keepalive":
            peer = Peer(port, [(None, full_request(port, token, PING, keep_alive=True))])
            peer.start()
            # The keep-alive response is complete once its JSON body arrived.
            wait_until(lambda: b"\r\n\r\n" in bytes(peer.raw) and bytes(peer.raw).endswith(b"}\n"), 15, "keep-alive reply")
            keep_first = parse_response(bytes(peer.raw))
        elif case in ("inflight-within", "inflight-keepalive", "inflight-exceeds", "second-signal"):
            peer = Peer(port, [(None, full_request(port, token, run_call(seconds, marker), case == "inflight-keepalive"))])
            peer.start()
            wait_until(lambda: marker.exists() and marker.read_text().strip().isdigit(), 30,
                       "the in-flight command never started")
            command_pid = int(marker.read_text())
        else:  # slowbody-*: a complete header block and one byte of the body
            body = PING.encode()
            parts = [(None, request_head(port, token, len(body)) + body[:1])]
            if case == "slowbody-within":
                parts.append((release, body[1:]))
            peer = Peer(port, parts)
            peer.start()
            time.sleep(0.5)  # the server has read the header block; no readiness signal exists for a partial body
            assert process.poll() is None

        sent = time.monotonic()
        os.kill(process.pid, SIGNALS[sig_name])
        if case == "slowbody-within":
            threading.Timer(1.0, release.set).start()  # the body completes inside the drain window
        during = None
        if case in ("inflight-within", "inflight-keepalive", "second-signal"):
            time.sleep(0.4)
            during = "accepted" if listener_open(port) else "refused"
        if case == "second-signal":
            time.sleep(0.4)
            os.kill(process.pid, SIGNALS[sig_name])
            time.sleep(0.2)
            os.kill(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired as error:
            raise AssertionError(f"{case}/{sig_name}: process did not exit after the signal") from error
        exited = time.monotonic() - sent
        # Neither implementation takes the command down with the server (Go leaves it in the server's
        # group, Rust in its own). Read this before the group cleanup below can end it, then reap it.
        row["command_outlives_server"] = None if command_pid is None else pid_alive(command_pid)
        if command_pid is not None and pid_alive(command_pid):
            os.kill(command_pid, signal.SIGKILL)
            wait_until(lambda: not pid_alive(command_pid), 10, "the harness could not reap its command")
        peer.join(10)
        assert not peer.is_alive(), "peer never saw the server close"
        response = parse_response(bytes(peer.raw))
        row.update(exit_elapsed=round(exited, 3), peer_closed_after=round(peer.ended_at - sent, 3),
                   in_window=window[0] <= exited <= window[1])
    finally:
        if process.poll() is None:
            stop_group(process)
            process.wait(timeout=15)
        stop_group(process)
        if command_pid is not None and pid_alive(command_pid):  # only after a failure above
            os.kill(command_pid, signal.SIGKILL)
        stdout, stderr = capture.finish()
        marker.unlink(missing_ok=True)
    row["listener_closed"] = not listener_open(port)
    final = tree_snapshot(home)
    if case == "idle-keepalive":
        # The peer's bytes must still be exactly the first keep-alive reply: closed, nothing more sent.
        outcome = "closed-at-once" if response == keep_first else "unexpected-extra-bytes"
        response = keep_first
    elif response is None:
        outcome = "force-closed-empty"
    else:
        outcome = "completed"
    row.update(outcome=outcome, response=response, peer_end=("eof" if peer.end == "eof" else "reset"),
               during_drain=during, exit_code=process.returncode, stdout=stdout.decode("utf-8"),
               stderr=normalise_process_text(stderr.decode("utf-8"), home), delta=snapshot_delta(ready, final),
               runtime_records=sorted(name for name in os.listdir(home / "vault") if name.startswith(".runtime")))
    return row


def exercise(binary, base, seed_vault, tokens, label):
    rows = []
    for index, (case, sig_name) in enumerate(RUNS):
        home = base / f"{label}-{index}-{case}-{sig_name}"
        home.mkdir()
        shutil.copytree(seed_vault, home / "vault")
        row = run_case(binary, home, tokens, case, sig_name)
        row["implementation"] = label
        rows.append(row)
    return rows


def compare(go, rust):
    """Raise AssertionError on the first observable difference."""
    assert [(r["case"], r["signal"]) for r in go] == [(r["case"], r["signal"]) for r in rust], "different case lists"
    for left, right in zip(go, rust):
        key = (left["case"], left["signal"])
        for field in ("exit_code", "stdout", "stderr", "outcome", "response", "peer_end", "during_drain",
                      "listener_closed", "command_outlives_server", "in_window", "runtime_records", "delta"):
            assert left.get(field) == right.get(field), (key, field, left.get(field), right.get(field))


def check_oracle(go):
    """What the Go oracle must do; a drifted or vacuous oracle fails before any comparison."""
    for row in go:
        key = (row["case"], row["signal"])
        outcome, status = GO_EXPECTED[row["case"]]
        assert row["exit_code"] == 0 and row["in_window"] and row["listener_closed"], ("oracle drifted", key, row)
        assert row["outcome"] == outcome, ("oracle drifted: peer outcome", key, row["outcome"])
        assert (int(row["response"]["status_line"].split()[1]) if row["response"] else None) == status, ("oracle status", key)
        assert row["runtime_records"] == [] and "vault/.runtime-port" in row["delta"]["removed"], ("records cleared", key)
        assert row["stdout"] == "", ("oracle stdout", key)
        if row["case"] == "inflight-exceeds":
            assert row["command_outlives_server"] is True, ("an uncooperative command outlives the server", key)
        assert ("Received SIGQUIT" in row["stderr"]) == (row["signal"] == "SIGQUIT"), ("SIGQUIT warning", key)
        if row["case"] in ("inflight-within", "inflight-keepalive", "second-signal"):
            assert row["during_drain"] == "refused", ("listener must close at the start of the drain", key)
            assert '"isError":false' in row["response"]["body"], ("the command must have completed", key)
        if row["case"] == "inflight-keepalive":
            assert ("connection", "close") in row["response"]["headers"], ("Go closes after a drained reply", key)
        if row["case"] == "slowbody-within":
            assert "context canceled" in row["response"]["body"], ("Go answers 403 context canceled", key)


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
    go, seed = destination / "symvault-go", destination / "symvault-seed"
    for output, package in ((go, "."), (seed, "./scripts/rust-port/cmd/httpprocessseed")):
        checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", output, package], cwd=source, env=env,
                timeout=oracle_build_timeout())
    return go, seed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--go", type=Path, help="prebuilt Go oracle (development only; needs --go-seed)")
    parser.add_argument("--go-seed", type=Path, help="prebuilt Go fixture seed helper (development only)")
    parser.add_argument("--expect-mismatch", action="store_true",
                        help="negative control: PASS only if the Rust binary differs from Go")
    parser.add_argument("--allow-dirty-for-development", action="store_true")
    args = parser.parse_args()
    if os.name == "nt":
        sys.exit("http_drain_contract.py is Unix-only; refusing to report a vacuous pass.")
    rust = args.rust.resolve()
    assert rust.is_file(), "a real Rust CLI binary is required"
    clean = not checked(["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    assert clean or args.allow_dirty_for_development or args.expect_mismatch, "commit the candidate first"
    receipt = dict(oracle_commit=ORACLE, candidate_commit=checked(["git", "rev-parse", "HEAD"]).decode().strip(),
                   candidate_worktree_clean=clean, native_os=platform.system(), architecture=platform.machine(),
                   rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(),
                   driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   seed_sha256=hashlib.sha256(SEED.read_bytes()).hexdigest(), drain_seconds=DRAIN_SECONDS,
                   expect_mismatch=args.expect_mismatch, go=[], rust=[], mismatch="", passed=False)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    try:
        with tempfile.TemporaryDirectory(prefix="symvault-http-drain-") as raw:
            base = Path(raw)
            go, seed = (args.go.resolve(), args.go_seed.resolve()) if args.go else build_oracle(base)
            receipt["go_binary_sha256"] = hashlib.sha256(go.read_bytes()).hexdigest()
            seed_home = base / "seed"
            seed_home.mkdir()
            tokens = json.loads(checked([seed, "--root", seed_home / "vault"], cwd=seed_home, env=isolated(seed_home)))
            roots = {name: base / name for name in ("go", "rust")}
            for root in roots.values():
                root.mkdir()
            receipt["go"] = exercise(go, roots["go"], seed_home / "vault", tokens, "go")
            check_oracle(receipt["go"])
            receipt["rust"] = exercise(rust, roots["rust"], seed_home / "vault", tokens, "rust")
            try:
                compare(receipt["go"], receipt["rust"])
            except AssertionError as error:
                receipt["mismatch"] = repr(error)[:2000]
            receipt["passed"] = bool(receipt["mismatch"]) if args.expect_mismatch else not receipt["mismatch"]
        receipt["candidate_worktree_clean_at_end"] = not checked(
            ["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    finally:
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    if not receipt["passed"]:
        sys.exit(f"FAIL: {receipt['mismatch'] or 'negative control was NOT rejected'}")
    if args.expect_mismatch:
        print(f"PASS (negative control): mutant rejected: {receipt['mismatch']}")
    else:
        print(f"PASS: {len(receipt['go'])} actual Go/Rust HTTP drain observations on {platform.system()}")


if __name__ == "__main__":
    main()
