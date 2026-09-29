#!/usr/bin/env python3
"""Drive the opt-in MCP approval acceptance through a real controlling PTY."""

import errno
import os
import pty
import select
import signal
import sys
import time


PROMPTS = (
    b"Approve this operation? (y/n): ",
    b"Approve this operation? (y/n/r, r=remember for session): ",
    b"Approve this operation? (y/n): ",
)
ANSWERS = (b"y\r", b"y\r", b"n\r")
TIMEOUT_SECONDS = 300


def reap_group(pid, grace_seconds):
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_seconds
    leader_reaped = False
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG) if not leader_reaped else (0, 0)
        except ChildProcessError:
            leader_reaped = True
            waited = 0
        if waited == pid:
            leader_reaped = True
        time.sleep(0.05)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if not leader_reaped:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


def stop_residual_group(pid):
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.025)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def main(argv):
    command = argv[1:] if len(argv) > 1 and argv[1] != "--" else argv[2:]
    if not command:
        print("usage: mcp-approval-pty.py -- COMMAND [ARG ...]", file=sys.stderr)
        return 2

    pid, master = pty.fork()
    if pid == 0:
        os.environ["SYMVAULT_PTY_ACCEPTANCE"] = "1"
        try:
            os.execvp(command[0], command)
        except OSError as error:
            os.write(2, f"PTY child exec failed: {error}\n".encode())
            os._exit(127)

    transcript = bytearray()
    sent = 0
    prompt_cursor = 0
    deadline = time.monotonic() + TIMEOUT_SECONDS
    status = None
    try:
        while status is None:
            if time.monotonic() >= deadline:
                print("PTY acceptance timed out", file=sys.stderr, flush=True)
                reap_group(pid, 2)
                status = 124 << 8
                break

            readable, _, _ = select.select([master], [], [], 0.05)
            if readable:
                try:
                    chunk = os.read(master, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        chunk = b""
                    else:
                        raise
                if chunk:
                    transcript.extend(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(sys.stdout.fileno(), view)
                        view = view[written:]
                    sys.stdout.flush()
                    while sent < len(ANSWERS):
                        prompt_at = transcript.find(PROMPTS[sent], prompt_cursor)
                        if prompt_at < 0:
                            break
                        prompt_cursor = prompt_at + len(PROMPTS[sent])
                        answer = memoryview(ANSWERS[sent])
                        while answer:
                            written = os.write(master, answer)
                            answer = answer[written:]
                        sent += 1

            waited, child_status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                status = child_status

        stop_residual_group(pid)

        drain_deadline = time.monotonic() + 2
        while time.monotonic() < drain_deadline:
            readable, _, _ = select.select([master], [], [], 0.05)
            if not readable:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            transcript.extend(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(sys.stdout.fileno(), view)
                view = view[written:]
            sys.stdout.flush()
    except BaseException:
        reap_group(pid, 1)
        raise
    finally:
        os.close(master)

    critical_prompts = transcript.count(PROMPTS[0])
    execute_prompts = transcript.count(PROMPTS[1])
    prompts = (transcript.count(PROMPTS[0]), execute_prompts, transcript.count(PROMPTS[2]))
    has_acceptance_receipt = b"PTY_ACCEPTANCE_RECEIPT " in transcript
    print(
        f"\nPTY_DRIVER_RECEIPT critical_prompts={critical_prompts} execute_prompts={execute_prompts} answers={sent} receipt={str(has_acceptance_receipt).lower()} bounded=true controlling_pty=true",
        flush=True,
    )
    exit_code = os.waitstatus_to_exitcode(status)
    if prompts != (2, 1, 2) or sent != len(ANSWERS) or not has_acceptance_receipt:
        print("PTY driver did not observe every real prompt or the MCP acceptance receipt", file=sys.stderr)
        return 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
