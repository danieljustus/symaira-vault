#!/usr/bin/env python3
"""Stdlib console driver for the native TUI contract (replaces the Go `tuifixture` helper).

The Go helper (`tui_fixture.go.txt`, kept for the one-time Go capture) did four jobs for the
Rust runs of tui_contract.py; this driver reproduces the three that need no Go:

  --root R --console-binary B --console-receipt P
        run B (`--vault R ui`) as a child on this process's controlling terminal, record the
        termios state of stdin and stdout before and after, write P (exit code and whether
        both modes were restored), then hold the controlling session until `P.release` exists
        (15 s), exactly as the Go console wrapper did.
  PATH  (one argument, with `<launcher>.editor.json` next to the launcher that exec'd this file
        as `python tui_driver.py --self <launcher> ...`)
        the fixture editor: observe the real private JSON document and the terminal, publish a
        ready receipt, wait for the release rendezvous (20 s), then edit as the sidecar's mode says.
  --root R --snapshot [--config-receipt P]
        read the encrypted store. Decryption is Rust (`$TUI_SNAPSHOT_BIN`, the `tui-snapshot`
        example of symvault-store): this file only forwards to it, so no Go reader remains.

The fourth job, seeding a vault with Go's own writer, is a recorded Go observation
(fixtures/go-observations/tui-contract.<goos>.json material), not code.
"""
import json
import os
import platform
import subprocess
import sys
import time

DARWIN_PENDIN = 0x20000000  # kernel bookkeeping, not an application terminal mode


def console_state(fd):
    """The native termios state of `fd` as plain data (every field, as term.GetState)."""
    import termios
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = termios.tcgetattr(fd)
    if platform.system() == "Darwin":
        lflag &= ~DARWIN_PENDIN
    return {"Iflag": iflag, "Oflag": oflag, "Cflag": cflag, "Lflag": lflag, "Ispeed": ispeed,
            "Ospeed": ospeed, "Cc": [ord(c) if isinstance(c, bytes) else int(c) for c in cc]}


def states():
    return {"input": console_state(0), "output": console_state(1)}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def atomic_write(path, data):
    temporary = path + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.rename(temporary, path)


def wait_for(path, seconds, what):
    deadline = time.monotonic() + seconds
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise SystemExit(what + " expired")
        time.sleep(0.01)


def console(root, binary, receipt):
    before = states()
    fd = os.open(receipt + ".before", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(encode(before))
    # stdin/stdout/stderr are inherited: the CLI owns this controlling terminal.
    code = subprocess.run([binary, "--vault", root, "ui"]).returncode
    if code < 0:
        code = -1  # os/exec ExitCode() of a signalled child
    after = states()
    atomic_write(receipt, encode({"exit_code": code, "input_restored": before["input"] == after["input"],
                                  "output_restored": before["output"] == after["output"]}))
    # Retain the controlling session while the parent independently checks modes.
    wait_for(receipt + ".release", 15, "console mode rendezvous")
    sys.exit(code & 0xFF)


def editor(spec, path):
    info = os.stat(path)
    receipt = {"input_is_terminal": os.isatty(0), "output_is_terminal": os.isatty(1),
               "mode": info.st_mode & 0o777, "document_bytes": info.st_size}
    with open(spec["Console"], "rb") as handle:
        before = handle.read()
    receipt["foreground_terminal_restored"] = before == encode(states())
    receipt["environment_filtered"] = (os.environ.get("TUI_PRIVATE_ENV", "") == ""
                                       and os.environ.get("SYMVAULT_TEST_KEYRING", "") == ""
                                       and os.environ.get("SYMVAULT_PASSPHRASE", "") == "")
    atomic_write(spec["Ready"], json.dumps(receipt).encode())
    sys.stdout.write("TUI_EDITOR_READY\n")
    sys.stdout.flush()
    wait_for(spec["Release"], 20, "private editor rendezvous")
    mode = spec["Mode"]
    if mode == "invalid":
        with open(path, "wb") as handle:
            handle.write(b"invalid-json")
    elif mode == "empty":
        with open(path, "wb"):
            pass
    elif mode == "failure":
        sys.exit(23)
    elif mode == "valid":
        with open(path, "rb") as handle:
            entry = json.loads(handle.read())
        if not isinstance(entry.get("data"), dict):
            entry["data"] = {}
        entry["data"]["password"] = "public-tui-edited-secret-782a"
        entry["data"]["username"] = "public-tui-edited-user"
        with open(path, "wb") as handle:
            handle.write(json.dumps(entry, separators=(",", ":")).encode())
    else:
        raise SystemExit("unknown private editor mode")


def snapshot(root, config_receipt):
    tool = os.environ.get("TUI_SNAPSHOT_BIN")
    if not tool:
        raise SystemExit("TUI_SNAPSHOT_BIN names the Rust tui-snapshot example")
    argv = [tool, "--root", root]
    if config_receipt:
        argv += ["--config-receipt", config_receipt]
    os.execv(tool, argv)


def option(args, name):
    return args[args.index(name) + 1] if name in args else None


def main(args):
    me = sys.argv[0]
    if args[:1] == ["--self"]:  # the launcher script (or a copy of it) that exec'd us
        me, args = args[1], args[2:]
    if len(args) == 1:
        sidecar = os.path.abspath(me) + ".editor.json"
        if os.path.exists(sidecar):
            with open(sidecar, "rb") as handle:
                editor(json.loads(handle.read()), args[0])
            return
    if option(args, "--console-binary"):
        console(option(args, "--root"), option(args, "--console-binary"), option(args, "--console-receipt"))
    elif "--snapshot" in args:
        snapshot(option(args, "--root"), option(args, "--config-receipt"))
    else:
        raise SystemExit("tui_driver.py: unsupported arguments (seeding is a recorded Go observation)")


if __name__ == "__main__":
    main(sys.argv[1:])
