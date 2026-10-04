#!/usr/bin/env python3
"""Execute real Go/Rust watcher CLIs in disposable memory-keyring roots."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
ORACLE = "55da4ca13ead39d4000cf6f866ac8671ca86d8f2"
PASSPHRASE = "correct horse battery staple"


def run(args, cwd=ROOT, env=None, timeout=120):
    result = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                            capture_output=True, timeout=timeout)
    return result


def checked(args, **kwargs):
    result = run(args, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): "
                           + result.stderr.decode(errors="replace")[-4000:])
    return result.stdout


def isolated(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SYMVAULT_")}
    env.update(HOME=str(home), USERPROFILE=str(home),
               XDG_CONFIG_HOME=str(home / "config"), XDG_DATA_HOME=str(home / "data"),
               XDG_CACHE_HOME=str(home / "cache"), SYMVAULT_TEST_KEYRING="memory",
               SYMVAULT_VAULT=str(home / "vault"), SYMVAULT_PASSPHRASE=PASSPHRASE,
               SYMVAULT_ALLOW_ENV_PASSPHRASE="1", SYMVAULT_NO_ENV_WARNING="1")
    return env


def normal(raw, home):
    text = raw.decode().replace(str(home), "__HOME__")
    return re.sub(r"intake-\d{8}-[0-9a-f]{8}", "__BATCH__", text).replace("\r\n", "\n")


def stop(child, sig):
    if os.name == "nt":
        if not ctypes.windll.kernel32.GenerateConsoleCtrlEvent(1, child.pid):
            raise ctypes.WinError()
    else:
        child.send_signal(sig)


def spawn(args, home):
    flags = 0
    if os.name == "nt":
        kernel = ctypes.windll.kernel32
        if not kernel.GetConsoleWindow() and not kernel.AllocConsole():
            raise ctypes.WinError()
        flags = subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen([str(x) for x in args], cwd=home, env=isolated(home),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            creationflags=flags)


def exercise(binary, inspector, root):
    records = []
    def case(name, args, home=None):
        home = home or root / name
        home.mkdir(exist_ok=True)
        result = run([binary, *args], cwd=home, env=isolated(home))
        records.append({"case": name, "exit": result.returncode,
                        "stdout": normal(result.stdout, home),
                        "stderr": normal(result.stderr, home)})
        return result, home

    for name, args, code in [
        ("missing-directory", ["intake", "watch", "missing", "--once"], 9),
        ("missing-argument", ["intake", "watch"], 1),
        ("disable-absent", ["intake", "watch", "disable"], 0),
        ("disable-quiet", ["--quiet", "intake", "watch", "disable"], 0),
    ]:
        result, home = case(name, args)
        assert result.returncode == code, (name, result.stderr)
        assert not (home / "vault").exists(), name

    home = root / "not-directory"
    home.mkdir()
    (home / "file").write_bytes(b"public fixture")
    result, _ = case("not-directory", ["intake", "watch", "file", "--once"], home)
    assert result.returncode == 9

    home = root / "disable-present"
    home.mkdir()
    plist = home / "Library/LaunchAgents/com.symaira.vault-intake.plist"
    plist.parent.mkdir(parents=True)
    plist.write_text("disposable invalid test plist")
    result, _ = case("disable-present", ["intake", "watch", "disable"], home)
    assert result.returncode == (0 if platform.system() == "Darwin" else 9)
    assert plist.exists() == (platform.system() != "Darwin")
    if platform.system() == "Darwin":
        result, _ = case("disable-repeat", ["intake", "watch", "disable"], home)
        assert result.returncode == 0

    for name, args in [
        ("empty-text", []), ("empty-quiet", ["--quiet"]),
        ("empty-json", ["--json"]), ("zero-defaults", ["--interval", "0", "--debounce", "0"]),
        ("negative-defaults", ["--interval=-1s", "--debounce=-1s"]),
    ]:
        home = root / name
        home.mkdir()
        (home / "inbox").mkdir()
        result, _ = case(name, ["intake", "watch", "inbox", "--once", *args], home)
        assert result.returncode == 0, (name, result.stderr)
        if "--json" in args:
            assert json.loads(result.stdout) == {"scanned": 0, "staged": None}
        assert not (home / "vault").exists()

    for name, args in [
        ("invalid-interval", ["intake", "watch", "missing", "--once", "--interval", "bad"]),
        ("invalid-debounce", ["intake", "watch", "missing", "--once", "--debounce", "bad"]),
        ("file-no-argument", ["intake"]),
        ("file-unknown-flag", ["intake", "missing", "--dry-run", "--unknown"]),
        ("file-count-limit", ["intake", "one", "two", "--dry-run", "--max-files", "1"]),
    ]:
        result, home = case(name, args)
        assert result.returncode and result.stderr and not result.stdout
        assert not (home / "vault").exists()

    # JSON --once only stages. The reported random private paths are already
    # removed on return. No unlock or encrypted-vault write is permitted here.
    home = root / "json-staging"
    home.mkdir()
    inbox = home / "inbox"
    inbox.mkdir()
    source = inbox / "fixture.env"
    source.write_bytes(b"USERNAME=fixture-user\nPASSWORD=fixture-password\n")
    os.utime(source, (1700000000, 1700000000))
    (inbox / ".hidden").write_bytes(b"hidden fixture")
    (inbox / "subdir").mkdir()
    result, _ = case("json-staging", ["intake", "watch", "inbox", "--once", "--json"], home)
    observed = json.loads(result.stdout)
    assert result.returncode == 0 and observed["scanned"] == 1 and len(observed["staged"]) == 1
    assert all(not Path(p).exists() for p in observed["staged"])
    assert not (home / "vault").exists()
    records[-1]["stdout"] = json.dumps({"scanned": 1, "staged": ["__PRIVATE_STAGED_PATH__"]})
    assert source.read_bytes().startswith(b"USERNAME=fixture-user")

    # Text --once hydrates the existing store and writes encrypted quarantine.
    # The inspector is real Go for both implementations, proving interchange.
    home = root / "encrypted-batch"
    home.mkdir()
    env = isolated(home)
    checked([inspector, "init", "--auth", "passphrase"], cwd=home, env=env)
    inbox = home / "inbox"
    inbox.mkdir()
    source = inbox / "fixture.env"
    payload = b"USERNAME=fixture-user\nPASSWORD=fixture-password\n"
    source.write_bytes(payload)
    os.utime(source, (1700000000, 1700000000))
    result, _ = case("encrypted-batch", ["intake", "watch", "inbox", "--once"], home)
    assert result.returncode == 0, result.stderr
    paths = checked([inspector, "list", "--json"], cwd=home, env=env)
    listing = json.loads(paths)
    # Go list emits {entries:[...]} with entry objects.
    rows = listing["entries"] if isinstance(listing, dict) else listing
    names = [row["path"] if isinstance(row, dict) else row for row in rows]
    assert len(names) == 1 and names[0].startswith("quarantine/intake-")
    attachment = checked([inspector, "get", names[0]+".attachment", "--no-pipe-warning"], cwd=home, env=env).strip()
    assert base64.b64decode(attachment) == payload
    password = checked([inspector, "get", names[0]+".password", "--no-pipe-warning"], cwd=home, env=env).strip()
    assert password == b"fixture-password"
    records.append({"case": "go-readback", "attachment_sha256": hashlib.sha256(payload).hexdigest(), "quarantine_only": True})
    result, _ = case("encrypted-batch-repeat", ["intake", "watch", "inbox", "--once"], home)
    assert result.returncode == 0 and b"No new files to stage." in result.stdout
    assert checked([inspector, "list", "--json"], cwd=home, env=env) == paths
    assert source.read_bytes() == payload

    for sig, name in [(signal.SIGINT, "interrupt"), (signal.SIGTERM, "terminate")]:
        if os.name == "nt" and sig == signal.SIGTERM:
            continue # Windows proves its real console-control event below.
        home = root / name
        home.mkdir()
        (home / "inbox").mkdir()
        child = spawn([binary, "intake", "watch", "inbox", "--interval", "1h"], home)
        try:
            # Both binaries flush their real startup status; bounded readiness
            # avoids sending a signal before their handler was installed.
            deadline = time.monotonic()+10
            ready = b""
            import threading
            reader = threading.Thread(target=lambda: readiness.append(child.stdout.readline()), daemon=True)
            readiness = []
            reader.start()
            while not readiness and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            assert readiness and readiness[0].startswith(b"Watching "), name
            ready = readiness[0]
            stop(child, sig)
            stdout, stderr = child.communicate(timeout=10)
            reader.join(timeout=1)
            assert child.returncode == 0, (name, stderr)
            records.append({"case": name, "exit": child.returncode,
                            "stdout": normal(ready+stdout, home), "stderr": normal(stderr, home)})
            assert not (home / "vault").exists()
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)

    for name, filename, payload, extra in [
        ("file-env", "fixture.env", b"# comment\nUSERNAME=fixture-user\nPASSWORD=fixture-password\n", []),
        ("file-text", "fixture.txt", b"User name: fixture-user\nPassword: fixture-password\nunknown: ignored\n", []),
        ("file-json", "fixture.json", b'{"username":"fixture-user","password":"fixture-password","notes":"fixture-note","ignored":123}', []),
        ("extension-not-type", "fixture.env", b"Password: fixture-password\n", []),
        ("attachment-empty", "empty.txt", b"", []),
        ("attachment-png", "fixture.png", b"\x89PNG\r\n\x1a\npublic fixture", []),
        ("file-ocr", "fixture.png", b"\x89PNG\r\n\x1a\npublic fixture", ["--ocr-text", "ocr.txt"]),
        ("file-byte-limit", "fixture.env", b"PASSWORD=fixture-password\n", ["--batch-limit", "1"]),
        ("file-default-limits", "fixture.env", b"PASSWORD=fixture-password\n", ["--batch-limit", "0", "--max-files", "0"]),
        ("file-bool-true", "fixture.env", b"PASSWORD=fixture-password\n", ["--dry-run=TRUE", "--move-to-trash=False"]),
    ]:
        home = root / name
        home.mkdir()
        (home / filename).write_bytes(payload)
        os.utime(home / filename, (1700000000, 1700000000))
        if "--ocr-text" in extra:
            (home / "ocr.txt").write_text("Password: fixture-ocr-password\n")
        result, _ = case(name, ["intake", filename, "--dry-run", "--json", *extra], home)
        assert result.returncode == 0, (name, result.stderr)
        observed = json.loads(normal(result.stdout, home))
        for item in observed["results"]:
            if "suggestions" in item:
                # Go iterates JSON object's keys in unspecified order; every
                # field here is distinct, so array order has no write effect.
                item["suggestions"].sort(key=lambda s: (s["path"], s["field"]))
        records[-1]["json"] = observed
        del records[-1]["stdout"]
        assert not (home / "vault").exists()
        assert b"fixture-password" not in result.stdout
        assert b"fixture-ocr-password" not in result.stdout
        assert (home / filename).read_bytes() == payload

    home = root / "ordinary-encrypted-file"
    home.mkdir()
    env = isolated(home)
    checked([inspector, "init", "--auth", "passphrase"], cwd=home, env=env)
    source = home / "source.env"
    source.write_bytes(b"USERNAME=fixture-user\nPASSWORD=fixture-password\n")
    os.utime(source, (1700000000,1700000000))
    for name in ["ordinary-encrypted-file", "ordinary-encrypted-file-repeat"]:
        result, _ = case(name, ["intake", "source.env", "--dry-run=false", "--json"], home)
        assert result.returncode == 0, (name,result.stderr)
        records[-1]["json"] = json.loads(normal(result.stdout,home))
        del records[-1]["stdout"]
        assert b"fixture-password" not in result.stdout
    assert records[-1]["json"]["results"][0]["status"] == "skipped"
    assert len(records[-1]["json"]["results"][0]["duplicates"]) == 1
    assert source.read_bytes() == b"USERNAME=fixture-user\nPASSWORD=fixture-password\n"
    return records


def compare(go, rust):
    assert [x["case"] for x in go] == [x["case"] for x in rust]
    for left, right in zip(go, rust):
        name = left["case"]
        if name in {"missing-directory", "missing-argument", "not-directory", "invalid-interval", "invalid-debounce", "file-no-argument", "file-unknown-flag"}:
            # OS/parser diagnostics belong to CLI-005. Require the same actual
            # denial, stderr placement, and no output or vault side effects.
            assert left["exit"] == right["exit"] and left["exit"] != 0 and not left["stdout"] and not right["stdout"]
            assert left["stderr"] and right["stderr"]
        else:
            assert left == right, (name, left, right)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--allow-dirty-for-development", action="store_true")
    args = parser.parse_args()
    rust = args.rust.resolve()
    assert rust.is_file(), "a real Rust CLI binary is required"
    clean = not checked(["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    assert clean or args.allow_dirty_for_development, "commit the candidate before recording native acceptance"
    candidate_sources = sorted(x for x in checked(["git", "ls-files", "--cached", "--others", "--exclude-standard"]).decode().splitlines()
                               if (x.startswith(("crates/", "third_party/", "testdata/"))
                                   and x.endswith((".rs", ".toml", ".lock", ".json", ".txt")))
                               or x in {"Cargo.toml", "Cargo.lock", "scripts/rust-port/intake_watch_contract.py"})
    candidate_digest = hashlib.sha256()
    for path in candidate_sources:
        candidate_digest.update(path.encode()+b"\0"+(ROOT/path).read_bytes()+b"\0")
    with tempfile.TemporaryDirectory(prefix="symvault-intake-contract-") as raw:
        base = Path(raw)
        tree = base / "oracle"
        checked(["git", "worktree", "add", "--detach", tree, ORACLE])
        try:
            go = base / ("go.exe" if os.name == "nt" else "go")
            checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", go, "."], cwd=tree)
            sources = sorted(x for x in checked(["git", "ls-tree", "-r", "--name-only", ORACLE]).decode().splitlines()
                             if x in {"go.mod", "go.sum"} or (x.endswith(".go") and not x.endswith("_test.go")))
            digest = hashlib.sha256()
            for path in sources:
                digest.update(path.encode()+b"\0"+(tree/path).read_bytes()+b"\0")
            go_root, rust_root = base / "go-roots", base / "rust-roots"
            go_root.mkdir(); rust_root.mkdir()
            observed_go = exercise(go, go, go_root)
            observed_rust = exercise(rust, go, rust_root)
            compare(observed_go, observed_rust)
            receipt = {"oracle_commit": ORACLE, "oracle_source_files": sources,
                       "oracle_source_digest": digest.hexdigest(),
                       "go_binary_sha256": hashlib.sha256(go.read_bytes()).hexdigest(),
                       "rust_binary_sha256": hashlib.sha256(rust.read_bytes()).hexdigest(),
                       "candidate_commit": checked(["git", "rev-parse", "HEAD"]).decode().strip(),
                       "candidate_worktree_clean": clean,
                       "candidate_source_files": candidate_sources,
                       "candidate_source_digest": candidate_digest.hexdigest(),
                       "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "native_os": platform.system(), "architecture": platform.machine(),
                       "keyring": "memory", "go": observed_go, "rust": observed_rust, "passed": True}
            args.receipt.write_text(json.dumps(receipt, indent=2)+"\n")
            print(f"PASS: {len(observed_go)} actual Go/Rust intake CLI observations on {platform.system()}")
        finally:
            checked(["git", "worktree", "remove", tree])


if __name__ == "__main__":
    main()
