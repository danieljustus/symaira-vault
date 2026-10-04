#!/usr/bin/env python3
"""Execute actual source-bound Go/Rust CONNECT round trips on the native OS."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
ORACLE = "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"
PROBE = ROOT / "scripts/rust-port/connect_contract_probe.go.txt"


def checked(args, cwd=ROOT):
    result = subprocess.run([str(x) for x in args], cwd=cwd, capture_output=True, timeout=180)
    assert result.returncode == 0, (args[0], result.stderr.decode(errors="replace")[-3000:])
    return result.stdout


def exercise(binary, home, is_go):
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("SYMVAULT_")}
    env.update(HOME=str(home), USERPROFILE=str(home),
               XDG_CONFIG_HOME=str(home / "config"), XDG_DATA_HOME=str(home / "data"),
               XDG_CACHE_HOME=str(home / "cache"), SYMVAULT_TEST_KEYRING="memory")
    child = subprocess.Popen([str(binary), *([str(home)] if is_go else [])], cwd=home, env=env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    first_line = queue.Queue()
    reader = threading.Thread(target=lambda: first_line.put(child.stdout.readline()))
    reader.start()
    records = []
    try:
        address = first_line.get(timeout=20).decode("ascii").strip()
        host, port = address.rsplit(":", 1)
        assert host == "127.0.0.1"
        for name, delay, fragmented in [("ordinary", 0, False), ("delayed", 0.25, False), ("fragmented-binary", 0.25, True)]:
            payload = b"public-CONNECT-fixture\0\xff"
            with socket.socket() as upstream:
                upstream.bind(("127.0.0.1", 0))
                upstream.listen(1)
                upstream.settimeout(10)
                target_port = upstream.getsockname()[1]
                observation = queue.Queue()

                def respond():
                    try:
                        with upstream.accept()[0] as connection:
                            connection.settimeout(10)
                            data = b""
                            while len(data) < len(payload):
                                part = connection.recv(len(payload)-len(data))
                                assert part, "upstream closed before all tunneled bytes arrived"
                                data += part
                            assert data == payload
                            connection.sendall(data[::-1])
                        observation.put(True)
                    except Exception as error:
                        observation.put(error)

                responder = threading.Thread(target=respond)
                responder.start()
                try:
                    with socket.create_connection((host, int(port)), timeout=10) as client:
                        target = f"127.0.0.1:{target_port}"
                        client.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
                        headers = b""
                        while not headers.endswith(b"\r\n\r\n"):
                            part = client.recv(1)
                            assert part and len(headers) < 65536
                            headers += part
                        assert headers == b"HTTP/1.1 200 Connection Established\r\n\r\n"
                        time.sleep(delay)
                        if fragmented:
                            for byte in payload:
                                client.sendall(bytes([byte]))
                                time.sleep(0.002)
                        else:
                            client.sendall(payload)
                        body = b""
                        while len(body) < len(payload):
                            part = client.recv(len(payload)-len(body))
                            assert part, "proxy closed before the response arrived"
                            body += part
                        assert body == payload[::-1]
                        records.append({"case": name, "response_headers": headers.decode("ascii"),
                                        "upstream_exact_bytes": True, "body_base64": base64.b64encode(body).decode("ascii")})
                finally:
                    responder.join(timeout=12)
                    assert not responder.is_alive(), "owned test upstream did not finish"
                result = observation.get_nowait()
                assert result is True, result
        return records
    finally:
        if child.poll() is None:
            child.kill()
        _, stderr = child.communicate(timeout=10)
        reader.join(timeout=5)
        assert not reader.is_alive()
        assert not stderr, stderr.decode(errors="replace")


def inventory(paths, root):
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode()+b"\0"+(root/path).read_bytes()+b"\0")
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--allow-dirty-for-development", action="store_true")
    args = parser.parse_args()
    rust = args.rust.resolve()
    assert rust.is_file()
    clean = not checked(["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    assert clean or args.allow_dirty_for_development
    sources = sorted(x for x in checked(["git", "ls-files", "--cached", "--others", "--exclude-standard"]).decode().splitlines()
                     if x.startswith(("crates/", "third_party/", "testdata/"))
                     or x in {"Cargo.toml", "Cargo.lock", ".gitattributes", "scripts/rust-port/connect_contract.py", "scripts/rust-port/connect_contract_probe.go.txt", ".github/workflows/rust-broker-connect.yml"})
    with tempfile.TemporaryDirectory(prefix="symvault-connect-contract-") as raw:
        base = Path(raw)
        tree = base / "oracle"
        checked(["git", "worktree", "add", "--detach", tree, ORACLE])
        try:
            oracle_sources = sorted(x for x in checked(["git", "ls-tree", "-r", "--name-only", ORACLE]).decode().splitlines()
                                    if x in {"go.mod", "go.sum"} or (x.endswith(".go") and not x.endswith("_test.go")))
            oracle_digest = inventory(oracle_sources, tree)
            helper = tree / "scripts/rust-port/cmd/connectprobe"
            helper.mkdir()
            (helper / "main.go").write_bytes(PROBE.read_bytes())
            go = base / ("go-probe.exe" if os.name == "nt" else "go-probe")
            checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", go, "./scripts/rust-port/cmd/connectprobe"], cwd=tree)
            observed = {"go": exercise(go, base / "go-home", True), "rust": exercise(rust, base / "rust-home", False)}
            assert observed["go"] == observed["rust"]
            receipt = {"passed": True, "oracle_commit": ORACLE, "oracle_source_files": oracle_sources,
                       "oracle_source_digest": oracle_digest, "probe_sha256": hashlib.sha256(PROBE.read_bytes()).hexdigest(),
                       "go_binary_sha256": hashlib.sha256(go.read_bytes()).hexdigest(),
                       "rust_binary_sha256": hashlib.sha256(rust.read_bytes()).hexdigest(),
                       "candidate_commit": checked(["git", "rev-parse", "HEAD"]).decode().strip(),
                       "candidate_worktree_clean": clean, "candidate_source_files": sources,
                       "candidate_source_digest": inventory(sources, ROOT),
                       "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "native_os": platform.system(), "architecture": platform.machine(),
                       "allow_private": "explicit controlled test seam; production CLI policy unchanged",
                       "termination": "forced-test-child-stop; signal/drain-not-measured", **observed}
            args.receipt.write_bytes((json.dumps(receipt, indent=2)+"\n").encode("utf-8"))
            print(f"PASS: three actual native Go/Rust CONNECT cases on {platform.system()}")
        finally:
            checked(["git", "worktree", "remove", "--force", tree])


if __name__ == "__main__":
    main()
