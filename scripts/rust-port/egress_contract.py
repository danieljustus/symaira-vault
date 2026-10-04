#!/usr/bin/env python3
"""Real native CLI and credential-owning TLS proxy observations, bound to source."""
import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import queue
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
ORACLE = "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"
PROBE = ROOT / "scripts/rust-port/egress_contract_probe.go.txt"
TOKEN = "public-fixture-secret-9f31"
NESTED = "public-nested-secret-c771"
DATA = {"credential": TOKEN, "username": "public-fixture-user", "header_name": "X-Api-Key",
        "param_name": "api_token", "nested": {"token": NESTED}}


def checked(args, cwd=ROOT):
    result = subprocess.run([str(x) for x in args], cwd=cwd, capture_output=True, timeout=240)
    assert result.returncode == 0, (args[0], result.stderr.decode(errors="replace")[-2000:])
    return result.stdout


def isolated(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SYMVAULT_")}
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"),
               XDG_DATA_HOME=str(home / "data"), XDG_CACHE_HOME=str(home / "cache"),
               SYMVAULT_VAULT=str(home / "vault"), SYMVAULT_TEST_KEYRING="memory",
               SYMVAULT_PASSPHRASE="correct horse battery staple", SYMVAULT_ALLOW_ENV_PASSPHRASE="1",
               SYMVAULT_NO_ENV_WARNING="1", SYMVAULT_SECUREUI="none", CI="1", NO_COLOR="1")
    return env


class Peer:
    """Own the listener and every fixture handler, including Go's dial probe."""
    def __init__(self, tls=True, redirect=None):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.tls = tls
        self.redirect = redirect
        self.records = []
        self.errors = []
        self.workers = []
        self.stop = threading.Event()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixture = ROOT / "crates/symvault-mcp/tests/fixtures"
        self.context.load_cert_chain(fixture / "tls-server.pem", fixture / "tls-server.key")
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.worker = threading.Thread(target=self.accept)

    def __enter__(self):
        self.worker.start()
        return self

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            assert len(self.workers) < 32, "fixture connection limit"
            worker = threading.Thread(target=self.handle, args=(connection,))
            self.workers.append(worker)
            worker.start()

    def handle(self, connection):
        try:
            connection.settimeout(2)
            if self.tls:
                connection = self.context.wrap_socket(connection, server_side=True)
            stream = connection.makefile("rb")
            first = stream.readline(8193)
            if not first:
                return
            method, target, version = first.decode("ascii").strip().split(" ")
            assert version == "HTTP/1.1"
            headers = {}
            size = 0
            while True:
                line = stream.readline(65537)
                size += len(line)
                assert size < 65536 and line
                if line == b"\r\n":
                    break
                name, value = line.decode("latin1").split(":", 1)
                headers[name.lower()] = value.strip()
            if headers.get("transfer-encoding", "").lower() == "chunked":
                body = b""
                while True:
                    size = int(stream.readline(1024).strip().split(b";", 1)[0], 16)
                    if not size:
                        assert stream.readline(1024) == b"\r\n"
                        break
                    assert size < 16 * 1024 * 1024
                    body += stream.read(size)
                    assert stream.read(2) == b"\r\n"
            else:
                body = stream.read(int(headers.get("content-length", "0")))
            self.records.append({"method": method, "target": target,
                                 "authorization": headers.get("authorization"),
                                 "x-api-key": headers.get("x-api-key"), "x-default": headers.get("x-default"),
                                 "x-sub": headers.get("x-sub"), "proxy_authorization_absent": "proxy-authorization" not in headers,
                                 "body_base64": base64.b64encode(body).decode("ascii")})
            response = (TOKEN+" "+NESTED).encode()+b"\x00\xff"
            status = 302 if self.redirect else 200
            extra = f"Location: {self.redirect}\r\n" if self.redirect else ""
            connection.sendall((f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(response)}\r\n"
                f"X-Echo: {TOKEN}\r\nSet-Cookie: a={TOKEN}\r\nSet-Cookie: b={NESTED}\r\n"
                f"{extra}Connection: close\r\n\r\n").encode()+response)
            stream.close()
        except (ssl.SSLError, TimeoutError, ConnectionResetError, BrokenPipeError):
            # TLS rejection and the Go reachability-only dial are expected;
            # an actual accepted HTTP observation is required separately.
            pass
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            connection.close()

    def __exit__(self, *args):
        self.stop.set()
        self.listener.close()
        self.worker.join(timeout=5)
        assert not self.worker.is_alive()
        for worker in self.workers:
            worker.join(timeout=5)
            assert not worker.is_alive(), "fixture handler did not join"
        assert not self.errors, self.errors


@contextlib.contextmanager
def proxy(binary, root, home, *, private=True, strict=False, passthrough=False, trusted=True):
    args = [binary, "--root", root, "--allow-private="+str(private).lower(), "--strict="+str(strict).lower()]
    if passthrough:
        args += ["--passthrough", "127.0.0.1"]
    if trusted:
        args += ["--upstream-ca", ROOT / "crates/symvault-mcp/tests/fixtures/tls-ca.pem"]
    child = subprocess.Popen([str(x) for x in args], cwd=home, env=isolated(home), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    line = queue.Queue()
    reader = threading.Thread(target=lambda: line.put(child.stdout.readline()))
    reader.start()
    try:
        address = line.get(timeout=30).decode("ascii").strip()
        assert address and child.poll() is None, "proxy did not reach real listen"
        host, port = address.rsplit(":", 1)
        yield (host, int(port))
    finally:
        if child.poll() is None:
            child.stdin.write(b"q")
            child.stdin.flush()
        try:
            stdout, stderr = child.communicate(timeout=75)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=10)
            raise AssertionError("proxy fixture did not terminate")
        reader.join(timeout=5)
        assert not reader.is_alive()
        assert child.returncode == 0 and not stdout and not stderr, (child.returncode, stderr[-1500:])


def request(address, root, peer, method="GET", path="/v1/allowed", body=b"", passthrough=False, host=None):
    target = f"127.0.0.1:{peer.port}"
    with socket.create_connection(address, timeout=10) as connection:
        connection.settimeout(15)
        if peer.tls:
            connection.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            response = http.client.HTTPResponse(connection)
            response.begin()
            if response.status != 200:
                return {"status": response.status, "body_base64": base64.b64encode(response.read()).decode(), "echo": None, "cookies": []}
            cafile = ROOT / "crates/symvault-mcp/tests/fixtures/tls-ca.pem" if passthrough else root / "probe-ca.pem"
            context = ssl.create_default_context(cafile=str(cafile))
            connection = context.wrap_socket(connection, server_hostname="127.0.0.1")
            destination = path
        else:
            destination = f"http://{target}{path}"
        try:
            connection.sendall((f"{method} {destination} HTTP/1.1\r\nHost: {host or target}\r\n"
                f"Content-Length: {len(body)}\r\nUser-Agent: public-fixture\r\nAccept-Encoding: identity\r\n"
                "X-Default: caller\r\nX-Sub: __SECRET__\r\nProxy-Authorization: public-proxy-input\r\nConnection: close\r\n\r\n").encode()+body)
            response = http.client.HTTPResponse(connection)
            response.begin()
            result = {"status": response.status, "body_base64": base64.b64encode(response.read()).decode(),
                      "echo": response.getheader("X-Echo"),
                      "cookies": [value for name, value in response.getheaders() if name.lower() == "set-cookie"]}
            return result
        finally:
            connection.close()


def template(root, peer, *, auth="bearer", port=None, scheme=None, substitutions=False, name="fixture", host="127.0.0.1"):
    directory = root / "templates"
    directory.mkdir(exist_ok=True)
    for existing in directory.glob("*.yaml"):
        existing.unlink()  # Only disposable fixture templates.
    definition = {"base_url": f"{scheme or ('https' if peer.tls else 'http')}://{host}:{port or peer.port}",
                  "auth_type": auth, "entry_ref": "fixture", "allowed_methods": ["GET", "POST"],
                  "allowed_endpoints": ["/v1/*"], "default_headers": {"X-Default": "template"}, "allow_private": True}
    if substitutions:
        definition["substitutions"] = [{"placeholder": "__SECRET__", "field": "credential", "in": ["path", "query", "header", "body"]}]
    # JSON is a YAML subset; no optional PyYAML dependency is used.
    (directory / (name+".yaml")).write_text(json.dumps(definition), encoding="utf-8")


def runtime_cases(binary, seed, home, records):
    home.mkdir()
    root = home / "vault"
    checked([seed, "--root", root, "--seed", home.parent / "entry.json"], cwd=home)
    for auth in ["bearer", "basic", "header", "query_param", "none"]:
        with Peer() as peer:
            template(root, peer, auth=auth, substitutions=auth == "none", name="github" if auth == "bearer" else "fixture")
            with proxy(binary, root, home) as address:
                result = request(address, root, peer)
            assert result["status"] == 200 and len(peer.records) == 1, (auth, result, peer.records)
            seen = peer.records[0]
            assert seen["x-default"] == "template" and seen["proxy_authorization_absent"], (auth, seen)
            if auth == "bearer": assert seen["authorization"] == "Bearer "+TOKEN
            if auth == "basic": assert seen["authorization"] == "Basic "+base64.b64encode((DATA["username"]+":"+TOKEN).encode()).decode()
            if auth == "header": assert seen["x-api-key"] == TOKEN
            if auth == "query_param": assert seen["target"] == "/v1/allowed?api_token="+TOKEN
            if auth == "none": assert seen["authorization"] is None and seen["x-api-key"] is None
            assert result["echo"] == "***" and result["cookies"] == ["a=***", "b=***"]
            assert base64.b64decode(result["body_base64"]) == b"*** ***\x00\xff", (auth, result)
            records.append({"case": "tls-auth-"+auth, "response": result, "upstream": seen, "tls_verified": True})
    with Peer() as peer:
        template(root, peer, substitutions=True)
        with proxy(binary, root, home) as address:
            result = request(address, root, peer, method="POST", path="/v1/__SECRET__?token=__SECRET__", body=b"__SECRET__")
        assert result["status"] == 200 and len(peer.records) == 1
        seen = peer.records[0]
        assert seen["target"] == f"/v1/{TOKEN}?token={TOKEN}" and seen["x-sub"] == TOKEN
        assert base64.b64decode(seen["body_base64"]) == TOKEN.encode()
        records.append({"case": "tls-all-substitution-surfaces", "response": result, "upstream": seen})
    for name, method, path in [("method-denied", "DELETE", "/v1/allowed"), ("endpoint-denied", "GET", "/denied")]:
        with Peer() as peer:
            template(root, peer)
            with proxy(binary, root, home) as address:
                result = request(address, root, peer, method=method, path=path)
            assert result["status"] == 403 and not peer.records
            records.append({"case": name, "status": 403, "upstream_requests": 0})
    for name, strict in [("unmatched-forwarded", False), ("unmatched-strict", True)]:
        with Peer(tls=False) as peer:
            for existing in (root / "templates").glob("*.yaml"): existing.unlink()
            with proxy(binary, root, home, strict=strict) as address:
                result = request(address, root, peer)
            assert result["status"] == (403 if strict else 200)
            assert len(peer.records) == (0 if strict else 1)
            if not strict: assert peer.records[0]["authorization"] is None
            records.append({"case": name, "status": result["status"], "upstream_requests": len(peer.records)})
    with Peer() as peer:
        template(root, peer)
        with proxy(binary, root, home, passthrough=True) as address:
            result = request(address, root, peer, passthrough=True)
        assert result["status"] == 200 and peer.records[0]["authorization"] is None
        assert result["echo"] == TOKEN  # Explicit passthrough does not sanitize or inject.
        records.append({"case": "passthrough-preserves-upstream-tls", "response": result, "upstream": peer.records[0]})
    with Peer() as peer:
        template(root, peer)
        with proxy(binary, root, home, trusted=False) as address:
            result = request(address, root, peer)
        assert result["status"] == 502 and not peer.records
        records.append({"case": "untrusted-upstream-tls", "status": 502, "upstream_requests": 0})
    # Measure actual Go authority and redirect behavior before deciding divergences.
    for name, tls, changed_port, changed_host in [("template-port-binding", True, True, False),
            ("template-plaintext-binding", False, False, False), ("connect-inner-authority-binding", True, False, True)]:
        with Peer(tls=tls) as peer:
            template(root, peer, port=(peer.port % 60000)+1024 if changed_port else None,
                     scheme="https", host="localhost" if changed_host else "127.0.0.1")
            with proxy(binary, root, home) as address:
                result = request(address, root, peer, host=f"localhost:{peer.port}" if changed_host else None)
            records.append({"case": name, "status": result["status"], "credential_received":
                            any(row["authorization"] == "Bearer "+TOKEN for row in peer.records)})
    with Peer() as redirected:
        with Peer(redirect=f"https://127.0.0.1:{redirected.port}/v1/redirected") as peer:
            template(root, peer)
            with proxy(binary, root, home) as address:
                result = request(address, root, peer)
            records.append({"case": "redirect-authority-binding", "status": result["status"],
                            "redirected_credential_received": any(row["authorization"] == "Bearer "+TOKEN for row in redirected.records)})
    return records


def inventory(paths, root):
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode()+b"\0"+(root / path).read_bytes()+b"\0")
    return digest.hexdigest()


def console_child(args, home):
    flags = 0
    if os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        members = (ctypes.c_ulong * 1)()
        kernel.GetConsoleProcessList.argtypes = [ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
        kernel.GetConsoleProcessList.restype = ctypes.c_ulong
        if not kernel.GetConsoleProcessList(members, 1) and not kernel.AllocConsole():
            raise ctypes.WinError()
        flags = subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen([str(x) for x in args], cwd=home, env=isolated(home),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=flags, bufsize=0)


def stop_cli(child):
    child.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
    stdout, stderr = child.communicate(timeout=15)
    assert child.returncode == 0 and not stderr, (child.returncode, stderr[-1000:])
    return stdout


def cli_cases(binary, seed, home, records):
    home.mkdir()
    for name, args in [("broker-missing-vault", ["broker"]),
                       ("broker-boolean-forms", ["broker", "--strict=TRUE", "--strict=0"]),
                       ("run-broker-flags-reach-vault", ["run", "--broker=TRUE", "--broker-strict=1", "--broker-passthrough", "a,b", "--", "public-missing-command"])]:
        result = subprocess.run([str(binary), *args], cwd=home, env=isolated(home), capture_output=True, timeout=30)
        assert result.returncode == 3, (name, result.returncode, result.stderr)
        records.append({"case": name, "exit": 3})
    root = home / "vault"
    checked([seed, "--root", root, "--seed", home.parent / "entry.json"], cwd=home)
    script = home / "child.py"
    script.write_text('''import json, os, pathlib, sys, time
keys = ['HTTPS_PROXY','HTTP_PROXY','SSL_CERT_FILE','NODE_EXTRA_CA_CERTS','REQUESTS_CA_BUNDLE','NO_PROXY']
record = {key:os.environ.get(key) for key in keys}
record['explicit'] = os.environ.get('EXPLICIT_FIXTURE')
record['passphrase_absent'] = 'SYMVAULT_PASSPHRASE' not in os.environ
pathlib.Path(sys.argv[1]).write_text(json.dumps(record), encoding='utf-8')
print(json.dumps(record), flush=True)
if sys.argv[2] == 'timeout': time.sleep(8)
sys.exit(7 if sys.argv[2] == 'error' else 0)
''', encoding="utf-8")
    for name, flags, mode, expected in [
            ("run-broker-disabled", ["--broker=false", "--broker-strict=TRUE", "--broker-passthrough", "a,b"], "ordinary", 0),
            ("run-broker-public-env", ["--broker"], "ordinary", 0),
            ("run-broker-strict-passthrough", ["--broker", "--broker-strict=TRUE", "--broker-passthrough", '"api.example.test",another.test', "--broker-passthrough", "extra.test"], "ordinary", 0),
            ("run-broker-child-error", ["--broker"], "error", 1),
            ("run-broker-timeout", ["--broker", "--timeout=2s"], "timeout", 1),
            ("run-broker-explicit-env", ["--broker", "--env", "EXPLICIT_FIXTURE=fixture.credential"], "ordinary", 0),
        ]:
        report = home / (name+".json")
        result = subprocess.run([str(binary), "run", *flags, "--", os.sys.executable, str(script), str(report), mode],
                                cwd=home, env=isolated(home), capture_output=True, timeout=90)
        assert result.returncode == expected, (name, result.returncode, result.stderr[-1200:])
        observed = json.loads(report.read_text(encoding="utf-8"))
        assert observed["passphrase_absent"]
        assert TOKEN.encode() not in result.stdout+result.stderr and NESTED.encode() not in result.stdout+result.stderr
        if name == "run-broker-disabled":
            assert all(observed[key] is None for key in observed if key not in {"explicit", "passphrase_absent"})
        else:
            assert observed["HTTPS_PROXY"] == observed["HTTP_PROXY"]
            assert observed["NO_PROXY"] == "127.0.0.1,localhost"
            ca = Path(observed["SSL_CERT_FILE"])
            assert ca.samefile(root / "broker-ca.pem") and ca.samefile(observed["NODE_EXTRA_CA_CERTS"]) and ca.samefile(observed["REQUESTS_CA_BUNDLE"])
            assert ssl.PEM_cert_to_DER_cert(ca.read_text(encoding="ascii"))
            assert "PRIVATE KEY" not in ca.read_text(encoding="ascii")
            if os.name != "nt": assert ca.stat().st_mode & 0o777 == 0o600
            host, port = observed["HTTP_PROXY"].removeprefix("http://").rsplit(":", 1)
            with socket.socket() as connection:
                connection.settimeout(2)
                assert connection.connect_ex((host, int(port))) != 0, "child-owned broker listener survived command exit"
        assert observed["explicit"] == (TOKEN if name == "run-broker-explicit-env" else None)
        records.append({"case": name, "exit": expected, "public_proxy_env_verified": name != "run-broker-disabled",
                        "listener_gone": name != "run-broker-disabled", "passphrase_absent": True,
                        "explicit_env_preserved": name == "run-broker-explicit-env", "canaries_absent_from_output": True})
    result = subprocess.run([str(binary), "run", "--broker", "--", str(home / "public-missing-command")],
                            cwd=home, env=isolated(home), capture_output=True, timeout=90)
    assert result.returncode == 1 and TOKEN.encode() not in result.stdout+result.stderr
    records.append({"case": "run-broker-launch-error", "exit": 1, "canaries_absent_from_output": True})
    for name, flags in [("standalone-broker", []), ("standalone-broker-flags", ["--addr", "127.0.0.1:0", "--strict=0", "--strict=TRUE",
            "--passthrough", '"api.example.test",another.test', "--passthrough", "extra.test"])]:
        child = console_child([binary, "--quiet", "broker", *flags], home)
        output = queue.Queue()
        reader = threading.Thread(target=lambda: output.put(child.stdout.readline()))
        reader.start()
        try:
            first = output.get(timeout=30).decode("utf-8")
            assert first.startswith("Symaira Vault egress broker listening on http://127.0.0.1:")
            address = first.strip().split("http://", 1)[1]
            with socket.create_connection(("127.0.0.1", int(address.rsplit(":", 1)[1])), timeout=5): pass
            if flags:
                with socket.create_connection(("127.0.0.1", int(address.rsplit(":", 1)[1])), timeout=5) as connection:
                    connection.sendall(b"GET http://127.0.0.1:1/v1/public HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n")
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    assert response.status == 403 and b"strict mode rejects unmatched hosts" in response.read()
            rest = stop_cli(child).decode("utf-8")
            assert "NO_PROXY=127.0.0.1,localhost" in rest
            assert ("Strict mode:" in rest) == bool(flags)
            if flags: assert "[api.example.test another.test extra.test]" in rest
            assert TOKEN not in first+rest and NESTED not in first+rest
            records.append({"case": name, "exit": 0, "actual_native_stop": "CTRL_BREAK" if os.name == "nt" else "SIGINT", "listen_verified": True,
                            "strict_and_csv_flags_verified": bool(flags), "canaries_absent_from_output": True})
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=10)
            reader.join(timeout=5)
            assert not reader.is_alive()
    # Actual Go accepts a public wildcard listener; the maintained Rust CLI is
    # deliberately restricted to loopback. The root contains only public fixtures.
    child = console_child([binary, "broker", "--addr", "0.0.0.0:0"], home)
    output = queue.Queue()
    reader = threading.Thread(target=lambda: output.put(child.stdout.readline()))
    reader.start()
    try:
        first = output.get(timeout=30)
        accepted = first.startswith(b"Symaira Vault egress broker listening on http://")
        if accepted:
            stop_cli(child)
        else:
            _, stderr = child.communicate(timeout=15)
            assert child.returncode == 1 and b"broker address must be loopback" in stderr
        records.append({"case": "loopback-listener-policy", "public_listener_accepted": accepted})
    finally:
        if child.poll() is None: child.kill(); child.communicate(timeout=10)
        reader.join(timeout=5)
        assert not reader.is_alive()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-probe", type=Path, required=True)
    parser.add_argument("--rust-cli", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--allow-dirty-for-development", action="store_true")
    args = parser.parse_args()
    rust = args.rust_probe.resolve()
    rust_cli = args.rust_cli.resolve()
    assert rust.is_file()
    assert rust_cli.is_file()
    if os.name != "nt": os.umask(0o022)
    clean = not checked(["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    assert clean or args.allow_dirty_for_development
    sources = sorted(x for x in checked(["git", "ls-files", "--cached", "--others", "--exclude-standard"]).decode().splitlines()
                     if x.startswith(("crates/", "third_party/", "testdata/", "internal/mcp/apitemplates/builtin/"))
                     or x in {"Cargo.toml", "Cargo.lock", ".gitattributes", "scripts/rust-port/egress_contract.py",
                              "scripts/rust-port/egress_contract_probe.go.txt", ".github/workflows/rust-broker-egress.yml"})
    receipt = {"passed": False, "candidate_commit": checked(["git", "rev-parse", "HEAD"]).decode().strip(),
               "candidate_worktree_clean": clean, "native_os": platform.system(), "architecture": platform.machine(),
               "candidate_source_files": sources, "candidate_source_digest": inventory(sources, ROOT),
               "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "probe_sha256": hashlib.sha256(PROBE.read_bytes()).hexdigest(),
               "rust_binary_sha256": hashlib.sha256(rust.read_bytes()).hexdigest(), "oracle_commit": ORACLE,
               "rust_cli_binary_sha256": hashlib.sha256(rust_cli.read_bytes()).hexdigest(),
               "fixture_identity_kdf": {"algorithm":"argon2id", "memory_kib":19456, "iterations":2, "lanes":1, "purpose":"explicit supported disposable-fixture settings; production defaults and performance not measured"},
               "transport_seams": "private fixture destinations and fixture CA only in library probes; never CLI flags"}
    try:
        with tempfile.TemporaryDirectory(prefix="symvault-egress-contract-") as raw:
            base = Path(raw)
            (base / "entry.json").write_text(json.dumps(DATA), encoding="utf-8")
            tree = base / "oracle"
            checked(["git", "worktree", "add", "--detach", tree, ORACLE])
            try:
                paths = checked(["git", "ls-tree", "-r", "--name-only", ORACLE]).decode().splitlines()
                oracle_sources = sorted(x for x in paths if x in {"go.mod", "go.sum"} or x.endswith(".go") and not x.endswith("_test.go"))
                embedded = sorted(x for x in paths if x.startswith("internal/mcp/apitemplates/builtin/"))
                assert len(embedded) == 17
                receipt.update(oracle_source_files=oracle_sources, oracle_source_digest=inventory(oracle_sources, tree),
                               oracle_embedded_files=embedded, oracle_embedded_digest=inventory(embedded, tree))
                helper = tree / "scripts/rust-port/cmd/egressprobe"
                helper.mkdir()
                (helper / "main.go").write_bytes(PROBE.read_bytes())
                go = base / ("go-probe.exe" if os.name == "nt" else "go-probe")
                checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", go, "./scripts/rust-port/cmd/egressprobe"], cwd=tree)
                receipt["go_binary_sha256"] = hashlib.sha256(go.read_bytes()).hexdigest()
                go_cli = base / ("go-cli.exe" if os.name == "nt" else "go-cli")
                checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", go_cli, "."], cwd=tree)
                receipt["go_cli_binary_sha256"] = hashlib.sha256(go_cli.read_bytes()).hexdigest()
                receipt["go"] = []
                runtime_cases(go, go, base / "go-home", receipt["go"])
                receipt["rust"] = []
                runtime_cases(rust, go, base / "rust-home", receipt["rust"])
                receipt["go_cli"] = []
                cli_cases(go_cli, go, base / "go-cli-home", receipt["go_cli"])
                receipt["rust_cli"] = []
                cli_cases(rust_cli, go, base / "rust-cli-home", receipt["rust_cli"])
                for left, right in zip(receipt["go_cli"], receipt["rust_cli"], strict=True):
                    if left["case"] == "loopback-listener-policy":
                        assert left["public_listener_accepted"] and not right["public_listener_accepted"]
                    else:
                        assert left == right, (left, right)
                for left, right in zip(receipt["go"], receipt["rust"], strict=True):
                    if left["case"] in {"template-port-binding", "template-plaintext-binding", "connect-inner-authority-binding"}:
                        assert left["status"] == 200 and left["credential_received"], left
                        assert right["status"] == 403 and not right["credential_received"], right
                    elif left["case"] == "redirect-authority-binding":
                        assert left["status"] == 200 and left["redirected_credential_received"], left
                        assert right["status"] == 302 and not right["redirected_credential_received"], right
                    else:
                        assert left == right, (left, right)
                receipt["passed"] = True
            finally:
                checked(["git", "worktree", "remove", "--force", tree])
    finally:
        args.receipt.write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8")
    print(f"PASS: {len(receipt['go'])} runtime and {len(receipt['go_cli'])} CLI cases from actual native Go/Rust on {platform.system()}")


if __name__ == "__main__":
    main()
