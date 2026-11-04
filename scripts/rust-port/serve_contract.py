#!/usr/bin/env python3
"""Source-bound actual Go/Rust serve launch and disposable service contracts."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

import go_observations_common as observations

ROOT = Path(__file__).resolve().parents[2]
ORACLE = "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"


def run(args, cwd=ROOT, env=None, data=b"", timeout=120):
    return subprocess.run([str(x) for x in args], cwd=cwd, env=env, input=data,
                          capture_output=True, timeout=timeout)


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
               SYMVAULT_VAULT=str(home / "vault"), CI="1", NO_COLOR="1",
               SYMVAULT_SECUREUI="none",
               SYMVAULT_PASSPHRASE="correct horse battery staple",
               SYMVAULT_ALLOW_ENV_PASSPHRASE="1", SYMVAULT_NO_ENV_WARNING="1")
    return env


def normal(data, home, binary):
    return data.decode("utf-8").replace(str(home), "__HOME__").replace(str(binary), "__BINARY__").replace("\r\n", "\n")


def observe(name, result, home, binary, protocol=False):
    stdout = normal(result.stdout, home, binary)
    return {"case": name, "exit": result.returncode,
            "stdout": [json.loads(line) for line in stdout.splitlines()] if protocol else stdout,
            "stderr": normal(result.stderr, home, binary)}


def protocol_input(locked, gui_metadata=False):
    requests = [
        (1, "initialize", {"protocolVersion": "2025-11-25", "clientInfo": {"name": "public-fixture", "version": "1"}, "capabilities": {}}),
        (2, "ping", {}), (3, "tools/list", {}), (4, "tools/list", {"_meta": {"includeAllTools": True}}),
        (5, "prompts/list", {}), (6, "tools/call", {"name": "get_entry", "arguments": {"path": "public/missing"}}),
        (7, "tools/call", {"name": "public_unknown_tool", "arguments": {}}),
    ]
    if not locked:
        # Tool-read anomaly callbacks use the real clock and can emit async
        # logs/desktop notifications after the reply. Bootstrap acceptance
        # exercises metadata and unknown dispatch; #1248 owns store tool calls.
        requests[5] = (6, "public_unknown_method", {})
    if gui_metadata:
        requests[6] = (7, "tools/call", {"name": "request_credential", "arguments": {
            "path": "public/missing", "field": "credential", "reason": "public-fixture"}})
    return b"".join((json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params})+"\n").encode("utf-8")
                    for i, method, params in requests)


def launch_cases(binary, seed, base):
    records = []
    missing = base / "missing"
    missing.mkdir()
    env = isolated(missing)
    for name, args, code in [
        ("bare-uninitialized", ["serve"], 3),
        ("quiet-uninitialized", ["--quiet", "serve"], 3),
        ("arbitrary-arguments", ["serve", "extra"], 3),
        ("stdio-agent-required", ["serve", "--stdio"], 1),
        ("empty-bind", ["serve", "--bind", ""], 1),
        ("locked-http-rejected", ["serve", "--allow-locked"], 1),
        ("signed-port-accepted", ["serve", "--stdio", "--agent", "default", "--port=-1"], 3),
        ("valued-bool", ["serve", "--stdio=TRUE", "--stdio=0"], 3),
        ("tls-flags-reach-vault", ["serve", "--tls-cert", "public-cert", "--tls-key", "public-key", "--tls-ca", "public-ca"], 3),
    ]:
        result = run([binary, *args], cwd=missing, env=env)
        assert result.returncode == code, (name, result.stderr)
        assert not (missing / "vault").exists()
        records.append(observe(name, result, missing, binary))
    home = base / "initialized"
    home.mkdir()
    env = isolated(home)
    seed(home)
    gui_bin = home / "gui-metadata-bin"
    gui_bin.mkdir()
    gui_name = "powershell.exe" if os.name == "nt" else "osascript" if platform.system() == "Darwin" else "zenity"
    gui_helper = gui_bin / gui_name
    # This is a lookup-only fixture. A locked tool call must never launch it.
    gui_helper.write_bytes(b"#!/bin/sh\nexit 99\n")
    gui_helper.chmod(0o755)
    before = {x.relative_to(home / "vault").as_posix(): hashlib.sha256(x.read_bytes()).hexdigest()
              for x in (home / "vault").rglob("*") if x.is_file()}
    for name, args, unlocked, code, frames in [
        ("locked-stdio", ["--quiet", "serve", "--stdio", "--agent", "default", "--allow-locked"], False, 0, True),
        ("locked-unknown-agent", ["--quiet", "serve", "--stdio", "--agent", "unknown", "--allow-locked"], False, 0, True),
        ("locked-canonical", ["--quiet", "mcp", "--stdio", "--agent", "default", "--allow-locked"], False, 0, True),
        ("locked-gui-metadata", ["--quiet", "serve", "--stdio", "--agent", "default", "--allow-locked"], False, 0, True),
        ("locked-without-opt-in", ["--quiet", "serve", "--stdio", "--agent", "default", "--allow-locked=false"], False, 4, False),
        ("unlocked-stdio", ["--quiet", "serve", "--stdio", "--agent", "default"], True, 0, True),
        ("unlocked-allow-locked", ["--quiet", "serve", "--stdio", "--agent", "default", "--allow-locked"], True, 0, True),
        ("unlocked-canonical", ["--quiet", "mcp", "--stdio", "--agent", "default"], True, 0, True),
        ("unlocked-unknown-agent", ["--quiet", "serve", "--stdio", "--agent", "unknown"], True, 1, False),
    ]:
        case_env = dict(env)
        if not unlocked:
            del case_env["SYMVAULT_PASSPHRASE"]
        gui_metadata = name == "locked-gui-metadata"
        if gui_metadata:
            case_env.update(SYMVAULT_SECUREUI="gui", PATH=str(gui_bin)+os.pathsep+case_env.get("PATH", ""))
        result = run([binary, *args], cwd=home, env=case_env, data=protocol_input(not unlocked, gui_metadata))
        assert result.returncode == code, (name, result.stderr)
        record = observe(name, result, home, binary, frames)
        if frames:
            assert len(record["stdout"]) == 7, name
            assert [row["id"] for row in record["stdout"]] == list(range(1, 8))
        if gui_metadata:
            assert "request_credential" in {row["name"] for row in record["stdout"][2]["result"]["tools"]}
            assert record["stdout"][6]["error"]["message"] == "vault locked: run 'symvault unlock' first"
        if not unlocked:
            after = {x.relative_to(home / "vault").as_posix(): hashlib.sha256(x.read_bytes()).hexdigest()
                     for x in (home / "vault").rglob("*") if x.is_file()}
            assert before == after, (name, "locked bootstrap mutated the vault")
        records.append(record)
    return records


def service_fixture(home):
    helper_dir = home / "helpers"
    helper_dir.mkdir()
    log, state = home / "helper-log", home / "helper-state"
    state.write_bytes(b"stopped")
    script = f'''#!/bin/sh
if [ -n "${{SYMVAULT_PASSPHRASE:-}}" ]; then exit 89; fi
printf '%s\\n' "$*" >> {shlex.quote(str(log))}
state=$(cat {shlex.quote(str(state))})
if [ "$state" = fail ]; then printf 'public helper failure\\n' >&2; exit 23; fi
case "$*" in
  '--user is-active symvault-mcp')
    if [ "$state" = running ]; then printf 'active\\n'; exit 0; fi
    printf 'inactive\\n'; exit 3 ;;
  '--user start symvault-mcp'|'load '*) printf running > {shlex.quote(str(state))} ;;
  'list com.symvault.mcp')
    if [ "$state" = running ]; then printf '\\"PID\\" = 42;\\n'; exit 0; fi
    exit 1 ;;
  '--user stop symvault-mcp'|'unload '*) printf stopped > {shlex.quote(str(state))} ;;
esac
exit 0
'''
    # Rust's helper environment intentionally excludes PATH. Absolute utility
    # paths keep this public fake helper independent of the inherited shell.
    script = script.replace('state=$(cat ', 'state=$(/bin/cat ')
    for name in ["systemctl", "launchctl"]:
        helper = helper_dir / name
        helper.write_bytes(script.encode("utf-8"))
        helper.chmod(0o700)
    return helper_dir, log, state


def service_cases(binary, base):
    home = base / "service"
    home.mkdir()
    env = isolated(home)
    legacy = home / ".symvault/config.yaml"
    legacy.parent.mkdir()
    legacy.write_bytes(b"mcp:\n  port: 9091\n  bind: 127.0.0.2\n")
    helper_dir, log, state = service_fixture(home)
    env["PATH"] = str(helper_dir)+os.pathsep+env["PATH"]
    relative = "LaunchAgents/com.symvault.mcp.plist" if platform.system() == "Darwin" else ".config/systemd/user/symvault-mcp.service"
    service = home / relative
    records = []
    for name, args in [
        ("service-status-absent", ["serve", "status"]),
        ("service-install", ["serve", "install"]),
        ("service-status-running", ["serve", "status"]),
        ("service-status-quiet", ["--quiet", "serve", "status"]),
        ("service-uninstall", ["serve", "uninstall"]),
        ("service-status-removed", ["serve", "status"]),
        ("canonical-service-status", ["mcp", "status"]),
    ]:
        result = run([binary, *args], cwd=home, env=env)
        assert result.returncode == (1 if os.name == "nt" else 0), (name, result.stderr)
        record = observe(name, result, home, binary)
        assert "'symvault serve' is deprecated" not in record["stderr"], name
        if os.name != "nt":
            installed = name in ["service-install", "service-status-running", "service-status-quiet"]
            assert service.exists() == installed, name
            if installed:
                assert service.stat().st_mode & 0o777 == 0o600
                assert service.parent.stat().st_mode & 0o777 == 0o700
                record["service_bytes"] = normal(service.read_bytes(), home, binary)
                record["service_mode"] = service.stat().st_mode & 0o777
                parents = [home / ".config", home / ".config/systemd", service.parent] if platform.system() == "Linux" else [service.parent, home / "Logs"]
                record["directory_modes"] = {x.relative_to(home).as_posix(): x.stat().st_mode & 0o777 for x in parents}
                assert all(mode == 0o700 for mode in record["directory_modes"].values())
            record["helper_calls"] = normal(log.read_bytes(), home, binary).splitlines() if log.exists() else []
        else:
            assert not service.exists() and not log.exists(), name
        records.append(record)
    if os.name != "nt":
        state.write_bytes(b"fail")
        result = run([binary, "serve", "install"], cwd=home, env=env)
        assert result.returncode == 1
        records.append(observe("service-helper-failure", result, home, binary))
    state.write_bytes(b"stopped")
    legacy.unlink()
    result = run([binary, "serve", "install"], cwd=home, env=env)
    assert result.returncode == (1 if os.name == "nt" else 0), result.stderr
    record = observe("service-default-config", result, home, binary)
    assert "Could not load config, using defaults: open " in record["stderr"]
    if os.name != "nt":
        record["service_bytes"] = normal(service.read_bytes(), home, binary)
        assert "8080" in record["service_bytes"] and "127.0.0.1" in record["service_bytes"]
        assert service.stat().st_mode & 0o777 == 0o600
        checked([binary, "serve", "uninstall"], cwd=home, env=env)
    records.append(record)
    return records


def http_cases(binary, seed, base):
    """Exercise real TLS listeners, runtime bind/port and effective flag paths.

    Force-stop only this test's child after observing startup. This is not a
    signal/drain contract; #1242 and #1249 own graceful lifecycle acceptance.
    """
    home = base / "http"
    home.mkdir()
    env = isolated(home)
    seed(home)
    vault = home / "vault"
    # An empty registry makes Go create a legacy wildcard token: the seeded home already holds the
    # scoped registry the public Go CLI created for this fixture.
    records = []
    for name, command, custom, mtls in [
        ("http-default-tls", "serve", False, False),
        ("http-custom-tls", "mcp", True, False),
        ("http-client-ca", "serve", True, True),
    ]:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        args = [binary, "--quiet", command, "--bind", "127.0.0.1", "--port", str(port)]
        cert, key = vault / "mcp-server.crt", vault / "mcp-server.key"
        if custom:
            cert, key = home / "custom.crt", home / "custom.key"
            if not cert.exists():
                shutil.copyfile(vault / "mcp-server.crt", cert)
                shutil.copyfile(vault / "mcp-server.key", key)
                if os.name != "nt":
                    cert.chmod(0o600)
                    key.chmod(0o600)
            args += ["--tls-cert", cert, "--tls-key", key]
        if mtls:
            args += ["--tls-ca", cert]
        for name_of_record in [".runtime-port", ".runtime-tls-cert"]:
            (vault / name_of_record).unlink(missing_ok=True)
        child = subprocess.Popen([str(x) for x in args], cwd=home, env=env,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response = None
        file_modes = None
        try:
            deadline = time.monotonic()+30
            while time.monotonic() < deadline:
                assert child.poll() is None, (name, child.communicate())
                try:
                    # Trust this disposable server's actual public certificate.
                    context = ssl.create_default_context(cafile=str(cert))
                    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=2, context=context)
                    try:
                        connection.request("GET", "/.well-known/oauth-protected-resource")
                        reply = connection.getresponse()
                        response = {"status": reply.status, "body": json.loads(reply.read())}
                    finally:
                        connection.close()
                    assert not mtls, (name, "mTLS accepted an unauthenticated client")
                    break
                except ssl.SSLCertVerificationError:
                    raise
                except (OSError, http.client.HTTPException) as error:
                    if mtls and isinstance(error, (ssl.SSLError, http.client.RemoteDisconnected)) and (vault / ".runtime-tls-cert").exists():
                        response = {"client_without_certificate_rejected": True}
                        break
                    time.sleep(0.1)
            assert response is not None, (name, "TLS server never became ready")
            assert json.loads((vault / ".runtime-port").read_bytes()) == {"bind": "127.0.0.1", "port": port}
            if custom:
                metadata = json.loads((vault / ".runtime-tls-cert").read_bytes())
                assert Path(metadata["certificate"]).samefile(cert)
                assert metadata.get("client_auth_required", False) == mtls
                if mtls:
                    assert Path(metadata["client_ca_file"]).samefile(cert)
                else:
                    assert metadata.get("client_ca_file", "") == ""
            if not mtls:
                assert response["status"] == 200
                body = response["body"]
                assert body["resource_name"] == "Symaira Vault MCP Server"
                assert body["bearer_methods_supported"] == ["header"]
                resource = body["resource"]
                assert resource in [f"http://127.0.0.1:{port}/mcp", f"https://127.0.0.1:{port}/mcp"]
                # ADR 0013 retains Rust's HTTPS discovery URL. The real Go
                # server advertises HTTP even over TLS; retain the actual
                # response in the receipt instead of rewriting that evidence.
                response["body"]["resource"] = resource.replace(str(port), "__PORT__")
            if os.name != "nt":
                file_modes = {"certificate": cert.stat().st_mode & 0o777, "private_key": key.stat().st_mode & 0o777}
                assert file_modes["certificate"] in {0o600, 0o644}
                assert key.stat().st_mode & 0o777 == 0o600
        finally:
            if child.poll() is None:
                child.kill()
            stdout, stderr = child.communicate(timeout=10)
        expected_stderr = "Warning: 'symvault serve' is deprecated, use 'symvault mcp' instead.\n" if command == "serve" else ""
        expected_stderr += f"MCP server listening on 127.0.0.1:{port}\n"
        assert normal(stdout, home, binary) == ""
        actual_stderr = normal(stderr, home, binary)
        assert actual_stderr.startswith(expected_stderr), (name, stderr)
        transport_logs = actual_stderr[len(expected_stderr):]
        if mtls:
            # Keep Go's complete measured transport diagnostics in the
            # receipt; Rust currently rejects the peer without this log.
            for line in transport_logs.splitlines():
                assert re.fullmatch(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} http: TLS handshake error from 127\.0\.0\.1:\d+: tls: client didn't provide a certificate", line), line
        else:
            assert transport_logs == "", (name, stderr)
        records.append({"case": name, "response": response,
                        "runtime_bind_and_port_verified": True, "tls_flag_paths_verified": custom,
                        "stdout": "", "stderr": expected_stderr.replace(str(port), "__PORT__"),
                        "transport_logs": transport_logs,
                        "tls_file_modes": file_modes,
                        "termination": "forced-test-child-stop; graceful-exit-not-measured"})
    return records


def inventory(paths, root):
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode()+b"\0"+(root/path).read_bytes()+b"\0")
    return digest.hexdigest()


def go_init(go, home):
    checked([go, "init", "--auth", "passphrase"], cwd=home, env=isolated(home))


def go_http_home(go, home):
    go_init(go, home)
    checked([go, "agent", "token", "new", "default", "--label", "public-fixture", "--tools", "get_entry"],
            cwd=home, env=isolated(home))


def material_seed(files):
    return lambda home: observations.unpack_tree(files, home)


def compare_observed(go_rows, rust_rows):
    for left, right in zip(go_rows, rust_rows, strict=True):
        if left["case"] in {"http-default-tls", "http-custom-tls"}:
            assert left["response"]["body"]["resource"] == "http://127.0.0.1:__PORT__/mcp"
            assert right["response"]["body"]["resource"] == "https://127.0.0.1:__PORT__/mcp"
            # Compare every other measured property unchanged.
            comparable = json.loads(json.dumps(right))
            comparable["response"]["body"]["resource"] = left["response"]["body"]["resource"]
            if left["case"] == "http-default-tls" and os.name != "nt":
                assert left["tls_file_modes"] == {"certificate": 0o644, "private_key": 0o600}
                assert right["tls_file_modes"] == {"certificate": 0o600, "private_key": 0o600}
                comparable["tls_file_modes"] = left["tls_file_modes"]
            assert left == comparable, (left, right)
        elif left["case"] == "http-client-ca":
            # Rejection is independently proven by the TLS exchange.
            # The async Go log may race this fixture's forced stop;
            # retain and strictly validate every observed line above.
            assert right["transport_logs"] == ""
            comparable = dict(right, transport_logs=left["transport_logs"])
            assert left == comparable, (left, right)
        else:
            assert left == right, (left, right)


def exercise(binary, material, root):
    return (launch_cases(binary, material_seed(material["initialized_home"]), root) + service_cases(binary, root)
            + http_cases(binary, material_seed(material["http_home"]), root))


def capture(args):
    """Capture mode: build the pinned Go oracle and exercise it alone (needs Go)."""
    from build_timeout import oracle_build_timeout, remove_worktree
    if os.name != "nt":
        os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="symvault-serve-capture-") as raw:
        base = Path(raw)
        tree = base / "oracle"
        checked(["git", "worktree", "add", "--detach", tree, ORACLE])
        try:
            go = base / "go"
            checked(["go", "build", "-trimpath", "-buildvcs=false", "-o", go, "."], cwd=tree, timeout=oracle_build_timeout())
            listing = checked(["git", "ls-tree", "-r", "--name-only", ORACLE]).decode().splitlines()
            oracle_sources = sorted(x for x in listing if x in {"go.mod", "go.sum"} or (x.endswith(".go") and not x.endswith("_test.go")))
            embedded = sorted(x for x in listing if x.startswith("internal/mcp/apitemplates/builtin/"))
            assert len(embedded) == 17
            recorded = {"oracle_source_files": oracle_sources, "oracle_source_digest": inventory(oracle_sources, tree),
                        "oracle_embedded_files": embedded, "oracle_embedded_digest": inventory(embedded, tree),
                        "go_binary_sha256": hashlib.sha256(go.read_bytes()).hexdigest()}
            material = observations.existing_material("serve-contract")
            if material is None:
                initialized, http_home = base / "seed-initialized", base / "seed-http"
                initialized.mkdir()
                http_home.mkdir()
                go_init(go, initialized)
                go_http_home(go, http_home)
                material = {"initialized_home": observations.pack_tree(initialized), "http_home": observations.pack_tree(http_home)}
            root = base / "go-roots"
            root.mkdir()
            recorded["go"] = exercise(go, material, root)
            for row in recorded["go"]:
                if row.get("transport_logs"):
                    # The live run already validated each line's exact shape; keep it, minus clock and peer port.
                    stamped = re.sub(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", "__TIMESTAMP__", row["transport_logs"])
                    row["transport_logs"] = re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:__PEER__", stamped)
        finally:
            remove_worktree(lambda: checked(["git", "worktree", "remove", tree]), "oracle worktree")
    target = observations.save("serve-contract", recorded, oracle_commit=ORACLE, version=observations.go_version(),
                               args=["serve_contract.py", "--capture-go"], material=material)
    print(f"captured {observations.rel(target)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--allow-dirty-for-development", action="store_true")
    observations.add_capture_flag(parser)
    args = parser.parse_args()
    if args.capture_go:
        return capture(args)
    assert args.rust and args.receipt, "--rust and --receipt are required"
    rust = args.rust.resolve()
    assert rust.is_file()
    if os.name != "nt":
        # Equal, explicit input: an inherited 0077 umask would conceal Go's
        # public-certificate 0644 versus Rust's private publication mode.
        os.umask(0o022)
    document = observations.load("serve-contract", oracle_commit=ORACLE)
    recorded, material = document["observations"], document["material"]
    clean = not checked(["git", "status", "--porcelain=v1", "--untracked-files=normal"]).strip()
    assert clean or args.allow_dirty_for_development, "commit the candidate before native acceptance"
    sources = sorted(x for x in checked(["git", "ls-files", "--cached", "--others", "--exclude-standard"]).decode().splitlines()
                     if x.startswith(("crates/", "third_party/", "testdata/", "internal/mcp/apitemplates/builtin/"))
                     or x in {"Cargo.toml", "Cargo.lock", ".gitattributes", "scripts/rust-port/serve_contract.py", ".github/workflows/rust-serve-cli.yml"})
    with tempfile.TemporaryDirectory(prefix="symvault-serve-contract-") as raw:
        base = Path(raw)
        root = base / "rust-roots"
        root.mkdir()
        observed = {"go": recorded["go"], "rust": exercise(rust, material, root)}
        compare_observed(observed["go"], observed["rust"])
        receipt = {"passed": True, "oracle_commit": ORACLE, "oracle_source_files": recorded["oracle_source_files"],
                   "oracle_source_digest": recorded["oracle_source_digest"],
                   "oracle_embedded_files": recorded["oracle_embedded_files"], "oracle_embedded_digest": recorded["oracle_embedded_digest"],
                   "go_binary_sha256": recorded["go_binary_sha256"],
                   "rust_binary_sha256": hashlib.sha256(rust.read_bytes()).hexdigest(),
                   "candidate_commit": checked(["git", "rev-parse", "HEAD"]).decode().strip(),
                   "candidate_worktree_clean": clean, "candidate_source_files": sources,
                   "candidate_source_digest": inventory(sources, ROOT),
                   "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "native_os": platform.system(), "architecture": platform.machine(),
                   "keyring": "memory", "service_manager_mode": "injected-process-outcomes",
                   "secure_ui_fixture": "none for bootstrap; explicit lookup-only GUI metadata case with locked credential call denied",
                   "test_umask": "0022" if os.name != "nt" else "native-Windows",
                   "stdio_scope": "locked metadata and locked tool-call rejection; unlocked bootstrap metadata and unknown dispatch; full store/anomaly tool acceptance remains #1248",
                   "go_observation": "replayed from scripts/rust-port/fixtures/go-observations/serve-contract.%s.json" % observations.host_goos(),
                   **observed}
        args.receipt.write_bytes((json.dumps(receipt, indent=2)+"\n").encode("utf-8"))
        print(f"PASS: {len(observed['go'])} recorded Go / live Rust serve observations on {platform.system()}")


if __name__ == "__main__":
    main()
