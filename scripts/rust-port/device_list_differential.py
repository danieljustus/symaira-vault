#!/usr/bin/env python3
"""Live pinned-Go / Rust device-list differential (explicit --vault, text/JSON).

No fixture expectations are invented: execute both real CLIs. Malformed registry
errors compare failure + stream placement only; exact error taxonomy, YAML,
config/profile resolution and mutating device commands remain unported.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
ORACLE = "caadd5e"


def run(argv, cwd, env, timeout=300):
    command = list(map(str, argv))
    with subprocess.Popen(command, cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=os.name != "nt") as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=15, check=False)
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=15)
            raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def checked(argv, cwd, env, timeout=300):
    result = run(argv, cwd, env, timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n"
                           + result.stderr.decode(errors="replace"))
    return result.stdout


def manifest(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        mode = path.lstat().st_mode
        item: dict[str, int | str] = {"type": stat.S_IFMT(mode), "mode": stat.S_IMODE(mode)}
        if stat.S_ISREG(mode):
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(mode):
            item["target"] = os.readlink(path)
        result[str(path.relative_to(root))] = item
    return result


def source_manifest(env):
    paths = checked(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], ROOT, env)
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in sorted(set(paths.decode().split("\0")))
            if name and (ROOT / name).is_file()}


def compare(go, rust, negative=False):
    if negative:
        assert go.returncode != 0 and rust.returncode != 0, "must fail closed"
        assert go.stdout == rust.stdout == b"", "error polluted stdout"
        assert go.stderr and rust.stderr, "error missing from stderr"
    else:
        assert go.returncode == rust.returncode == 0, "unexpected exit"
        assert go.stdout == rust.stdout, "stdout differs"
        assert go.stderr == rust.stderr, "stderr differs"


def run_case(adapter, binary, case, cwd, env):
    request = json.dumps({"binary": str(binary), "case": case}).encode()
    result = subprocess.run([str(adapter)], input=request, cwd=cwd, env=env,
                            capture_output=True, timeout=45, check=True)
    observation = json.loads(result.stdout)
    assert not observation["TimedOut"], "native runner timed out"
    assert not observation["Signal"], "native runner observed signal"
    assert observation["FilesBefore"] == observation["Files"], "list mutated sandbox"
    return subprocess.CompletedProcess(case["args"], observation["ExitCode"],
        base64.b64decode(observation["Stdout"] or ""),
        base64.b64decode(observation["Stderr"] or "")), observation


def main():
    if os.name == "nt":
        raise SystemExit("Windows device-list acceptance is pending reuse of the Go job-object runner; refusing unsafe timeout cleanup")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise SystemExit("report already exists; choose a fresh evidence path")
    env = os.environ.copy()
    head = checked(["git", "rev-parse", "HEAD"], ROOT, env).decode().strip()
    oracle = checked(["git", "rev-parse", ORACLE], ROOT, env).decode().strip()
    assert Path(checked(["git", "rev-parse", "--show-toplevel"], ROOT, env).decode().strip()).resolve() == ROOT
    go_version = checked(["go", "version"], ROOT, env).decode().strip()
    rust_version = checked(["rustc", "--version"], ROOT, env).decode().strip()
    assert "go1.26.6" in go_version
    assert "rustc 1.98.0" in rust_version
    for key, default in [("CARGO_HOME", Path.home() / ".cargo"),
                         ("RUSTUP_HOME", Path.home() / ".rustup")]:
        env.setdefault(key, str(default))
    caches = json.loads(checked(["go", "env", "-json", "GOCACHE", "GOMODCACHE"], ROOT, env))
    env.update(caches)
    metadata = json.loads(checked(["cargo", "metadata", "--manifest-path", ROOT / "Cargo.toml",
                                  "--no-deps", "--format-version", "1"], ROOT, env))
    assert Path(metadata["workspace_root"]).resolve() == ROOT
    package = next(p for p in metadata["packages"] if p["name"] == "symvault-cli")
    assert Path(package["manifest_path"]).resolve() == ROOT / "crates/symvault-cli/Cargo.toml"
    assert Path(metadata["target_directory"]).resolve().is_relative_to(ROOT), "target must belong to candidate"
    source = source_manifest(env)
    report = {"head": head, "oracle": oracle, "platform": platform.platform(),
              "cwd": str(ROOT), "toolchains": [go_version, rust_version],
              "source_sha256": source, "started": time.time(), "cases": [], "success": False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="sv-list-") as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            for key in list(env):
                if key.startswith("SYMVAULT_"):
                    del env[key]
            # Preserve explicitly pinned build caches, never user runtime state.
            env.update(HOME=str(home), USERPROFILE=str(home),
                       XDG_CONFIG_HOME=str(home / "config"), XDG_DATA_HOME=str(home / "data"),
                       XDG_CACHE_HOME=str(home / "cache"), XDG_STATE_HOME=str(home / "state"),
                       GOTOOLCHAIN="go1.26.6", GOWORK="off", NO_COLOR="1", TERM="dumb", TZ="UTC")
            env.update(TMPDIR=str(temp), TMP=str(temp), TEMP=str(temp))
            assert "go1.26.6" in checked(["go", "version"], ROOT, env).decode()
            oracle_dir = temp / "oracle"
            oracle_dir.mkdir()
            archive = checked(["git", "archive", oracle], ROOT, env)
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                tar.extractall(oracle_dir, filter="data")
            go_binary = temp / ("go-symvault.exe" if os.name == "nt" else "go-symvault")
            checked(["go", "build", "-o", go_binary, "."], oracle_dir, env, 600)
            adapter = temp / ("caserun.exe" if os.name == "nt" else "caserun")
            checked(["go", "build", "-o", adapter, "./scripts/rust-port/cmd/caserun"], ROOT, env, 600)
            checked(["cargo", "build", "--manifest-path", ROOT / "Cargo.toml", "-p", "symvault-cli", "--locked"], ROOT, env, 600)
            rust_binary = Path(metadata["target_directory"]) / "debug" / ("symvault.exe" if os.name == "nt" else "symvault")
            report["binaries"] = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for name, path in [("go", go_binary), ("rust", rust_binary), ("caserun", adapter)]}
            key = "age1" + "a" * 58
            other = "age1" + "b" * 58
            device = {"name": "laptop<&>\u2028", "public_key": key,
                      "added_at": "2026-09-14T12:34:56.123456789+02:00"}
            seen = {"name": "second", "public_key": other,
                    "added_at": "2026-01-01T00:00:00Z", "last_seen": "2026-09-14T10:11:12.9Z"}
            seeds = [("missing", None, None), ("null", "null", None),
                     ("empty", "[]", "# comment\n"),
                     ("unmanaged", "[]", key + "\n" + key + "\n"),
                     ("registered", json.dumps([device, seen]), key + "\n" + other + "\n" + "extra-key\n"),
                     ("zero", "[{}]", None)]
            variants = [("text", []), ("json", ["--output", "json"]),
                        ("json-alias", ["--json"]), ("quiet", ["--quiet"]),
                        ("extra", ["ignored", "--output", "json"])]
            for name, registry, recipients in seeds + [("malformed", "not json", None)]:
                for mode, flags in variants:
                    setup = []
                    if registry is not None:
                        setup.append({"path": ".symvault/devices.json", "content": registry})
                    if recipients is not None:
                        setup.append({"path": "recipients.txt", "content": recipients})
                    argv = ["--vault", "${WORKSPACE}", "device", "list", *flags]
                    case = {"id": f"{name}/{mode}", "args": argv, "setup": setup, "timeout_ms": 10000}
                    go, go_native = run_case(adapter, go_binary, case, temp, env)
                    rust, rust_native = run_case(adapter, rust_binary, case, temp, env)
                    observation = {"id": f"{name}/{mode}", "argv": argv,
                                   "negative": name == "malformed", "success": False,
                                   "native": {"go": go_native, "rust": rust_native}}
                    for language, result in [("go", go), ("rust", rust)]:
                        observation[language] = {"exit": result.returncode,
                            "stdout_b64": base64.b64encode(result.stdout).decode(),
                            "stderr_b64": base64.b64encode(result.stderr).decode()}
                    report["cases"].append(observation)
                    compare(go, rust, name == "malformed")
                    observation["success"] = True
            # Mutation control exercises the same comparator as acceptance.
            altered = subprocess.CompletedProcess([], 0, b"wrong-but-successful\n", b"")
            try:
                compare(subprocess.CompletedProcess([], 0, b"expected\n", b""), altered)
            except AssertionError:
                report["mutation_rejected"] = True
            else:
                raise AssertionError("comparator accepted changed stdout")
            assert len(report["cases"]) == len(seeds + [(None, None, None)]) * len(variants)
            assert len({case["id"] for case in report["cases"]}) == len(report["cases"])
            assert all(case["success"] is True for case in report["cases"])
            assert source_manifest(env) == source, "candidate changed while under test"
            report["success"] = True
    finally:
        report["ended"] = time.time()
        with args.report.open("x", encoding="utf-8") as destination:
            destination.write(json.dumps(report, indent=2) + "\n")
    print(f"PASS {len(report['cases'])} live device-list cases; report {args.report}")


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("acceptance requires Python assertions enabled")
    main()
