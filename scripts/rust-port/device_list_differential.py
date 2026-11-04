#!/usr/bin/env python3
"""Live pinned-Go / Rust device-list differential (explicit --vault, text/JSON/YAML).

No fixture expectations are invented: execute both real CLIs. Malformed registry
errors compare failure + stream placement only; exact error taxonomy,
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
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

import go_observations_common as observations

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


def compare(go, rust, negative=False, semantic_yaml=False):
    if negative:
        assert go.returncode != 0 and rust.returncode != 0, "must fail closed"
        assert go.stdout == rust.stdout == b"", "error polluted stdout"
        assert go.stderr and rust.stderr, "error missing from stderr"
    else:
        assert go.returncode == rust.returncode == 0, "unexpected exit"
        if semantic_yaml:
            assert go.stdout and rust.stdout, "YAML output is empty"
        else:
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


def windows_job_guard():
    # Check the actual innermost job, not merely a caller-provided flag. The
    # reviewed Go supervisor creates a kill-on-close, non-breakaway job.
    import ctypes
    from ctypes import wintypes

    class Limits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t),
                    ("max_working_set", ctypes.c_size_t), ("active", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                    ("scheduling", wintypes.DWORD)]

    kernel = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    query = kernel.QueryInformationJobObject
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    limits = Limits()
    if not query(None, 2, ctypes.byref(limits), ctypes.sizeof(limits), None):
        raise SystemExit("native Windows job query failed; use the Go supervisor")
    if not limits.flags & 0x2000 or limits.flags & 0x1800:
        raise SystemExit("native Windows job must kill on close and disallow breakaway")


SEEDS = None  # filled by build_cases(); the registry fixtures below are shared by capture and replay
VARIANTS = [("text", []), ("json", ["--output", "json"]), ("yaml", ["--output", "yaml"]),
            ("json-quiet", ["--output", "json", "--quiet"]), ("yaml-quiet", ["--output", "yaml", "--quiet"]),
            ("json-alias", ["--json"]), ("quiet", ["--quiet"]), ("extra", ["ignored", "--output", "json"])]
SEED_NAMES = ["missing", "null", "empty", "unmanaged", "registered", "zero", "malformed"]
SANDBOX = "${SANDBOX}"


def build_cases():
    key = "age1" + "a" * 58
    other = "age1" + "b" * 58
    device = {"name": "laptop<&>\u2028", "public_key": key, "added_at": "2026-09-14T12:34:56.123456789+02:00"}
    seen = {"name": "second", "public_key": other, "added_at": "2026-01-01T00:00:00Z", "last_seen": "2026-09-14T10:11:12.9Z"}
    seeds = [("missing", None, None), ("null", "null", None), ("empty", "[]", "# comment\n"),
             ("unmanaged", "[]", key + "\n" + key + "\n"),
             ("registered", json.dumps([device, seen]), key + "\n" + other + "\n" + "extra-key\n"),
             ("zero", "[{}]", None), ("malformed", "not json", None)]
    assert [s[0] for s in seeds] == SEED_NAMES
    cases = []
    for name, registry, recipients in seeds:
        for mode, flags in VARIANTS:
            setup = []
            if registry is not None:
                setup.append({"path": ".symvault/devices.json", "content": registry})
            if recipients is not None:
                setup.append({"path": "recipients.txt", "content": recipients})
            argv = ["--vault", "${WORKSPACE}", "device", "list", *flags]
            cases.append((name, mode, argv, {"id": f"{name}/{mode}", "args": argv, "setup": setup, "timeout_ms": 10000}))
    return cases


def sandbox_environment(home, tmp, runtime, state, base_env):
    env = {"HOME": home, "USERPROFILE": home, "XDG_CONFIG_HOME": home + "/.config", "XDG_DATA_HOME": home + "/.local/share",
           "XDG_CACHE_HOME": home + "/.cache", "XDG_STATE_HOME": state, "XDG_RUNTIME_DIR": runtime, "TMPDIR": tmp,
           "TMP": tmp, "TEMP": tmp, "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "TERM": "dumb", "NO_COLOR": "1",
           "SYMVAULT_TEST_KEYRING": "memory", "SYMVAULT_SECUREUI": "none"}
    if "PATH" in base_env:
        env["PATH"] = base_env["PATH"]
    return env


def run_case_native(binary, case, base_env):
    """Python port of scripts/rust-port/internal/diff Run for one case (POSIX): fresh HOME/XDG/workspace
    sandbox, setup files, isolated environment, bounded run in its own process group, before/after manifests."""
    root = Path(tempfile.mkdtemp(prefix="symvault-port-"))
    try:
        home, workspace, tmp, runtime = root / "home", root / "workspace", root / "tmp", root / "runtime"
        state = home / ".local" / "state"
        for directory in (home, workspace, tmp, runtime, state):
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        for item in case.get("setup", []):
            relative = Path(item["path"])
            assert not relative.is_absolute() and ".." not in relative.parts, "workspace path escapes sandbox"
            target = workspace / relative
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            target.write_text(item.get("content", ""))
            target.chmod(item.get("mode") or 0o600)
        before = manifest(root)
        replacements = {"${SANDBOX}": str(root), "${HOME}": str(home), "${WORKSPACE}": str(workspace), "${TMPDIR}": str(tmp)}

        def replace(value):
            for key in sorted(replacements):
                value = value.replace(key, replacements[key])
            return value

        argv = [str(Path(binary).resolve()), *[replace(a) for a in case["args"]]]
        env = sandbox_environment(str(home), str(tmp), str(runtime), str(state), base_env)
        timed_out, signalled = False, ""
        with subprocess.Popen(argv, cwd=workspace, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(b"", timeout=case.get("timeout_ms", 10000) / 1000)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=15)
        code = process.returncode
        if code < 0:
            signalled, code = signal.Signals(-code).name, -1
        result = subprocess.CompletedProcess(argv, code, stdout.replace(str(root).encode(), SANDBOX.encode()),
                                             stderr.replace(str(root).encode(), SANDBOX.encode()))
        return result, {"TimedOut": timed_out, "Signal": signalled, "FilesBefore": before, "Files": manifest(root)}
    finally:
        shutil.rmtree(root, ignore_errors=True)


def mini_yaml(text):
    """Parse the block-style YAML both `device list --output yaml` encoders emit (nested mappings,
    sequences of mappings or scalars, `[]`, `null`). Quoting and indentation differ between yaml.v3 and
    serde_yaml_ng; the parsed values must not."""
    def fold(text):
        # libyaml folds breaks inside quoted scalars: U+2028/U+2029 stay data and the indentation
        # an encoder adds after one is skipped; a lone NEL folds to a space.
        text = re.sub(r"[ \t]*([\u2028\u2029])[ \t]*", r"\1", text)
        return re.sub(r"[ \t]*\u0085[ \t]*", " ", text)

    def scalar(raw):
        raw = raw.strip()
        if raw in ("null", "~", ""):
            return None
        if raw in ("true", "false"):
            return raw == "true"
        if raw == "[]":
            return []
        if raw == "{}":
            return {}
        if raw[0] == '"' and raw[-1] == '"':
            return json.loads(re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: "\\u00" + m.group(1), fold(raw)))
        if raw[0] == "'" and raw[-1] == "'":
            return fold(raw[1:-1]).replace("''", "'")
        if re.fullmatch(r"-?\d+", raw):
            return int(raw)
        if re.fullmatch(r"-?\d+\.\d*([eE][-+]?\d+)?", raw):
            return float(raw)
        return raw

    def split_key(content):
        match = re.match(r"""^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s:'"][^:]*?)\s*:(?:\s+(.*))?$""", content)
        return None if match is None else (scalar(match.group(1)), match.group(2) or "")

    lines = [[len(l) - len(l.lstrip(" ")), l.strip()] for l in text.split("\n")  # not splitlines(): U+2028 is data here
             if l.strip() and not l.strip().startswith("#")]
    assert lines, "empty YAML document"
    position = 0

    def is_dash(content):
        return content == "-" or content.startswith("- ")

    def parse(indent):
        nonlocal position
        if is_dash(lines[position][1]):
            items = []
            while position < len(lines) and lines[position][0] == indent and is_dash(lines[position][1]):
                rest = lines[position][1][1:].strip()
                if not rest:
                    position += 1
                    items.append(parse(lines[position][0]) if position < len(lines) and lines[position][0] > indent else None)
                elif rest[0] not in "\"'" and split_key(rest) is not None:
                    lines[position] = [indent + 2, rest]
                    items.append(parse(indent + 2))
                else:
                    position += 1
                    items.append(scalar(rest))
            return items
        mapping = {}
        while position < len(lines) and lines[position][0] == indent and not is_dash(lines[position][1]):
            parsed = split_key(lines[position][1])
            assert parsed is not None, ("unsupported YAML line", lines[position])
            key, value = parsed
            position += 1
            if value.strip():
                mapping[key] = scalar(value)
            elif position < len(lines) and (lines[position][0] > indent or (lines[position][0] == indent and is_dash(lines[position][1]))):
                mapping[key] = parse(lines[position][0])
            else:
                mapping[key] = None
        return mapping

    if len(lines) == 1 and split_key(lines[0][1]) is None and not is_dash(lines[0][1]):
        return scalar(lines[0][1])
    value = parse(lines[0][0])
    assert position == len(lines), ("unparsed YAML tail", lines[position])
    return value


def compare_yaml(go_stdout, rust_stdout):
    assert go_stdout.strip() and rust_stdout.strip(), "YAML output is empty"
    left, right = mini_yaml(go_stdout.decode()), mini_yaml(rust_stdout.decode())
    # type-strict: Python's == makes True == 1 and 1 == 1.0, which would hide a bool/int/float encoder difference
    found = observations.first_difference(left, right)
    assert found is None, f"YAML values differ: {found}"


def validate_report(report, head):
    """Port of cmd/devicelistdriver validateObservations: provenance, case inventory, sandbox stability,
    exit/stream invariants and Go-vs-Rust agreement."""
    assert head and report["head"] == head and report["success"] and report["mutation_rejected"], \
        "report provenance, success, or mutation control is invalid"
    expected = {f"{seed}/{mode}": seed == "malformed" for seed in SEED_NAMES for mode, _ in VARIANTS}
    assert len(report["cases"]) == len(expected), f"report has {len(report['cases'])} cases, want {len(expected)}"
    for observed in report["cases"]:
        negative = expected.get(observed["id"])
        assert negative is not None and observed["success"] and observed["negative"] == negative, \
            f"invalid, duplicate or failed case {observed['id']!r}"
        del expected[observed["id"]]
        go_native, rust_native = observed["native"]["go"], observed["native"]["rust"]
        assert not go_native["TimedOut"] and not go_native["Signal"] and go_native["files_unchanged"], \
            f"timeout, signal or changed sandbox: {observed['id']} (go)"
        assert not rust_native["TimedOut"] and not rust_native["Signal"] and rust_native["FilesBefore"] and \
            rust_native["FilesBefore"] == rust_native["Files"], f"timeout, signal or changed sandbox: {observed['id']} (rust)"
        for name in ("go", "rust"):
            stdout, stderr = observed[name]["stdout_b64"], observed[name]["stderr_b64"]
            if negative:
                assert observed[name]["exit"] != 0 and not stdout and stderr, f"invalid negative result: {observed['id']}"
            else:
                assert observed[name]["exit"] == 0, f"failed positive case: {observed['id']}"
        if not negative:
            go_out, rust_out = (base64.b64decode(observed[n]["stdout_b64"]) for n in ("go", "rust"))
            if observed["id"].endswith("/yaml"):
                compare_yaml(go_out, rust_out)
            else:
                assert go_out == rust_out and observed["go"]["stderr_b64"] == observed["rust"]["stderr_b64"], \
                    f"report mismatch {observed['id']}"


def toolchain_env(env):
    for key, default in [("CARGO_HOME", Path.home() / ".cargo"), ("RUSTUP_HOME", Path.home() / ".rustup")]:
        env.setdefault(key, str(default))
    return env


def sandbox_env_for_build(temp, env):
    home = temp / "home"
    home.mkdir()
    for key in list(env):
        if key.startswith("SYMVAULT_"):
            del env[key]
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"), XDG_DATA_HOME=str(home / "data"),
               XDG_CACHE_HOME=str(home / "cache"), XDG_STATE_HOME=str(home / "state"),
               GOWORK="off", NO_COLOR="1", TERM="dumb", TZ="UTC")
    env.update(TMPDIR=str(temp), TMP=str(temp), TEMP=str(temp))
    return env


def capture():
    """Capture mode: pinned Go oracle through the Go case runner, no Rust (needs Go)."""
    env = toolchain_env(os.environ.copy())
    oracle = checked(["git", "rev-parse", ORACLE], ROOT, env).decode().strip()
    go_version = checked(["go", "version"], ROOT, env).decode().strip()
    assert "go1.26.6" in go_version
    caches = json.loads(checked(["go", "env", "-json", "GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT"], ROOT, env))
    env.update(caches)
    env["PATH"] = str(Path(caches["GOROOT"]) / "bin") + os.pathsep + env.get("PATH", os.defpath)
    rows = []
    with tempfile.TemporaryDirectory(prefix="sv-list-") as temp:
        temp = Path(temp)
        env = sandbox_env_for_build(temp, env)
        env["GOTOOLCHAIN"] = "local"
        assert "go1.26.6" in checked(["go", "version"], ROOT, env).decode()
        oracle_dir = temp / "oracle"
        oracle_dir.mkdir()
        archive = checked(["git", "archive", oracle], ROOT, env)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(oracle_dir, filter="data")
        go_binary = temp / "go-symvault"
        checked(["go", "build", "-buildvcs=false", "-o", go_binary, "."], oracle_dir, env, 600)
        adapter = temp / "caserun"
        checked(["go", "build", "-o", adapter, "./scripts/rust-port/cmd/caserun"], ROOT, env, 600)
        for name, mode, argv, case in build_cases():
            go, native = run_case(adapter, go_binary, case, temp, env)
            root = native.get("SandboxRoot") or ""
            clean = lambda raw: raw.replace(root.encode(), SANDBOX.encode()) if root else raw
            rows.append({"id": case["id"], "argv": argv, "negative": name == "malformed",
                         "go": {"exit": go.returncode, "stdout_b64": base64.b64encode(clean(go.stdout)).decode(),
                                "stderr_b64": base64.b64encode(clean(go.stderr)).decode()},
                         "native_go": {"TimedOut": native["TimedOut"], "Signal": native["Signal"],
                                       "files_unchanged": native["FilesBefore"] == native["Files"] and bool(native["FilesBefore"])}})
    target = observations.save("device-list-differential", {"cases": rows, "binary": "built from the oracle archive without -trimpath: its bytes depend on the temporary build path"},
                               oracle_commit=oracle, version=go_version, args=["device_list_differential.py", "--capture-go"])
    print(f"captured {observations.rel(target)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--rust", type=Path, help="the symvault CLI built from this checkout")
    parser.add_argument("--supervised", action="store_true", help=argparse.SUPPRESS)
    observations.add_capture_flag(parser)
    args = parser.parse_args()
    if os.name == "nt":
        raise SystemExit("native Windows is out of scope for the local port")
    if args.capture_go:
        return capture()
    if args.report and args.report.exists():
        raise SystemExit("report already exists; choose a fresh evidence path")
    assert args.report and args.rust, "--report and --rust are required"
    env = toolchain_env(os.environ.copy())
    head = checked(["git", "rev-parse", "HEAD"], ROOT, env).decode().strip()
    oracle = checked(["git", "rev-parse", ORACLE], ROOT, env).decode().strip()
    assert Path(checked(["git", "rev-parse", "--show-toplevel"], ROOT, env).decode().strip()).resolve() == ROOT
    rust_version = checked(["rustc", "--version"], ROOT, env).decode().strip()
    assert "rustc 1.98.0" in rust_version
    document = observations.load("device-list-differential")
    assert document["oracle_commit"] == oracle, "recorded Go observation belongs to another oracle commit"
    recorded = {row["id"]: row for row in document["observations"]["cases"]}
    rust_binary = args.rust.resolve()
    assert rust_binary.is_file()
    source = source_manifest(env)
    report = {"head": head, "oracle": oracle, "platform": platform.platform(), "cwd": str(ROOT),
              "toolchains": [document["go_version"] + " (recorded)", rust_version],
              "source_sha256": source, "started": time.time(), "cases": [], "success": False,
              "go_observation": "replayed from scripts/rust-port/fixtures/go-observations/device-list-differential.%s.json" % observations.host_goos()}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        report["binaries"] = {"go": document["observations"]["binary"], "rust": hashlib.sha256(rust_binary.read_bytes()).hexdigest()}
        cases = build_cases()
        assert set(recorded) == {case["id"] for *_, case in cases}, "recorded Go observation lacks cases"
        for name, mode, argv, case in cases:
            row = recorded[case["id"]]
            assert row["native_go"]["files_unchanged"] and not row["native_go"]["TimedOut"] and not row["native_go"]["Signal"]
            go = subprocess.CompletedProcess(case["args"], row["go"]["exit"], base64.b64decode(row["go"]["stdout_b64"]),
                                             base64.b64decode(row["go"]["stderr_b64"]))
            rust, native = run_case_native(rust_binary, case, env)
            assert not native["TimedOut"] and not native["Signal"], "native runner timed out or observed signal"
            assert native["FilesBefore"] == native["Files"], "list mutated sandbox"
            observation = {"id": case["id"], "argv": argv, "negative": name == "malformed", "success": False,
                           "native": {"go": row["native_go"], "rust": native},
                           "go": {k: row["go"][k] for k in ("exit", "stdout_b64", "stderr_b64")},
                           "rust": {"exit": rust.returncode, "stdout_b64": base64.b64encode(rust.stdout).decode(),
                                    "stderr_b64": base64.b64encode(rust.stderr).decode()}}
            report["cases"].append(observation)
            if name == "malformed":
                compare(go, rust, True)
            elif mode == "yaml":
                compare(go, rust, False, semantic_yaml=True)
                compare_yaml(go.stdout, rust.stdout)
            else:
                compare(go, rust, False)
            observation["success"] = True
        # Mutation control exercises the same comparator as acceptance.
        altered = subprocess.CompletedProcess([], 0, b"wrong-but-successful\n", b"")
        try:
            compare(subprocess.CompletedProcess([], 0, b"expected\n", b""), altered)
        except AssertionError:
            report["mutation_rejected"] = True
        else:
            raise AssertionError("comparator accepted changed stdout")
        assert len(report["cases"]) == len(SEED_NAMES) * len(VARIANTS)
        assert len({case["id"] for case in report["cases"]}) == len(report["cases"])
        assert all(case["success"] is True for case in report["cases"])
        assert source_manifest(env) == source, "candidate changed while under test"
        report["success"] = True
    finally:
        report["ended"] = time.time()
        with args.report.open("x", encoding="utf-8") as destination:
            destination.write(json.dumps(report, indent=2) + "\n")
    validate_report(report, head)
    print(f"PASS {len(report['cases'])} recorded Go / live Rust device-list cases; report {args.report}")


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("acceptance requires Python assertions enabled")
    main()
