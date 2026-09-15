#!/usr/bin/env python3
"""Bounded native closeout gates; private runtime roots, retained exact-head logs.

Service mode is only authorized on disposable GitHub-hosted runners. Go native
keyring evidence proves resource availability, not a missing Rust adapter.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


def checked(argv, root, env):
    return subprocess.check_output(argv, cwd=root, env=env, text=True, timeout=60).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["portable", "keyring", "daemon"])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    assert Path(checked(["git", "rev-parse", "--show-toplevel"], root, env)).resolve() == root
    if args.mode != "portable":
        assert env.get("GITHUB_ACTIONS") == "true"
        assert env.get("SYMVAULT_DISPOSABLE_NATIVE_RUNNER") == "1"
    head = checked(["git", "rev-parse", "HEAD"], root, env)
    assert not checked(["git", "status", "--porcelain"], root, env), "native acceptance requires clean source"
    if env.get("GITHUB_SHA"):
        assert env["GITHUB_SHA"] == head
    output = root / "target" / "native-closeout" / args.mode
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report = {"head": head, "platform": platform.system(), "architecture": platform.machine(), "mode": args.mode, "passed": False, "commands": []}
    home = Path.home()
    env["CARGO_HOME"] = env.get("CARGO_HOME", str(home / ".cargo"))
    env["RUSTUP_HOME"] = env.get("RUSTUP_HOME", str(home / ".rustup"))
    env.update(GOTOOLCHAIN="go1.26.6", RUSTUP_TOOLCHAIN="1.98.0", GOWORK="off")
    goroot = checked(["go", "env", "GOROOT"], root, env)
    env["PATH"] = str(Path(goroot) / "bin") + os.pathsep + env["PATH"]
    env["GOMODCACHE"] = checked(["go", "env", "GOMODCACHE"], root, env)
    env["GOCACHE"] = checked(["go", "env", "GOCACHE"], root, env)
    env["CARGO_TARGET_DIR"] = str(root / "target")
    env.pop("SYMVAULT_PASSPHRASE", None)
    env.pop("SYMVAULT_ALLOW_ENV_PASSPHRASE", None)
    report["go"] = checked(["go", "version"], root, env)
    report["rust"] = checked(["rustc", "--version"], root, env)
    assert report["go"].startswith("go version go1.26.6 ")
    assert report["rust"].startswith("rustc 1.98.0 ")
    cargo = ["cargo", "test", "--manifest-path", str(root / "Cargo.toml"), "--locked"]
    if args.mode == "portable":
        native_fixture = output / "policy-contract.json"
        generator = ["go", "run", "./scripts/rust-port/cmd/policygen", "--output", str(native_fixture), "--oracle-commit", "caadd5e", "--oracle-release", "v0.22.1"]
        report["policy_generator"] = generator
        checked(generator, root, env)
        checked(generator + ["--check"], root, env)
        report["policy_fixture_sha256"] = hashlib.sha256(native_fixture.read_bytes()).hexdigest()
        env["SYMVAULT_POLICY_FIXTURE"] = str(native_fixture)
        commands = [cargo + ["-p", "symvault-cli", "--test", "device_pairing_cli", "--", "--nocapture"],
                    cargo + ["-p", "symvault-core", "-p", "symvault-platform", "--all-targets", "--all-features", "--", "--nocapture"]]
    elif args.mode == "daemon":
        assert platform.system() == "Darwin"
        commands = [cargo + ["-p", "symvault-platform", "--test", "native_daemon", "--all-features", "--", "--ignored", "--exact", "native_daemon_private_home_lifecycle_attempt", "--nocapture"]]
    else:
        probe = ["go", "run", "./scripts/rust-port/cmd/nativekeyringprobe"]
        if platform.system() == "Linux":
            # A new D-Bus session and private HOME isolate Secret Service. This
            # password protects only the disposable test keyring, never user data.
            probe = ["dbus-run-session", "--", "bash", "-euc", "printf 'disposable-native-test\\n' | gnome-keyring-daemon --unlock --components=secrets; go run ./scripts/rust-port/cmd/nativekeyringprobe"]
        commands = [probe]
        if platform.system() == "Darwin":
            commands.append(cargo + ["-p", "symvault-platform", "--test", "native_keyring", "--all-features", "--", "--ignored", "--exact", "native_keyring_binary_roundtrip_and_delete", "--nocapture"])
    report_path.write_text(json.dumps(report, indent=2))
    tmp_parent = "/private/tmp" if platform.system() == "Darwin" else None
    try:
        with tempfile.TemporaryDirectory(prefix="sv-native-", dir=tmp_parent) as temporary:
            for key, leaf in [("HOME", "home"), ("USERPROFILE", "home"), ("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime"), ("TMPDIR", "tmp"), ("TMP", "tmp"), ("TEMP", "tmp")]:
                directory = Path(temporary) / leaf
                directory.mkdir(mode=0o700, exist_ok=True)
                env[key] = str(directory)
            for index, command in enumerate(commands):
                log_path = output / f"{index}.log"
                entry = {"argv": command, "cwd": str(root), "start": datetime.datetime.now(datetime.timezone.utc).isoformat(), "log": str(log_path)}
                report["commands"].append(entry)
                report_path.write_text(json.dumps(report, indent=2))
                with log_path.open("wb") as log:
                    result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=900)
                raw = log_path.read_bytes()
                text = raw.decode("utf-8", errors="replace")
                entry.update(exit_code=result.returncode, sha256=hashlib.sha256(raw).hexdigest(), end=datetime.datetime.now(datetime.timezone.utc).isoformat())
                if result.returncode != 0:
                    entry["failed"] = True
                    continue
                if command[0] == "cargo":
                    counts = [int(n) for n in re.findall(r"test result: ok\. (\d+) passed", text)]
                    entry["executed_tests"] = sum(counts)
                    assert entry["executed_tests"] > 0, "zero executed tests"
                    if "--ignored" in command:
                        assert counts == [1], "native test must execute exactly once"
                else:
                    records = [json.loads(line) for line in text.splitlines() if line.startswith('{"')]
                    assert len(records) == 1 and records[0]["passed"] is True
                    entry["native_observation"] = records[0]
                assert result.returncode == 0, f"gate failed: {command}; inspect {log_path}"
            assert checked(["git", "rev-parse", "HEAD"], root, env) == head
            assert not checked(["git", "status", "--porcelain"], root, env)
            report["passed"] = all(not entry.get("failed", False) for entry in report["commands"])
    finally:
        report_path.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
