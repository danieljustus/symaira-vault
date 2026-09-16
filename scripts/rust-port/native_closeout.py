#!/usr/bin/env python3
"""Bounded native closeout gates; private runtime roots, retained exact-head logs.

Service mode is only authorized on disposable GitHub-hosted runners. Go native
keyring evidence proves resource availability, not a missing Rust adapter.
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time


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
        # POLICY-001 deliberately advances its own production-Go oracle. policygen
        # verifies this commit against git objects, so a stale pin here fails loudly
        # rather than silently regenerating a mislabeled fixture.
        generator = ["go", "run", "./scripts/rust-port/cmd/policygen", "--output", str(native_fixture), "--oracle-commit", "f195aab", "--oracle-release", "unreleased"]
        report["policy_generator"] = generator
        checked(generator, root, env)
        checked(generator + ["--check"], root, env)
        native_bytes = native_fixture.read_bytes()
        report["policy_fixture_sha256"] = hashlib.sha256(native_bytes).hexdigest()
        # The policy contract is defined over slash-separated logical paths and is
        # OS-independent, so a fixture regenerated natively on this host must be
        # byte-identical to the committed one. This is the input-equality gate:
        # before it, the generator rewrote paths to native separators for Go only
        # and the two implementations were compared on different inputs.
        committed_bytes = (root / "testdata" / "port" / "core" / "policy-contract.json").read_bytes()
        report["policy_fixture_matches_committed"] = native_bytes == committed_bytes
        if native_bytes != committed_bytes:
            raise SystemExit(
                f"natively generated policy fixture differs from the committed one on {platform.system()}: "
                f"{report['policy_fixture_sha256']} vs {hashlib.sha256(committed_bytes).hexdigest()}"
            )
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

            # Cross-implementation exchange. The two commands above each
            # round-trip their own entry, which is why the probe used to report
            # rust_parity: false -- neither side ever read what the other
            # wrote, so both would stay green even if the adapters disagreed
            # about encoding. Here Go writes, Rust reads it back and writes its
            # own value, and Go reads that. One namespace, generated per run,
            # and the Go verify step deletes it even when the comparison fails.
            #
            # Both payloads are deliberately invalid UTF-8: Go's backend takes a
            # string and Rust's takes a byte slice, which is exactly where a
            # silent encoding difference would hide. They travel as hex so argv
            # carries them intact.
            parity_key = f"symvault:rust-port-cross-parity-{os.getpid()}-{time.time_ns()}|session"
            go_payload = "00ff0180 0a0d7c00".replace(" ", "")
            rust_payload = "fe01ff00 7c0a0d02".replace(" ", "")
            report["cross_parity_key"] = parity_key
            report["cross_parity_go_payload_hex"] = go_payload
            report["cross_parity_rust_payload_hex"] = rust_payload
            env["SYMVAULT_PARITY_KEY"] = parity_key
            env["SYMVAULT_PARITY_EXPECT_HEX"] = go_payload
            env["SYMVAULT_PARITY_WRITE_HEX"] = rust_payload
            commands.append(["go", "run", "./scripts/rust-port/cmd/nativekeyringprobe",
                             "-mode=write", f"-key={parity_key}", f"-hex={go_payload}"])
            commands.append(cargo + ["-p", "symvault-platform", "--test", "native_keyring", "--all-features", "--", "--ignored", "--exact", "native_keyring_cross_parity", "--nocapture"])
            commands.append(["go", "run", "./scripts/rust-port/cmd/nativekeyringprobe",
                             "-mode=verify", f"-key={parity_key}", f"-hex={rust_payload}"])
    report_path.write_text(json.dumps(report, indent=2))
    tmp_parent = "/private/tmp" if platform.system() == "Darwin" else None
    try:
        with tempfile.TemporaryDirectory(prefix="sv-native-", dir=tmp_parent) as temporary, contextlib.ExitStack() as cleanup:
            for key, leaf in [("HOME", "home"), ("USERPROFILE", "home"), ("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime"), ("TMPDIR", "tmp"), ("TMP", "tmp"), ("TEMP", "tmp")]:
                directory = Path(temporary) / leaf
                directory.mkdir(mode=0o700, exist_ok=True)
                env[key] = str(directory)
            if args.mode == "keyring" and platform.system() == "Darwin":
                # Configure the same private HOME used by the adapters, not the
                # runner's ambient preference domain. Only test data is stored.
                #
                # The keychain "user" domain is resolved through $HOME, so this
                # private HOME redirects it away from the operator's real login
                # keychain. That redirection is also why the directories below
                # must exist first: security writes the search list and default
                # keychain into $HOME/Library/Preferences and silently does
                # nothing when that directory is absent, still exiting 0. The
                # provisioning then looked successful while the domain stayed
                # empty, and every keyring probe failed with "OS keyring
                # unavailable (locked or non-interactive)".
                for leaf in ("Preferences", "Keychains"):
                    (Path(env["HOME"]) / "Library" / leaf).mkdir(parents=True, exist_ok=True)
                keychain = str(Path(temporary) / "native-test.keychain-db")
                checked(["security", "create-keychain", "-p", "disposable-native-test", keychain], root, env)
                cleanup.callback(checked, ["security", "delete-keychain", keychain], root, env)
                checked(["security", "unlock-keychain", "-p", "disposable-native-test", keychain], root, env)
                checked(["security", "set-keychain-settings", "-lut", "1800", keychain], root, env)
                checked(["security", "list-keychains", "-d", "user", "-s", keychain], root, env)
                checked(["security", "default-keychain", "-d", "user", "-s", keychain], root, env)
                # Read the domain back rather than trusting the exit codes, so a
                # silently ineffective provisioning fails here instead of
                # surfacing later as an unexplained keyring failure.
                search_list = checked(["security", "list-keychains", "-d", "user"], root, env)
                default_keychain = checked(["security", "default-keychain", "-d", "user"], root, env)
                if keychain not in search_list or keychain not in default_keychain:
                    raise SystemExit(
                        "private keychain provisioning did not take effect: "
                        f"search list {search_list!r}, default {default_keychain!r}, want {keychain!r}"
                    )
                report["private_keychain_provisioned"] = True
                report["private_keychain"] = keychain
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
    except BaseException:
        report["passed"] = False
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
