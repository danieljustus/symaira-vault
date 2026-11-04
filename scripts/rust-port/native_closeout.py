#!/usr/bin/env python3
"""Bounded native closeout gates; private runtime roots, retained exact-head logs.

Service mode is only authorized on disposable GitHub-hosted runners. Go native
keyring evidence proves resource availability, not a missing Rust adapter.

Go-free. The two places that needed the Go oracle were recorded once per OS:

  portable   `policygen` regenerated the policy fixture natively and `--check`ed it. The committed
             fixture still has the bytes that native Go regeneration produced (observation
             `native-closeout-policy.<goos>.json`), and Rust runs against it.
  keyring    Go wrote an item to the native keyring, Rust updated it, Go read it. The Go halves are
             the attestation `native-keyring-interop.<goos>.json` (a historical three-stage run); the
             Rust half (store the attested payload, update, read back, delete) runs live.

There is no live-Go, capture or attest mode in this tree (tag `legacy/go-oracle` holds them).
A missing or malformed record is a failure, never a skip.
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
import shlex
import subprocess
import sys
import tempfile

import go_observations_common as obs

POLICY_FIXTURE = "testdata/port/core/policy-contract.json"
POLICY_OBSERVATION = "native-closeout-policy"
KEYRING_ATTESTATION = "native-keyring-interop"
POLICY_ORACLE_COMMIT = "f195aab"


def checked(argv, root, env):
    return subprocess.check_output(argv, cwd=root, env=env, text=True, timeout=60).strip()


def replay_policy(root, report):
    """Go-free: the committed fixture is the one native Go regeneration produced on this OS."""
    document = obs.load(POLICY_OBSERVATION)
    recorded = document["observations"]
    committed = hashlib.sha256((root / POLICY_FIXTURE).read_bytes()).hexdigest()
    if not (recorded.get("native_matches_committed") is True and recorded.get("check_exit") == 0
            and recorded.get("oracle_pin") == POLICY_ORACLE_COMMIT
            and recorded.get("committed_fixture") == POLICY_FIXTURE):
        raise SystemExit(f"{obs.rel(obs.path(POLICY_OBSERVATION))}: not an accepting native policy regeneration")
    if recorded.get("native_fixture_sha256") != committed:
        raise SystemExit(f"{POLICY_FIXTURE} no longer has the bytes native Go regeneration produced "
                         f"({committed} vs {recorded.get('native_fixture_sha256')})")
    report["policy_fixture_sha256"] = committed
    report["policy_fixture_matches_committed"] = True
    report["policy_go_observation"] = {"goos": document["goos"], "go_version": document["go_version"],
                                       "oracle_commit": document["oracle_commit"]}
    return root / POLICY_FIXTURE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["portable", "keyring", "daemon", "clipboard"])
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
    report = {"head": head, "platform": platform.system(), "architecture": platform.machine(), "mode": args.mode, "passed": False,
              "commands": [], "go_free": True}
    home = Path.home()
    env["CARGO_HOME"] = env.get("CARGO_HOME", str(home / ".cargo"))
    env["RUSTUP_HOME"] = env.get("RUSTUP_HOME", str(home / ".rustup"))
    env.update(RUSTUP_TOOLCHAIN="1.98.0")
    env["CARGO_TARGET_DIR"] = env.get("CARGO_TARGET_DIR", str(root / "target"))
    env.pop("SYMVAULT_PASSPHRASE", None)
    env.pop("SYMVAULT_ALLOW_ENV_PASSPHRASE", None)
    report["rust"] = checked(["rustc", "--version"], root, env)
    assert report["rust"].startswith("rustc 1.98.0 ")
    cargo = ["cargo", "test", "--manifest-path", str(root / "Cargo.toml"), "--locked"]
    if args.mode == "portable":
        native_fixture = replay_policy(root, report)
        env["SYMVAULT_POLICY_FIXTURE"] = str(native_fixture)
        commands = [cargo + ["-p", "symvault-cli", "--test", "device_pairing_cli", "--", "--nocapture"],
                    cargo + ["-p", "symvault-core", "-p", "symvault-platform", "--all-targets", "--all-features", "--", "--nocapture"]]
    elif args.mode == "daemon":
        assert platform.system() == "Darwin"
        commands = [cargo + ["-p", "symvault-platform", "--test", "native_daemon", "--all-features", "--", "--ignored", "--exact", "native_daemon_private_home_lifecycle_attempt", "--nocapture"]]
    elif args.mode == "clipboard":
        assert platform.system() == "Darwin"
        commands = [cargo + ["-p", "symvault-platform", "--test", "native_clipboard", "--all-features", "--", "--ignored", "--exact", "native_clipboard_set_read_clear", "--nocapture"]]
    else:
        # The Go write/verify halves are the committed attestation; Rust stores the attested payload itself.
        attestation = obs.check_attestation(KEYRING_ATTESTATION)
        report["go_attestation"] = {"name": KEYRING_ATTESTATION, "goos": attestation["goos"],
                                    "oracle_commit": attestation["oracle_commit"]}
        if attestation.get("source") == "ci-run":
            report["go_attestation"].update(source="ci-run", run_url=attestation["run_url"], job_id=attestation["job_id"],
                                            commit=attestation["commit"], source_digest=attestation["source_digest"])
        else:
            report["go_attestation"].update(source="local-go-run", go_version=attestation["go_version"],
                                            rust_commit=attestation["rust_commit"])
        stages = [cargo + ["-p", "symvault-platform", "--test", "native_keyring_interop", "--all-features", "--", "--ignored", "--exact", "native_keyring_rust_half_set_update_read_delete", "--nocapture"]]
        sequence = " && ".join(shlex.join(stage) for stage in stages)
        if platform.system() == "Linux":
            # All stages must use the same disposable Secret Service.
            sequence = "printf 'disposable-native-test\\n' | gnome-keyring-daemon --unlock --components=secrets; " + sequence
            commands = [["dbus-run-session", "--", "bash", "-euc", sequence]]
        else:
            # Native Windows bash may resolve to the WSL launcher. Execute argv
            # arrays directly on Windows/macOS; preserve one combined gate log.
            commands = [[sys.executable, "-c",
                         "import json,subprocess,sys; "
                         "[subprocess.run(argv, check=True) for argv in json.loads(sys.argv[1])]",
                         json.dumps(stages)]]
        report["interop_stages"] = stages
    report_path.write_text(json.dumps(report, indent=2))
    tmp_parent = env.get("TMPDIR") or ("/private/tmp" if platform.system() == "Darwin" else None)
    try:
        with tempfile.TemporaryDirectory(prefix="sv-native-", dir=tmp_parent) as temporary, contextlib.ExitStack() as cleanup:
            for key, leaf in [("HOME", "home"), ("USERPROFILE", "home"), ("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime"), ("TMPDIR", "tmp"), ("TMP", "tmp"), ("TEMP", "tmp")]:
                directory = Path(temporary) / leaf
                directory.mkdir(mode=0o700, exist_ok=True)
                env[key] = str(directory)
            env["SYMVAULT_NATIVE_KEYRING_INTEROP_REPORT"] = str(Path(temporary) / "keyring-interop.json")
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
                counts = [int(n) for n in re.findall(r"test result: ok\. (\d+) passed", text)]
                entry["executed_tests"] = sum(counts)
                assert entry["executed_tests"] > 0, "zero executed tests"
                if any("--ignored" in str(part) for part in command):
                    assert counts == [1], "native test must execute exactly once"
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
