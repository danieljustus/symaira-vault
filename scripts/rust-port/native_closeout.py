#!/usr/bin/env python3
"""Bounded native closeout gates; private runtime roots, retained exact-head logs.

Service mode is only authorized on disposable GitHub-hosted runners. Go native
keyring evidence proves resource availability, not a missing Rust adapter.

Go-free by default. The two places that needed the Go oracle are recorded once per OS:

  portable   `policygen` regenerated the policy fixture natively and `--check`ed it. The committed
             fixture still has the bytes that native Go regeneration produced (observation
             `native-closeout-policy.<goos>.json`, `--capture-go`), and Rust runs against it.
  keyring    Go wrote an item to the native keyring, Rust updated it, Go read it. The Go halves are
             the attestation `native-keyring-interop.<goos>.json` (`--attest-go`, a live three-stage
             run); the Rust half (store the attested payload, update, read back, delete) runs live.

`--live-go` keeps the original Go-driven runs (hosted CI, a Go capture host); `--capture-go`
(portable) and `--attest-go` (keyring, which implies `--live-go`) write the records above.
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


def policy_generator(output):
    # POLICY-001 deliberately advances its own production-Go oracle. policygen
    # verifies this commit against git objects, so a stale pin here fails loudly
    # rather than silently regenerating a mislabeled fixture.
    return ["go", "run", "./scripts/rust-port/cmd/policygen", "--output", str(output),
            "--oracle-commit", POLICY_ORACLE_COMMIT, "--oracle-release", "unreleased"]


def native_policy_regeneration(root, env, output, report):
    """Live Go: regenerate the policy fixture natively and require it to equal the committed one."""
    generator = policy_generator(output)
    report["policy_generator"] = generator
    # Set the test backend in the child environment before Go initializes
    # packages that capture their keyring backend.
    generator_env = env.copy()
    generator_env["SYMVAULT_TEST_KEYRING"] = "memory"
    checked(generator, root, generator_env)
    checked(generator + ["--check"], root, generator_env)
    native_bytes = output.read_bytes()
    report["policy_fixture_sha256"] = hashlib.sha256(native_bytes).hexdigest()
    # The policy contract is defined over slash-separated logical paths and is
    # OS-independent, so a fixture regenerated natively on this host must be
    # byte-identical to the committed one. This is the input-equality gate:
    # before it, the generator rewrote paths to native separators for Go only
    # and the two implementations were compared on different inputs.
    committed_bytes = (root / POLICY_FIXTURE).read_bytes()
    report["policy_fixture_matches_committed"] = native_bytes == committed_bytes
    if native_bytes != committed_bytes:
        raise SystemExit(
            f"natively generated policy fixture differs from the committed one on {platform.system()}: "
            f"{report['policy_fixture_sha256']} vs {hashlib.sha256(committed_bytes).hexdigest()}"
        )


def capture_policy(root, env, output_dir):
    """`--capture-go portable`: record the native Go regeneration of the policy fixture (needs Go)."""
    env.update(GOTOOLCHAIN="go1.26.6", GOWORK="off")
    report = {}
    output_dir.mkdir(parents=True, exist_ok=True)
    native_policy_regeneration(root, env, output_dir / "policy-contract.json", report)
    observations = {"oracle_pin": POLICY_ORACLE_COMMIT, "oracle_release": "unreleased", "check_exit": 0,
                    "committed_fixture": POLICY_FIXTURE, "native_fixture_sha256": report["policy_fixture_sha256"],
                    "native_matches_committed": True}
    commit, version = obs.tree_oracle_commit(), obs.go_version(env, root)
    saved = obs.save(POLICY_OBSERVATION, observations, oracle_commit=commit, version=version, args=policy_generator("<output>"))
    print(f"captured {obs.rel(saved)}")


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
    parser.add_argument("--live-go", action="store_true", help="drive the Go oracle live (hosted CI, capture hosts)")
    parser.add_argument("--capture-go", action="store_true", help="portable: record the native Go policy regeneration")
    parser.add_argument("--attest-go", action="store_true", help="keyring: live three-stage run, then write the attestation")
    args = parser.parse_args()
    if args.attest_go:
        args.live_go = True
    assert not (args.capture_go and args.mode != "portable"), "--capture-go records the portable policy regeneration"
    assert not (args.attest_go and args.mode != "keyring"), "--attest-go records the keyring interop attestation"
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    assert Path(checked(["git", "rev-parse", "--show-toplevel"], root, env)).resolve() == root
    if args.capture_go:
        capture_policy(root, env, root / "target" / "native-closeout" / "policy-capture")
        return
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
              "commands": [], "go_free": not args.live_go}
    home = Path.home()
    env["CARGO_HOME"] = env.get("CARGO_HOME", str(home / ".cargo"))
    env["RUSTUP_HOME"] = env.get("RUSTUP_HOME", str(home / ".rustup"))
    env.update(RUSTUP_TOOLCHAIN="1.98.0")
    if args.live_go:
        env.update(GOTOOLCHAIN="go1.26.6", GOWORK="off")
        goroot = checked(["go", "env", "GOROOT"], root, env)
        env["PATH"] = str(Path(goroot) / "bin") + os.pathsep + env["PATH"]
        env["GOMODCACHE"] = checked(["go", "env", "GOMODCACHE"], root, env)
        env["GOCACHE"] = checked(["go", "env", "GOCACHE"], root, env)
    env["CARGO_TARGET_DIR"] = env.get("CARGO_TARGET_DIR", str(root / "target"))
    env.pop("SYMVAULT_PASSPHRASE", None)
    env.pop("SYMVAULT_ALLOW_ENV_PASSPHRASE", None)
    if args.live_go:
        report["go"] = checked(["go", "version"], root, env)
        assert report["go"].startswith("go version go1.26.6 ")
    report["rust"] = checked(["rustc", "--version"], root, env)
    assert report["rust"].startswith("rustc 1.98.0 ")
    cargo = ["cargo", "test", "--manifest-path", str(root / "Cargo.toml"), "--locked"]
    attested_stages = None
    if args.mode == "portable":
        if args.live_go:
            native_fixture = output / "policy-contract.json"
            native_policy_regeneration(root, env, native_fixture, report)
        else:
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
        if args.live_go:
            stages = [
                ["go", "run", "./scripts/rust-port/cmd/nativekeyringinterop", "write"],
                cargo + ["-p", "symvault-platform", "--test", "native_keyring_interop", "--all-features", "--", "--ignored", "--exact", "native_keyring_go_write_rust_update_go_read_delete", "--nocapture"],
                ["go", "run", "./scripts/rust-port/cmd/nativekeyringinterop", "verify"],
            ]
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
                rust_only = command[0] == "cargo" or (args.mode == "keyring" and not args.live_go)
                if rust_only:
                    counts = [int(n) for n in re.findall(r"test result: ok\. (\d+) passed", text)]
                    entry["executed_tests"] = sum(counts)
                    assert entry["executed_tests"] > 0, "zero executed tests"
                    if any("--ignored" in str(part) for part in command):
                        assert counts == [1], "native test must execute exactly once"
                else:
                    records = [json.loads(line) for line in text.splitlines() if line.startswith('{"')]
                    if args.mode == "keyring":
                        assert len(records) == 2 and [r["mode"] for r in records] == ["write", "verify"]
                        assert all(r["passed"] is True for r in records)
                        assert re.findall(r"test result: ok\. (\d+) passed", text) == ["1"]
                        entry["native_observation"] = {"passed": True, "rust_parity": True, "stages": records}
                        attested_stages = records
                    else:
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
    if args.attest_go and report["passed"]:
        # The Go verdict is the pair of stage records (write, verify), without the per-run item key.
        verdict = json.dumps(attested_stages, sort_keys=True)
        saved = obs.record_attestation(
            KEYRING_ATTESTATION, ["rust-native-keyring-test=crates/symvault-platform/tests/native_keyring_interop.rs"],
            ["native_closeout.py", "keyring", "--attest-go"], env, 0, verdict,
            "Go NewOSKeyring writes a native item, the Rust adapter updates it, Go reads it back and deletes it")
        print(f"attested {obs.rel(saved)}")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
