#!/usr/bin/env python3
"""Capture the selected resource policy from an actual immutable Go checkout.

All fixture commands use disposable HOME/XDG/vault roots and public identities.
Resource observations are strict. Import-review cases must retain their already
recorded exit/stdout/stderr and post-command behavior before provenance advances.
"""
import argparse
import datetime
import platform
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "testdata/port/store/read-resource-policy.json"
REVIEW = ROOT / "crates/symvault-cli/tests/fixtures/import-review/cases.json"
GENERATORS = ["scripts/rust-port/cmd/entrypolicygen/main.go",
              "scripts/rust-port/refresh-read-policy-fixtures.py"]
PUBLIC_PASSPHRASE = "correct horse battery staple"


def run(args, cwd=ROOT, env=None, timeout=300):
    result = subprocess.run(args, cwd=cwd, env=env, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): "
                           + result.stderr.decode(errors="replace")[-5000:])
    return result.stdout


def digest(base, names):
    value = hashlib.sha256()
    for name in names:
        value.update(name.encode() + b"\0" + (base / name).read_bytes() + b"\0")
    return value.hexdigest()


def isolated_env(home, vault=None):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("SYMVAULT_")}
    env.update(SYMVAULT_TEST_KEYRING="memory",
               HOME=str(home), USERPROFILE=str(home),
               XDG_CONFIG_HOME=str(home / ".config"),
               XDG_DATA_HOME=str(home / ".local/share"),
               XDG_CACHE_HOME=str(home / ".cache"))
    if vault is not None:
        env.update(SYMVAULT_VAULT=str(vault),
                   SYMVAULT_PASSPHRASE=PUBLIC_PASSPHRASE,
                   SYMVAULT_ALLOW_ENV_PASSPHRASE="1")
        if os.name != "nt":
            env["PATH"] = "/usr/bin:/bin"
    return env


def import_observations(binary, base, fixture):
    cases = json.loads(json.dumps(fixture["cases"]))
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="symvault-import-policy-", dir=base) as name:
            home = Path(name)
            env = isolated_env(home, home / "vault")

            def invoke(argv):
                return subprocess.run([str(binary), *argv], cwd=home, env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=60)

            for argv in case["seed"]:
                seeded = invoke(argv)
                if seeded.returncode:
                    raise RuntimeError(f"seed failed for {case['id']}: "
                                       + seeded.stderr.decode(errors="replace"))
            result = invoke(case["argv"])
            observed = {"exit": result.returncode,
                        "stdout": result.stdout.decode(),
                        "stderr": result.stderr.decode()}
            if case.get("post_argv") is not None:
                post = invoke(case["post_argv"])
                observed.update(post_exit=post.returncode,
                                post_stdout=post.stdout.decode())
            for key, value in observed.items():
                if value != case[key]:
                    raise RuntimeError(f"import-review semantic drift: {case['id']} {key}")
            case.update(observed)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-commit")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    previous = json.loads(POLICY.read_text()) if POLICY.exists() else None
    label = args.oracle_commit or (previous["oracle"]["commit_sha"] if previous else None)
    if not label:
        parser.error("initial generation requires --oracle-commit")
    commit = run(["git", "rev-parse", "--verify", "--end-of-options",
                  label + "^{commit}"]).decode().strip()
    names = run(["git", "ls-tree", "-r", "--name-only", commit]).decode().splitlines()
    sources = sorted(name for name in names
                     if name in {"go.mod", "go.sum"}
                     or (name.endswith(".go") and not name.endswith("_test.go")))
    original_review = json.loads(REVIEW.read_text())
    with tempfile.TemporaryDirectory(prefix="symvault-read-policy-") as name:
        base = Path(name)
        tree = base / "oracle"
        run(["git", "worktree", "add", "--detach", str(tree), commit])
        try:
            source_digest = digest(tree, sources)
            for generator in GENERATORS:
                if (tree / generator).read_bytes() != (ROOT / generator).read_bytes():
                    raise RuntimeError(f"generator is not from oracle commit: {generator}")
            capture = base / ("capture.exe" if os.name == "nt" else "capture")
            cli = base / ("symvault-go.exe" if os.name == "nt" else "symvault-go")
            run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(capture),
                 "./scripts/rust-port/cmd/entrypolicygen"], cwd=tree)
            home = base / "capture-home"
            home.mkdir(mode=0o700)
            observations = json.loads(run([str(capture)], cwd=home, env=isolated_env(home)))
            metadata = {"commit": commit, "commit_sha": commit,
                        "release": "unreleased-vault-read-resources-v2",
                        "source_files": sources, "source_digest": source_digest,
                        "generator_files": GENERATORS,
                        "generator_digest": digest(tree, GENERATORS)}
            fixture = {"schema_version": 1, "policy": "vault-read-resources-v2",
                       "oracle": metadata, "cases": observations}
            if args.check:
                if fixture != previous:
                    raise RuntimeError("actual pinned Go resource observations or provenance changed")
            run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(cli), "."], cwd=tree)
            cases = import_observations(cli, base, original_review)
            review_names = original_review["oracle"]["source_files"]
            review_digest = digest(tree, review_names)
            if args.check:
                if original_review["oracle"]["commit"] != commit:
                    raise RuntimeError("import-review oracle does not use the resource-policy pin")
                if original_review["oracle"]["source_digest"] != review_digest:
                    raise RuntimeError("import-review source digest changed")
            else:
                POLICY.parent.mkdir(parents=True, exist_ok=True)
                POLICY.write_text(json.dumps(fixture, indent=2) + "\n")
                original_review["cases"] = cases
                original_review["oracle"].update(
                    commit=commit, captured=datetime.datetime.now(datetime.UTC).date().isoformat(),
                    binary="actual detached Go build (-trimpath -buildvcs=false)",
                    sha256=hashlib.sha256(cli.read_bytes()).hexdigest(),
                    source_digest=review_digest,
                    generator_files=GENERATORS,
                    generator_digest=digest(tree, GENERATORS))
                REVIEW.write_text(json.dumps(original_review, indent=1) + "\n")
            receipt = {"oracle_commit": commit, "native_os": platform.system(), "session_backend": "memory",
                       "capture_binary_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
                       "cli_binary_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
                       "resource_cases": len(observations), "import_review_cases": len(cases)}
            if args.receipt:
                args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"PASS actual immutable Go: {len(observations)} resource cases, "
                  f"{len(cases)} unchanged import-review cases; {commit}")
        finally:
            run(["git", "worktree", "remove", str(tree)])


if __name__ == "__main__":
    main()
