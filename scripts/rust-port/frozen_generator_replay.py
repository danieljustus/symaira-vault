#!/usr/bin/env python3
"""Go-free replay of the frozen fixtures that three retired Go fixture generators produced.

The kdf-policy, read-policy and update fixtures were produced by Go fixture generators
(kdf_policy_fixtures.py, refresh-read-policy-fixtures.py, refresh-update-fixtures.py) that re-ran a
pinned Go oracle. The generators are gone from this tree (ADR 0036; they live at tag `legacy/go-oracle`),
so there is no capture mode and no generator script to hash. This script only replays:

  replay KIND   no Go: the fixture bytes are the recorded ones, the oracle pin resolves in git and every
                provenance digest recomputes from git blobs (the generator blobs at the pinned commit
                where the pin names them)

KIND is kdf-policy, read-policy or update. A missing observation is a failure, never a skip.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_observations_common as observations

ROOT = observations.ROOT
HERE = Path(__file__).resolve().parent
KDF_SOURCE = "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
READ_POLICY_FIXTURES = ["testdata/port/store/read-resource-policy.json",
                        "crates/symvault-cli/tests/fixtures/import-review/cases.json"]
UPDATE_COMMIT = "58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9"
UPDATE_NAMES = ["update-apply-unsupported", "update-apply-stable", "update-check-cache", "update-check-http",
                "update-apply-transaction"]


def sha256(relative):
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, stdout=subprocess.PIPE).stdout


def blob_digest(commit, names):
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b"\0" + git("show", f"{commit}:{name}") + b"\0")
    return digest.hexdigest()


def require_commit(commit):
    git("cat-file", "-e", commit + "^{commit}")


# ---- kdf-policy -----------------------------------------------------------------

MODULE_FILES = ("go.mod", "go.sum")
KDF_PROGRAM = HERE / "kdf_policy_oracle.go.txt"
KDF_FIXTURE = "testdata/port/crypto/kdf-policy-v1.json"


def kdf_replay(recorded):
    stored = json.loads((ROOT / KDF_FIXTURE).read_text())
    require_commit(KDF_SOURCE)
    # driver_digest names the retired generator script; it is pinned by the frozen fixture bytes, not recomputed.
    files = stored["source_files"]
    assert files[:2] == list(MODULE_FILES) and len(files) == 4 and all(name.endswith(".go") for name in files[2:]), \
        "historical KDF source file list changed"
    provenance = {"schema_version": 1, "oracle_commit": KDF_SOURCE, "source_files": files,
                  "source_digest": module_digest(KDF_SOURCE, files),
                  "program_digest": hashlib.sha256(KDF_PROGRAM.read_bytes()).hexdigest()}
    if any(stored.get(k) != v for k, v in provenance.items()):
        raise SystemExit("historical KDF fixture provenance changed")
    assert stored["go_version"] == recorded["go_version"] == "go1.26.6" and len(stored["cases"]) == 4
    assert [{k: c[k] for k in ("name", "time", "memory_kib", "threads")} for c in stored["cases"]] == recorded["cases"], "historical case drift"
    return "PASS four recorded historical Go KDF envelopes: authentication verdict and provenance"


def module_digest(commit, names):
    """kdf_policy_fixtures.py's own algorithm: name NUL then the blob, no trailing NUL."""
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b"\0")
        digest.update(git("show", f"{commit}:{name}"))
    return digest.hexdigest()


# ---- read-policy ----------------------------------------------------------------

def read_policy_replay(recorded, receipt_path=None):
    policy = json.loads((ROOT / READ_POLICY_FIXTURES[0]).read_text())
    review = json.loads((ROOT / READ_POLICY_FIXTURES[1]).read_text())
    commit = policy["oracle"]["commit_sha"]
    require_commit(commit)
    assert commit == recorded["oracle_commit"], "fixture oracle pin differs from the recorded Go observation"
    sources = sorted(n for n in git("ls-tree", "-r", "--name-only", commit).decode().splitlines()
                     if n in MODULE_FILES or (n.endswith(".go") and not n.endswith("_test.go")))
    assert sources == policy["oracle"]["source_files"], "oracle source file list changed"
    assert blob_digest(commit, sources) == policy["oracle"]["source_digest"], "oracle source digest differs from git blobs"
    assert blob_digest(commit, policy["oracle"]["generator_files"]) == policy["oracle"]["generator_digest"], \
        "generator digest differs from git blobs"
    assert review["oracle"]["commit"] == commit, "import-review oracle does not use the resource-policy pin"
    assert blob_digest(commit, review["oracle"]["source_files"]) == review["oracle"]["source_digest"], "import-review source digest changed"
    assert len(policy["cases"]) == recorded["resource_cases"] and len(review["cases"]) == recorded["import_review_cases"]
    if receipt_path:
        Path(receipt_path).write_text(json.dumps({
            "oracle_commit": commit, "native_os": platform.system(), "session_backend": "memory",
            "resource_cases": recorded["resource_cases"], "import_review_cases": recorded["import_review_cases"],
            "candidate": recorded["candidate"],
            "go_observation": "replayed from scripts/rust-port/fixtures/go-observations/frozen-read-policy.%s.json" % observations.host_goos(),
        }, indent=2) + "\n")
    return (f"PASS recorded Go: {recorded['resource_cases']} resource cases, {recorded['import_review_cases']} "
            f"unchanged import-review cases; {commit}")


# ---- update ---------------------------------------------------------------------

def update_files():
    return [f"crates/symvault-cli/tests/fixtures/{name}/cases.json" for name in UPDATE_NAMES]


def update_replay(recorded):
    commit = git("rev-parse", UPDATE_COMMIT + "^{commit}").decode().strip()
    assert recorded["commit"] == UPDATE_COMMIT
    for name, file in zip(UPDATE_NAMES, update_files()):
        oracle = json.loads((ROOT / file).read_text())["oracle"]
        files = list(oracle["source_files"])
        for module_file in MODULE_FILES:
            if module_file not in files:
                files.append(module_file)
        pinned = [name for name in files if name not in MODULE_FILES]  # the pin covers production code only
        assert oracle["commit"] == commit, f"{name}: oracle pin differs from {UPDATE_COMMIT}"
        assert oracle["source_pin_digest"] == blob_digest(commit, pinned), f"{name}: pinned sources differ from git blobs"
        assert oracle["go_version"] == "go1.26.6"
    return f"PASS recorded Go: {len(UPDATE_NAMES)} update fixture sets, oracle {commit}"


KINDS = {
    "kdf-policy": ("frozen-kdf-policy", kdf_replay),
    "read-policy": ("frozen-read-policy", read_policy_replay),
    "update": ("frozen-update", update_replay),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["replay"])
    parser.add_argument("kind", choices=sorted(KINDS))
    parser.add_argument("--receipt", help="read-policy replay: where to write the receipt")
    args = parser.parse_args(argv)
    contract, replay = KINDS[args.kind]
    document = observations.load(contract)
    recorded = document["observations"]
    for relative, digest in recorded["fixtures"].items():
        if sha256(relative) != digest:
            raise SystemExit(f"{relative}: not the bytes the Go oracle accepted at capture")
    try:
        message = replay(recorded, args.receipt) if args.kind == "read-policy" else replay(recorded)
    except AssertionError as error:
        raise SystemExit(f"FAIL {args.kind}: {error}")
    print(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
