#!/usr/bin/env python3
"""Go-free replay of the three fixture refresh scripts whose bytes are themselves hashed into frozen fixtures.

kdf_policy_fixtures.py, refresh-read-policy-fixtures.py and refresh-update-fixtures.py check their
committed fixtures by re-running a pinned Go oracle. The scripts' own bytes are digests inside
those fixtures (and in Rust tests), so they stay byte-identical; this companion adds the two modes:

  capture KIND   run the original script's `--check` (Go oracle), then record the fixture bytes it
                 accepted under scripts/rust-port/fixtures/go-observations/frozen-<kind>.<goos>.json
  replay  KIND   no Go: the fixture bytes are the recorded ones, the oracle pin resolves in git and
                 every provenance digest recomputes from git blobs

KIND is kdf-policy, read-policy or update. A missing observation is a failure, never a skip.
"""
import argparse
import hashlib
import importlib.util
import json
import os
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


def load_script(file):
    spec = importlib.util.spec_from_file_location(Path(file).stem.replace("-", "_"), HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def blob_digest(commit, names):
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b"\0" + git("show", f"{commit}:{name}") + b"\0")
    return digest.hexdigest()


def require_commit(commit):
    git("cat-file", "-e", commit + "^{commit}")


# ---- kdf-policy -----------------------------------------------------------------

def kdf_files():
    module = load_script("kdf_policy_fixtures.py")
    return module, ["testdata/port/crypto/kdf-policy-v1.json"]


def kdf_capture():
    subprocess.run([sys.executable, str(HERE / "kdf_policy_fixtures.py")], cwd=ROOT, check=True)
    module, files = kdf_files()
    stored = json.loads((ROOT / files[0]).read_text())
    return {"fixtures": {f: sha256(f) for f in files}, "oracle_commit": KDF_SOURCE, "cases": [
        {k: case[k] for k in ("name", "time", "memory_kib", "threads")} for case in stored["cases"]],
        "go_version": stored["go_version"]}, KDF_SOURCE


def kdf_replay(recorded):
    module, files = kdf_files()
    stored = json.loads((ROOT / files[0]).read_text())
    require_commit(KDF_SOURCE)
    provenance = {"schema_version": 1, "oracle_commit": KDF_SOURCE, "source_files": list(module.SOURCE_FILES),
                  "source_digest": module_digest(KDF_SOURCE, module.SOURCE_FILES),
                  "program_digest": hashlib.sha256(module.PROGRAM.read_bytes()).hexdigest(),
                  "driver_digest": hashlib.sha256((HERE / "kdf_policy_fixtures.py").read_bytes()).hexdigest()}
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

def read_policy_capture():
    receipt = ROOT / "target" / "go-observations-read-policy-receipt.json"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.unlink(missing_ok=True)
    subprocess.run([sys.executable, str(HERE / "refresh-read-policy-fixtures.py"), "--check", "--receipt", str(receipt)],
                   cwd=ROOT, check=True)
    data = json.loads(receipt.read_text())
    policy = json.loads((ROOT / READ_POLICY_FIXTURES[0]).read_text())
    commit = policy["oracle"]["commit_sha"]
    recorded = {"fixtures": {f: sha256(f) for f in READ_POLICY_FIXTURES}, "oracle_commit": commit,
                "resource_cases": data["resource_cases"], "import_review_cases": data["import_review_cases"],
                "candidate": {k: data["candidate"][k] for k in ("source_digest", "generator_digest",
                                                                "resource_cases", "import_review_cases")}}
    return recorded, commit


def read_policy_replay(recorded, receipt_path=None):
    module = load_script("refresh-read-policy-fixtures.py")
    policy = json.loads((ROOT / READ_POLICY_FIXTURES[0]).read_text())
    review = json.loads((ROOT / READ_POLICY_FIXTURES[1]).read_text())
    commit = policy["oracle"]["commit_sha"]
    require_commit(commit)
    assert commit == recorded["oracle_commit"], "fixture oracle pin differs from the recorded Go observation"
    sources = sorted(n for n in git("ls-tree", "-r", "--name-only", commit).decode().splitlines()
                     if n in {"go.mod", "go.sum"} or (n.endswith(".go") and not n.endswith("_test.go")))
    assert sources == policy["oracle"]["source_files"], "oracle source file list changed"
    assert blob_digest(commit, sources) == policy["oracle"]["source_digest"], "oracle source digest differs from git blobs"
    assert blob_digest(commit, module.GENERATORS) == policy["oracle"]["generator_digest"], "generator digest differs from git blobs"
    assert (ROOT / "scripts/rust-port/refresh-read-policy-fixtures.py").read_bytes() == git(
        "show", f"{commit}:scripts/rust-port/refresh-read-policy-fixtures.py"), "generator script is not the oracle commit's"
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


def update_capture():
    env = dict(os.environ, GOWORK="off")
    # `go list -m -json` (inside the generator) reports the module directory only once the module is in the
    # module cache, which a fresh Linux GOMODCACHE lacks; the generator itself is hashed into the fixtures.
    subprocess.run(["go", "mod", "download", "github.com/danieljustus/symaira-corekit@v0.18.2"], cwd=ROOT, env=env, check=True)
    subprocess.run([sys.executable, str(HERE / "refresh-update-fixtures.py"), "--commit", UPDATE_COMMIT, "--check"],
                   cwd=ROOT, env=env, check=True)
    return {"fixtures": {f: sha256(f) for f in update_files()}, "commit": UPDATE_COMMIT}, UPDATE_COMMIT


def update_replay(recorded):
    module = load_script("refresh-update-fixtures.py")
    commit = git("rev-parse", UPDATE_COMMIT + "^{commit}").decode().strip()
    assert recorded["commit"] == UPDATE_COMMIT
    generator = module.digest([module.SCRIPT])
    for name, file in zip(UPDATE_NAMES, update_files()):
        oracle = json.loads((ROOT / file).read_text())["oracle"]
        files = list(oracle["source_files"])
        for module_file in ("go.mod", "go.sum"):
            if module_file not in files:
                files.append(module_file)
        pinned = module.source_pin_files(files)
        assert oracle["commit"] == commit, f"{name}: oracle pin differs from {UPDATE_COMMIT}"
        assert oracle["source_pin_digest"] == blob_digest(commit, pinned), f"{name}: pinned sources differ from git blobs"
        assert oracle["generator_digest"] == generator, f"{name}: generator digest differs from the unchanged script"
        assert oracle["go_version"] == module.ORACLE_GO
    return f"PASS recorded Go: {len(UPDATE_NAMES)} update fixture sets, oracle {commit}"


KINDS = {
    "kdf-policy": ("frozen-kdf-policy", kdf_capture, kdf_replay),
    "read-policy": ("frozen-read-policy", read_policy_capture, read_policy_replay),
    "update": ("frozen-update", update_capture, update_replay),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["capture", "replay"])
    parser.add_argument("kind", choices=sorted(KINDS))
    parser.add_argument("--receipt", help="read-policy replay: where to write the receipt")
    args = parser.parse_args(argv)
    contract, capture, replay = KINDS[args.kind]
    if args.mode == "capture":
        recorded, commit = capture()
        target = observations.save(contract, recorded, oracle_commit=commit, version=observations.go_version(),
                                   args=["frozen_generator_replay.py", "capture", args.kind])
        print(f"captured {observations.rel(target)}")
        return 0
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
