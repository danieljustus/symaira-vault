#!/usr/bin/env python3
"""Capture/check real historical Go envelopes in an isolated pinned checkout."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
SOURCE_FILES = ("go.mod", "go.sum", "internal/crypto/argon2id.go", "internal/crypto/symmetric.go")
GO_TOOLCHAIN = "go1.26.6"
PROGRAM = ROOT / "scripts/rust-port/kdf_policy_oracle.go.txt"
FIXTURE = ROOT / "testdata/port/crypto/kdf-policy-v1.json"


def run(argv, **kwargs):
    try:
        return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout
    except subprocess.CalledProcessError as error:
        # The child's stderr is the only evidence of why it failed.
        sys.stderr.write(f"command failed (exit {error.returncode}): {argv}\n")
        sys.stderr.write(error.stderr.decode(errors="replace") if error.stderr else "")
        raise


def pinned_go(parent_env):
    """Resolve the pinned compiler with the caller's real HOME, before isolation.

    GOTOOLCHAIN=go1.26.6 makes cmd/go exec a `go1.26.6` found on PATH. That is
    usually the golang.org/dl wrapper in ~/go/bin, which needs $HOME/sdk, or else
    cmd/go downloads the toolchain and its modules into a cache below HOME. Both
    break (silently, exit 1, or after a ten second download) once HOME is blank.
    Resolve GOROOT and the caches here, then run <GOROOT>/bin/go with
    GOTOOLCHAIN=local so that no later step can switch or fetch a compiler.
    """
    env = dict(parent_env, GOTOOLCHAIN=GO_TOOLCHAIN, GOWORK="off")
    with tempfile.TemporaryDirectory(prefix="symvault-kdf-go-") as neutral:
        # A neutral directory: no go.mod may influence the toolchain choice.
        raw = run(["go", "env", "-json", "GOROOT", "GOVERSION", "GOCACHE", "GOMODCACHE", "GOPATH"],
                  cwd=neutral, env=env)
    if not raw.strip():
        raise ValueError(f"`go env` printed nothing for GOTOOLCHAIN={GO_TOOLCHAIN}: the toolchain wrapper on PATH failed")
    settings = json.loads(raw)
    if settings["GOVERSION"] != GO_TOOLCHAIN:
        raise ValueError(f"pinned Go is {GO_TOOLCHAIN}, resolved {settings['GOVERSION']}")
    go = Path(settings["GOROOT"]) / "bin" / "go"
    if not go.is_file():
        raise ValueError(f"resolved compiler is missing: {go}")
    return str(go), {"GOROOT": settings["GOROOT"], "GOCACHE": settings["GOCACHE"],
                     "GOMODCACHE": settings["GOMODCACHE"], "GOPATH": settings["GOPATH"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    digest = hashlib.sha256()
    for name in SOURCE_FILES:
        digest.update(name.encode() + b"\0")
        digest.update(run(["git", "show", f"{SOURCE}:{name}"], cwd=ROOT))
    provenance = {
        "schema_version": 1,
        "oracle_commit": SOURCE,
        "source_files": list(SOURCE_FILES),
        "source_digest": digest.hexdigest(),
        "program_digest": hashlib.sha256(PROGRAM.read_bytes()).hexdigest(),
        "driver_digest": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    stored = None if args.generate else json.loads(FIXTURE.read_text())
    if stored is not None and any(stored.get(k) != v for k, v in provenance.items()):
        raise ValueError("historical fixture provenance changed")
    go, go_dirs = pinned_go(os.environ)
    with tempfile.TemporaryDirectory(prefix="symvault-kdf-policy-") as private:
        private = Path(private)
        checkout = private / "oracle"
        checkout.mkdir()
        archive = run(["git", "archive", SOURCE], cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            source.extractall(checkout, filter="data")
        command = checkout / "cmd/kdf-policy-oracle"
        command.mkdir()
        (command / "main.go").write_bytes(PROGRAM.read_bytes())
        env = {k: v for k, v in os.environ.items() if not k.startswith("SYMVAULT_")}
        for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
            target = private / key.lower()
            target.mkdir(mode=0o700)
            env[key] = str(target)
        env.update(go_dirs, GOTOOLCHAIN="local", GOWORK="off", GOENV="off")
        env["PATH"] = str(Path(go).parent) + os.pathsep + env.get("PATH", os.defpath)
        argv = [go, "run", "./cmd/kdf-policy-oracle"]
        if stored is not None:
            retained = private / "retained.json"
            retained.write_text(json.dumps(stored))
            argv.append(str(retained))
        fresh = json.loads(run(argv, cwd=checkout, env=env, timeout=180))
    if fresh["go_version"] != "go1.26.6" or len(fresh["cases"]) != 4:
        raise ValueError("pinned Go identity or case count changed")
    if args.generate:
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(json.dumps({**provenance, **fresh}, indent=2) + "\n")
    else:
        # Randomized ciphertext is authenticated by the pinned Go program;
        # compare its actual public inputs, never pretend fresh bytes are equal.
        for key in ("go_version", "identity", "passphrase"):
            if stored[key] != fresh[key]:
                raise ValueError(f"{key} drift")
        for retained, current in zip(stored["cases"], fresh["cases"], strict=True):
            if any(retained[k] != current[k] for k in ("name", "time", "memory_kib", "threads")):
                raise ValueError("historical case drift")
    print("PASS four actual historical Go KDF envelopes, authentication and provenance")


if __name__ == "__main__":
    main()
