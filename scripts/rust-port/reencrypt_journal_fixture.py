#!/usr/bin/env python3
"""Frozen Go-written re-encryption crash states for the Rust recovery test.

  reencrypt_journal_fixture.py capture     needs Go; writes testdata/port/store/reencrypt-journal.json

The Go production journal functions (collect, persist, stage, commit) leave two vaults behind a crash: one
with the replacement only staged (journal says installed=false, temp file present) and one with the
replacement committed but the journal not yet removed (installed=true, backup present). Go's own recovery
(`vault.Open`) is then run on the same vault and its post-recovery tree is recorded. The Rust test
`crates/symvault-store/tests/reencrypt_journal_go_fixture.rs` recovers the frozen pre-crash trees with
`Store::open` and asserts the same tree (stable files byte for byte, the re-built manifest by decryption).
No Go is needed to run that test.

The Go test is `reencrypt_journal_probe.go.txt`, copied into a worktree of the pinned oracle commit; the
vault paths inside the journal are stored as @TREE_ROOT@.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_observations_common as obs
from build_timeout import oracle_build_timeout, remove_worktree

ROOT = obs.ROOT
FIXTURE = ROOT / "testdata" / "port" / "store" / "reencrypt-journal.json"
PROBE = Path(__file__).resolve().parent / "reencrypt_journal_probe.go.txt"
SCENARIOS = ["staged", "committed"]


def pack(directory, original_root):
    """{relative path: base64 | None}: the original (temporary) vault root is stored as the @TREE_ROOT@ token."""
    files = {}
    for entry in sorted(Path(directory).rglob("*")):
        name = entry.relative_to(directory).as_posix()
        if entry.is_dir():
            files[name] = None
        else:
            data = obs.tokenize_paths(entry.read_bytes(), {original_root: obs.TREE_ROOT})
            files[name] = base64.b64encode(data).decode("ascii")
    return files


def capture():
    commit = obs.tree_oracle_commit()
    env = dict(os.environ, GOWORK="off", GOTOOLCHAIN=os.environ.get("GOTOOLCHAIN", "go1.26.6"), SYMVAULT_TEST_KEYRING="memory")
    with tempfile.TemporaryDirectory(prefix="symvault-reencrypt-capture-") as raw:
        base = Path(raw)
        tree, out = base / "oracle", base / "out"
        subprocess.run(["git", "worktree", "add", "--detach", str(tree), commit], cwd=ROOT, check=True, capture_output=True)
        try:
            (tree / "internal" / "vault" / "zz_reencrypt_journal_capture_test.go").write_bytes(PROBE.read_bytes())
            done = subprocess.run(["go", "test", "./internal/vault", "-run", "^TestReencryptJournalFixtureCapture$", "-count=1", "-v"],
                                  cwd=tree, env=dict(env, SYMVAULT_REENCRYPT_FIXTURE_OUT=str(out)), capture_output=True,
                                  text=True, timeout=oracle_build_timeout())
            if done.returncode != 0 or "--- PASS: TestReencryptJournalFixtureCapture" not in done.stdout:
                sys.exit(f"Go capture failed:\n{done.stdout[-2000:]}{done.stderr[-2000:]}")
            version = obs.go_version(env, tree)
            scenarios = []
            for name in SCENARIOS:
                directory = out / name
                original_root = Path((directory / "root").read_text())
                pre = pack(directory / "vault", original_root)
                scenarios.append({"name": name, "identity": (directory / "identity").read_text(), "entry": "cross-language",
                                  "value": "go-production", "pre_crash": pre,
                                  "go_post_recovery": json.loads((directory / "go_post.json").read_text())})
        finally:
            remove_worktree(lambda: subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=ROOT, check=True,
                                                   capture_output=True), "oracle worktree")
    document = {"schema": 1, "contract": "reencrypt-journal-go-fixture", "oracle_commit": commit, "go_version": version,
                "generator": "scripts/rust-port/reencrypt_journal_fixture.py capture", "scenarios": scenarios}
    text = obs.canonical(document).encode()
    leaked = obs.operator_paths(text)
    if leaked:
        sys.exit(f"refusing to write operator paths: {leaked}")
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_bytes(text)
    print(f"captured {obs.rel(FIXTURE)}: {', '.join(SCENARIOS)} ({hashlib.sha256(text).hexdigest()[:12]})")


if __name__ == "__main__":
    if sys.argv[1:] != ["capture"]:
        sys.exit(__doc__)
    capture()
