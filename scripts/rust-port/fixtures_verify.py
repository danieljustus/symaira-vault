#!/usr/bin/env python3
"""Go-free replay check of the frozen oracle fixtures.

Replaces every "re-run the Go generator with --check" step.  Python stdlib and
git only: no Go toolchain, no network.

  default      check   (exit 0 = frozen state intact, 1 = a check failed)
  --write      regenerate testdata/port/FROZEN.sha256 and
               testdata/port/FROZEN.oracle.json (run by the coordinator at the
               freeze commit, never by a check)
  --list-pins  print every oracle commit the fixtures pin ("<sha> <where>")

Three checks, each fails closed:

1. Bytes.  FROZEN.sha256 holds ``sha256  path`` (``sha256sum -c`` format) for
   every frozen fixture.  The frozen set is the file set matched by FROZEN_GLOBS
   below.  A changed, missing or unlisted file fails.
2. Pins.  Every commit a fixture names as its oracle (``commit``,
   ``commit_sha``, ``oracle_commit``, ``oracle_commit_sha``, ``base_commit``,
   ``source_commit``, ``revision`` when hex) must resolve with
   ``git cat-file -e <sha>^{commit}`` AND be contained in a branch or tag
   (``git for-each-ref --contains``).  A loose object that no ref holds is
   one object-store cleanup away from vanishing and fails.  ``candidate_commit`` is CI
   evidence about a candidate, not an oracle pin, and ``corekit_revision`` names
   an external module; both are ignored.
3. Digests.  Every digest a fixture records is classified at ``--write`` time
   and stored in FROZEN.oracle.json:

   recomputed  rebuilt from ``git cat-file blob <sha>:<file>`` with the
               provenance algorithm (scripts/rust-port/internal/provenance:
               ``name NUL content NUL`` per file, go.mod/go.sum excluded from
               the enforced set, or included/sorted variants) or, for per-file
               ``sha256`` maps, from each blob.  Re-derived on every check.
   recorded    the generator used an algorithm this tool does not reproduce (or
               there is no commit/blob to read).  The claimed value is stored in
               the sidecar; a check requires the fixture to still claim it.
   no-digest   the oracle block carries no digest of that kind.

R11 (accepted): this proves frozen bytes are unchanged and that the pinned
oracle is still addressable, not that a generator would reproduce them.  The
generators live at tag ``legacy/go-oracle`` (docs/rust-port/go-oracle-archive.md).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MANIFEST = "testdata/port/FROZEN.sha256"
ORACLE_MANIFEST = "testdata/port/FROZEN.oracle.json"

# The frozen set.  Relative to the repository root, '**' recurses.
FROZEN_GLOBS = [
    "testdata/**",  # incl. testdata/port/**, testdata/importer/**
    "crates/*/tests/fixtures/**",
    "crates/symvault-mcp/testdata/**",
    "scripts/rust-port/fixtures/**",
    "scripts/rust-port/*.go.txt",  # frozen detached Go oracle programs
]
IGNORED_NAMES = {".DS_Store"}

PIN_KEYS = (
    "commit",
    "commit_sha",
    "oracle_commit",
    "oracle_commit_sha",
    "base_commit",
    "source_commit",
    "revision",
)
HEX = re.compile(r"^[0-9a-f]{7,40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REF_PATTERNS = ["refs/heads", "refs/remotes", "refs/tags"]
MODULE_FILES = ("go.mod", "go.sum")

SOURCE_DIGEST_KEYS = ("source_digest", "source_hash", "source_pin_digest")
GENERATOR_DIGEST_KEYS = ("generator_digest", "generator_hash", "generator_sha256")


class Failures:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, message: str) -> None:
        self.items.append(message)
        print(f"FAIL {message}")


class Git:
    def __init__(self, root: Path, git_dir: str | None) -> None:
        self.base = ["git", "--git-dir", git_dir] if git_dir else ["git", "-C", str(root)]
        self._blobs: dict[tuple[str, str], bytes | None] = {}
        self._contains: dict[str, list[str]] = {}
        self._resolved: dict[str, str | None] = {}

    def run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([*self.base, *args], capture_output=True)

    def resolve(self, sha: str) -> str | None:
        if sha not in self._resolved:
            out = self.run("rev-parse", "--verify", "--quiet", "--end-of-options", sha + "^{commit}")
            existing = self.run("cat-file", "-e", sha + "^{commit}")
            ok = out.returncode == 0 and existing.returncode == 0
            self._resolved[sha] = out.stdout.decode().strip() if ok else None
        return self._resolved[sha]

    def refs_containing(self, full: str) -> list[str]:
        if full not in self._contains:
            out = self.run("for-each-ref", "--contains", full, "--format=%(refname)", *REF_PATTERNS)
            self._contains[full] = out.stdout.decode().split() if out.returncode == 0 else []
        return self._contains[full]

    def blob(self, commit: str, path: str) -> bytes | None:
        key = (commit, path)
        if key not in self._blobs:
            out = self.run("cat-file", "blob", f"{commit}:{path}")
            self._blobs[key] = out.stdout if out.returncode == 0 else None
        return self._blobs[key]


# ---------------------------------------------------------------- digests


def enforced(names: list[str]) -> list[str]:
    return [n for n in names if n not in MODULE_FILES]


def algo_parts(algo: str) -> tuple[bool, bool, bool]:
    """(include go.mod/go.sum, sort names, trailing NUL after content)."""
    tokens = algo.split("-")
    if tokens[0] not in ("provenance", "provenance+modules"):
        raise ValueError(algo)
    return tokens[0] == "provenance+modules", "sorted" in tokens[1:], "nonul" not in tokens[1:]


def algo_names(algo: str, names: list[str]) -> list[str]:
    modules, ordered, _ = algo_parts(algo)
    chosen = list(names) if modules else enforced(names)
    return sorted(chosen) if ordered else chosen


# provenance            internal/provenance.Digest over the enforced sources (go.mod/go.sum dropped)
# +modules              the same over every declared file
# -sorted               names sorted before hashing
# -nonul                legacy MCP generators: `name NUL content` without the closing NUL
ALGOS = tuple(
    f"provenance{m}{o}{t}"
    for m in ("", "+modules")
    for o in ("", "-sorted")
    for t in ("", "-nonul")
)


def entry_digest(git: Git, commit: str, algo: str, names: list[str]) -> str | None:
    """sha256 over `name NUL content NUL` of the blobs at commit."""
    chosen = algo_names(algo, names)
    trailing = b"\0" if algo_parts(algo)[2] else b""
    if not chosen:
        return None
    h = hashlib.sha256()
    for name in chosen:
        data = git.blob(commit, name)
        if data is None:
            return None
        h.update(name.encode() + b"\0" + data + trailing)
    return h.hexdigest()


def per_file_digest(git: Git, commit: str, files: dict[str, str]) -> str | None:
    """Verify each ``path -> sha256`` against the blob; return a digest of the map."""
    if not files:
        return None
    for name, want in files.items():
        data = git.blob(commit, name)
        if data is None or hashlib.sha256(data).hexdigest() != want:
            return None
    return map_digest(files)


def map_digest(files: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def source_names(block: dict) -> tuple[list[str] | None, dict[str, str]]:
    """Return (file names, claimed per-file sha256) of a block, or (None, {}) for prose."""
    for key in ("source_files", "sources"):
        value = block.get(key)
        if isinstance(value, list):
            names, hashes = [], {}
            for entry in value:
                if isinstance(entry, str):
                    names.append(entry)
                elif isinstance(entry, dict) and isinstance(entry.get("path"), str):
                    names.append(entry["path"])
                    if isinstance(entry.get("sha256"), str):
                        hashes[entry["path"]] = entry["sha256"]
                else:
                    return None, {}
            return names, hashes
        if isinstance(value, dict):
            names = list(value)
            return names, {k: v for k, v in value.items() if isinstance(v, str) and HEX64.match(v)}
    if isinstance(block.get("source_file"), str):
        return [block["source_file"]], {}
    return None, {}


def generator_names(block: dict) -> list[str] | None:
    value = block.get("generator_files")
    if isinstance(value, list) and all(isinstance(v, str) for v in value) and value:
        return value
    for key in ("generator", "generator_file"):
        if isinstance(block.get(key), str):
            return [block[key]]
    return None


# ---------------------------------------------------------------- fixture walk


def walk_dicts(node, pointer=""):
    if isinstance(node, dict):
        yield pointer or "/", node
        for key, value in node.items():
            yield from walk_dicts(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_dicts(value, f"{pointer}/{index}")


def block_pins(block: dict) -> list[tuple[str, str]]:
    pins = []
    for key in PIN_KEYS:
        value = block.get(key)
        if isinstance(value, str) and HEX.match(value):
            pins.append((key, value))
    return pins


def block_commit(block: dict) -> str | None:
    for key in ("commit_sha", "commit", "oracle_commit", "oracle_commit_sha", "base_commit"):
        value = block.get(key)
        if isinstance(value, str) and HEX.match(value):
            return value
    return None


def digest_claims(block: dict):
    """Yield (kind, key, claimed value) for each digest-like field of a block."""
    names, hashes = source_names(block)
    for key in SOURCE_DIGEST_KEYS:
        value = block.get(key)
        if isinstance(value, str) and HEX64.match(value):
            yield ("source_pin" if key == "source_pin_digest" else "source"), key, value
    if hashes and len(hashes) == len(names or []):
        yield "source", "source_files[sha256]", map_digest(hashes)
    for key in GENERATOR_DIGEST_KEYS:
        value = block.get(key)
        if isinstance(value, str) and HEX64.match(value):
            yield "generator", key, value
    handled = set(SOURCE_DIGEST_KEYS) | set(GENERATOR_DIGEST_KEYS)
    for key, value in block.items():
        if key in handled or not isinstance(value, str) or not HEX64.match(value):
            continue
        if key.endswith(("_digest", "_hash", "_sha256", "_sum")) or key == "sha256":
            yield "other", key, value


class Scan:
    """Everything discovered in the fixture JSON files."""

    def __init__(self) -> None:
        self.pins: list[tuple[str, str, str, str]] = []  # (fixture, pointer, key, sha)
        self.blocks: list[dict] = []  # fixture, pointer, block, commit
        self.errors: list[str] = []


def scan_fixtures(root: Path, files: list[str]) -> Scan:
    scan = Scan()
    for rel in files:
        if not rel.endswith(".json"):
            continue
        try:
            data = json.loads((root / rel).read_bytes())
        except (OSError, ValueError) as exc:
            scan.errors.append(f"{rel}: unparseable JSON: {exc}")
            continue
        for pointer, block in walk_dicts(data):
            pins = block_pins(block)
            for key, sha in pins:
                scan.pins.append((rel, pointer, key, sha))
            if pins or source_names(block)[0] is not None or generator_names(block):
                scan.blocks.append(
                    {"fixture": rel, "pointer": pointer, "block": block, "commit": block_commit(block)}
                )
    return scan


# ---------------------------------------------------------------- bytes


def frozen_files(root: Path) -> list[str]:
    found: set[str] = set()
    for pattern in FROZEN_GLOBS:
        for path in root.glob(pattern):
            if path.is_file() and path.name not in IGNORED_NAMES:
                rel = path.relative_to(root).as_posix()
                if rel != MANIFEST:
                    found.add(rel)
    return sorted(found)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest(root: Path, failures: Failures) -> dict[str, str]:
    path = root / MANIFEST
    if not path.is_file():
        failures.add(f"{MANIFEST}: missing (generate with --write at the freeze commit)")
        return {}
    entries: dict[str, str] = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        if not match:
            failures.add(f"{MANIFEST}:{number}: malformed line")
            continue
        if match.group(2) in entries:
            failures.add(f"{MANIFEST}:{number}: duplicate entry {match.group(2)}")
        entries[match.group(2)] = match.group(1)
    return entries


def in_scope(rel: str, selected: list[str]) -> bool:
    if not selected:
        return True
    return any(rel == s or rel.startswith(s.rstrip("/") + "/") for s in selected)


def check_bytes(root: Path, files: list[str], selected: list[str], failures: Failures) -> int:
    manifest = read_manifest(root, failures)
    checked = 0
    for rel in files:
        if not in_scope(rel, selected):
            continue
        if rel not in manifest:
            failures.add(f"{rel}: frozen file is not listed in {MANIFEST}")
            continue
        if sha256_file(root / rel) != manifest[rel]:
            failures.add(f"{rel}: bytes differ from {MANIFEST}")
            continue
        checked += 1
    on_disk = set(files)
    for rel in manifest:
        if in_scope(rel, selected) and rel not in on_disk:
            failures.add(f"{rel}: listed in {MANIFEST} but missing on disk")
    for sel in selected:
        if not any(in_scope(rel, [sel]) for rel in files):
            failures.add(f"{sel}: no frozen fixture matches")
    return checked


# ---------------------------------------------------------------- pins


def check_pins(git: Git, scan: Scan, selected: list[str], failures: Failures) -> int:
    status: dict[str, str] = {}
    count = 0
    for fixture, pointer, key, sha in scan.pins:
        if not in_scope(fixture, selected):
            continue
        count += 1
        where = f"{fixture}{pointer if pointer != '/' else ''}.{key}"
        if sha not in status:
            full = git.resolve(sha)
            if full is None:
                status[sha] = "missing"
            elif not git.refs_containing(full):
                status[sha] = "unheld"
            else:
                status[sha] = "ok"
        if status[sha] == "missing":
            failures.add(f"{where}: oracle commit {sha} is not present in this repository")
        elif status[sha] == "unheld":
            failures.add(
                f"{where}: oracle commit {sha} resolves but no branch or tag contains it "
                "(tag it before the object store is cleaned, e.g. oracle/<name>)"
            )
    return count


def list_pins(scan: Scan) -> dict[str, list[str]]:
    pins: dict[str, list[str]] = {}
    for fixture, pointer, key, sha in scan.pins:
        pins.setdefault(sha, []).append(f"{fixture}{pointer if pointer != '/' else ''}.{key}")
    return pins


# ---------------------------------------------------------------- digests


def classify_entry(git: Git, commit: str | None, block: dict, kind: str, key: str, claim: str, generator_ref: str | None):
    """Return (class, algo, ref)."""
    full = git.resolve(commit) if commit else None
    candidates: list[str] = []
    if full:
        candidates.append(full)
    if kind == "generator" and generator_ref and generator_ref not in candidates:
        candidates.append(generator_ref)
    if kind in ("source", "source_pin") or kind == "generator":
        names = source_names(block)[0] if kind != "generator" else generator_names(block)
        if key == "source_files[sha256]":
            _, hashes = source_names(block)
            if full and per_file_digest(git, full, hashes) == claim:
                return "recomputed", "per-file-sha256", full
        elif names:
            for ref in candidates:
                for algo in ALGOS:
                    if entry_digest(git, ref, algo, names) == claim:
                        return "recomputed", algo, ref
    return "recorded", "claimed", None


def collect_entries(scan: Scan, git: Git, generator_ref: str | None, selected: list[str] | None = None):
    """Yield one record per digest claim and one 'no-digest' record per missing kind."""
    for item in scan.blocks:
        fixture, pointer, block, commit = item["fixture"], item["pointer"], item["block"], item["commit"]
        if selected is not None and not in_scope(fixture, selected):
            continue
        claims = list(digest_claims(block))
        kinds = {kind for kind, _, _ in claims}
        for kind, key, claim in claims:
            yield {"fixture": fixture, "pointer": pointer, "kind": kind, "key": key, "claim": claim, "commit": commit, "block": block}
        has_source = commit is not None or source_names(block)[0] is not None
        if has_source and "source" not in kinds:
            yield {"fixture": fixture, "pointer": pointer, "kind": "source", "key": None, "claim": None, "commit": commit, "block": block}
        if generator_names(block) and "generator" not in kinds:
            yield {"fixture": fixture, "pointer": pointer, "kind": "generator", "key": None, "claim": None, "commit": commit, "block": block}


def entry_id(fixture: str, pointer: str, key: str) -> str:
    return f"{fixture}#{pointer}#{key}"


def build_oracle_manifest(scan: Scan, git: Git, generator_ref: str | None) -> dict:
    entries = {}
    for rec in collect_entries(scan, git, generator_ref):
        if rec["key"] is None:
            continue
        cls, algo, ref = classify_entry(git, rec["commit"], rec["block"], rec["kind"], rec["key"], rec["claim"], generator_ref)
        entries[entry_id(rec["fixture"], rec["pointer"], rec["key"])] = {
            "kind": rec["kind"],
            "class": cls,
            "algo": algo,
            "ref": ref,
            "value": rec["claim"],
        }
    return {"version": 1, "generator_ref": generator_ref, "entries": dict(sorted(entries.items()))}


def check_digests(root: Path, git: Git, scan: Scan, selected: list[str], failures: Failures):
    path = root / ORACLE_MANIFEST
    stored: dict = {}
    if not path.is_file():
        failures.add(f"{ORACLE_MANIFEST}: missing (generate with --write at the freeze commit)")
    else:
        try:
            stored = json.loads(path.read_text())["entries"]
        except (ValueError, KeyError) as exc:
            failures.add(f"{ORACLE_MANIFEST}: unreadable: {exc}")
    counts: dict[str, dict[str, int]] = {}
    block_class: dict[tuple[str, str, str], str] = {}
    seen_ids = set()
    gen_ref = None
    for rec in collect_entries(scan, git, None, selected):
        kind = rec["kind"]
        bucket = counts.setdefault(kind, {"recomputed": 0, "recorded": 0, "no-digest": 0})
        if rec["key"] is None:
            bucket["no-digest"] += 1
            continue
        eid = entry_id(rec["fixture"], rec["pointer"], rec["key"])
        seen_ids.add(eid)
        want = stored.get(eid)
        if want is None:
            failures.add(f"{eid}: digest not recorded in {ORACLE_MANIFEST} (re-run --write at the freeze)")
            continue
        if want["value"] != rec["claim"]:
            failures.add(f"{eid}: fixture now claims {rec['claim']}, {ORACLE_MANIFEST} recorded {want['value']}")
            continue
        if want["class"] == "recorded":
            bucket["recorded"] += 1
            continue
        ref = want["ref"]
        full_ref = git.resolve(ref) if ref else None
        if full_ref is None:
            failures.add(f"{eid}: recompute ref {ref} is not present in this repository")
            continue
        if not git.refs_containing(full_ref):
            failures.add(f"{eid}: recompute ref {ref} is held by no branch or tag")
            continue
        if want["algo"] == "per-file-sha256":
            _, hashes = source_names(rec["block"])
            got = map_digest(hashes) if per_file_digest(git, ref, hashes) else None
        else:
            names = generator_names(rec["block"]) if kind == "generator" else source_names(rec["block"])[0]
            got = entry_digest(git, ref, want["algo"], names or [])
        if got != rec["claim"]:
            failures.add(f"{eid}: {rec['key']} recomputed from git blobs at {ref[:12]} ({want['algo']}) is {got}, fixture claims {rec['claim']}")
            continue
        bucket["recomputed"] += 1
    for eid in stored:
        fixture = eid.split("#", 1)[0]
        if in_scope(fixture, selected) and eid not in seen_ids:
            failures.add(f"{eid}: recorded in {ORACLE_MANIFEST} but absent from the fixture")
    return counts


# ---------------------------------------------------------------- main


def default_root() -> Path:
    return Path(__file__).resolve().parents[2]


def pick_generator_ref(git: Git, requested: str | None) -> str | None:
    for candidate in ([requested] if requested else ["legacy/go-oracle", "HEAD"]):
        if candidate and git.resolve(candidate):
            return git.resolve(candidate)
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("fixtures", nargs="*", help="restrict the check to these fixture files/directories (relative to the root)")
    parser.add_argument("--root", type=Path, default=default_root(), help="repository root")
    parser.add_argument("--git-dir", default=None, help="git directory holding the oracle objects (default: the root's repository)")
    parser.add_argument("--write", action="store_true", help="regenerate the manifests (freeze step)")
    parser.add_argument("--allow-downgrade", action="store_true", help="with --write: accept recomputed digests becoming recorded")
    parser.add_argument("--list-pins", action="store_true", help="print the oracle commits pinned by the fixtures")
    parser.add_argument("--generator-ref", default=None, help="ref whose blobs generator digests are recomputed from (default: legacy/go-oracle, else HEAD)")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    git = Git(root, args.git_dir)
    selected = [os.path.relpath(f, root) if os.path.isabs(f) else os.path.normpath(f) for f in args.fixtures]
    files = frozen_files(root)
    scan = scan_fixtures(root, files)
    failures = Failures()
    for error in scan.errors:
        failures.add(error)

    if args.list_pins:
        for sha, where in sorted(list_pins(scan).items()):
            print(f"{sha} {where[0]}{' +%d more' % (len(where) - 1) if len(where) > 1 else ''}")
        return 1 if failures.items else 0

    if args.write:
        if selected:
            print("--write regenerates the whole manifest; do not combine with fixture arguments", file=sys.stderr)
            return 2
        generator_ref = pick_generator_ref(git, args.generator_ref)
        oracle = build_oracle_manifest(scan, git, generator_ref)
        # Ratchet: a refreeze must not silently turn a recomputed digest into a
        # merely recorded one (that would let a tampered digest pass).
        old_path = root / ORACLE_MANIFEST
        if old_path.is_file() and not args.allow_downgrade:
            try:
                old = json.loads(old_path.read_text()).get("entries", {})
            except ValueError:
                old = {}
            downgraded = sorted(
                key for key, entry in oracle["entries"].items()
                if old.get(key, {}).get("class") == "recomputed" and entry["class"] != "recomputed"
            )
            if downgraded:
                for key in downgraded:
                    print(f"--write refused: {key} was recomputed and would become {oracle['entries'][key]['class']}", file=sys.stderr)
                print("rerun with --allow-downgrade only after reviewing why the digest no longer recomputes", file=sys.stderr)
                return 1
        (root / MANIFEST).write_text("".join(f"{sha256_file(root / rel)}  {rel}\n" for rel in files))
        (root / ORACLE_MANIFEST).write_text(json.dumps(oracle, indent=1, sort_keys=False) + "\n")
        # The oracle manifest is itself a frozen file: list it now that it exists.
        files = frozen_files(root)
        (root / MANIFEST).write_text("".join(f"{sha256_file(root / rel)}  {rel}\n" for rel in files))
        print(f"wrote {MANIFEST} ({len(files)} files) and {ORACLE_MANIFEST} ({len(oracle['entries'])} digests, generator ref {generator_ref})")
        selected = []

    checked = check_bytes(root, files, selected, failures)
    pins = check_pins(git, scan, selected, failures)
    counts = check_digests(root, git, scan, selected, failures)

    print(f"bytes:  {checked} frozen files match {MANIFEST}")
    print(f"pins:   {pins} oracle commit references resolve and are held by a branch or tag"
          if not failures.items else f"pins:   {pins} oracle commit references examined")
    print("digests (recomputed = rebuilt from git blobs; recorded = claim stored in "
          f"{ORACLE_MANIFEST}; no-digest = block carries none):")
    for kind in ("source", "source_pin", "generator", "other"):
        if kind in counts:
            c = counts[kind]
            print(f"  {kind:<11} recomputed={c['recomputed']:<4} recorded={c['recorded']:<4} no-digest={c['no-digest']}")
    if failures.items:
        print(f"fixtures-verify: FAILED ({len(failures.items)} problem(s))")
        return 1
    print("fixtures-verify: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
