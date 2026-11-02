#!/usr/bin/env python3
"""DIST-005 / RUST-014 data-safety contract (maintainer decision D1).

Runs the real Rust CLI over Go-created vaults and checks, per seed vault:

  1. a read-only battery (list/get/verify/find/export to stdout) leaves the
     tree byte-identical and writes no Rust marker and no backup;
  2. the first mutation (set) creates a backup and the marker, the marker's
     sha256 matches the archive, and restoring the archive with the Rust
     `restore` command into a fresh directory reproduces the pre-mutation tree
     (the only permitted extra is the empty `.lock` the write lock creates);
  3. a second mutation creates no second backup;
  4. the frozen Go oracle opens the mutated vault and reads old and new data
     (D2: Go can still read what Rust wrote);
  5. zero-key seed: the heal on unlock (a read command that rewrites
     identity.age) is preceded by the backup, which restores to the
     pre-heal tree, and Go opens the healed vault;
  6. negative controls: an unwritable backup directory refuses the mutation
     (tree untouched, no marker); a corrupted backup is refused by the
     production verification (no marker); with the restore verification
     short-circuited the corrupted backup is accepted by the gate and THIS
     harness's independent restore comparison must then fail;
  7. marker binding: a marker copied from another vault (go-vault-backup and
     rust-created), a go-vault-backup marker whose backup points at a foreign
     file, carries a wrong sha256 or a wrong size, is no marker at all and the
     next mutation backs up again;
  8. crash leftovers: a `.partial` archive and a `.verify-*` scratch directory
     of a dead process are swept by the next gate, those of a live one stay;
  9. the mutator sweep includes `remote init` on a git-backed Go vault (it
     rewrites `.git/config`): marker and backup precede the config change.

Seeds: the frozen Go-created passphrase vault of testdata/port/ffi/mobilebind.json
(`seed.vault`), a vault made by the Go oracle's own `init` + `set`, and the
zero-key identity of testdata/port/crypto/age-kdf.json inside a Go-initialised
vault.

Usage: data_safety_contract.py --rust BIN --go BIN --probe BIN
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEED_PASS = "correct horse battery staple"
INIT_PASS = "initial passphrase value"
ZERO_PASS = "abcdefghijklmnopqrstuvw"
STRONG = "StrongPassword123!"
MARKER = ".symvault-rust"
AUDIT = "audit-symvault.log"
GO_READ_SIDE_EFFECTS = {".symvault-migrated", AUDIT}
EMPTY_SHA = hashlib.sha256(b"").hexdigest()

cases = 0


class Failure(AssertionError):
    pass


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        raise Failure(message)


def tree(root):
    """rel path -> (kind, mode, sha256|target) for every node, symlinks as-is."""
    result = {}
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        for name in names + files:
            path = Path(directory, name)
            rel = str(path.relative_to(root))
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                result[rel] = ("link", 0, os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                result[rel] = ("dir", mode, "")
            else:
                result[rel] = ("file", mode, hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def diff_trees(before, after):
    keys = sorted(set(before) | set(after))
    return [k for k in keys if before.get(k) != after.get(k)]


class Sandbox:
    """Disposable HOME/XDG roots plus a vault directory."""

    def __init__(self, base, name):
        self.base = Path(base, name)
        self.home = self.base / "home"
        self.vault = self.base / "vault"
        self.state = self.home / ".local" / "state"
        for sub in ("config", "data", "cache"):
            (self.home / sub).mkdir(parents=True, exist_ok=True)
        self.vault.mkdir(parents=True, exist_ok=True)

    def env(self, passphrase, vault=None, extra=None):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / "config"),
            "XDG_DATA_HOME": str(self.home / "data"),
            "XDG_CACHE_HOME": str(self.home / "cache"),
            "SYMVAULT_VAULT": str(vault or self.vault),
            "SYMVAULT_TEST_KEYRING": "memory",
            "CI": "1",
        }
        if passphrase is not None:
            env["SYMVAULT_PASSPHRASE"] = passphrase
            env["SYMVAULT_ALLOW_ENV_PASSPHRASE"] = "1"
        env.update(extra or {})
        return env

    def run(self, binary, args, passphrase=SEED_PASS, vault=None, extra=None):
        return subprocess.run(
            [str(binary), *args],
            env=self.env(passphrase, vault, extra),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    def backups(self):
        directory = self.state / "symvault" / "backups"
        if not directory.is_dir():
            return []
        return sorted(p for p in directory.iterdir() if p.name.endswith(".tar.gz"))

    def state_listing(self):
        return sorted(tree(self.state)) if self.state.exists() else []


def materialize_ffi_seed(sandbox):
    fixture = json.loads((ROOT / "testdata/port/ffi/mobilebind.json").read_text())
    seed = fixture["seed"]["vault"]
    for item in seed["files"]:
        path = sandbox.vault / item["path"]
        if item.get("dir"):
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(base64.b64decode(item["b64"]))
        os.chmod(path, item["mode"])
    return seed


def go_init(sandbox, go, entries):
    out = sandbox.run(go, ["init", "--auth", "passphrase"], passphrase=INIT_PASS)
    check(out.returncode == 0, f"go init failed: {out.stderr}")
    for path, value in entries:
        out = sandbox.run(go, ["set", path, "--value", value], passphrase=INIT_PASS)
        check(out.returncode == 0, f"go set {path} failed: {out.stderr}")


def zero_key_seed(sandbox, go):
    go_init(sandbox, go, [("w/a.password", STRONG)])
    kdf = json.loads((ROOT / "testdata/port/crypto/age-kdf.json").read_text())
    case = next(c for c in kdf["zero_key_cases"] if c["name"] == "historical_zero_key_length_23")
    identity = base64.b64decode(case["ciphertext"])
    (sandbox.vault / "identity.age").write_bytes(identity)
    (sandbox.vault / "recipients.txt").write_text(case["expected_recipient"] + "\n")
    return identity


def read_battery(first_entry):
    return [
        ["list"],
        ["get", first_entry, "--output", "json"],
        ["verify"],
        ["find", first_entry.split("/")[-1][:3]],
        ["export", "--format", "json", "--yes"],
    ]


def check_no_state(sandbox, label):
    check(not (sandbox.vault / MARKER).exists(), f"{label}: marker written by a read")
    check(not sandbox.backups(), f"{label}: backup written by a read")


def restore_and_compare(sandbox, rust, archive, pre_tree, label, pre_audit=b""):
    """Independent verification: the real `restore` command, then a tree diff."""
    fresh = sandbox.base / f"restored-{label}"
    shutil.rmtree(fresh, ignore_errors=True)
    out = sandbox.run(rust, ["restore", str(archive)], passphrase=None, vault=fresh)
    check(out.returncode == 0, f"{label}: restore of {archive.name} failed: {out.stderr.strip()}")
    restored = tree(fresh)
    # Go's restore keeps only a file's owner rw bits (header.Mode & 0o600) and
    # recreates directories 0700 (SafeMkdirAll): compare files through that mask,
    # directories by presence.
    def masked(nodes):
        return {k: (v[0], 0, v[2]) if v[0] == "dir" else (v[0], v[1] & 0o600, v[2])
                for k, v in nodes.items()}
    restored = masked(restored)
    pre_tree = masked(pre_tree)
    # The write lock file is created before the backup is taken, and the audit
    # log is append-only: the backup may hold lines appended since `pre_tree`.
    restored.pop(".lock", None)
    expected = {k: v for k, v in pre_tree.items() if k != ".lock"}
    # Go's Open also creates the empty `.symvault-migrated` before any write.
    if restored.get(".symvault-migrated", ("", 0, EMPTY_SHA))[2] == EMPTY_SHA:
        restored.pop(".symvault-migrated", None)
        expected.pop(".symvault-migrated", None)
    if AUDIT in restored and AUDIT in expected:
        check((fresh / AUDIT).read_bytes().startswith(pre_audit or b""),
              f"{label}: restored audit log is not an extension of the pre-mutation log")
        restored.pop(AUDIT)
        expected.pop(AUDIT)
    differences = diff_trees(expected, restored)
    check(not differences, f"{label}: restored backup differs from pre-mutation tree: {differences[:5]}")
    return fresh


def read_marker(vault):
    return json.loads((vault / MARKER).read_text())


def run_seed(base, rust, go, name, prepare, passphrase, first_entry, entries):
    sandbox = Sandbox(base, name)
    prepare(sandbox)
    pre = tree(sandbox.vault)
    check(MARKER not in pre, f"{name}: seed already carries a marker")

    # 1. reads never trigger the gate
    for args in read_battery(first_entry):
        out = sandbox.run(rust, args, passphrase)
        check(out.returncode == 0, f"{name}: rust {args} failed: {out.stderr.strip()[:200]}")
    check_no_state(sandbox, f"{name}/reads")
    # Go parity (cmd/vault Open): a read creates the empty `.symvault-migrated`
    # file and appends to `audit-symvault.log`. Both are append-only/empty
    # side effects of Go's own reads, not data changes; everything else must be
    # byte-identical.
    after_reads = tree(sandbox.vault)
    differences = diff_trees(pre, after_reads)
    check(set(differences) <= GO_READ_SIDE_EFFECTS, f"{name}: reads changed the tree: {differences[:5]}")
    if ".symvault-migrated" in differences:
        check(after_reads[".symvault-migrated"][2] == EMPTY_SHA, f"{name}: migration marker not empty")
    pre = after_reads
    pre_audit = (sandbox.vault / AUDIT).read_bytes() if (sandbox.vault / AUDIT).exists() else b""

    # 2. first mutation: backup + marker, restore reproduces the pre-mutation tree
    out = sandbox.run(rust, ["set", "harness/new", "--value", STRONG], passphrase)
    check(out.returncode == 0, f"{name}: rust set failed: {out.stderr.strip()[:300]}")
    marker = read_marker(sandbox.vault)
    check(marker["schema"] == 1 and marker["kind"] == "go-vault-backup", f"{name}: marker {marker}")
    backups = sandbox.backups()
    check(len(backups) == 1, f"{name}: expected one backup, found {backups}")
    archive = backups[0]
    check(Path(marker["backup"]["path"]) == archive.resolve(), f"{name}: marker path mismatch")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    check(marker["backup"]["sha256"] == digest, f"{name}: marker sha256 mismatch")
    check(marker["backup"]["bytes"] == archive.stat().st_size, f"{name}: marker size mismatch")
    check(stat.S_IMODE(archive.stat().st_mode) == 0o600, f"{name}: backup mode")
    check(stat.S_IMODE((sandbox.vault / MARKER).stat().st_mode) == 0o600, f"{name}: marker mode")
    check(not any(p.name.startswith(".verify-") for p in archive.parent.iterdir()),
          f"{name}: scratch restore directory left behind")
    check(not any(p.name.startswith(MARKER + ".tmp") for p in sandbox.vault.iterdir()),
          f"{name}: marker temp file left behind")
    restore_and_compare(sandbox, rust, archive, pre, name, pre_audit)

    # the mutation itself landed
    out = sandbox.run(rust, ["get", "harness/new.password", "--print"], passphrase)
    check(out.returncode == 0 and STRONG in out.stdout, f"{name}: new entry unreadable by rust")

    # 3. a second mutation creates no second backup and keeps the marker
    first_marker = (sandbox.vault / MARKER).read_bytes()
    out = sandbox.run(rust, ["set", "harness/second", "--value", STRONG], passphrase)
    check(out.returncode == 0, f"{name}: second set failed: {out.stderr.strip()[:200]}")
    check(len(sandbox.backups()) == 1, f"{name}: second mutation made another backup")
    check((sandbox.vault / MARKER).read_bytes() == first_marker, f"{name}: marker rewritten")

    # 4. D2: the Go oracle still opens what Rust wrote
    out = sandbox.run(go, ["get", first_entry, "--output", "json"], passphrase)
    check(out.returncode == 0, f"{name}: go cannot read {first_entry}: {out.stderr.strip()[:200]}")
    for entry in ("harness/new", "harness/second"):
        out = sandbox.run(go, ["get", entry + ".password", "--print"], passphrase)
        check(out.returncode == 0 and STRONG in out.stdout,
              f"{name}: go cannot read {entry}: {out.stderr.strip()[:200]}")
    out = sandbox.run(go, ["verify"], passphrase)
    check(out.returncode == 0, f"{name}: go verify failed after rust writes: {out.stderr.strip()[:200]}")
    out = sandbox.run(go, ["set", "harness/by-go", "--value", STRONG], passphrase)
    check(out.returncode == 0, f"{name}: go cannot write after rust: {out.stderr.strip()[:200]}")
    return sandbox


def run_zero_key(base, rust, go):
    name = "zero-key"
    sandbox = Sandbox(base, name)
    identity = zero_key_seed(sandbox, go)
    pre = tree(sandbox.vault)
    out = sandbox.run(rust, ["list"], ZERO_PASS)
    check(out.returncode == 0, f"{name}: rust list failed: {out.stderr.strip()[:300]}")
    check((sandbox.vault / "identity.age").read_bytes() != identity, f"{name}: identity was not healed")
    check((sandbox.vault / "identity.age.bak").read_bytes() == identity, f"{name}: old identity not kept")
    check((sandbox.vault / MARKER).exists(), f"{name}: heal without marker")
    backups = sandbox.backups()
    check(len(backups) == 1, f"{name}: expected one backup, found {backups}")
    marker = read_marker(sandbox.vault)
    check(marker["backup"]["sha256"] == hashlib.sha256(backups[0].read_bytes()).hexdigest(),
          f"{name}: marker sha256 mismatch")
    restored = restore_and_compare(sandbox, rust, backups[0], pre, name)
    check((restored / "identity.age").read_bytes() == identity, f"{name}: backup lost the pre-heal identity")
    out = sandbox.run(go, ["list"], ZERO_PASS)
    check(out.returncode == 0, f"{name}: go cannot open the healed vault: {out.stderr.strip()[:200]}")
    return sandbox


POLICY = (
    "version: v1\ndescription: Applied policy\nrules:\n"
    "  - name: allow-read\n    priority: 10\n    action: allow\n"
)


def git_backed(sandbox):
    """Makes the seed vault a git repository the way the Go oracle's git
    integration leaves it: a committed worktree and a repository-local config."""
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(sandbox.home),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    for args in (["init", "--quiet"],
                 ["symbolic-ref", "HEAD", "refs/heads/master"],
                 ["config", "user.name", "Symaira Vault"],
                 ["config", "user.email", "symvault@example.com"],
                 ["add", "--all"],
                 ["commit", "--quiet", "-m", "seed"]):
        out = subprocess.run(["git", *args], cwd=sandbox.vault, env=env,
                             capture_output=True, text=True, check=False)
        check(out.returncode == 0, f"git {args[0]} failed in the seed: {out.stderr.strip()}")


def sweep_cases(inputs):
    """(name, rust args, oracle setup: Go args | callable(sandbox) | None, must_mutate_tree)."""
    kdf = json.loads((ROOT / "testdata/port/crypto/age-kdf.json").read_text())
    recipient = kdf["zero_key_cases"][0]["expected_recipient"]
    inputs.mkdir(exist_ok=True)
    (inputs / "policy.yaml").write_text(POLICY)
    (inputs / "attach.bin").write_bytes(b"attachment bytes")
    (inputs / "import.csv").write_text("title,username,password\nimported/a,user,StrongPassword123!\n")
    return [
        ("set", ["set", "sweep/new", "--value", STRONG], None, True),
        ("delete", ["delete", "top", "--yes"], None, True),
        ("file add", ["file", "add", "sweep/file", "--field", "blob", "--from", str(inputs / "attach.bin")],
         None, True),
        ("recipients add", ["recipients", "add", recipient], None, True),
        ("recipients remove", ["recipients", "remove", recipient, "--yes", "--no-reencrypt"],
         ["recipients", "add", recipient], True),
        ("policy apply", ["policy", "apply", str(inputs / "policy.yaml")], None, True),
        ("agent token new", ["agent", "token", "new", "cli"], None, True),
        ("migrate pseudonymize", ["migrate", "pseudonymize", "--yes"], None, True),
        ("device pair", ["device", "pair"], None, True),
        ("import csv", ["import", str(inputs / "import.csv"), "--format", "csv"], None, True),
        ("remote init", ["remote", "init", "git@backup.invalid", "--path", "vault.git"],
         git_backed, True),
    ]


def run_sweep(base, rust, go):
    """Every Rust command that changes a Go-created vault must have taken the
    verified backup first: tree changed => marker + exactly one backup that
    restores to the pre-command tree."""
    # `.git/info/exclude` is where the marker hides itself from git add.
    ignored = GO_READ_SIDE_EFFECTS | {".lock", MARKER, ".git/info/exclude", ".git/info"}
    names = [case[0] for case in sweep_cases(Path(base, "sweep-names"))]
    outcomes = []
    for index, name in enumerate(names):
        label = "sweep-" + name.replace(" ", "-")
        sandbox = Sandbox(base, label)
        _, args, setup, must_mutate = sweep_cases(sandbox.base / "inputs")[index]
        materialize_ffi_seed(sandbox)
        if callable(setup):
            setup(sandbox)
        elif setup:
            out = sandbox.run(go, setup, SEED_PASS)
            check(out.returncode == 0, f"{label}: oracle setup {setup} failed: {out.stderr.strip()[:200]}")
        pre = tree(sandbox.vault)
        audit = sandbox.vault / AUDIT
        pre_audit = audit.read_bytes() if audit.exists() else b""
        out = sandbox.run(rust, args, SEED_PASS)
        post = tree(sandbox.vault)
        changed = [k for k in diff_trees(pre, post) if k not in ignored]
        if must_mutate:
            check(out.returncode == 0 and changed,
                  f"{label}: expected a successful mutation, rc={out.returncode} changed={changed} "
                  f"err={out.stderr.strip()[-200:]}")
        if changed:
            check((sandbox.vault / MARKER).exists(), f"{label}: tree changed ({changed[:3]}) without a marker")
            backups = sandbox.backups()
            check(len(backups) == 1, f"{label}: expected one backup, found {len(backups)}")
            restore_and_compare(sandbox, rust, backups[0], pre, label, pre_audit)
            if name == "remote init":
                # The config rewrite is what the gate had to precede: the live
                # config has the remote, the restored backup's does not.
                check(post[".git/config"] != pre[".git/config"], f"{label}: .git/config unchanged")
                restored = sandbox.base / f"restored-{label}"
                check('[remote "origin"]' not in (restored / ".git/config").read_text()
                      and '[remote "origin"]' in (sandbox.vault / ".git/config").read_text(),
                      f"{label}: backup does not hold the pre-change .git/config")
        outcomes.append(f"{name}:{'mutated' if changed else 'unchanged'}")
    return outcomes


def negative_unwritable_backup_dir(base, rust):
    sandbox = Sandbox(base, "neg-unwritable")
    materialize_ffi_seed(sandbox)
    pre = tree(sandbox.vault)
    blocker = sandbox.base / "not-a-directory"
    blocker.write_text("x")
    out = sandbox.run(rust, ["set", "harness/new", "--value", STRONG], SEED_PASS,
                      extra={"XDG_STATE_HOME": str(blocker / "state")})
    check(out.returncode != 0, "neg-unwritable: mutation was not refused")
    check("backup" in out.stderr.lower(), f"neg-unwritable: unclear error: {out.stderr.strip()[:200]}")
    check(not (sandbox.vault / MARKER).exists(), "neg-unwritable: marker written")
    ignored = GO_READ_SIDE_EFFECTS | {".lock"}
    after = {k: v for k, v in tree(sandbox.vault).items() if k not in ignored}
    differences = diff_trees({k: v for k, v in pre.items() if k not in ignored}, after)
    check(not differences, f"neg-unwritable: vault changed: {differences[:5]}")
    # and the refusal is not sticky: with a usable directory the mutation works
    out = sandbox.run(rust, ["set", "harness/new", "--value", STRONG], SEED_PASS)
    check(out.returncode == 0, f"neg-unwritable: retry failed: {out.stderr.strip()[:200]}")


def negative_probe(base, rust, probe):
    # corrupted backup, production verification: refused, no marker
    sandbox = Sandbox(base, "neg-corrupt")
    materialize_ffi_seed(sandbox)
    pre = tree(sandbox.vault)
    scratch = sandbox.base / "backups"
    out = subprocess.run([str(probe), str(sandbox.vault), str(scratch), "corrupt"],
                         capture_output=True, text=True, check=False)
    check(out.returncode == 1 and "gate refused" in out.stdout, f"neg-corrupt: {out.stdout} {out.stderr}")
    check(not (sandbox.vault / MARKER).exists(), "neg-corrupt: marker written for a corrupted backup")
    check(not list(scratch.glob("*.tar.gz")), "neg-corrupt: damaged archive kept")
    differences = diff_trees({k: v for k, v in pre.items() if k != ".lock"},
                             {k: v for k, v in tree(sandbox.vault).items() if k != ".lock"})
    # the probe only runs the gate: no Go-parity read side effect can appear
    check(not differences, f"neg-corrupt: vault changed: {differences[:5]}")

    # restore verification short-circuited: the gate accepts the corrupted
    # backup, so the harness's independent restore comparison must fail.
    sandbox = Sandbox(base, "neg-shortcircuit")
    materialize_ffi_seed(sandbox)
    pre = tree(sandbox.vault)
    scratch = sandbox.base / "backups"
    out = subprocess.run([str(probe), str(sandbox.vault), str(scratch), "short-circuit"],
                         capture_output=True, text=True, check=False)
    check(out.returncode == 0 and "gate accepted" in out.stdout, f"neg-shortcircuit: {out.stdout}")
    marker = read_marker(sandbox.vault)
    try:
        restore_and_compare(sandbox, rust, Path(marker["backup"]["path"]), pre, "neg-shortcircuit")
    except Failure:
        return
    raise Failure("neg-shortcircuit: harness did not notice a corrupted backup behind a short-circuited gate")


def second_backup_taken(sandbox, rust, before, label):
    """Runs a mutation and expects exactly one more backup and a valid marker."""
    out = sandbox.run(rust, ["set", f"harness/{label}", "--value", STRONG], SEED_PASS)
    check(out.returncode == 0, f"{label}: set failed: {out.stderr.strip()[:200]}")
    check(len(sandbox.backups()) == before + 1,
          f"{label}: expected the invalid marker to trigger a backup ({before} -> {len(sandbox.backups())})")
    marker = read_marker(sandbox.vault)
    archive = Path(marker["backup"]["path"])
    check(archive.resolve().parent == sandbox.backups()[0].resolve().parent and marker["backup"]["sha256"]
          == hashlib.sha256(archive.read_bytes()).hexdigest(), f"{label}: marker not rewritten with a real backup")
    return marker


def negative_marker_binding(base, rust):
    # a marker copied from another (Go-seeded, then mutated) vault
    donor = Sandbox(base, "neg-marker-donor")
    materialize_ffi_seed(donor)
    out = donor.run(rust, ["set", "harness/new", "--value", STRONG], SEED_PASS)
    check(out.returncode == 0, f"neg-marker: donor set failed: {out.stderr.strip()[:200]}")
    donor_marker = (donor.vault / MARKER).read_bytes()

    copied = Sandbox(base, "neg-marker-copied")
    materialize_ffi_seed(copied)
    (copied.vault / MARKER).write_bytes(donor_marker)
    check(not copied.backups(), "neg-marker: fixture already has a backup")
    marker = second_backup_taken(copied, rust, 0, "copied-go-marker")
    check(marker["vault_id"] != json.loads(donor_marker)["vault_id"], "neg-marker: vault_id not per vault")

    # a rust-created marker (made by the real `init`) copied onto a Go vault
    creator = Sandbox(base, "neg-marker-creator")
    out = creator.run(rust, ["init", "--auth", "passphrase"], passphrase=INIT_PASS)
    check(out.returncode == 0, f"neg-marker: rust init failed: {out.stderr.strip()[:200]}")
    created = json.loads((creator.vault / MARKER).read_text())
    check(created["kind"] == "rust-created" and "vault_id" in created, f"neg-marker: unexpected marker {created}")
    check(not creator.backups(), "neg-marker: a vault Rust creates must not be backed up")
    foreign = Sandbox(base, "neg-marker-rust-created")
    materialize_ffi_seed(foreign)
    shutil.copy(creator.vault / MARKER, foreign.vault / MARKER)
    second_backup_taken(foreign, rust, 0, "copied-rust-created-marker")

    # go-vault-backup marker with a backup that is not this vault's backup
    victim = Sandbox(base, "neg-marker-backup")
    materialize_ffi_seed(victim)
    out = victim.run(rust, ["set", "harness/new", "--value", STRONG], SEED_PASS)
    check(out.returncode == 0, f"neg-marker: victim set failed: {out.stderr.strip()[:200]}")
    count = 1
    check(len(victim.backups()) == count, "neg-marker: expected the first backup")
    out = victim.run(rust, ["set", "harness/steady", "--value", STRONG], SEED_PASS)
    check(out.returncode == 0 and len(victim.backups()) == count, "neg-marker: a valid marker took another backup")
    other_file = victim.base / "foreign.bin"
    other_file.write_bytes(b"not a backup of this vault")

    def edit(change):
        marker = read_marker(victim.vault)
        change(marker)
        (victim.vault / MARKER).write_text(json.dumps(marker))

    edit(lambda m: m["backup"].update(path=str(other_file)))  # the review's /etc/hosts probe
    second_backup_taken(victim, rust, count, "foreign-file"); count += 1
    edit(lambda m: m["backup"].update(sha256="ab" * 32))
    second_backup_taken(victim, rust, count, "wrong-sha256"); count += 1
    edit(lambda m: m["backup"].update(bytes=m["backup"]["bytes"] + 1))
    second_backup_taken(victim, rust, count, "wrong-size"); count += 1
    edit(lambda m: m.pop("vault_id"))
    second_backup_taken(victim, rust, count, "no-vault-id"); count += 1
    edit(lambda m: m["backup"].update(path="/etc/hosts"))
    second_backup_taken(victim, rust, count, "etc-hosts")


def negative_stale_partials(base, rust):
    sandbox = Sandbox(base, "neg-partials")
    materialize_ffi_seed(sandbox)
    backups = sandbox.state / "symvault" / "backups"
    backups.mkdir(parents=True)
    child = subprocess.Popen(["true"])
    child.wait()
    dead = child.pid
    stale_partial = backups / f"pre-rust-vault-0.tar.gz.{dead}.partial"
    stale_scratch = backups / f".verify-{dead}-leftover"
    stale_partial.write_bytes(b"half an archive from a killed run")
    stale_scratch.mkdir()
    (stale_scratch / "vault").write_bytes(b"half a restore")
    live = subprocess.Popen(["sleep", "60"])
    try:
        live_partial = backups / f"pre-rust-vault-1.tar.gz.{live.pid}.partial"
        live_partial.write_bytes(b"another gate is writing this")
        out = sandbox.run(rust, ["set", "harness/new", "--value", STRONG], SEED_PASS)
        check(out.returncode == 0, f"neg-partials: set failed: {out.stderr.strip()[:200]}")
        check(not stale_partial.exists(), "neg-partials: stale .partial archive was not swept")
        check(not stale_scratch.exists(), "neg-partials: stale .verify-* scratch directory was not swept")
        check(live_partial.exists(), "neg-partials: a live process's .partial was swept")
        check(len(sandbox.backups()) == 1, "neg-partials: expected exactly one finished backup")
    finally:
        live.kill()
        live.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    for binary in (args.rust, args.go, args.probe):
        if not Path(binary).is_file():
            print(f"missing binary: {binary}", file=sys.stderr)
            return 2
    rust, go, probe = (Path(p).resolve() for p in (args.rust, args.go, args.probe))
    base = Path(tempfile.mkdtemp(prefix="data-safety-"))
    try:
        run_seed(base, rust, go, "ffi-seed", materialize_ffi_seed, SEED_PASS, "personal/email", [])
        run_seed(base, rust, go, "go-init",
                 lambda s: go_init(s, go, [("work/github.password", STRONG), ("notes/a", STRONG)]),
                 INIT_PASS, "work/github", [])
        run_zero_key(base, rust, go)
        swept = run_sweep(base, rust, go)
        negative_unwritable_backup_dir(base, rust)
        negative_probe(base, rust, probe)
        negative_marker_binding(base, rust)
        negative_stale_partials(base, rust)
    except Failure as failure:
        print(f"FAIL after {cases} checks: {failure}", file=sys.stderr)
        print(f"sandboxes kept in {base}", file=sys.stderr)
        return 1
    if not args.keep:
        shutil.rmtree(base, ignore_errors=True)
    print(f"mutator sweep: {', '.join(swept)}")
    print(f"data-safety contract: PASS ({cases} checks, 3 seed vaults, {len(swept)} mutators, 5 negative-control groups)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
