#!/usr/bin/env python3
"""Negative controls for fixtures_verify.py.

Each test builds a throw-away git repository with one pinned oracle commit and
a few frozen fixtures, freezes it with --write, proves the check passes, then
breaks exactly one thing and requires exit status 1.  Python stdlib and git
only.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "fixtures_verify.py"
SOURCE = b"package oracle\n"


def run(root, *args, check=False):
    proc = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--root", str(root), *args],
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(proc.stdout + proc.stderr)
    return proc


def git(root, *args, input=None):
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    out = subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        capture_output=True, text=True, check=True, env=env, input=input,
    )
    return out.stdout.strip()


class FixturesVerifyControls(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / "src").mkdir()
        (self.root / "src/a.go").write_bytes(SOURCE)
        git(self.root, "add", "src")
        git(self.root, "commit", "-q", "-m", "oracle")
        self.commit = git(self.root, "rev-parse", "HEAD")
        digest = hashlib.sha256(b"src/a.go\0" + SOURCE + b"\0").hexdigest()
        self.digest = digest
        fixture = {
            "oracle": {
                "commit": self.commit[:8],
                "commit_sha": self.commit,
                "source_files": ["src/a.go"],
                "source_digest": digest,
            },
            "cases": [1, 2, 3],
        }
        self.fixture = self.root / "testdata/port/x.json"
        self.fixture.parent.mkdir(parents=True)
        self.fixture.write_text(json.dumps(fixture, indent=1) + "\n")
        (self.root / "testdata/port/y.txt").write_text("golden\n")
        run(self.root, "--write", check=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_baseline_passes_and_counts_classes(self):
        proc = run(self.root, check=True)
        self.assertIn("fixtures-verify: OK", proc.stdout)
        self.assertIn("recomputed=1", proc.stdout)

    def test_flipped_fixture_byte_fails(self):
        target = self.root / "testdata/port/y.txt"
        data = bytearray(target.read_bytes())
        data[0] ^= 0x01
        target.write_bytes(bytes(data))
        proc = run(self.root)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("y.txt: bytes differ", proc.stdout)

    def test_unknown_commit_fails_even_when_manifest_is_regenerated(self):
        data = json.loads(self.fixture.read_text())
        data["oracle"]["commit"] = "deadbeef"
        data["oracle"]["commit_sha"] = "d" * 40
        self.fixture.write_text(json.dumps(data, indent=1) + "\n")
        proc = run(self.root)  # bytes now differ
        self.assertEqual(proc.returncode, 1, proc.stdout)
        refrozen = run(self.root, "--write")  # an honest-looking refreeze must still fail
        self.assertEqual(refrozen.returncode, 1, refrozen.stdout)
        self.assertEqual(run(self.root).returncode, 1)
        self.assertIn("is not present in this repository", run(self.root).stdout)

    def test_deleted_manifest_line_fails(self):
        manifest = self.root / "testdata/port/FROZEN.sha256"
        lines = [line for line in manifest.read_text().splitlines() if not line.endswith("y.txt")]
        manifest.write_text("\n".join(lines) + "\n")
        proc = run(self.root)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("y.txt: frozen file is not listed", proc.stdout)

    def test_missing_manifest_fails(self):
        (self.root / "testdata/port/FROZEN.sha256").unlink()
        self.assertEqual(run(self.root).returncode, 1)

    def test_commit_reachable_from_no_ref_fails_then_tag_fixes_it(self):
        tree = git(self.root, "rev-parse", "HEAD^{tree}")
        orphan = git(self.root, "commit-tree", tree, "-m", "orphan")  # loose, no ref
        self.assertEqual(git(self.root, "for-each-ref", "--contains", orphan), "")
        data = json.loads(self.fixture.read_text())
        data["oracle"]["commit"] = orphan[:8]
        data["oracle"]["commit_sha"] = orphan
        self.fixture.write_text(json.dumps(data, indent=1) + "\n")
        run(self.root, "--write")
        proc = run(self.root)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("no branch or tag contains it", proc.stdout)
        git(self.root, "tag", "oracle/orphan", orphan)
        run(self.root, "--write", check=True)
        run(self.root, check=True)

    def test_tampered_recomputable_digest_fails_even_with_updated_byte_manifest(self):
        data = json.loads(self.fixture.read_text())
        data["oracle"]["source_digest"] = "0" * 64
        self.fixture.write_text(json.dumps(data, indent=1) + "\n")
        manifest = self.root / "testdata/port/FROZEN.sha256"
        rel = "testdata/port/x.json"
        new = hashlib.sha256(self.fixture.read_bytes()).hexdigest()
        manifest.write_text("".join(
            (f"{new}  {rel}\n" if line.endswith(rel) else line + "\n")
            for line in manifest.read_text().splitlines()
        ))
        proc = run(self.root)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("fixture now claims", proc.stdout)

    def test_refreeze_refuses_to_downgrade_a_recomputed_digest(self):
        data = json.loads(self.fixture.read_text())
        data["oracle"]["source_digest"] = "0" * 64
        self.fixture.write_text(json.dumps(data, indent=1) + "\n")
        proc = run(self.root, "--write")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("--write refused", proc.stderr)
        # the explicit override still works, and the check then reports it as recorded
        run(self.root, "--write", "--allow-downgrade", check=True)

    def test_unlisted_new_fixture_and_fixture_argument(self):
        (self.root / "testdata/port/z.txt").write_text("new\n")
        self.assertEqual(run(self.root).returncode, 1)
        # a restricted run only judges the named fixture
        run(self.root, "testdata/port/y.txt", check=True)
        self.assertEqual(run(self.root, "testdata/port/z.txt").returncode, 1)
        self.assertEqual(run(self.root, "testdata/port/nope.json").returncode, 1)

    def test_list_pins(self):
        proc = run(self.root, "--list-pins", check=True)
        self.assertIn(self.commit, proc.stdout)


class OracleReachabilityScript(unittest.TestCase):
    """check_oracle_reachability.sh collects pins from fixtures + mcp_oracle.py constants."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / "f.txt").write_text("x\n")
        git(self.root, "add", "f.txt")
        git(self.root, "commit", "-q", "-m", "c1")
        self.held = git(self.root, "rev-parse", "HEAD")
        tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.orphan = git(self.root, "commit-tree", tree, "-m", "orphan")
        scripts = self.root / "scripts/rust-port"
        scripts.mkdir(parents=True)
        for name in ("fixtures_verify.py", "check_oracle_reachability.sh"):
            (scripts / name).write_bytes((SCRIPT.parent / name).read_bytes())
        (scripts / "check_oracle_reachability.sh").chmod(0o755)
        self.write_constants(self.held, self.held, self.held)
        fixture = self.root / "testdata/port/x.json"
        fixture.parent.mkdir(parents=True)
        self.fixture = fixture
        self.write_fixture(self.held)

    def tearDown(self):
        self._tmp.cleanup()

    def write_constants(self, historical, ordered, product):
        scripts = self.root / "scripts/rust-port"
        (scripts / "mcp_oracle.py").write_text(f"HISTORICAL = '{historical}'\nORDERED = '{ordered}'\n")
        (scripts / "mcp_fixture_contract.py").write_text(f"PRODUCT_SOURCE = '{product}'\n")

    def write_fixture(self, sha):
        self.fixture.write_text(json.dumps({"oracle": {"commit_sha": sha, "commit": sha[:8]}}) + "\n")

    def run_script(self):
        return subprocess.run(
            ["bash", str(self.root / "scripts/rust-port/check_oracle_reachability.sh")],
            capture_output=True, text=True,
        )

    def test_reachable_pins_pass_with_a_branch_only(self):
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS all 1 pinned", proc.stdout)

    def test_fixture_pin_without_ref_fails(self):
        self.write_fixture(self.orphan)
        proc = self.run_script()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("no branch or tag contains it", proc.stdout)

    def test_constant_pin_without_ref_fails(self):
        self.write_constants(self.held, self.orphan, self.held)
        proc = self.run_script()
        self.assertEqual(proc.returncode, 1, proc.stdout)

    def test_unknown_fixture_pin_fails(self):
        self.write_fixture("d" * 40)
        self.assertEqual(self.run_script().returncode, 1)


if __name__ == "__main__":
    unittest.main()
