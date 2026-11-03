#!/usr/bin/env python3
"""Negative controls for check_worktree_prune.py."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECK = HERE / "check_worktree_prune.py"
ROOT = HERE.parents[1]


def run(root):
    return subprocess.run([sys.executable, "-I", str(CHECK), str(root)], capture_output=True, text=True)


class Check(unittest.TestCase):
    def tree(self, tmp, bad=None):
        root = Path(tmp)
        for rel in ["scripts/rust-port/local-gate.sh", "scripts/rust-port/local-gate/Dockerfile"]:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text((ROOT / rel).read_text())
        (root / "Makefile").write_text("all:\n\ttrue\n")
        if bad:
            (root / "scripts/rust-port/x.sh").write_text(bad)
        return root

    def test_repository_is_clean(self):
        result = run(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bare_prune_fails(self):
        for bad in ["git worktree prune\n", "  git -C \"$r\" worktree prune --expire=now\n", "git gc --auto\n",
                    "git worktree repair\n", "run([\"git\", \"worktree\", \"prune\"])\n"]:
            with tempfile.TemporaryDirectory() as tmp:
                result = run(self.tree(tmp, bad))
                self.assertEqual(result.returncode, 1, bad)
                self.assertIn("x.sh:1", result.stderr)

    def test_comment_and_remove_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(self.tree(tmp, "# never git worktree prune\ngit worktree remove --force t\n"))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_guard_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.tree(tmp)
            gate = root / "scripts/rust-port/local-gate.sh"
            gate.write_text(gate.read_text().replace("gc.worktreePruneExpire", "gc.x"))
            result = run(root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("missing container git guard", result.stderr)


if __name__ == "__main__":
    unittest.main()
