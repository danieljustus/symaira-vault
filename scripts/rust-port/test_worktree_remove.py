#!/usr/bin/env python3
"""Scratch-repository tests of worktree_remove.sh (shared by area_http_write_mutation.sh
and area_pairing_oracle.sh).

Every case builds its own repository under a temp dir, with a *foreign* worktree
`wtA` next to the scratch tree that is to be removed, and asserts the foreign
checkout and its admin dir survive. The two attacks a review reproduced against
the previous per-script function are covered (symlinked tree; a `.git` file that
points at another worktree's admin dir), plus normal, missing, locked,
outside-root and basename-collision cases. `LegacyFunction` re-creates the old
function to prove the attack cases would have destroyed wtA (a negative control of
the harness itself). WORKTREE_REMOVE_HELPER=<path> runs the same cases against a
mutated copy of the helper (used for guard-revert controls).
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER = Path(os.environ.get("WORKTREE_REMOVE_HELPER", HERE / "worktree_remove.sh"))

LEGACY = r"""
remove_worktree_only() { # tree root  (the pre-fix implementation)
  local tree="$1" admin="" common
  [ -f "$tree/.git" ] && admin="$(sed -n 's/^gitdir: //p' "$tree/.git")"
  git worktree remove --force "$tree" >/dev/null 2>&1 && return 0
  rm -rf "$tree"
  common="$(cd "$(git rev-parse --git-common-dir)" && pwd -P)"
  admin="$(cd "$admin" 2>/dev/null && pwd -P)" || return 0
  case "$admin" in "$common"/worktrees/*) rm -rf "$admin" ;; esac
}
"""

ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
ENV.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null", GIT_TERMINAL_PROMPT="0",
           GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, env=ENV, capture_output=True, text=True, check=True).stdout


class Scratch(unittest.TestCase):
    prelude = f'. "{HELPER}"\n'

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="ga-fu-")
        self.addCleanup(self._tmp.cleanup)
        self.top = Path(self._tmp.name).resolve()
        self.repo = self.top / "repo"
        self.evidence = self.top / "evidence"
        self.other = self.top / "other"
        for d in (self.repo, self.evidence, self.other):
            d.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "init")
        self.wt_a = self.other / "wtA"
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.wt_a), "HEAD")
        (self.wt_a / "precious.txt").write_text("keep\n")

    def admins(self):
        return sorted(p.name for p in (self.repo / ".git" / "worktrees").glob("*"))

    def admin_for(self, tree):
        want = str(Path(tree) / ".git")
        for p in (self.repo / ".git" / "worktrees").glob("*"):
            if (p / "gitdir").read_text().strip() == want:
                return p
        return None

    def remove(self, tree, root=None, prelude=None):
        script = (prelude or self.prelude) + f'remove_worktree_only "{tree}" "{root or self.evidence}"\n'
        return subprocess.run(["bash", "-c", script], cwd=self.repo, env=ENV, capture_output=True, text=True)

    def add_scratch(self, name="tree"):
        tree = self.evidence / name
        git(self.repo, "worktree", "add", "-q", "--detach", str(tree), "HEAD")
        return tree

    def assert_wt_a_intact(self):
        self.assertEqual((self.wt_a / "precious.txt").read_text(), "keep\n", "wtA checkout was deleted")
        self.assertIsNotNone(self.admin_for(self.wt_a), "wtA admin dir was deleted")
        self.assertIn(str(self.wt_a), git(self.repo, "worktree", "list", "--porcelain"))


class RemoveWorktree(Scratch):
    def test_normal_removes_tree_and_only_its_admin(self):
        tree = self.add_scratch()
        before = self.admins()
        self.assertEqual(len(before), 2)
        result = self.remove(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tree.exists())
        self.assertIsNone(self.admin_for(tree))
        self.assertEqual(len(self.admins()), 1)
        self.assert_wt_a_intact()

    def test_missing_tree_is_a_noop(self):
        before = self.admins()
        result = self.remove(self.evidence / "never-created")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.remove(self.evidence / "no-such-dir" / "tree")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.admins(), before)
        self.assert_wt_a_intact()

    def test_symlink_to_another_worktree_is_refused(self):
        link = self.evidence / "tree"
        link.symlink_to(self.wt_a)
        result = self.remove(link)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self.assertTrue(link.is_symlink())
        self.assert_wt_a_intact()

    def test_symlinked_parent_is_refused(self):
        (self.evidence / "via").symlink_to(self.other)
        result = self.remove(self.evidence / "via" / "wtA")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside", result.stderr)
        self.assert_wt_a_intact()

    def test_gitfile_pointing_at_another_worktrees_admin_dir(self):
        tree = self.evidence / "tree"
        tree.mkdir()
        admin_a = self.admin_for(self.wt_a)
        (tree / ".git").write_text(f"gitdir: {admin_a}\n")
        result = self.remove(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tree.exists(), "the scratch tree itself is still removed")
        self.assert_wt_a_intact()

    def test_gitfile_copy_of_a_registered_worktree(self):
        # a registered scratch tree whose .git was swapped for wtA's
        tree = self.add_scratch()
        own = self.admin_for(tree)
        (tree / ".git").write_text((self.wt_a / ".git").read_text())
        result = self.remove(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tree.exists())
        self.assertFalse(own.exists(), "its own admin dir (found by gitdir) is removed")
        self.assert_wt_a_intact()

    def test_path_outside_the_evidence_dir_is_refused(self):
        for victim in (self.wt_a, self.other, self.top):
            result = self.remove(victim)
            self.assertNotEqual(result.returncode, 0, victim)
            self.assertIn("outside", result.stderr)
        result = self.remove(self.evidence)  # the root itself is not a tree below it
        self.assertNotEqual(result.returncode, 0)
        result = self.remove(self.evidence / "..")
        self.assertNotEqual(result.returncode, 0)
        self.assert_wt_a_intact()
        self.assertTrue(self.evidence.is_dir())

    def test_basename_collision_removes_the_right_admin(self):
        # foreign worktree and scratch tree both called `tree`: git names the admin dirs
        # tree and tree1, whichever is registered first
        foreign = self.other / "tree"
        git(self.repo, "worktree", "add", "-q", "--detach", str(foreign), "HEAD")
        (foreign / "precious.txt").write_text("keep\n")
        tree = self.add_scratch("tree")
        self.assertEqual({p.name for p in (self.repo / ".git" / "worktrees").glob("tree*")}, {"tree", "tree1"})
        result = self.remove(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tree.exists())
        self.assertIsNone(self.admin_for(tree))
        self.assertIsNotNone(self.admin_for(foreign))
        self.assertEqual((foreign / "precious.txt").read_text(), "keep\n")
        self.assert_wt_a_intact()

    def test_basename_collision_with_unregistered_scratch_tree(self):
        foreign = self.other / "tree"
        git(self.repo, "worktree", "add", "-q", "--detach", str(foreign), "HEAD")
        tree = self.evidence / "tree"
        tree.mkdir()
        (tree / ".git").write_text(f"gitdir: {self.admin_for(foreign)}\n")
        result = self.remove(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tree.exists())
        self.assertIsNotNone(self.admin_for(foreign))
        self.assertTrue(foreign.is_dir())

    def test_locked_worktree_falls_back_to_deleting_it(self):
        tree = self.add_scratch()
        git(self.repo, "worktree", "lock", str(tree))
        result = self.remove(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tree.exists())
        self.assertIsNone(self.admin_for(tree))
        self.assert_wt_a_intact()

    def test_stale_registration_of_a_missing_tree_is_cleared(self):
        tree = self.add_scratch()
        import shutil
        shutil.rmtree(tree)
        self.assertIsNotNone(self.admin_for(tree))
        result = self.remove(tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(self.admin_for(tree))
        self.assert_wt_a_intact()

    def test_usage_errors(self):
        script = self.prelude + 'remove_worktree_only "" ""\n'
        result = subprocess.run(["bash", "-c", script], cwd=self.repo, env=ENV, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_wt_a_intact()


class LegacyFunction(Scratch):
    """The pre-fix function loses to both reviewed attacks: this is what the
    cases above are guarding against, and proves the harness can see the loss."""
    prelude = LEGACY

    def test_symlink_attack_destroyed_wt_a(self):
        link = self.evidence / "tree"
        link.symlink_to(self.wt_a)
        self.remove(link)
        self.assertFalse((self.wt_a / "precious.txt").exists())

    def test_gitfile_attack_destroyed_wt_a_admin(self):
        tree = self.evidence / "tree"
        tree.mkdir()
        (tree / ".git").write_text(f"gitdir: {self.admin_for(self.wt_a)}\n")
        self.remove(tree)
        self.assertIsNone(self.admin_for(self.wt_a))


class CallSites(unittest.TestCase):
    def test_both_scripts_use_the_shared_helper_and_no_private_copy(self):
        for name in ("area_http_write_mutation.sh", "area_pairing_oracle.sh"):
            text = (HERE / name).read_text()
            self.assertIn("worktree_remove.sh", text, name)
            self.assertNotIn("remove_worktree_only() {", text, name)
            self.assertNotIn("rm -rf \"$admin\"", text, name)
            self.assertRegex(text, r'remove_worktree_only "\$tree" ', name)


if __name__ == "__main__":
    unittest.main()
