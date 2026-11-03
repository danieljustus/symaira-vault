#!/usr/bin/env python3
"""Fail when a gate script prunes worktrees globally.

`git worktree prune` (and `git gc`/`git prune`/`git worktree repair`) act on the
whole shared common dir. The Linux gate container mounts that dir read-write
but not the host worktree paths, so a prune there deleted every host worktree's
admin dir. Scripts unregister only their own worktree (`git worktree remove`).
Also checks that the container carries the git config guards.

  check_worktree_prune.py [ROOT]      (ROOT defaults to the repository root)
"""
import re
import sys
from pathlib import Path

BAD = re.compile(r"git\s+(?:-C\s+\S+\s+)?(?:worktree\s+(?:prune|repair)|gc|prune)\b"
                 r"|\[\s*\"git\"\s*,\s*\"(?:gc|prune)\"|\"worktree\"\s*,\s*\"(?:prune|repair)\"")
SUFFIXES = {".sh", ".py", ".go", ".txt", ".mk", ""}
# Files that only talk about the command (this checker, marker lists of the
# hosted-workflow structure tests) are exempt.
EXEMPT = {"scripts/rust-port/check_worktree_prune.py", "scripts/rust-port/test_check_worktree_prune.py",
          "scripts/test_ci_macos_satellites.py"}
GUARDS = {
    "scripts/rust-port/local-gate.sh": ["GIT_CONFIG_KEY_0=gc.auto", "gc.worktreePruneExpire"],
    "scripts/rust-port/local-gate/Dockerfile": ["gc.auto 0", "gc.worktreePruneExpire never"],
}


def findings(root: Path):
    out = []
    for path in sorted((root / "scripts").rglob("*")):
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or rel in EXEMPT or "__pycache__" in rel:
            continue
        if path.suffix not in SUFFIXES and path.name != "Dockerfile":
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            if BAD.search(line):
                out.append(f"{rel}:{number}: global worktree/gc command: {line.strip()}")
    makefile = root / "Makefile"
    if makefile.is_file():
        for number, line in enumerate(makefile.read_text(encoding="utf-8").splitlines(), 1):
            if not line.lstrip().startswith("#") and BAD.search(line):
                out.append(f"Makefile:{number}: global worktree/gc command: {line.strip()}")
    for rel, needles in GUARDS.items():
        path = root / rel
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        for needle in needles:
            if needle not in text:
                out.append(f"{rel}: missing container git guard {needle!r}")
    return out


def main(argv):
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    problems = findings(root)
    for problem in problems:
        print(f"check_worktree_prune: FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("check_worktree_prune: ok (no global worktree prune/gc in scripts/ or Makefile; container guards present)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
