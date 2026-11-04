#!/usr/bin/env bash
# Sourced by area_http_write_mutation.sh (tested by
# test_worktree_remove.py): unregister and delete exactly one scratch worktree.
#
# Never `git worktree prune`: it is global to the shared common dir, and in the
# Linux container the host worktrees' paths do not exist, so a prune there
# deletes their admin dirs (.git/worktrees/*). The removal below is therefore
# keyed on identity, not on what the scratch tree claims about itself:
#
#   - a symlinked TREE is refused (rm -rf / `git worktree remove` would act on
#     the link's target, another worktree);
#   - the TREE's parent is resolved with `pwd -P` and must lie inside ROOT (the
#     evidence dir), so a symlinked parent cannot redirect the removal either;
#   - an admin dir (<common>/worktrees/NAME) is removed only when its `gitdir`
#     file names exactly "<real TREE>/.git". The TREE's own `.git` file is never
#     trusted: a copy of another worktree's `.git` must not make that
#     worktree's admin dir ours, and the admin dir's basename (which git
#     de-duplicates as NAME, NAME1, ...) is never used to find it.
#
#   remove_worktree_only TREE ROOT      (run inside the repository; 0 = removed or
#                                         already absent, 1 = refused)

# worktree_canon PATH: PATH with its directory resolved by `pwd -P`.
worktree_canon() {
  local dir base
  dir="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" || return 1
  base="$(basename "$1")"
  case "$base" in "" | . | ..) return 1 ;; esac
  printf '%s/%s\n' "$dir" "$base"
}

# worktree_admin_of TREE_REAL COMMON: the admin dir whose gitdir file names
# TREE_REAL/.git (empty when none does).
worktree_admin_of() {
  local want="$1/.git" common="$2" dir recorded canon
  for dir in "$common"/worktrees/*/; do
    [ -f "${dir}gitdir" ] || continue
    recorded="$(sed -n '1p' "${dir}gitdir")"
    canon="$(worktree_canon "$recorded" 2>/dev/null)" || canon="$recorded"
    if [ "$recorded" = "$want" ] || [ "$canon" = "$want" ]; then
      printf '%s\n' "${dir%/}"
      return 0
    fi
  done
  return 0
}

remove_worktree_only() { # tree root
  local tree="${1:-}" root="${2:-}" real_tree real_root common admin
  if [ -z "$tree" ] || [ -z "$root" ]; then
    echo "remove_worktree_only: usage: TREE ROOT" >&2
    return 1
  fi
  if [ -L "$tree" ]; then
    echo "remove_worktree_only: refusing symlink $tree" >&2
    return 1
  fi
  case "$(basename "$tree")" in
    . | .. | /)
      echo "remove_worktree_only: refusing $tree: not a directory name below $root" >&2
      return 1
      ;;
  esac
  real_tree="$(worktree_canon "$tree")" || return 0 # parent absent: nothing there
  real_root="$(cd "$root" 2>/dev/null && pwd -P)" || {
    [ -e "$tree" ] || return 0
    echo "remove_worktree_only: evidence root $root is missing; refusing $tree" >&2
    return 1
  }
  case "$real_tree" in
    "$real_root"/?*) ;;
    *)
      echo "remove_worktree_only: refusing $tree: outside $real_root" >&2
      return 1
      ;;
  esac
  common="$(cd "$(git rev-parse --git-common-dir)" && pwd -P)" || return 1
  admin="$(worktree_admin_of "$real_tree" "$common")"

  if [ -n "$admin" ]; then
    # Registered under exactly this path: let git unregister it, and fall back to
    # deleting the checkout when git refuses (locked, missing pieces).
    git worktree remove --force "$real_tree" >/dev/null 2>&1 || true
  fi
  if [ -e "$real_tree" ] || [ -L "$real_tree" ]; then rm -rf "$real_tree"; fi
  # `git worktree remove` normally took the admin dir along; re-resolve by the
  # same gitdir rule rather than trusting the earlier path.
  admin="$(worktree_admin_of "$real_tree" "$common")"
  case "$admin" in
    "$common"/worktrees/?*) rm -rf "$admin" ;;
  esac
  return 0
}
