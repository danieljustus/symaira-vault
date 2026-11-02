#!/usr/bin/env bash
# Runs http_write_mutation.py (rust-http-write.yml: reject a mutant output
# deadline) on a scratch copy of HEAD with its own cargo target directory.
#
# http_write_mutation.py rewrites crates/symvault-mcp/src/http.rs, rebuilds the
# CLI and restores both afterwards. Run in the live tree that would let an
# interrupted gate leave a mutated source file and a mutated target/debug/symvault
# behind, and a concurrent build would break its binary-hash checks. Here the
# live tree and its binary are only read: before and after, this script compares
# git's view of crates/ and the live binary's sha256, and fails (restoring the
# file when it differs) should either have changed.
#
#   area_http_write_mutation.sh LIVE_ROOT SCRATCH_TREE SCRATCH_TARGET LIVE_BINARY RECEIPT CMD_WORDS
#
# CMD_WORDS: one string, the VAR=value assignments and the Python interpreter
# the contract runs with (what the Makefile runs the other area contracts with).
# Env: CARGO (default cargo).
set -uo pipefail

live="${1:?live root}"
tree="${2:?scratch tree}"
target="${3:?scratch cargo target dir}"
binary="${4:?live binary}"
receipt="${5:?receipt}"
cmd_words="${6:?command words}"
cargo="${CARGO:-cargo}"
mutated=crates/symvault-mcp/src/http.rs

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$live" || exit 2

fingerprint() { # live view: tracked changes under crates/, then the binary
  git diff HEAD -- crates | shasum -a 256 | cut -c1-64
  if [ -f "$binary" ]; then shasum -a 256 "$binary" | cut -c1-64; else echo "no-binary"; fi
}

before="$(fingerprint)"
status_before="$(git status --porcelain)"

# Unregister exactly this worktree (never a global `git worktree prune`; see
# worktree_remove.sh). The scratch tree must lie inside the receipt's directory,
# the evidence dir.
# shellcheck source=scripts/rust-port/worktree_remove.sh
. "$here/worktree_remove.sh"
remove_tree() { remove_worktree_only "$tree" "$(dirname "$receipt")"; }

child=""
# shellcheck disable=SC2329 # invoked by the traps
guard() { # exit status of the guarded run in $1
  local ec="$1"
  trap - EXIT INT TERM
  if [ -n "$child" ]; then # a signal arrived while the mutation run was live
    pkill -TERM -P "$child" 2>/dev/null
    kill -TERM "$child" 2>/dev/null
    wait "$child" 2>/dev/null
  fi
  remove_tree
  if ! git -C "$live" diff --quiet HEAD -- "$mutated"; then
    git -C "$live" checkout -- "$mutated"
    echo "http-write-mutation: live $mutated was modified; restored it" >&2
    ec=1
  fi
  if [ "$(cd "$live" && fingerprint)" != "$before" ] || [ "$(git -C "$live" status --porcelain)" != "$status_before" ]; then
    echo "http-write-mutation: live tree or $binary changed during the mutation run" >&2
    ec=1
  fi
  exit "$ec"
}
trap 'guard 143' TERM
trap 'guard 130' INT
trap 'guard $?' EXIT

remove_tree || exit 1
git worktree add --detach "$tree" HEAD >/dev/null || exit 1
mkdir -p "$target"

echo "http-write-mutation: live binary sha256 before: $(sed -n 2p <<<"$before")"
(
  cd "$tree" || exit 1
  export CARGO_TARGET_DIR="$target"
  "$cargo" build --locked -p symvault-cli --bin symvault || exit 1
  # shellcheck disable=SC2086 # CMD_WORDS is a list of VAR=value words and an interpreter
  env $cmd_words -B scripts/rust-port/http_write_mutation.py \
    --rust "$target/debug/symvault" --receipt "$receipt"
) &
child=$!
wait "$child"
ec=$?
child=""
echo "http-write-mutation: live binary sha256 after:  $(sed -n 2p <<<"$(fingerprint)")"
exit "$ec"
