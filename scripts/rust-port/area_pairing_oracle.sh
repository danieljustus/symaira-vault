#!/usr/bin/env bash
# The oracle-bound steps of .github/workflows/rust-pairing.yml that no other
# local target runs: stateful CLI differential, import quarantine differential,
# auth root-trust differential, startup-profile differential (all four replay
# the committed Go transcripts, no Go oracle) and HTTP-001 keyring isolation.
# (pairing-differential, config-profile-differential and
# device-list-differential are separate local-area targets.)
#
# Every replay step checks its log for an executed, passing test and for a
# non-zero count of replayed Go calls.
#
#   scripts/rust-port/area_pairing_oracle.sh EVIDENCE_DIR
#
# Env: CARGO (default cargo), AREA_CHECK (command prefix of
#      gate_area_check.py). Logs are written below EVIDENCE_DIR; the live tree
#      is never touched.
set -euo pipefail

evidence="${1:?usage: $0 EVIDENCE_DIR}"
cargo="${CARGO:-cargo}"
check="${AREA_CHECK:-python3 -B scripts/rust-port/gate_area_check.py}"
root="$(git rev-parse --show-toplevel)"
cd "$root"
work="$evidence/pairing-oracle"
rm -rf "$work"
mkdir -p "$work"
export SYMVAULT_TEST_KEYRING=memory TZ=UTC

# Unregister exactly this worktree (never a global `git worktree prune`; see
# worktree_remove.sh). Oracle trees must lie inside $work, below the evidence dir.
# shellcheck source=scripts/rust-port/worktree_remove.sh
. "$root/scripts/rust-port/worktree_remove.sh"

worktrees=()
cleanup() {
  local tree
  for tree in "${worktrees[@]:-}"; do
    [ -n "$tree" ] || continue
    remove_worktree_only "$tree" "$work"
  done
}
trap cleanup EXIT

# Toolchain identity (workflow step "Verify toolchain identity").
[ "$(rustc --version | awk '{print $2}')" = "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" ] \
  || { echo "area-pairing: rustc is not the pinned toolchain" >&2; exit 1; }

# replay LOG CARGO_TEST_ARGS...: replay the committed Go transcripts
# (testdata/port/cli-transcripts; no oracle binary), then require an executed,
# passing test that really replayed recorded Go calls. Re-recording needs the
# archived oracle (tag legacy/go-oracle, docs/rust-port/go-oracle-archive.md).
replay() {
  local log="$1"
  shift
  "$cargo" test -p symvault-cli --locked "$@" >"$log" 2>&1 \
    || { cat "$log"; exit 1; }
  cat "$log"
  grep -q "go_oracle: replayed [1-9][0-9]* cases" "$log" \
    || { echo "area-pairing: no recorded Go call was replayed (see $log)" >&2; exit 1; }
  # shellcheck disable=SC2086 # AREA_CHECK is a command word list
  $check log-ok "$log" --results-ok
}

# Stateful CLI differential (recorded Go transcript).
replay "$work/cli-differential.log" \
  --test cli_differential init_list_get_match_go_cli_on_a_disposable_vault -- --exact
# shellcheck disable=SC2086
$check log-ok "$work/cli-differential.log" init_list_get_match_go_cli_on_a_disposable_vault

# Import quarantine differential (recorded Go transcript).
replay "$work/import-quarantine.log" \
  --test cli_differential import_quarantine_matches_pinned_go_cli_batch_contract -- --exact
# shellcheck disable=SC2086
$check log-ok "$work/import-quarantine.log" import_quarantine_matches_pinned_go_cli_batch_contract

# Auth root-trust differential (recorded Go transcript).
replay "$work/auth-differential.log" --test auth_differential auth_rotate

# Startup-profile differential (recorded Go transcript of the pinned Go source,
# oracle ecaf4d0c64bc; the Go source is archived at tag legacy/go-oracle).
startup_commit=ecaf4d0c64bcd21138468080f93f7ea097d7803a
git merge-base --is-ancestor "$startup_commit" HEAD
replay "$work/startup-profile.log" --test startup_profile_differential

# HTTP-001 generator keyring isolation (the workflow runs it on macOS only; it
# is cheap and platform-independent).
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/test_http001init_isolation.py

echo "area-pairing-oracle: ok"
