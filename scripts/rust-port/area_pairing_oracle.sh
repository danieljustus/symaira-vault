#!/usr/bin/env bash
# The oracle-bound steps of .github/workflows/rust-pairing.yml that no other
# local target runs: stateful CLI differential against Go v0.22.1, import
# quarantine differential, auth root-trust differential, startup-profile
# differential, the process-tree adapter tests, and HTTP-001 keyring isolation.
# (pairing-differential, config-profile-differential and
# device-list-differential are separate local-area targets.)
#
# The cargo differentials skip silently without SYMVAULT_GO_BINARY, so every
# step checks its log for an executed, passing test and for the absence of the
# skip notice.
#
#   scripts/rust-port/area_pairing_oracle.sh EVIDENCE_DIR
#
# Env: CARGO (default cargo), GO (default go), AREA_CHECK (command prefix of
#      gate_area_check.py). Oracles are built in detached worktrees below
#      EVIDENCE_DIR and removed on exit; the live tree is never touched.
set -euo pipefail

evidence="${1:?usage: $0 EVIDENCE_DIR}"
cargo="${CARGO:-cargo}"
go="${GO:-go}"
check="${AREA_CHECK:-python3 -B scripts/rust-port/gate_area_check.py}"
root="$(git rev-parse --show-toplevel)"
cd "$root"
work="$evidence/pairing-oracle"
rm -rf "$work"
mkdir -p "$work"
export GOWORK=off SYMVAULT_TEST_KEYRING=memory TZ=UTC

# Unregister exactly this worktree. Never `git worktree prune`: it is global to
# the shared common dir, and in the Linux container the host worktrees' paths do
# not exist, so a prune there deletes their admin dirs (.git/worktrees/*).
remove_worktree_only() { # tree
  local tree="$1" admin="" common
  [ -f "$tree/.git" ] && admin="$(sed -n 's/^gitdir: //p' "$tree/.git")"
  git worktree remove --force "$tree" >/dev/null 2>&1 && return 0
  rm -rf "$tree"
  common="$(cd "$(git rev-parse --git-common-dir)" && pwd -P)"
  admin="$(cd "$admin" 2>/dev/null && pwd -P)" || return 0
  case "$admin" in "$common"/worktrees/*) rm -rf "$admin" ;; esac
}

worktrees=()
cleanup() {
  local tree
  for tree in "${worktrees[@]:-}"; do
    [ -n "$tree" ] || continue
    remove_worktree_only "$tree"
  done
}
trap cleanup EXIT

# Toolchain identity (workflow step "Verify toolchain identity").
[ "$(GOTOOLCHAIN="${BUILD_GO_TOOLCHAIN:-go1.26.10}" "$go" env GOVERSION)" = "${BUILD_GO_TOOLCHAIN:-go1.26.10}" ] \
  || { echo "area-pairing: build Go is not ${BUILD_GO_TOOLCHAIN:-go1.26.10}" >&2; exit 1; }
[ "$(rustc --version | awk '{print $2}')" = "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" ] \
  || { echo "area-pairing: rustc is not the pinned toolchain" >&2; exit 1; }
[ "$(GOTOOLCHAIN=go1.26.6 "$go" env GOVERSION)" = go1.26.6 ] \
  || { echo "area-pairing: oracle Go is not go1.26.6" >&2; exit 1; }

# build_oracle REV NAME: detached worktree of REV, binary at $work/NAME.
# -buildvcs=false: `go build` stamps VCS state by running git in the source
# tree, which fails (exit 128) in a worktree of a repository with extensions;
# the stamp is not part of what the differentials compare.
build_oracle() {
  local rev="$1" name="$2" tree="$work/$2-source"
  git worktree add --detach "$tree" "$rev" >/dev/null
  worktrees+=("$tree")
  [ "$(git -C "$tree" rev-parse HEAD)" = "$(git rev-parse "$rev^{commit}")" ] \
    || { echo "area-pairing: worktree for $rev is at the wrong commit" >&2; exit 1; }
  GOTOOLCHAIN=go1.26.6 "$go" -C "$tree" build -buildvcs=false -o "$work/$name" .
  test -f "$work/$name"
}

# differential LOG BINARY CARGO_TEST_ARGS...: run, then require an executed pass.
differential() {
  local log="$1" binary="$2"
  shift 2
  SYMVAULT_GO_BINARY="$binary" "$cargo" test -p symvault-cli --locked "$@" >"$log" 2>&1 \
    || { cat "$log"; exit 1; }
  cat "$log"
  if grep -q "skipping Go differential" "$log"; then
    echo "area-pairing: a Go differential was skipped (see $log)" >&2
    exit 1
  fi
  # shellcheck disable=SC2086 # AREA_CHECK is a command word list
  $check log-ok "$log" --results-ok
}

# Stateful CLI differential against Go v0.22.1.
[ "$(git rev-parse 'refs/tags/v0.22.1^{commit}')" = caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44 ]
build_oracle refs/tags/v0.22.1 go-v0.22.1
differential "$work/cli-differential.log" "$work/go-v0.22.1" \
  --test cli_differential init_list_get_match_go_cli_on_a_disposable_vault -- --exact
# shellcheck disable=SC2086
$check log-ok "$work/cli-differential.log" init_list_get_match_go_cli_on_a_disposable_vault

# Import quarantine differential against the pinned Go CLI.
[ "$(git rev-parse '3232e31f^{commit}')" = 3232e31fb91362b6e6202774f7e95f6d477305d2 ]
build_oracle 3232e31fb91362b6e6202774f7e95f6d477305d2 go-cli-3232e31f
differential "$work/import-quarantine.log" "$work/go-cli-3232e31f" \
  --test cli_differential import_quarantine_matches_pinned_go_cli_batch_contract -- --exact
# shellcheck disable=SC2086
$check log-ok "$work/import-quarantine.log" import_quarantine_matches_pinned_go_cli_batch_contract

# Auth root-trust differential against the current Go oracle.
GOTOOLCHAIN=go1.26.6 "$go" build -buildvcs=false -o "$work/go-auth" .
differential "$work/auth-differential.log" "$work/go-auth" --test auth_differential auth_rotate

# Startup-profile differential against the pinned Go source.
startup_commit=ecaf4d0c64bcd21138468080f93f7ea097d7803a
git merge-base --is-ancestor "$startup_commit" HEAD
git diff --quiet "$startup_commit" HEAD -- cmd/admin/startup_profile.go
differential "$work/startup-profile.log" "$work/go-auth" --test startup_profile_differential

# Process-tree adapter and cleanup.
GOTOOLCHAIN=go1.26.6 "$go" test -count=1 -v \
  ./scripts/rust-port/cmd/caserun ./scripts/rust-port/cmd/devicelistdriver ./scripts/rust-port/internal/diff \
  >"$work/process-tree.log" 2>&1 || { cat "$work/process-tree.log"; exit 1; }
grep -q '^ok ' "$work/process-tree.log" || { echo "area-pairing: no Go package ran" >&2; exit 1; }
if grep -q '^FAIL' "$work/process-tree.log"; then echo "area-pairing: a Go package failed" >&2; exit 1; fi

# HTTP-001 generator keyring isolation (the workflow runs it on macOS only; it
# is cheap and platform-independent).
PYTHONDONTWRITEBYTECODE=1 GOTOOLCHAIN=go1.26.6 python3 scripts/rust-port/test_http001init_isolation.py

echo "area-pairing-oracle: ok"
