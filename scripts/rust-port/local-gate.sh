#!/usr/bin/env bash
# Local replacement for the per-PR CI gate during the local-first Rust port
# (docs/rust-port/local-first.md). Runs the Rust/port-contract gates natively
# on macOS and in a native Linux container, and appends one receipt per run.
#
#   scripts/rust-port/local-gate.sh macos|linux|all
#
# Env: LOCAL_GATE_LOG_DIR / LOCAL_GATE_RECEIPTS (defaults below), RUN_MIRI=1,
#      ALLOW_DIRTY=1 (receipt is then marked dirty and is not evidence),
#      MAKE_PREFIX (e.g. a build launcher such as dev-external).
set -euo pipefail

mode="${1:-all}"
root="$(git rev-parse --show-toplevel)"
cd "$root"
sha="$(git rev-parse HEAD)"
dirty=false
if [ -n "$(git status --porcelain)" ]; then
  [ "${ALLOW_DIRTY:-0}" = 1 ] || { echo "local-gate: working tree is dirty; commit first or set ALLOW_DIRTY=1" >&2; exit 2; }
  dirty=true
fi
log_dir="${LOCAL_GATE_LOG_DIR:-$root/target/local-gate}"
receipts="${LOCAL_GATE_RECEIPTS:-$log_dir/receipts.jsonl}"
mkdir -p "$log_dir" "$(dirname "$receipts")"
image=symvault-local-gate:1

receipt() { # target exit started log
  printf '{"sha":"%s","dirty":%s,"target":"%s","exit":%s,"started":"%s","finished":"%s","log":"%s"}\n' \
    "$sha" "$dirty" "$1" "$2" "$3" "$(date -u +%FT%TZ)" "$4" >> "$receipts"
}

# shellcheck disable=SC2329 # invoked as "run_$target"
run_macos() {
  [ "$(uname -s)/$(uname -m)" = Darwin/arm64 ] || { echo "local-gate: macos needs native Darwin/arm64" >&2; return 2; }
  # Same TMPDIR rule as the self-hosted CI runner (trusted /var alias case).
  TMPDIR="$(getconf DARWIN_USER_TEMP_DIR)" ${MAKE_PREFIX:-} make \
    rust-lint rust-check rust-test port-contract mcp-approval-pty-acceptance
  # Go is the frozen oracle: test it only when this branch changed Go code.
  # ponytail: changes confined to scripts/ (leaf generator mains) test just
  # those packages; anything else runs the full race suite.
  go_changed="$(git diff --name-only origin/main -- '*.go' go.mod go.sum)"
  if [ -z "$go_changed" ]; then
    :
  elif ! grep -qv '^scripts/' <<<"$go_changed"; then
    # shellcheck disable=SC2046 # one ./dir argument per changed package
    go test -race -count=1 $(xargs -n1 dirname <<<"$go_changed" | sort -u | sed 's|^|./|')
  else
    ${MAKE_PREFIX:-} make test
  fi
}

# shellcheck disable=SC2329 # invoked as "run_$target"
run_linux() {
  docker build -q -t "$image" scripts/rust-port/local-gate >/dev/null
  common="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
  targets="rust-gates-core port-contract mcp-approval-pty-acceptance"
  # ponytail: Miri takes about an hour; opt in for slices touching
  # symvault-core. The closing hosted CI run always includes it.
  [ "${RUN_MIRI:-0}" = 1 ] && targets="$targets rust-miri"
  # shellcheck disable=SC2086 # $targets is a word list
  # Same absolute paths as the host so a worktree's .git file still resolves.
  docker run --rm -v "$root:$root" -v "$common:$common" -w "$root" \
    -v symvault-gate-registry:/home/dev/.cargo/registry \
    -v symvault-gate-go:/home/dev/go \
    -v symvault-gate-target:/home/dev/target \
    -e CARGO_TARGET_DIR=/home/dev/target \
    -e CARGO_INCREMENTAL=0 -e GOCACHE=/home/dev/go/cache \
    -e RUST_TEST_THREADS=1 \
    "$image" make $targets MIRI_TARGET_DIR=/home/dev/target/miri
}

status=0
for target in $( [ "$mode" = all ] && echo "macos linux" || echo "$mode" ); do
  case "$target" in macos|linux) ;; *) echo "usage: $0 macos|linux|all" >&2; exit 2 ;; esac
  log="$log_dir/${target}-${sha:0:8}.log"
  started="$(date -u +%FT%TZ)"
  echo "local-gate: $target @ ${sha:0:8} -> $log"
  # The subshell re-enables errexit: `set +e` around a bare function call
  # would disable it inside the function too, and a failed `make` would then
  # be masked by the exit status of the function's last command.
  set +e
  (set -e; "run_$target") > "$log" 2>&1
  ec=$?
  set -e
  receipt "$target" "$ec" "$started" "$log"
  echo "local-gate: $target exit=$ec"
  [ "$ec" = 0 ] || { status=1; tail -n 40 "$log"; }
done
exit "$status"
