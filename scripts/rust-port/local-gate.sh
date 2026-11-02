#!/usr/bin/env bash
# Local replacement for the per-PR CI gate during the local-first Rust port
# (docs/rust-port/local-first.md). Runs the Rust/port-contract gates natively
# on macOS and in a native Linux container, and appends one receipt per run.
#
#   scripts/rust-port/local-gate.sh macos|linux|all
#   scripts/rust-port/local-gate.sh macos-area|linux-area   (only the local-area
#       targets of that lane; for iteration, negative controls and slices that
#       touch an area workflow's contract)
#
# Env: LOCAL_GATE_LOG_DIR / LOCAL_GATE_RECEIPTS (defaults below), RUN_MIRI=1,
#      LOCAL_AREA_ONLY (subset of local-area targets, see local-gate-area.sh;
#      only with macos-area|linux-area, where the receipt is marked partial;
#      refused with exit 2 for macos|linux|all),
#      ALLOW_DIRTY=1 (receipt is then marked dirty and is not evidence),
#      MAKE_PREFIX (e.g. a build launcher such as dev-external),
#      LOCAL_GATE_MOUNT_AS (linux lane: absolute path to mount this worktree
#      at inside the container, and to derive the cargo target volume from;
#      point it at another worktree's path to reuse that worktree's existing
#      volume instead of creating a new multi-GB one when disk is tight).
set -euo pipefail

mode="${1:-all}"
case "$mode" in
  macos|linux|all)
    if [ -n "${LOCAL_AREA_ONLY:-}" ]; then
      echo "local-gate: LOCAL_AREA_ONLY narrows the area targets and cannot be combined with the full '$mode' gate" >&2
      exit 2
    fi ;;
esac
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

# Area targets that ran, as "name:exit,..." from the log's `area-target:`
# lines (local-gate-area.sh), so a receipt names what it covers.
area_targets() { # log
  sed -n 's/^area-target: \([^ ]*\) exit=\([0-9]*\).*/\1:\2/p' "$1" | paste -sd, -
}

# The area run's own bookkeeping lines (local-gate-area.sh): whether the run
# was narrowed by LOCAL_AREA_ONLY, the list `make local-area-list` expects, and
# the targets that actually ran. `area_complete` is true only for an unnarrowed
# run that executed exactly the expected list and exited 0.
area_line() { # log prefix
  sed -n "s/^$2: //p" "$1" | tail -n 1
}

receipt() { # target exit started log
  local partial expected ran complete=false
  partial="$(area_line "$4" area-partial)"
  expected="$(area_line "$4" area-expected | sed 's/^lane=[a-z]* //')"
  ran="$(sed -n 's/^area-target: \([^ ]*\) exit=.*/\1/p' "$4" | paste -sd' ' -)"
  if [ "$2" = 0 ] && [ "$partial" = false ] && [ -n "$expected" ] && [ "$ran" = "$expected" ]; then complete=true; fi
  printf '{"sha":"%s","dirty":%s,"target":"%s","exit":%s,"started":"%s","finished":"%s","log":"%s","area_targets":"%s","partial":%s,"area_expected":"%s","area_complete":%s}\n' \
    "$sha" "$dirty" "$1" "$2" "$3" "$(date -u +%FT%TZ)" "$4" "$(area_targets "$4")" \
    "${partial:-false}" "$expected" "$complete" >> "$receipts"
}

# Targets no ci.yml job reaches (Makefile LOCAL_AREA_TARGETS, macOS lane): one
# line per target in the log, every target runs, status 1 if any failed.
# shellcheck disable=SC2329 # invoked as "run_$target"
run_macos_area() {
  [ "$(uname -s)/$(uname -m)" = Darwin/arm64 ] || { echo "local-gate: macos-area needs native Darwin/arm64" >&2; return 2; }
  # shellcheck disable=SC2154 # root is set above
  "$root/scripts/rust-port/local-gate-area.sh" macos
}

# shellcheck disable=SC2329 # invoked as "run_$target"
run_macos() {
  [ "$(uname -s)/$(uname -m)" = Darwin/arm64 ] || { echo "local-gate: macos needs native Darwin/arm64" >&2; return 2; }
  # Mirrors ci.yml `rust-native` (macos-latest); `port-contract` runs on Linux,
  # as in CI.
  ${MAKE_PREFIX:-} make rust-lint rust-check mcp-call-fixtures-check rust-test
  # The trusted-alias auth case needs TMPDIR below the root-owned /var ->
  # /private/var alias (same rule as the self-hosted CI runner). A make
  # command-line variable overrides the external TMPDIR a build launcher sets.
  # ponytail: only this target uses the internal per-user temp dir.
  ${MAKE_PREFIX:-} make config-cli-differential TMPDIR="$(getconf DARWIN_USER_TEMP_DIR)"
  ${MAKE_PREFIX:-} make mcp-approval-pty-acceptance
  LOCAL_AREA_FULL=1 run_macos_area
  # Go is the frozen oracle: test it only when this branch changed Go code.
  # Pin the toolchain CI uses (go.mod `toolchain`, = Makefile
  # BUILD_GO_TOOLCHAIN): direct `go test` bypasses the Makefile export, and a
  # newer host Go compresses differently, so restoregen's gzip fixture reads
  # as stale (go1.27.3, receipt 4bf2978a macos).
  GOTOOLCHAIN="$(sed -n 's/^toolchain //p' go.mod)"
  [ -n "$GOTOOLCHAIN" ] || { echo "local-gate: go.mod has no toolchain line" >&2; return 2; }
  export GOTOOLCHAIN
  # The changed packages always run with -race.
  go_changed="$(git diff --name-only origin/main -- '*.go' go.mod go.sum)"
  [ -n "$go_changed" ] || return 0
  # shellcheck disable=SC2046 # one ./dir argument per changed package
  go test -race -count=1 $(xargs -n1 dirname <<<"$go_changed" | grep -v '^\.$' | sort -u | sed 's|^|./|')
  # Changes outside scripts/ (leaf generator mains) also run the full suite
  # the way ci.yml `test` runs it on macOS: no -race, CGO off, 30m budget.
  # The full -race suite is CI's ubuntu job; under -race on this host
  # cmd/crud's scrypt cases alone exceed go test's default 10m timeout.
  grep -qv '^scripts/' <<<"$go_changed" || return 0
  # Same cleanup as CI: stale generator evidence packages under target/ are
  # enumerated by `./...` and deleted mid-run by the test that rewrites them.
  find target -mindepth 1 -maxdepth 1 -type d 2>/dev/null | while IFS= read -r dir; do
    if find "$dir" -name '*.go' -print -quit | grep -q .; then chmod -R u+w "$dir"; rm -rf "$dir"; fi
  done
  CGO_ENABLED=0 SYMVAULT_ALLOW_ENV_PASSPHRASE=1 ${MAKE_PREFIX:-} python3 scripts/run_go_tests.py cargo -- \
    go test -timeout=30m -skip 'TestFlow|TestBinaryE2E|Integration' ./...
}

# Docker command shared by the full linux lane and linux-area: the same absolute
# paths as the host so a worktree's .git file still resolves, one cargo target
# volume per worktree (cargo names workspace-member artifacts by
# workspace-relative path, so a shared target dir reuses test binaries whose
# env!("CARGO_MANIFEST_DIR") points into another or a removed worktree).
# shellcheck disable=SC2329 # called from run_linux and run_linux_area
linux_docker() { # shell command run inside the container
  docker build -q -t "$image" scripts/rust-port/local-gate >/dev/null
  common="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
  mount="${LOCAL_GATE_MOUNT_AS:-$root}"
  target_volume="symvault-gate-target-$(printf '%s' "$mount" | shasum -a 256 | cut -c1-12)"
  docker run --rm -v "$root:$mount" -v "$common:$common" -w "$mount" \
    -v symvault-gate-registry:/home/dev/.cargo/registry \
    -v symvault-gate-go:/home/dev/go \
    -v "$target_volume:/home/dev/target" \
    -e CARGO_TARGET_DIR=/home/dev/target \
    -e CARGO_INCREMENTAL=0 -e GOCACHE=/home/dev/go/cache \
    -e RUST_TEST_THREADS=1 -e LOCAL_AREA_ONLY="${LOCAL_AREA_ONLY:-}" \
    "$image" bash -c "$1"
}

# shellcheck disable=SC2329 # invoked as "run_$target"
run_linux_area() {
  linux_docker 'scripts/rust-port/local-gate-area.sh linux'
}

# shellcheck disable=SC2329 # invoked as "run_$target"
run_linux() {
  targets="rust-gates-core port-contract mcp-approval-pty-acceptance"
  # local-area runs target by target (local-gate-area.sh) so the log names
  # each one; set -e stops the lane at the first failing make above it.
  cmd="set -e; make $targets; LOCAL_AREA_FULL=1 scripts/rust-port/local-gate-area.sh linux"
  # ponytail: Miri takes about an hour; opt in for slices touching
  # symvault-core. The closing hosted CI run always includes it.
  [ "${RUN_MIRI:-0}" = 1 ] && cmd="$cmd; make rust-miri MIRI_TARGET_DIR=/home/dev/target/miri"
  linux_docker "$cmd"
}

status=0
for target in $( [ "$mode" = all ] && echo "macos linux" || echo "$mode" ); do
  case "$target" in macos|linux|macos-area|linux-area) ;; *) echo "usage: $0 macos|linux|all|macos-area|linux-area" >&2; exit 2 ;; esac
  log="$log_dir/${target}-${sha:0:8}.log"
  started="$(date -u +%FT%TZ)"
  echo "local-gate: $target @ ${sha:0:8} -> $log"
  # The subshell re-enables errexit: `set +e` around a bare function call
  # would disable it inside the function too, and a failed `make` would then
  # be masked by the exit status of the function's last command.
  set +e
  (set -e; "run_${target//-/_}") > "$log" 2>&1
  ec=$?
  set -e
  receipt "$target" "$ec" "$started" "$log"
  echo "local-gate: $target exit=$ec"
  [ "$ec" = 0 ] || { status=1; tail -n 40 "$log"; }
done
exit "$status"
