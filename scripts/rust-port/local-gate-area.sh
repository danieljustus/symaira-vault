#!/usr/bin/env bash
# Runs the local-area targets of one lane one by one and prints a line per
# target, so a receipt log names every target and its exit status
# (docs/rust-port/local-first.md). Used by local-gate.sh.
#
#   scripts/rust-port/local-gate-area.sh macos|linux
#
# Env: LOCAL_AREA_ONLY (space separated subset of the lane's targets, for
#      negative controls and iteration; the run is then marked `area-partial:
#      true` and is never a full-gate result), LOCAL_AREA_FULL=1 (set by
#      local-gate.sh for the full macos/linux/all modes: LOCAL_AREA_ONLY is then
#      refused, exit 2), MAKE_PREFIX (build launcher placed before `make`).
# The lane's expected list always comes from `make local-area-list`; a full run
# must execute exactly that list. Every target runs even after a failure (like
# `make -k`); the exit status is 1 when any failed or the list did not match.
#
# Run with a 1-minute load average below about 16 (`uptime`): the slow-reader and
# signal contracts are timing-sensitive, and the log carries an `area-load:`
# line per target.
#
# Area targets edit files of a scratch copy only (http-write-contract), but
# should a signal or a defect ever change tracked files of this tree, the guard
# below restores them (when the run started clean) and fails the run.
set -uo pipefail
# Job control: each target runs in its own process group with default signal
# dispositions. A plain `&` in a non-interactive shell starts the job with SIGINT
# ignored, and the signal contracts (signal-process-contract) observe exactly
# that inheritance. The group also lets a signal reach the whole target tree.
set -m

lane="${1:-}"
case "$lane" in macos|linux) ;; *) echo "usage: $0 macos|linux" >&2; exit 2 ;; esac
cd "$(git rev-parse --show-toplevel)" || exit 2

if [ "${LOCAL_AREA_FULL:-0}" = 1 ] && [ -n "${LOCAL_AREA_ONLY:-}" ]; then
  echo "local-gate-area: LOCAL_AREA_ONLY is not allowed in a full gate run (exit 2)" >&2
  exit 2
fi

# shellcheck disable=SC2086 # MAKE_PREFIX is a command word list
expected="$(${MAKE_PREFIX:-} make --no-print-directory -s local-area-list LOCAL_AREA_LANE="$lane")"
[ -n "$expected" ] || { echo "local-gate-area: no targets for lane $lane" >&2; exit 2; }

partial=false
targets="$expected"
if [ -n "${LOCAL_AREA_ONLY:-}" ]; then
  partial=true
  targets="$LOCAL_AREA_ONLY"
  for target in $targets; do
    case " $expected " in
      *" $target "*) ;;
      *) echo "local-gate-area: $target is not a $lane-lane area target" >&2; exit 2 ;;
    esac
  done
fi
echo "area-expected: lane=$lane $expected"
echo "area-partial: $partial"
echo "area-targets: lane=$lane $targets"

start_clean=false
git diff --quiet HEAD && start_clean=true
tree_print() { git diff HEAD | shasum -a 256 | cut -c1-64; }
start_print="$(tree_print)"

# guard: fail (and restore tracked files when the run started clean) if the
# tracked tree differs from its state at the start of the run.
guard() {
  [ "$(tree_print)" = "$start_print" ] && return 0
  echo "area-guard: tracked files changed during the run:" >&2
  git diff HEAD --stat >&2
  if [ "$start_clean" = true ]; then
    git checkout -- . && echo "area-guard: restored the tracked tree" >&2
  fi
  return 1
}

child=""
# shellcheck disable=SC2329 # invoked by the TERM/INT traps
interrupted() { # exit status for the signal
  trap - TERM INT
  if [ -n "$child" ]; then kill -TERM -- "-$child" 2>/dev/null; wait "$child" 2>/dev/null; fi
  guard
  echo "area-summary: lane=$lane interrupted" >&2
  exit "$1"
}
trap 'interrupted 143' TERM
trap 'interrupted 130' INT

pass=0
failed=""
ran=""
for target in $targets; do
  started=$SECONDS
  echo "area-target-begin: $target"
  # Timing-sensitive contracts (http-write slow reader, signal-process) fail
  # under heavy host load; the load average at start makes such a log readable.
  echo "area-load: $target $(uptime | sed 's/.*load averages*: *//')"
  # A background job (own process group, see `set -m`) so that a signal reaches
  # the trap while make runs; stdin stays attached (non-interactive background
  # jobs default to /dev/null).
  # shellcheck disable=SC2086
  ${MAKE_PREFIX:-} make --no-print-directory "$target" <&0 &
  child=$!
  wait "$child"
  ec=$?
  child=""
  guard || ec=1
  echo "area-target: $target exit=$ec secs=$((SECONDS - started))"
  ran="$ran $target"
  if [ "$ec" = 0 ]; then pass=$((pass + 1)); else failed="$failed $target"; fi
done

status=0
[ -z "$failed" ] || status=1
if [ "$partial" = false ] && [ "${ran# }" != "$expected" ]; then
  echo "area-summary: executed targets differ from the expected list" >&2
  status=1
fi
echo "area-summary: lane=$lane partial=$partial pass=$pass fail=$(wc -w <<<"$failed" | tr -d ' ') failed=[${failed# }]"
exit "$status"
