#!/usr/bin/env bash
# Runs the local-area targets of one lane one by one and prints a line per
# target, so a receipt log names every target and its exit status
# (docs/rust-port/local-first.md). Used by local-gate.sh.
#
#   scripts/rust-port/local-gate-area.sh macos|linux
#
# Env: LOCAL_AREA_ONLY (space separated target subset, for negative controls
#      and iteration), MAKE_PREFIX (build launcher placed before `make`).
# Every target runs even after a failure (like `make -k`); the exit status is 1
# when any failed.
set -uo pipefail

lane="${1:-}"
case "$lane" in macos|linux) ;; *) echo "usage: $0 macos|linux" >&2; exit 2 ;; esac
cd "$(git rev-parse --show-toplevel)" || exit 2

# shellcheck disable=SC2086 # MAKE_PREFIX is a command word list
targets="${LOCAL_AREA_ONLY:-$(${MAKE_PREFIX:-} make --no-print-directory -s local-area-list LOCAL_AREA_LANE="$lane")}"
[ -n "$targets" ] || { echo "local-gate-area: no targets for lane $lane" >&2; exit 2; }
echo "area-targets: lane=$lane $targets"

pass=0
failed=""
for target in $targets; do
  started=$SECONDS
  echo "area-target-begin: $target"
  # shellcheck disable=SC2086
  ${MAKE_PREFIX:-} make --no-print-directory "$target"
  ec=$?
  echo "area-target: $target exit=$ec secs=$((SECONDS - started))"
  if [ "$ec" = 0 ]; then pass=$((pass + 1)); else failed="$failed $target"; fi
done
echo "area-summary: lane=$lane pass=$pass fail=$(wc -w <<<"$failed" | tr -d ' ') failed=[${failed# }]"
[ -z "$failed" ]
