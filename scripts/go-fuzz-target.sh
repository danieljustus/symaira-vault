#!/usr/bin/env bash
#
# Runs one Go fuzz target and retries it once when, and only when, the run
# ended with the fuzzing engine's own `context deadline exceeded` without
# reporting a failing input (#1473). That outcome means a worker was still
# inside an input when -fuzztime expired; it is not a finding.
#
# Every real finding still fails: a crash or hang prints "Failing input written
# to ..." and writes a new testdata/fuzz corpus entry, and any other non-zero
# exit is returned unchanged. The retry happens at most once.
#
# Usage: scripts/go-fuzz-target.sh <go test args...>
#   e.g. scripts/go-fuzz-target.sh -run '^$' -fuzz=FuzzX -fuzztime=3s -timeout=30s ./internal/crypto
set -uo pipefail

go_bin=${GO:-go}
log=$(mktemp "${TMPDIR:-/tmp}/go-fuzz-target.XXXXXX")
trap 'rm -f "$log"' EXIT

# A real finding writes a corpus file; detect one even if output is unusual.
corpus_state() {
  git status --porcelain --untracked-files=all -- '*/testdata/fuzz/*' 2>/dev/null
}

for attempt in 1 2; do
  before=$(corpus_state)
  "$go_bin" test "$@" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  [ "$status" -eq 0 ] && exit 0
  after=$(corpus_state)
  if [ "$attempt" -eq 1 ] \
    && grep -q 'context deadline exceeded' "$log" \
    && ! grep -q 'Failing input written to' "$log" \
    && [ "$before" = "$after" ]; then
    echo "go-fuzz-target: engine deadline without a failing input; retrying once (#1473)" >&2
    continue
  fi
  exit "$status"
done
