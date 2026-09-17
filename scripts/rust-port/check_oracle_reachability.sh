#!/usr/bin/env bash
# Every pinned Go oracle commit must stay reachable from a ref.
#
# The generators read their oracle's blobs out of git. A commit that is only
# reachable through some branch that happens to contain it disappears the
# moment that branch is deleted: the gate then still passes on a clone that
# already has the object and fails on a fresh one. That is exactly how
# STORE-002's oracle fe098b91 broke, so it now carries the tag oracle/store-002.
#
# Reachable from HEAD, from main, or held by a tag is sufficient. Anything else
# is one branch deletion away from breaking a fresh clone.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

main_ref="origin/main"
git rev-parse --verify --quiet "$main_ref" >/dev/null 2>&1 || main_ref="main"

# Pins live in three shapes: Go constants in the generators, struct-literal
# fields where a generator pins each fixture kind separately, and
# *_ORACLE_COMMIT variables in the Makefile. storemetagen used only the last,
# which is why it was the row that broke; coregen uses the middle one, which
# an earlier version of this collector also could not see.
collect_pins() {
    {
        grep -rhoE '(pinnedOracleCommit|oracleCommit|const revision)[[:space:]]*=[[:space:]]*"[0-9a-f]{7,40}"' \
            "$@" 2>/dev/null || true
        grep -rhoE 'commit:[[:space:]]*"[0-9a-f]{7,40}"' "$@" 2>/dev/null || true
    } | grep -oE '[0-9a-f]{7,40}"?$' | tr -d '"' | sort -u
}

generator_sources=$(find scripts/rust-port/cmd -name '*.go' ! -name '*_test.go')
# shellcheck disable=SC2086
pins=$(
    {
        collect_pins $generator_sources
        grep -hoE '^[A-Z_]*ORACLE_COMMIT[[:space:]]*[:?]?=[[:space:]]*[0-9a-f]{7,40}' Makefile 2>/dev/null || true
    } | grep -oE '[0-9a-f]{7,40}' | sort -u
)

if [ -z "$pins" ]; then
    echo "FAIL the collector found no oracle pins at all; it has stopped matching the generators"
    exit 1
fi

# A generator that verifies provenance must contribute a pin this script can
# see. Without this, a pin written in a shape the collector cannot parse goes
# unchecked and the row passes on a clone that happens to hold the object.
status=0
for dir in $(grep -rl 'provenance.Verify' scripts/rust-port/cmd --include='*.go' | xargs -n1 dirname | sort -u); do
    found=$(collect_pins "$dir"/*.go) || found=""
    if [ -z "$found" ]; then
        if ! grep -qE "^[A-Z_]*ORACLE_COMMIT" Makefile || ! grep -q "$(basename "$dir")" Makefile; then
            echo "FAIL $(basename "$dir") verifies provenance but contributes no pin this script can see"
            status=1
        fi
    fi
done

for sha in $pins; do
    if ! git cat-file -e "${sha}^{commit}" 2>/dev/null; then
        echo "FAIL ${sha}: oracle commit is not present in this clone"
        status=1
        continue
    fi
    for ref in HEAD "$main_ref"; do
        if git merge-base --is-ancestor "$sha" "$ref" 2>/dev/null; then
            echo "ok   ${sha:0:12} reachable from ${ref}"
            continue 2
        fi
    done
    tags=$(git tag --points-at "$sha" | tr '\n' ' ')
    if [ -n "$tags" ]; then
        echo "ok   ${sha:0:12} held by tag ${tags}"
        continue
    fi
    echo "FAIL ${sha}: reachable from neither HEAD nor ${main_ref}, and no tag points at it."
    echo "     Tag it before the branch that carries it is deleted."
    status=1
done

[ "$status" -eq 0 ] && echo "PASS all pinned oracle commits are reachable"
exit "$status"
