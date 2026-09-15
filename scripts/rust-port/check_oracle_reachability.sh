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

# Pins live in two places: Go constants in the generators, and *_ORACLE_COMMIT
# variables in the Makefile. storemetagen uses only the latter, which is why it
# was the row that broke.
pins=$(
    {
        grep -rhoE '(pinnedOracleCommit|const revision)[[:space:]]*=[[:space:]]*"[0-9a-f]{7,40}"' \
            scripts/rust-port/cmd/*/main.go 2>/dev/null || true
        grep -hoE '^[A-Z_]*ORACLE_COMMIT[[:space:]]*[:?]?=[[:space:]]*[0-9a-f]{7,40}' Makefile 2>/dev/null || true
    } | grep -oE '[0-9a-f]{7,40}"?$' | tr -d '"' | sort -u
)

status=0
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
