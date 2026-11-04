#!/usr/bin/env bash
# Every pinned oracle commit must resolve AND stay reachable from a ref.
#
# The frozen fixtures name the Go oracle revision they were recorded from, and
# their source digests are recomputed from that revision's git blobs
# (scripts/rust-port/fixtures_verify.py). A commit that no branch or tag
# contains is one object-store cleanup away from vanishing: the gate still passes on a clone
# that holds the loose object and fails on a fresh one. That is how STORE-002's
# oracle fe098b91 broke, which is why oracle commits carry oracle/* tags.
#
# Pins are collected from the fixtures themselves (every oracle block of every
# frozen fixture JSON: commit, commit_sha, oracle_commit, ...) plus the
# constants of scripts/rust-port/mcp_oracle.py and mcp_fixture_contract.py. No
# Go source is read. A commit passes when it resolves and at least one branch
# (local or remote) or tag contains it; a tag is preferred and reported.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

fixture_pins=$(python3 -B scripts/rust-port/fixtures_verify.py --list-pins | awk 'NF {print $1}')

constant_pins=$(
    python3 -B - <<'PY'
import ast
from pathlib import Path

for filename, wanted in [('mcp_oracle.py', {'HISTORICAL', 'ORDERED'}),
                         ('mcp_fixture_contract.py', {'PRODUCT_SOURCE'})]:
    tree = ast.parse(Path('scripts/rust-port', filename).read_text())
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    print(ast.literal_eval(node.value))
                    found.add(target.id)
    if found != wanted:
        raise SystemExit('FAIL missing oracle pin constants in ' + filename + ': ' + ', '.join(sorted(wanted - found)))
PY
)

pins=$(printf '%s\n%s\n' "$fixture_pins" "$constant_pins" | grep -E '^[0-9a-f]{7,40}$' | sort -u || true)

if [ -z "$fixture_pins" ] || [ -z "$pins" ]; then
    echo "FAIL the collector found no oracle pins in the fixtures; it has stopped matching them"
    exit 1
fi

status=0
count=0
seen=" "
for sha in $pins; do
    full=$(git rev-parse --verify --quiet --end-of-options "${sha}^{commit}" 2>/dev/null) || full=""
    if [ -z "$full" ] || ! git cat-file -e "${full}^{commit}" 2>/dev/null; then
        echo "FAIL ${sha}: oracle commit is not present in this clone"
        status=1
        continue
    fi
    # The same commit is pinned in short and full form; judge it once.
    case "$seen" in *" $full "*) continue ;; esac
    seen="$seen$full "
    count=$((count + 1))
    refs=$(git for-each-ref --contains "$full" --format='%(refname)' refs/heads refs/remotes refs/tags)
    if [ -z "$refs" ]; then
        echo "FAIL ${sha}: resolves, but no branch or tag contains it."
        echo "     Tag it (git tag oracle/<name> ${full:0:12}) before the object store is cleaned."
        status=1
        continue
    fi
    tags=$(printf '%s\n' "$refs" | grep '^refs/tags/' | sed 's|^refs/tags/||' | head -3 | tr '\n' ' ' || true)
    if [ -n "$tags" ]; then
        echo "ok   ${full:0:12} held by tag ${tags}"
    else
        first=$(printf '%s\n' "$refs" | head -1)
        echo "ok   ${full:0:12} held by ${first} (branch only: add an oracle/* tag before pruning)"
    fi
done

if [ "$status" -eq 0 ]; then
    echo "PASS all ${count} pinned oracle commits are reachable"
fi
exit "$status"
