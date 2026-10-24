#!/usr/bin/env bash
#
# Maps changed PR paths (NUL-separated on stdin) to the CI jobs they can affect
# and prints `code=true|false` for $GITHUB_OUTPUT (.github/workflows/ci.yml).
# Run from the repository root of the checked-out PR head.
#
# Fail-safe by design: any path this table does not list as inert sets
# code=true, so a new directory can never silently lose its tests. An inert
# path still counts as code when its path (or file name) is referenced by any
# tracked non-documentation file, because tests, generators and oracle pins
# read some documents (e.g. docs/scripting-contract.md, ARCHITECTURE.md).
# editors/** has its own job (Editors (Ubuntu)); Vaultcore keeps its own gate.
set -euo pipefail

code=false

referenced() {
  local path=$1 name
  name=${path##*/}
  git grep -q -F -e "$path" -e "$name" -- . ':(exclude)*.md' ':(exclude)docs/**' \
    ':(exclude)scripts/ci-changed-areas.sh' ':(exclude)scripts/test-ci-changed-areas.sh' 2>/dev/null
}

while IFS= read -r -d '' path || [ -n "${path:-}" ]; do
  [ -n "$path" ] || continue
  case "$path" in
    # No ci.yml code job builds or reads these, unless referenced (below).
    docs/* | *.md | LICENSE | editors/* | \
    .github/dependabot.yml | .github/CODEOWNERS | .github/ISSUE_TEMPLATE/* | \
    .github/workflows/codeql.yml)
      if referenced "$path"; then code=true; fi ;;
    *) code=true ;;
  esac
  [ "$code" = false ] || break
done

printf 'code=%s\n' "$code"
