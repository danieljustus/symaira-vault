#!/usr/bin/env bash
# Table test for scripts/ci-changed-areas.sh in a throwaway Git repository.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/ci-changed-areas.sh"
repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
cd "$repo"
git init -q
mkdir -p docs/adr cmd editors/vscode
printf 'see docs/contract.md\n' > cmd/contract_test.go
for f in docs/contract.md docs/guide.md docs/adr/0001-x.md README.md editors/vscode/main.ts; do
  printf 'x\n' > "$f"
done
git add -A
git -c user.email=t@example.invalid -c user.name=t commit -qm fixture

failures=0
expect() {
  local want=$1 got
  shift
  got="$(printf '%s\0' "$@" | "$script")"
  if [ "$got" != "code=$want" ]; then
    echo "FAIL: [$*] -> $got, want code=$want" >&2
    failures=$((failures + 1))
  fi
}

expect false docs/guide.md
expect false docs/adr/0001-x.md README.md LICENSE
expect false editors/vscode/main.ts .github/dependabot.yml .github/CODEOWNERS
expect false .github/ISSUE_TEMPLATE/bug_report.yml .github/workflows/codeql.yml
expect true docs/contract.md                    # read by a test
expect true docs/guide.md cmd/contract_test.go  # any code path wins
expect true internal/audit/audit.go
expect true crates/symvault-store/src/lib.rs
expect true Cargo.lock
expect true .github/workflows/ci.yml
expect true .github/workflows/rust-http-tls.yml
expect true scripts/ci-changed-areas.sh
expect true Makefile
expect true unknown/new-area.txt               # unknown paths run everything
expect false                                   # empty diff

got="$(printf '' | "$script")"
[ "$got" = code=false ] || { echo "FAIL: empty stdin -> $got" >&2; failures=$((failures + 1)); }

if [ "$failures" -ne 0 ]; then
  echo "$failures ci-changed-areas case(s) failed" >&2
  exit 1
fi
echo "ci-changed-areas: all cases passed"
