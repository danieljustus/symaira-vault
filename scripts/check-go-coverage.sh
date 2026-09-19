#!/usr/bin/env bash
set -euo pipefail
coverage_profile=${1:-coverage.out}
echo "=== Total coverage check ==="
COVERAGE_THRESHOLD=63.5
echo "Threshold: ${COVERAGE_THRESHOLD}%"
TOTAL_LINE=$(go tool cover -func="$coverage_profile" | grep "total:")
echo "Coverage line: $TOTAL_LINE"
COVERAGE=$(echo "$TOTAL_LINE" | grep -oE '[0-9]+\.[0-9]+' | tail -1)
echo "Total coverage: ${COVERAGE}%"
if awk "BEGIN {exit !($COVERAGE < $COVERAGE_THRESHOLD)}"; then
  echo "FAIL: Total coverage ${COVERAGE}% is below threshold of ${COVERAGE_THRESHOLD}%"
  exit 1
fi
echo "PASS: Total coverage ${COVERAGE}% meets threshold of ${COVERAGE_THRESHOLD}%"

echo ""
echo "=== Per-package coverage checks for security-critical packages ==="
# Derived from the supplied profile (single test pass): the default
# -coverpkg scopes each test binary to its own package, so filtering
# profile lines by full package path equals a dedicated per-package
# run (verified locally: crypto 87.2, session 70.9, auth 91.5,
# serverbootstrap 84.4 — identical; vault 85.0 vs 84.9 rounding).
# NOTE: filter by FULL path — "/auth/" alone would also match cmd/auth.
PKG_COV_TMP=$(mktemp -d)
trap 'rm -rf "$PKG_COV_TMP"' EXIT
for PACKAGE in "internal/crypto" \
               "internal/session" \
               "internal/vault" \
               "internal/mcp/auth" \
               "internal/mcp/serverbootstrap"; do
  PKG_NAME=$(basename "$PACKAGE")
  PKG_PROFILE="$PKG_COV_TMP/${PKG_NAME}.out"
  { head -1 "$coverage_profile"; grep "symaira-vault/${PACKAGE}/" "$coverage_profile" || true; } > "$PKG_PROFILE"
  PKG_COV=$(go tool cover -func="$PKG_PROFILE" | grep '^total:' | grep -oE '[0-9]+\.[0-9]+' | tail -1)
  [ -z "$PKG_COV" ] && PKG_COV=0
  case "$PKG_NAME" in
    crypto)          PKG_THRESHOLD=85.0 ;;
    session)         PKG_THRESHOLD=70.0 ;;
    vault)           PKG_THRESHOLD=72.0 ;;
    auth)            PKG_THRESHOLD=82.0 ;;
    serverbootstrap) PKG_THRESHOLD=78.0 ;;
    *)               PKG_THRESHOLD=65.0 ;;
  esac
  echo "${PKG_NAME}: ${PKG_COV}% (threshold: ${PKG_THRESHOLD}%)"
  if awk "BEGIN {exit !($PKG_COV < $PKG_THRESHOLD)}"; then
    echo "FAIL: ${PKG_NAME} coverage ${PKG_COV}% is below threshold of ${PKG_THRESHOLD}%"
    exit 1
  fi
  echo "PASS: ${PKG_NAME} coverage ${PKG_COV}% meets threshold of ${PKG_THRESHOLD}%"
done
