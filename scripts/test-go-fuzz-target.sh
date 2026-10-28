#!/usr/bin/env bash
# Decision table for scripts/go-fuzz-target.sh with a scripted fake `go`.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d "${TMPDIR:-/tmp}/go-fuzz-target-test.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Fake go: pops the next scripted outcome from $work/plan (one per line).
cat > "$work/go" <<'EOF'
#!/usr/bin/env bash
plan="$FAKE_PLAN"; n=$(cat "$plan.count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$plan.count"
case "$(sed -n "${n}p" "$plan")" in
  pass) echo ok; exit 0 ;;
  deadline) printf -- '--- FAIL: FuzzX (3.08s)\n    context deadline exceeded\nFAIL\n'; exit 1 ;;
  crash) printf -- '--- FAIL: FuzzX\n    Failing input written to testdata/fuzz/FuzzX/abc\n    context deadline exceeded\n'; exit 1 ;;
  other) echo 'build failed'; exit 2 ;;
esac
EOF
chmod +x "$work/go"

check() {
  local name=$1 plan=$2 want_exit=$3 want_calls=$4
  tr ' ' '\n' <<<"$plan" > "$work/$name"; rm -f "$work/$name.count"
  set +e; FAKE_PLAN="$work/$name" GO="$work/go" scripts/go-fuzz-target.sh -fuzz=FuzzX >/dev/null 2>&1; got=$?; set -e
  calls=$(cat "$work/$name.count")
  if [ "$got" -ne "$want_exit" ] || [ "$calls" -ne "$want_calls" ]; then
    echo "FAIL $name: exit $got (want $want_exit), calls $calls (want $want_calls)" >&2; exit 1
  fi
}

check pass "pass" 0 1
check deadline-then-pass "deadline pass" 0 2
check deadline-twice "deadline deadline" 1 2
check crash-not-retried "crash pass" 1 1
check other-failure-not-retried "other pass" 2 1
echo "PASS go-fuzz-target decision table (5 cases)"
