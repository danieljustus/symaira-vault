#!/bin/sh
# CONFIG-WRITER: Go's Config.SaveTo bytes against the Rust writer.
#
#   check_config_rewrite.sh             replay (no Go toolchain, no oracle binary):
#       1. replays the frozen Go-recorded SaveTo fixture against the Rust writer
#          (declared differences: Go drops paymentPolicies and security on
#          rewrite; Rust keeps them);
#       2. replays the recorded Go runs of the rewriting commands (agent
#          uninstall, doctor --fix, config validate) from
#          testdata/port/cli-transcripts/config_rewrite_differential.json
#          against the Rust CLI and compares the resulting config.yaml bytes.
#       A missing or stale recording is a failure.
#   check_config_rewrite.sh --capture   rebuilds the pinned oracle commit and
#       re-records those transcripts (needs Go; `make config-rewrite-capture`).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
while case ${TMPDIR:-} in ?*/) true ;; *) false ;; esac; do TMPDIR=${TMPDIR%/}; done
[ -z "${TMPDIR:-}" ] || export TMPDIR

mode=replay
case ${1:-} in
    "") ;;
    --capture) mode=capture ;;
    *) echo "usage: $0 [--capture]" >&2; exit 2 ;;
esac

if [ "$mode" = replay ]; then
    # Replay must not be able to reach a Go oracle.
    unset SYMVAULT_GO_BINARY SYMVAULT_ORACLE
    "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
        -p symvault-core --test config_rewrite_contract --locked
    "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
        -p symvault-cli --test config_rewrite_differential --locked
    exit 0
fi

# ----------------------------------------------------------------- capture ---
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
oracle_commit=690647c5068a818a4b237738882bb20c865a134a
run_root=$(mktemp -d "${TMPDIR:-/tmp}/config-rewrite.XXXXXX")
trap 'rm -rf "$run_root"' EXIT HUP INT TERM
export TMPDIR="$run_root"
export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"
git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
(cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$run_root/symvault-go" .)
export SYMVAULT_ORACLE=capture
export SYMVAULT_GO_BINARY="$run_root/symvault-go"
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_rewrite_differential --locked
