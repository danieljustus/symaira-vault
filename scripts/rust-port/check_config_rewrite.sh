#!/bin/sh
# CONFIG-WRITER: Go's Config.SaveTo bytes against the Rust writer.
#
# 1. Re-verifies the frozen Go-recorded fixture (non-writing) against the
#    pinned oracle's sources.
# 2. Replays it against the Rust writer (declared differences: Go drops
#    paymentPolicies and security on rewrite; Rust keeps them).
# 3. Runs the rewriting commands (agent uninstall, doctor --fix) on the live Go
#    binary built from the same pinned commit and on the Rust CLI, and compares
#    the resulting config.yaml bytes.
#
# A supplied oracle (SYMVAULT_GO_BINARY) is used as is; without one the pinned
# commit is cloned and built here, like check_config_cli.sh does.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
export GOWORK=off
while case ${TMPDIR:-} in ?*/) true ;; *) false ;; esac; do TMPDIR=${TMPDIR%/}; done
[ -z "${TMPDIR:-}" ] || export TMPDIR
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
oracle_commit=690647c5068a818a4b237738882bb20c865a134a
oracle_binary=${SYMVAULT_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/config-rewrite.XXXXXX")
    trap 'rm -rf "$run_root"' EXIT HUP INT TERM
    export TMPDIR="$run_root"
    export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"
    git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
    git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
    (cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$run_root/symvault-go" .)
    oracle_binary="$run_root/symvault-go"
fi
"${GO:-go}" run ./scripts/rust-port/cmd/configrewritegen --check
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-core --test config_rewrite_contract --locked
SYMVAULT_GO_BINARY="$oracle_binary" "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_rewrite_differential --locked
