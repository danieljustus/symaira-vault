#!/bin/sh
# CLI-006 positive output matrix gate: for every command path whose output-format
# gate accepts --json and/or --output, re-verify the frozen Go corpus (text,
# --json, --output yaml, --output json, --quiet) against the pinned oracle, then
# replay it against the native CLI.
#
# A supplied oracle (SYMVAULT_OUTPUT_MODES_GO_BINARY) is still verified by
# outputmodegen (revision, clean VCS metadata and toolchain). Without one, the
# pinned commit is cloned and built here, like check_import_cli.sh does.
#
# Deliberate regeneration (never automatic, never part of the gate):
#   SYMVAULT_OUTPUT_MODES_REGENERATE=1 ./scripts/rust-port/check_output_modes_cli.sh
# rewrites the frozen fixture from the same verified oracle build, KEEPING the
# frozen seed vaults, and stops before the replay. Add
# SYMVAULT_OUTPUT_MODES_NEW_SEEDS=1 to rebuild the seeds too (fresh keys).
#
# Platform: the corpus is recorded on one OS (oracle.goos in the fixture; doctor,
# auth status and several path spellings are host probes). On any other OS the
# Go re-verification cannot reproduce the recorded bytes, so this script prints
# a visible SKIP for it and goes straight to the Rust test, which prints its own
# visible SKIP for the replay. Never a silent pass: both notices are on stderr.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
recorded_goos=darwin
host_goos=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$host_goos" != "$recorded_goos" ] && [ "${SYMVAULT_OUTPUT_MODES_REGENERATE:-}" != 1 ]; then
    echo "SKIP output-modes oracle re-verification: corpus recorded on $recorded_goos, running on $host_goos (cmd/outputmodegen --check is darwin-only; the Rust test below also reports its replay as skipped)" >&2
    "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
        -p symvault-cli --test output_modes --locked
    exit 0
fi
oracle_binary=${SYMVAULT_OUTPUT_MODES_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/output-modes-cli.XXXXXX")
    trap 'rm -rf "$run_root"' EXIT HUP INT TERM
    oracle_commit=bf7f687bb8f57316e8333965635e733b8f567c72
    export TMPDIR="$run_root"
    export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"
    # Ordinary clones give Go reliable VCS metadata; nested worktrees do not.
    git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
    git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
    (cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$run_root/symvault-go" .)
    oracle_binary="$run_root/symvault-go"
fi
if [ "${SYMVAULT_OUTPUT_MODES_REGENERATE:-}" = 1 ]; then
    if [ "${SYMVAULT_OUTPUT_MODES_NEW_SEEDS:-}" = 1 ]; then
        "${GO:-go}" run ./scripts/rust-port/cmd/outputmodegen --go-binary "$oracle_binary" --new-seeds
    else
        "${GO:-go}" run ./scripts/rust-port/cmd/outputmodegen --go-binary "$oracle_binary"
    fi
    exit 0
fi
"${GO:-go}" run ./scripts/rust-port/cmd/outputmodegen \
    --check --go-binary "$oracle_binary"
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test output_modes --locked
