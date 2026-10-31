#!/bin/sh
# IO-001 complete `symvault import <source>` command gate: re-verify the frozen
# Go corpus against the pinned oracle, then replay it against the native CLI.
#
# A supplied oracle (SYMVAULT_IMPORT_CLI_GO_BINARY) is still verified by
# importcligen (revision, clean VCS metadata and toolchain). Without one, the
# pinned commit is cloned and built here, like check_error_taxonomy_cli.sh does.
#
# Deliberate regeneration (never automatic, never part of the gate):
#   SYMVAULT_IMPORT_CLI_REGENERATE=1 ./scripts/rust-port/check_import_cli.sh
# rewrites the frozen fixture from the same verified oracle build and stops
# before the replay; review the diff, then run the gate normally.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
oracle_binary=${SYMVAULT_IMPORT_CLI_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/import-cli.XXXXXX")
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
if [ "${SYMVAULT_IMPORT_CLI_REGENERATE:-}" = 1 ]; then
    "${GO:-go}" run ./scripts/rust-port/cmd/importcligen --go-binary "$oracle_binary"
    exit 0
fi
"${GO:-go}" run ./scripts/rust-port/cmd/importcligen \
    --check --go-binary "$oracle_binary"
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test import_command_contract --locked
