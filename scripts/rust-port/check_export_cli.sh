#!/bin/sh
# IO-002 complete-CLI gate: `symvault export`, `symvault backup ARCHIVE` and
# `symvault restore ARCHIVE` (every flag, argv, confirmation, output-file
# handling, stdout/stderr/exit status and the resulting file tree).
#
# Re-verifies the frozen Go corpus against the pinned oracle, then replays it
# against the native CLI. A supplied oracle (SYMVAULT_EXPORT_CLI_GO_BINARY) is
# still verified by exportcligen (revision, clean VCS metadata and toolchain).
# Without one, the pinned commit is cloned and built here, like
# check_error_taxonomy_cli.sh does.
#
# Verification is read-only: `--check` regenerates every observation from the
# oracle and fails on any byte of difference; it never writes the fixture. To
# regenerate deliberately (vault seeds are kept; add --new-seeds to replace
# them):
#   go run ./scripts/rust-port/cmd/exportcligen --go-binary <oracle> \
#       --oracle-commit "$oracle_commit" --oracle-release unreleased
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
oracle_commit=bf7f687bb8f57316e8333965635e733b8f567c72
oracle_binary=${SYMVAULT_EXPORT_CLI_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/export-cli.XXXXXX")
    trap 'rm -rf "$run_root"' EXIT HUP INT TERM
    export TMPDIR="$run_root"
    export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"
    # Ordinary clones give Go reliable VCS metadata; nested worktrees do not.
    git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
    git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
    (cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$run_root/symvault-go" .)
    oracle_binary="$run_root/symvault-go"
fi
"${GO:-go}" run ./scripts/rust-port/cmd/exportcligen \
    --check --go-binary "$oracle_binary"
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test export_backup_restore_contract --locked
