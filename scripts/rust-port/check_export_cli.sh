#!/bin/sh
# IO-002 complete-CLI gate: `symvault export`, `symvault backup ARCHIVE` and
# `symvault restore ARCHIVE` (every flag, argv, confirmation, output-file
# handling, stdout/stderr/exit status and the resulting file tree).
#
# Verifies the frozen Go corpus (sha256 manifest, git-resolvable oracle pin,
# git-blob source digests -- no Go toolchain), then replays it against the
# native CLI. The generator is archived at tag legacy/go-oracle
# (docs/rust-port/go-oracle-archive.md).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
python3 -B scripts/rust-port/fixtures_verify.py testdata/port/cli/export-backup-restore.json
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test export_backup_restore_contract --locked
