#!/bin/sh
# IO-001 complete `symvault import <source>` command gate: verify the frozen Go
# corpus (sha256 manifest, git-resolvable oracle pin, git-blob source digests --
# no Go toolchain), then replay it against the native CLI.
#
# Regeneration needs the archived Go generator (tag legacy/go-oracle, see
# docs/rust-port/go-oracle-archive.md); it is not available on this branch.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
python3 -B scripts/rust-port/fixtures_verify.py crates/symvault-cli/tests/fixtures/import-command
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test import_command_contract --locked
