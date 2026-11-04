#!/bin/sh
# CLI-005/CLI-006 error taxonomy and output-format gate: verify the frozen Go
# corpus (sha256 manifest, git-resolvable oracle pin, git-blob source digests --
# no Go toolchain), then replay it against the native CLI. The generator is
# archived at tag legacy/go-oracle (docs/rust-port/go-oracle-archive.md).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
python3 -B scripts/rust-port/fixtures_verify.py testdata/port/cli/error-taxonomy.json
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --bin symvault --locked cobra_usage
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test error_taxonomy --locked
