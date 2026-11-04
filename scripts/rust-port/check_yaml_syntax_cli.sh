#!/bin/sh
# CLI-005 go-yaml syntax-error dialect: verify the frozen Go corpus (sha256
# manifest, git-resolvable oracle pin, git-blob source digests -- no Go
# toolchain), then replay it against the native CLI. The generator that
# recorded the corpus is archived at tag legacy/go-oracle
# (docs/rust-port/go-oracle-archive.md).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
python3 -B scripts/rust-port/fixtures_verify.py testdata/port/cli/config-yaml-syntax.json
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-core --lib --locked go_yaml
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_yaml_syntax --locked
