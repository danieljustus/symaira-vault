#!/bin/sh
# CLI-006 positive output matrix gate: for every command path whose output-format
# gate accepts --json and/or --output, verify the frozen Go corpus (text,
# --json, --output yaml, --output json, --quiet) -- sha256 manifest,
# git-resolvable oracle pin, git-blob source digests, no Go toolchain -- then
# replay it against the native CLI.
#
# Platform: the corpus is recorded on one OS (oracle.goos in the fixture; doctor,
# auth status and several path spellings are host probes). The byte/pin
# verification below is host independent; the Rust replay prints its own visible
# SKIP on any other OS and never passes silently. The live Touch ID comparison
# against a Go binary is not part of this gate any more (plan risk R6).
#
# Regeneration needs the archived Go generator (tag legacy/go-oracle, see
# docs/rust-port/go-oracle-archive.md).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
python3 -B scripts/rust-port/fixtures_verify.py testdata/port/cli/output-modes.json
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test output_modes --locked -- --nocapture
