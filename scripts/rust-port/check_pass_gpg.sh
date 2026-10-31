#!/bin/sh
# IO-001 pass importer against REAL gpg: re-verify the frozen Go corpus, then
# replay it against the production Rust importer.
#
#  1. `passgpggen -check` verifies oracle provenance (pinned commit and source
#     digests), imports the recorded test key into a disposable GNUPGHOME,
#     decrypts every stored ciphertext with the system gpg and re-runs the REAL
#     Go importer. It never re-encrypts, so it does not depend on gpg's random
#     ciphertext, and it is platform independent: the fixture records the gpg
#     version and goos it was generated with, and a different gpg version is
#     compared under the documented N2 rule only for version_variant cases.
#  2. The Rust replay imports the same key and runs import_pass over the same
#     ciphertext bytes.
#
# gpg is required: a missing gpg fails this gate, it never skips it. Every gpg
# call runs in a disposable GNUPGHOME and its agent is killed afterwards.
#
# Deliberate regeneration (never automatic, never part of the gate):
#   go run ./scripts/rust-port/cmd/passgpggen
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
if ! command -v gpg >/dev/null 2>&1; then
    echo "check_pass_gpg: gpg is required (fail closed, not skipped)" >&2
    exit 1
fi
"${GO:-go}" run ./scripts/rust-port/cmd/passgpggen -check
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-sync --test pass_gpg_contract --locked
