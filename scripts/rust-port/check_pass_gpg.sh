#!/bin/sh
# IO-001 pass importer against REAL gpg: verify the frozen Go corpus, then
# replay it against the production Rust importer.
#
#  1. `fixtures_verify.py` checks the corpus bytes (sha256 manifest), the pinned
#     oracle commit and the source digests from git blobs -- no Go toolchain.
#     The Go importer re-run that used to follow (passgpggen -check) is archived
#     at tag legacy/go-oracle (docs/rust-port/go-oracle-archive.md).
#  2. The Rust replay imports the recorded test key into a disposable GNUPGHOME
#     and runs import_pass over the same ciphertext bytes with the system gpg.
#
# gpg is required: a missing gpg fails this gate, it never skips it. Every gpg
# call runs in a disposable GNUPGHOME and its agent is killed afterwards.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
if ! command -v gpg >/dev/null 2>&1; then
    echo "check_pass_gpg: gpg is required (fail closed, not skipped)" >&2
    exit 1
fi
python3 -B scripts/rust-port/fixtures_verify.py testdata/port/sync/pass-gpg.json testdata/importer/pass
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-sync --test pass_gpg_contract --locked
