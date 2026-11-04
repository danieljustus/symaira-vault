#!/bin/sh
# CONFIG-WRITER: Go's Config.SaveTo bytes against the Rust writer (replay; no
# Go toolchain, no oracle binary):
#   1. replays the frozen Go-recorded SaveTo fixture against the Rust writer
#      (declared differences: Go drops paymentPolicies and security on
#      rewrite; Rust keeps them);
#   2. replays the recorded Go runs of the rewriting commands (agent
#      uninstall, doctor --fix, config validate) from
#      testdata/port/cli-transcripts/config_rewrite_differential.json
#      against the Rust CLI and compares the resulting config.yaml bytes.
# A missing or stale recording is a failure. Re-recording needs the archived
# oracle (tag legacy/go-oracle, docs/rust-port/go-oracle-archive.md).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
while case ${TMPDIR:-} in ?*/) true ;; *) false ;; esac; do TMPDIR=${TMPDIR%/}; done
[ -z "${TMPDIR:-}" ] || export TMPDIR

case ${1:-} in
    "") ;;
    *) echo "usage: $0" >&2; exit 2 ;;
esac

"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-core --test config_rewrite_contract --locked
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_rewrite_differential --locked
