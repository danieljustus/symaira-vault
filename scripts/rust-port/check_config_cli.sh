#!/bin/sh
# config-cli differential: replays the committed Go transcripts
# (testdata/port/cli-transcripts/*.json) against the Rust binary. No Go
# toolchain and no oracle binary: a recording that is missing or no longer
# matched is a failure. Re-recording needs the archived oracle (tag
# legacy/go-oracle, docs/rust-port/go-oracle-archive.md).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
# macOS TMPDIR ends in '/'. Sandboxes created under it would keep a doubled
# separator that the CLI's cleaned paths never contain (#1474).
while case ${TMPDIR:-} in ?*/) true ;; *) false ;; esac; do TMPDIR=${TMPDIR%/}; done
[ -z "${TMPDIR:-}" ] || export TMPDIR

case ${1:-} in
    "") ;;
    *) echo "usage: $0" >&2; exit 2 ;;
esac

tests="--test config_inspect --test cli_differential --test profile_differential --test remote_differential --test sync_differential --test audit_export_commands --test run_differential --test share_differential --test agent_whoami_differential --test agent_list_differential --test agent_profile_differential --test agent_token_mutations_differential --test policy_differential --test path_migration_differential --test auth_differential --test audit_rotate_differential --test config_validate_differential --test doctor_differential --test migrate_kdf_differential"

# shellcheck disable=SC2086 # $tests is a word list of cargo flags
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" -p symvault-cli $tests --locked
