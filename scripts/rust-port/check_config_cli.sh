#!/bin/sh
# config-cli differential.
#
#   check_config_cli.sh             replay the committed Go transcripts
#                                   (testdata/port/cli-transcripts/*.json) against
#                                   the Rust binary. No Go toolchain, no oracle
#                                   binary, no SYMVAULT_GO_BINARY: a recording that
#                                   is missing or no longer matched is a failure.
#   check_config_cli.sh --capture   rebuild the pinned Go oracles and re-record the
#                                   transcripts (needs Go; used by
#                                   `make config-cli-capture`). Existing entries
#                                   whose Go answer is unchanged are kept byte for
#                                   byte; delete a transcript to re-record it from
#                                   scratch.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
# macOS TMPDIR ends in '/'. Sandboxes created under it would keep a doubled
# separator that the CLI's cleaned paths never contain (#1474).
while case ${TMPDIR:-} in ?*/) true ;; *) false ;; esac; do TMPDIR=${TMPDIR%/}; done
[ -z "${TMPDIR:-}" ] || export TMPDIR

mode=replay
case ${1:-} in
    "") ;;
    --capture) mode=capture ;;
    *) echo "usage: $0 [--capture]" >&2; exit 2 ;;
esac

tests="--test config_inspect --test cli_differential --test profile_differential --test remote_differential --test sync_differential --test audit_export_commands --test run_differential --test share_differential --test agent_whoami_differential --test agent_list_differential --test agent_profile_differential --test agent_token_mutations_differential --test policy_differential --test path_migration_differential --test auth_differential --test audit_rotate_differential --test config_validate_differential --test doctor_differential --test migrate_kdf_differential"

if [ "$mode" = replay ]; then
    # Replay must not be able to reach a Go oracle.
    unset SYMVAULT_GO_BINARY SYMVAULT_ORACLE
    # shellcheck disable=SC2086 # $tests is a word list of cargo flags
    "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" -p symvault-cli $tests --locked
    exit 0
fi

# ----------------------------------------------------------------- capture ---
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
run_root=$(mktemp -d "${TMPDIR:-/tmp}/config-cli.XXXXXX")
trap 'rm -rf "$run_root"' EXIT HUP INT TERM
export TMPDIR="$run_root"
export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"

# build_oracle COMMIT NAME TOOLCHAIN: an ordinary clone gives Go reliable VCS
# metadata (nested worktrees do not).
build_oracle() {
    git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/$2-src"
    git -C "$run_root/$2-src" checkout --quiet --detach "$1"
    (cd "$run_root/$2-src" && GOTOOLCHAIN=$3 "${GO:-go}" build -buildvcs=true -o "$run_root/$2" .)
}

# The config-cli oracle (every test of the list above unless noted below).
config_commit=fca3f89401833b5e14ec4ec74ef736b0f63bca74
# The last commit that still carried the Go sources: migrate_kdf's resource
# policy test and the startup-profile differential are recorded against it.
policy_commit=c069d3f2b17d704525cedc1bd42840cc6a3e9896
build_oracle "$config_commit" oracle-config "${GO_TOOLCHAIN:-go1.26.6}"
build_oracle "$policy_commit" oracle-policy "${BUILD_GO_TOOLCHAIN:-go1.26.10}"

# configclicasesgen re-derives the config_inspect fixture from the live Go
# oracle (revision, clean VCS metadata, toolchain).
"${GO:-go}" run ./scripts/rust-port/cmd/configclicasesgen \
    --check --go-binary "$run_root/oracle-config"

export SYMVAULT_ORACLE=capture
export SYMVAULT_GO_BINARY="$run_root/oracle-config"
export SYMVAULT_GO_BINARY_c069d3f2="$run_root/oracle-policy"
# shellcheck disable=SC2086
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" -p symvault-cli $tests \
    --test startup_profile_differential --locked
