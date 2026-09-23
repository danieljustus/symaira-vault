#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
# A supplied oracle is still verified by configclicasesgen (revision,
# clean VCS metadata and toolchain). CI builds one when none is provided.
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
# The pinned Go oracle logs an unrelated, timestamped package-init warning on
# FreeBSD before every command; keep command stderr comparisons deterministic.
if [ "$(uname -s)" = FreeBSD ]; then
    export SYMVAULT_LOG_LEVEL=error
fi
oracle_commit=fca3f89401833b5e14ec4ec74ef736b0f63bca74
oracle_binary=${SYMVAULT_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/config-cli.XXXXXX")
    trap 'rm -rf "$run_root"' EXIT HUP INT TERM
    export TMPDIR="$run_root"
    export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"
    # Ordinary clones give Go reliable VCS metadata; nested worktrees do not.
    git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
    git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
    oracle_suffix=
    if [ "$("${GO:-go}" env GOOS)" = windows ]; then
        oracle_suffix=.exe
    fi
    oracle_binary="$run_root/symvault-go$oracle_suffix"
    (cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$oracle_binary" .)
fi
if ! "${GO:-go}" run ./scripts/rust-port/cmd/configclicasesgen \
    --check --go-binary "$oracle_binary"; then
    diagnostic_output=$(mktemp "${TMPDIR:-/tmp}/config-cli-actual.XXXXXX")
    "${GO:-go}" run ./scripts/rust-port/cmd/configclicasesgen \
        --go-binary "$oracle_binary" --oracle-commit "$oracle_commit" \
        --oracle-release unreleased --output "$diagnostic_output"
    diff -u testdata/port/cli/config-inspect.json "$diagnostic_output" || true
    exit 1
fi
SYMVAULT_GO_BINARY="$oracle_binary" "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_inspect --test cli_differential --test cli_error_taxonomy_differential --test list_output_differential --test get_output_differential --test get_entry_output_differential --test get_empty_fields_differential --test rollback_go --test profile_differential --test remote_differential --test sync_differential --test audit_export_commands --test run_differential --test share_differential --test agent_whoami_differential --test agent_list_differential --test agent_profile_differential --test agent_token_mutations_differential --test policy_differential --test path_migration_differential --test auth_differential --test audit_rotate_differential --test config_validate_differential --test doctor_differential --test cli_intake_watch_disable --test cli_intake_watch_once --test daemon_status_differential --locked
SYMVAULT_GO_BINARY="$oracle_binary" "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test migrate_kdf_differential --locked -- --ignored
