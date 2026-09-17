#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
# A supplied oracle is still verified by configclicasesgen (revision,
# clean VCS metadata and toolchain). CI builds one when none is provided.
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
oracle_binary=${SYMVAULT_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/config-cli.XXXXXX")
    trap 'rm -rf "$run_root"' EXIT HUP INT TERM
    oracle_commit=fca3f89401833b5e14ec4ec74ef736b0f63bca74
    export TMPDIR="$run_root"
    export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"
    # Ordinary clones give Go reliable VCS metadata; nested worktrees do not.
    git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
    git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
    (cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$run_root/symvault-go" .)
    oracle_binary="$run_root/symvault-go"
fi
"${GO:-go}" run ./scripts/rust-port/cmd/configclicasesgen \
    --check --go-binary "$oracle_binary"
SYMVAULT_GO_BINARY="$oracle_binary" "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_inspect --test cli_differential --test profile_differential --test remote_differential --test sync_differential --test audit_export_commands --test agent_profile_differential --test policy_differential --locked
SYMVAULT_GO_BINARY="$oracle_binary" "${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test migrate_kdf_differential --locked -- --ignored
