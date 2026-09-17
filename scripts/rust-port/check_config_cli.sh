#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
# Inherit the caller's storage policy; locally TMPDIR and caches are on NVMe.
run_root=$(mktemp -d "${TMPDIR:-/tmp}/config-cli.XXXXXX")
trap 'rm -rf "$run_root"' EXIT HUP INT TERM
oracle_commit=fca3f89401833b5e14ec4ec74ef736b0f63bca74
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
export TMPDIR="$run_root"
export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"

# Ordinary clones give Go reliable VCS metadata; nested worktrees do not.
git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
(cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$run_root/symvault-go" .)
"${GO:-go}" run ./scripts/rust-port/cmd/configclicasesgen \
    --check --go-binary "$run_root/symvault-go"
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_inspect --locked
