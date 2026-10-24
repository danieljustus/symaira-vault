#!/bin/sh
# CLI-005/CLI-006 error taxonomy and output-format gate: re-verify the frozen Go
# corpus against the pinned oracle, then replay it against the native CLI.
#
# A supplied oracle (SYMVAULT_ERROR_TAXONOMY_GO_BINARY) is still verified by
# errtaxgen (revision, clean VCS metadata and toolchain). Without one, the
# pinned commit is cloned and built here, like check_yaml_syntax_cli.sh does.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
export GOWORK=off
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
oracle_binary=${SYMVAULT_ERROR_TAXONOMY_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/error-taxonomy-cli.XXXXXX")
    trap 'rm -rf "$run_root"' EXIT HUP INT TERM
    oracle_commit=0cc780626d3275afad14eb64c44abf8adb23d2ce
    export TMPDIR="$run_root"
    export TMP="$run_root" TEMP="$run_root" GOTMPDIR="$run_root"
    # Ordinary clones give Go reliable VCS metadata; nested worktrees do not.
    git clone --quiet --no-hardlinks --no-checkout --local "$repo_root" "$run_root/oracle"
    git -C "$run_root/oracle" checkout --quiet --detach "$oracle_commit"
    (cd "$run_root/oracle" && "${GO:-go}" build -buildvcs=true -o "$run_root/symvault-go" .)
    oracle_binary="$run_root/symvault-go"
fi
"${GO:-go}" run ./scripts/rust-port/cmd/errtaxgen \
    --check --go-binary "$oracle_binary"
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --bin symvault --locked cobra_usage
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test error_taxonomy --locked
