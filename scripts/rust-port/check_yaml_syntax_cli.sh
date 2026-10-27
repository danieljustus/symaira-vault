#!/bin/sh
# CLI-005 go-yaml syntax-error dialect: re-verify the frozen Go corpus against
# the pinned oracle, then replay it against the native CLI.
#
# A supplied oracle (SYMVAULT_YAML_SYNTAX_GO_BINARY) is still verified by
# yamlsyntaxgen (revision, clean VCS metadata and toolchain). Without one, the
# pinned commit is cloned and built here, like check_config_cli.sh does.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$repo_root"
export GOWORK=off
# macOS TMPDIR ends in '/'. Sandboxes created under it would keep a doubled
# separator that the CLI's cleaned paths never contain (#1474).
while case ${TMPDIR:-} in ?*/) true ;; *) false ;; esac; do TMPDIR=${TMPDIR%/}; done
[ -z "${TMPDIR:-}" ] || export TMPDIR
export GOTOOLCHAIN=${GO_TOOLCHAIN:-go1.26.6}
oracle_binary=${SYMVAULT_YAML_SYNTAX_GO_BINARY:-}
if [ -z "$oracle_binary" ]; then
    run_root=$(mktemp -d "${TMPDIR:-/tmp}/yaml-syntax-cli.XXXXXX")
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
"${GO:-go}" run ./scripts/rust-port/cmd/yamlsyntaxgen \
    --check --go-binary "$oracle_binary"
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-core --lib --locked go_yaml
"${CARGO:-cargo}" test --manifest-path "$repo_root/Cargo.toml" \
    -p symvault-cli --test config_yaml_syntax --locked
