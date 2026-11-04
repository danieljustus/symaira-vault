#!/usr/bin/env bash
# Run a Go-observation capture or attestation on Linux, inside the local-gate image.
#
#   scripts/rust-port/go-observations-capture-linux.sh NAME 'COMMAND...'
#
# NAME     container name suffix (the container is cap-obs-NAME and is removed afterwards)
# COMMAND  run with `bash -c` in the repository root, e.g.
#            'make go-observations-capture-other'     Go side of the process contracts (writes *.linux.json)
#            'make go-attest-other'                    Go reverse checks (writes the *.linux.json attestations)
#
# The image is the one scripts/rust-port/local-gate.sh builds on its first run (tag derived from the Dockerfile
# digest); run the local gate once if it is missing. The checkout and its git
# common directory are bind-mounted at their host paths so worktrees resolve; Cargo output goes to the
# container layer (no host target directory is used) and Go/registry caches to named docker volumes.
# The committed *.linux.json files record no host paths: captures normalize them.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  sed -n '2,15p' "$0" >&2
  exit 2
fi
name="cap-obs-$1"
shift
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
image="symvault-local-gate:1-$(shasum -a 256 scripts/rust-port/local-gate/Dockerfile | cut -c1-12)"
docker image inspect "$image" >/dev/null
common="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
exec docker run --rm --init --name "$name" -v "$root:$root" -v "$common:$common" -w "$root" \
  -v symvault-gate-registry:/home/dev/.cargo/registry \
  -v symvault-gate-go:/home/dev/go \
  -e CARGO_TARGET_DIR=/home/dev/ctarget -e CARGO_INCREMENTAL=0 -e GOCACHE=/home/dev/go/cache \
  -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_TEST_DEBUG=0 -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
  -e GIT_CONFIG_COUNT=3 -e GIT_CONFIG_KEY_0=gc.auto -e GIT_CONFIG_VALUE_0=0 \
  -e GIT_CONFIG_KEY_1=gc.worktreePruneExpire -e GIT_CONFIG_VALUE_1=never \
  -e GIT_CONFIG_KEY_2=maintenance.auto -e GIT_CONFIG_VALUE_2=false \
  "$image" bash -c "$*"
