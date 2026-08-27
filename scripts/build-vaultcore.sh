#!/usr/bin/env bash
# Generate the Vaultcore.xcframework consumed by the iOS client.
#
# gomobile bind requires golang.org/x/mobile in the module graph (recorded as a
# `tool` directive in go.mod) and a full Xcode with the iOS SDK. The resulting
# framework is written under client/.build/mobilecore and is git-ignored.
#
# We invoke gomobile via `go run` (not the installed binary) so it resolves the
# module version pinned in go.mod rather than performing a stricter standalone
# dependency check.
#
# Usage: scripts/build-vaultcore.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode-beta.app ]]; then
  export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
fi

OUT_DIR="client/.build/mobilecore"
FRAMEWORK="$OUT_DIR/Vaultcore.xcframework"

if [[ -d "$FRAMEWORK" ]]; then
  echo "Vaultcore.xcframework already present at $FRAMEWORK"
  exit 0
fi

mkdir -p "$OUT_DIR"
GOFLAGS=-mod=mod go run golang.org/x/mobile/cmd/gomobile bind -target=ios -o "$FRAMEWORK" ./pkg/mobilebind
echo "Built $FRAMEWORK"
