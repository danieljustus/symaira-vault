#!/bin/bash
#
# build-mcpb.sh — Package a symvault binary into a .mcpb MCP Bundle
#
# Usage:
#   scripts/build-mcpb.sh --version <version> --os <goos> --arch <goarch> [--binary <path>]
#
# Without --binary the script searches dist/ for the matching goreleaser output.
#
# Output: dist/symvault_<version>_<os>_<arch>.mcpb
#
# .mcpb is a ZIP archive containing:
#   manifest.json  — MCP Bundle manifest (v0.3)
#   server/
#     symvault     — Binary (or symvault.exe on Windows)

set -euo pipefail

NAME="${NAME:-symvault}"
VERSION="${VERSION:-dev}"
GOOS="${GOOS:-}"
GOARCH="${GOARCH:-}"
BINARY_PATH=""

while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --os) GOOS="$2"; shift 2 ;;
    --arch) GOARCH="$2"; shift 2 ;;
    --binary) BINARY_PATH="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [ -z "$GOOS" ] || [ -z "$GOARCH" ]; then
  echo "Usage: $0 --version <ver> --os <goos> --arch <goarch> [--binary <path>]"
  exit 1
fi

DIST_DIR="${DIST_DIR:-dist}"

BINARY_NAME="$NAME"
[ "$GOOS" = "windows" ] && BINARY_NAME="${NAME}.exe"

if [ -z "$BINARY_PATH" ]; then
  BINARY_PATH=$(find "$DIST_DIR" -maxdepth 2 -type f -name "$BINARY_NAME" -path "*/${GOOS}_${GOARCH}*" | head -1 || true)
  if [ -z "$BINARY_PATH" ]; then
    echo "ERROR: Binary not found for ${GOOS}/${GOARCH} in ${DIST_DIR}" >&2
    exit 1
  fi
elif [ ! -f "$BINARY_PATH" ]; then
  echo "ERROR: Binary not found at $BINARY_PATH" >&2
  exit 1
fi

VERSION_CLEAN="${VERSION#v}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/manifest.json" <<ENDMARKER
{
  "manifest_version": "0.3",
  "name": "symvault",
  "version": "${VERSION_CLEAN}",
  "description": "Secure password manager MCP server",
  "author": {"name": "danieljustus"},
  "server": {
    "type": "binary",
    "entry_point": "server/${BINARY_NAME}",
    "mcp_config": {
      "command": "\${__dirname}/server/${BINARY_NAME}",
      "args": ["serve", "--stdio"]
    }
  }
}
ENDMARKER

mkdir -p "$TMPDIR/server"
cp "$BINARY_PATH" "$TMPDIR/server/$BINARY_NAME"
chmod +x "$TMPDIR/server/$BINARY_NAME"

if [[ "${DIST_DIR}" = /* ]]; then
  MCPB_FILE="${DIST_DIR}/${NAME}_${VERSION_CLEAN}_${GOOS}_${GOARCH}.mcpb"
else
  MCPB_FILE="$(pwd)/${DIST_DIR}/${NAME}_${VERSION_CLEAN}_${GOOS}_${GOARCH}.mcpb"
fi
mkdir -p "$(dirname "$MCPB_FILE")"
(cd "$TMPDIR" && zip -q -r "$MCPB_FILE" .)

echo "Created: $MCPB_FILE"
