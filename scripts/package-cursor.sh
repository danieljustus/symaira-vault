#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CURSOR_DIR="${PROJECT_ROOT}/editors/cursor"

echo "=== Packaging Cursor Extension ==="

cd "${CURSOR_DIR}"

if ! command -v vsce > /dev/null 2>&1; then
  echo "Installing vsce..."
  npm install -g @vscode/vsce
fi

npm run build
vsce package --out "symaira-cursor-${VERSION:-1.0.0}.vsix"

echo "✓ Created: ${CURSOR_DIR}/symaira-cursor-${VERSION:-1.0.0}.vsix"
