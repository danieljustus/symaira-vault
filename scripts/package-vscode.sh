#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VSCODE_DIR="${PROJECT_ROOT}/editors/vscode"

echo "=== Packaging VS Code Extension ==="

cd "${VSCODE_DIR}"

if ! command -v vsce > /dev/null 2>&1; then
  echo "Installing vsce..."
  npm install -g @vscode/vsce
fi

npm run build
vsce package --out "symaira-vscode-${VERSION:-1.0.0}.vsix"

echo "✓ Created: ${VSCODE_DIR}/symaira-vscode-${VERSION:-1.0.0}.vsix"
