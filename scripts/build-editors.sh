#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
EDITORS_DIR="${PROJECT_ROOT}/editors"

echo "=== Building Symaira Vault Editor Plugins ==="

echo "Building shared MCP client..."
cd "${EDITORS_DIR}/mcp-client"
if [ ! -d "node_modules" ]; then
  npm install
fi
npm run build

echo "Building VS Code extension..."
cd "${EDITORS_DIR}/vscode"
if [ ! -d "node_modules" ]; then
  npm install
fi
npm run build

echo "Building Cursor extension..."
cd "${EDITORS_DIR}/cursor"
if [ ! -d "node_modules" ]; then
  npm install
fi
npm run build

echo "Verifying Neovim plugin..."
cd "${EDITORS_DIR}/nvim"
if command -v luac > /dev/null 2>&1; then
  for f in lua/symvault/*.lua; do
    luac -p "$f"
    echo "  ✓ $(basename "$f")"
  done
else
  echo "  ⚠ luac not found, skipping Lua syntax check"
fi

echo ""
echo "=== Build Complete ==="
