#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NVIM_DIR="${PROJECT_ROOT}/editors/nvim"
VERSION="${VERSION:-1.0.0}"

echo "=== Packaging Neovim Plugin ==="

cd "${PROJECT_ROOT}"


TAR_NAME="openpass-nvim-${VERSION}.tar.gz"
tar -czf "${EDITORS_DIR}/${TAR_NAME}" -C "${EDITORS_DIR}" nvim/

echo "✓ Created: ${EDITORS_DIR}/${TAR_NAME}"
