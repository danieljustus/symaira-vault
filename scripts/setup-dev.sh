#!/usr/bin/env bash
#
# Development Environment Setup Script for Symaira Vault
#
# Sets up the Rust development environment for contributors (macOS arm64 and
# Linux). It is idempotent and safe to run multiple times. No Go toolchain is
# needed: the shipped CLI is the Rust workspace, and the historical
# observations the differential tests replay are committed fixtures.
#
# Usage: ./scripts/setup-dev.sh [--check]
#   --check   Verify all tools are installed without installing

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# The pinned toolchain lives in rust-toolchain.toml; read it instead of
# duplicating the version here.
RUST_VERSION="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml | head -1)"
RUST_COMPONENTS="clippy,rustfmt,llvm-tools-preview"
# Cargo helper binaries used by `make rust-test` and `make rust-security`
# (versions match .github/workflows/ci.yml).
CARGO_TOOLS=(
    "cargo-nextest@0.9.143"
    "cargo-deny@0.20.2"
    "cargo-audit@0.22.2"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "macos" ;;
        Linux*)  echo "linux" ;;
        *)       echo "unknown" ;;
    esac
}

OS=$(detect_os)

if [[ "$OS" == "unknown" ]]; then
    log_error "Unsupported operating system: $(uname -s)"
    log_error "This script supports macOS (arm64) and Linux only."
    exit 1
fi

log_info "Detected OS: $OS"

CHECK_MODE=false
if [[ "${1:-}" == "--check" ]]; then
    CHECK_MODE=true
    log_info "Running in check mode (verification only)"
fi

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ── rustup / Rust toolchain ─────────────────────────────────────────────────

check_rustup() {
    if command_exists rustup; then
        log_success "rustup is installed ($(rustup --version 2>/dev/null | head -1))"
        return 0
    fi
    log_warn "rustup is not installed"
    return 1
}

install_rustup() {
    log_info "Installing rustup (minimal profile, no default toolchain)..."
    if ! command_exists curl; then
        log_error "curl is required to install rustup. Install it and re-run."
        exit 1
    fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
        sh -s -- -y --profile minimal --default-toolchain none
    # shellcheck disable=SC1091
    [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
    log_warn "Add \$HOME/.cargo/bin to your PATH (rustup normally edits your shell profile)."
}

check_rust_toolchain() {
    if ! command_exists rustup; then
        return 1
    fi
    if rustup toolchain list | grep -q "^${RUST_VERSION}"; then
        log_success "Rust ${RUST_VERSION} toolchain is installed"
        return 0
    fi
    log_warn "Rust ${RUST_VERSION} toolchain is not installed"
    return 1
}

install_rust_toolchain() {
    log_info "Installing Rust ${RUST_VERSION} (${RUST_COMPONENTS})..."
    rustup toolchain install "$RUST_VERSION" --profile minimal --component "$RUST_COMPONENTS"
    log_success "Rust ${RUST_VERSION} installed"
}

# ── cargo helper tools ──────────────────────────────────────────────────────

cargo_tool_installed() {
    local bin="${1%@*}"
    # cargo-nextest -> `cargo nextest`, cargo-deny -> `cargo deny`, ...
    cargo "${bin#cargo-}" --version >/dev/null 2>&1
}

check_cargo_tools() {
    local missing=()
    local tool
    for tool in "${CARGO_TOOLS[@]}"; do
        if cargo_tool_installed "$tool"; then
            log_success "${tool%@*} is installed"
        else
            log_warn "${tool%@*} is not installed"
            missing+=("$tool")
        fi
    done
    [[ ${#missing[@]} -eq 0 ]]
}

install_cargo_tools() {
    local tool
    for tool in "${CARGO_TOOLS[@]}"; do
        if ! cargo_tool_installed "$tool"; then
            log_info "Installing $tool..."
            cargo install --locked "${tool%@*}" --version "${tool#*@}"
        fi
    done
}

# ── make / python3 / git ────────────────────────────────────────────────────

check_make() {
    if command_exists make; then
        log_success "make is installed"
        return 0
    fi
    log_warn "make is not installed"
    return 1
}

install_make() {
    log_info "Installing make..."
    case "$OS" in
        macos) xcode-select --install 2>/dev/null || log_info "Command Line Tools may already be installed" ;;
        linux)
            if command_exists apt-get; then
                sudo apt-get update && sudo apt-get install -y build-essential
            elif command_exists dnf; then
                sudo dnf install -y make gcc
            else
                log_error "Please install make and a C toolchain manually"
                exit 1
            fi
            ;;
    esac
}

check_python3() {
    if command_exists python3; then
        log_success "python3 is installed ($(python3 --version 2>&1))"
        return 0
    fi
    log_warn "python3 is not installed (needed by the contract scripts under scripts/)"
    return 1
}

check_git() {
    if command_exists git; then
        log_success "git is installed ($(git --version))"
        return 0
    fi
    log_warn "git is not installed (the CLI shells out to git at runtime)"
    return 1
}

# ── pre-commit (optional) ───────────────────────────────────────────────────

check_precommit() {
    if command_exists pre-commit; then
        log_success "pre-commit is installed ($(pre-commit --version))"
        return 0
    fi
    log_warn "pre-commit is not installed (optional but recommended)"
    return 1
}

install_precommit() {
    log_info "Installing pre-commit..."
    if command_exists pip3; then
        pip3 install --user pre-commit
    elif command_exists brew; then
        brew install pre-commit
    else
        log_warn "Could not install pre-commit automatically."
        log_info "Please install manually: https://pre-commit.com/#install"
        return 1
    fi
}

install_precommit_hooks() {
    if [[ -f ".pre-commit-config.yaml" ]] && command_exists pre-commit; then
        log_info "Installing pre-commit hooks..."
        pre-commit install
        log_success "Pre-commit hooks installed"
    fi
}

# ── main ────────────────────────────────────────────────────────────────────

main() {
    echo
    log_info "======================================"
    log_info "Symaira Vault Development Setup"
    log_info "======================================"
    echo

    local all_good=true

    if ! check_rustup; then
        if [[ "$CHECK_MODE" == true ]]; then
            all_good=false
        else
            install_rustup
        fi
    fi

    if command_exists rustup; then
        if ! check_rust_toolchain; then
            if [[ "$CHECK_MODE" == true ]]; then
                all_good=false
            else
                install_rust_toolchain
            fi
        fi
        if ! check_cargo_tools; then
            if [[ "$CHECK_MODE" == true ]]; then
                all_good=false
            else
                install_cargo_tools
            fi
        fi
    fi

    if ! check_make; then
        if [[ "$CHECK_MODE" == true ]]; then
            all_good=false
        else
            install_make
        fi
    fi

    check_python3 || all_good=false
    check_git || all_good=false

    if ! check_precommit; then
        if [[ "$CHECK_MODE" != true ]]; then
            install_precommit || true  # optional; never fail the setup on it
        fi
    fi

    if [[ "$CHECK_MODE" != true ]]; then
        install_precommit_hooks
    fi

    echo
    log_info "======================================"

    if [[ "$CHECK_MODE" == true ]]; then
        if [[ "$all_good" == true ]]; then
            log_success "All required tools are installed!"
            exit 0
        else
            log_error "Some required tools are missing. Run without --check to install."
            exit 1
        fi
    else
        log_success "Development environment setup complete!"
        echo
        log_info "Next steps:"
        log_info "  1. Run 'make rust-test' to verify everything works"
        log_info "  2. Run 'make rust-cli' to build the symvault binary (target/release/symvault)"
        log_info "  3. See CONTRIBUTING.md for development guidelines"
    fi
}

main "$@"
