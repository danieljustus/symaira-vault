#!/usr/bin/env bash
#
# Development Environment Setup Script for Symaira Vault
#
# This script sets up the development environment for Symaira Vault contributors.
# It is idempotent and safe to run multiple times.
#
# Usage: ./scripts/setup-dev.sh [--check]
#   --check   Verify all tools are installed without installing

set -euo pipefail

# Configuration
GO_VERSION="1.26"
GOLANGCI_LINT_VERSION="v2.11.4"
MINIMUM_GO_VERSION="1.25"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS
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
    log_error "This script supports macOS and Linux only."
    exit 1
fi

log_info "Detected OS: $OS"

# Check mode
CHECK_MODE=false
if [[ "${1:-}" == "--check" ]]; then
    CHECK_MODE=true
    log_info "Running in check mode (verification only)"
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to compare versions (returns 0 if $1 >= $2)
version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Function to get installed Go version
get_go_version() {
    go version | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
}

# Check and install Go
check_go() {
    if command_exists go; then
        local installed_version
        installed_version=$(get_go_version)
        if version_ge "$installed_version" "$MINIMUM_GO_VERSION"; then
            log_success "Go $installed_version is installed (>= $MINIMUM_GO_VERSION required)"
            return 0
        else
            log_warn "Go $installed_version is installed, but >= $MINIMUM_GO_VERSION is required"
            return 1
        fi
    else
        log_warn "Go is not installed"
        return 1
    fi
}

install_go() {
    log_info "Installing Go $GO_VERSION..."
    
    case "$OS" in
        macos)
            if command_exists brew; then
                brew install go
            else
                log_error "Homebrew is required but not installed."
                log_info "Install Homebrew from: https://brew.sh"
                exit 1
            fi
            ;;
        linux)
            log_info "Installing Go via official tarball..."
            
            # Detect architecture
            local arch
            arch=$(uname -m)
            case "$arch" in
                x86_64)  arch="amd64" ;;
                aarch64) arch="arm64" ;;
                arm64)   arch="arm64" ;;
                *)       log_error "Unsupported architecture: $arch"; exit 1 ;;
            esac
            
            local go_tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
            local go_url="https://go.dev/dl/${go_tarball}"
            local temp_dir
            temp_dir=$(mktemp -d)
            
            log_info "Downloading Go from $go_url..."
            curl -fsSL "$go_url" -o "${temp_dir}/${go_tarball}"
            
            log_info "Extracting Go to /usr/local..."
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf "${temp_dir}/${go_tarball}"
            rm -rf "$temp_dir"
            
            # Add to PATH if not already there
            if ! grep -q "/usr/local/go/bin" "$HOME/.profile" 2>/dev/null && \
               ! grep -q "/usr/local/go/bin" "$HOME/.bashrc" 2>/dev/null && \
               ! grep -q "/usr/local/go/bin" "$HOME/.zshrc" 2>/dev/null; then
                log_info "Adding Go to PATH in ~/.profile"
                echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.profile"
                log_warn "Please run: source ~/.profile  (or restart your shell)"
            fi
            
            export PATH=$PATH:/usr/local/go/bin
            ;;
    esac
    
    # Verify installation
    if command_exists go; then
        log_success "Go $(get_go_version) installed successfully"
    else
        log_error "Go installation failed"
        exit 1
    fi
}

# Check and install git
check_git() {
    if command_exists git; then
        log_success "Git is installed ($(git --version))"
        return 0
    else
        log_warn "Git is not installed"
        return 1
    fi
}

install_git() {
    log_info "Installing git..."
    
    case "$OS" in
        macos)
            if command_exists brew; then
                brew install git
            else
                log_error "Homebrew is required but not installed."
                exit 1
            fi
            ;;
        linux)
            if command_exists apt-get; then
                sudo apt-get update
                sudo apt-get install -y git
            elif command_exists yum; then
                sudo yum install -y git
            elif command_exists dnf; then
                sudo dnf install -y git
            else
                log_error "Unable to install git. Please install manually."
                exit 1
            fi
            ;;
    esac
}

# Check and install make
check_make() {
    if command_exists make; then
        log_success "Make is installed ($(make --version | head -1))"
        return 0
    else
        log_warn "Make is not installed"
        return 1
    fi
}

install_make() {
    log_info "Installing make..."
    
    case "$OS" in
        macos)
            # Xcode Command Line Tools usually includes make
            if ! command_exists make; then
                log_info "Installing Xcode Command Line Tools..."
                xcode-select --install 2>/dev/null || true
                log_warn "Please complete the Xcode Command Line Tools installation and re-run this script"
                exit 1
            fi
            ;;
        linux)
            if command_exists apt-get; then
                sudo apt-get update
                sudo apt-get install -y build-essential
            elif command_exists yum; then
                sudo yum groupinstall -y "Development Tools"
            elif command_exists dnf; then
                sudo dnf groupinstall -y "Development Tools"
            else
                log_error "Unable to install make. Please install manually."
                exit 1
            fi
            ;;
    esac
}

# Check and install golangci-lint
check_golangci_lint() {
    if command_exists golangci-lint; then
        local installed_version
        installed_version=$(golangci-lint --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "golangci-lint $installed_version is installed"
        return 0
    else
        log_warn "golangci-lint is not installed"
        return 1
    fi
}

install_golangci_lint() {
    log_info "Installing golangci-lint $GOLANGCI_LINT_VERSION..."
    
    # Use the official install script
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
        sh -s -- -b "$(go env GOPATH)/bin" "$GOLANGCI_LINT_VERSION"
    
    # Verify installation
    if command_exists golangci-lint; then
        log_success "golangci-lint installed successfully"
    else
        # Try adding GOPATH/bin to PATH
        export PATH="$(go env GOPATH)/bin:$PATH"
        if command_exists golangci-lint; then
            log_success "golangci-lint installed successfully"
            log_warn "Added $(go env GOPATH)/bin to PATH for this session"
            log_info "Consider adding 'export PATH=\$(go env GOPATH)/bin:\$PATH' to your shell profile"
        else
            log_error "golangci-lint installation failed"
            exit 1
        fi
    fi
}

# Check and install pre-commit
check_precommit() {
    if command_exists pre-commit; then
        log_success "pre-commit is installed ($(pre-commit --version))"
        return 0
    else
        log_warn "pre-commit is not installed (optional but recommended)"
        return 1
    fi
}

install_precommit() {
    log_info "Installing pre-commit..."
    
    if command_exists pip3; then
        pip3 install --user pre-commit
    elif command_exists pip; then
        pip install --user pre-commit
    elif command_exists brew; then
        brew install pre-commit
    else
        log_warn "Could not install pre-commit automatically."
        log_info "Please install manually: https://pre-commit.com/#install"
        return 1
    fi
    
    if command_exists pre-commit; then
        log_success "pre-commit installed successfully"
    else
        log_warn "pre-commit may have been installed but is not in PATH"
        log_info "You may need to add Python user bin directory to your PATH"
    fi
}

# Install project dependencies
install_project_deps() {
    log_info "Installing project dependencies..."
    
    if [[ -f "go.mod" ]]; then
        go mod download
        go mod tidy
        log_success "Go dependencies installed"
    else
        log_warn "go.mod not found in current directory"
        log_info "Make sure you're running this script from the project root"
    fi
}

# Install pre-commit hooks
install_precommit_hooks() {
    if [[ -f ".pre-commit-config.yaml" ]] && command_exists pre-commit; then
        log_info "Installing pre-commit hooks..."
        pre-commit install
        log_success "Pre-commit hooks installed"
    fi
}

# Main execution
main() {
    log_info "Symaira Vault Development Environment Setup"
    log_info "======================================"
    echo
    
    # Check if we're in the right directory
    if [[ ! -f "go.mod" ]] || ! grep -q "github.com/danieljustus/symaira-vault" go.mod 2>/dev/null; then
        log_warn "This doesn't appear to be the Symaira Vault repository root"
        log_info "Please run this script from the Symaira Vault project root directory"
        exit 1
    fi
    
    local all_good=true
    
    # Check Go
    if ! check_go; then
        if [[ "$CHECK_MODE" == true ]]; then
            all_good=false
        else
            install_go
        fi
    fi
    
    # Check git
    if ! check_git; then
        if [[ "$CHECK_MODE" == true ]]; then
            all_good=false
        else
            install_git
        fi
    fi
    
    # Check make
    if ! check_make; then
        if [[ "$CHECK_MODE" == true ]]; then
            all_good=false
        else
            install_make
        fi
    fi
    
    # Check golangci-lint
    if ! check_golangci_lint; then
        if [[ "$CHECK_MODE" == true ]]; then
            all_good=false
        else
            install_golangci_lint
        fi
    fi
    
    # Check pre-commit (optional)
    if ! check_precommit; then
        if [[ "$CHECK_MODE" != true ]]; then
            install_precommit || true  # Don't fail if pre-commit install fails
        fi
    fi
    
    # Install project dependencies
    if [[ "$CHECK_MODE" != true ]]; then
        install_project_deps
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
        log_info "  1. Run 'make test' to verify everything works"
        log_info "  2. Run 'make build' to build the binary"
        log_info "  3. See CONTRIBUTING.md for development guidelines"
        
        # Warn about PATH if needed
        if ! command_exists golangci-lint 2>/dev/null; then
            echo
            log_warn "Note: golangci-lint was installed but may not be in your PATH"
            log_info "Add the following to your shell profile (.bashrc, .zshrc, etc.):"
            log_info "  export PATH=\$(go env GOPATH)/bin:\$PATH"
        fi
    fi
}

main "$@"
