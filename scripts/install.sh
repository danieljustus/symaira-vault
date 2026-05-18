#!/bin/sh
# OpenPass installer script for macOS and Linux.
# Downloads the latest (or specified) release from GitHub, verifies the
# SHA-256 checksum, and installs the binary.
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/danieljustus/OpenPass/main/scripts/install.sh | sh
#
# Flags:
#   --version X.Y.Z     Install a specific version (default: latest)
#   --install-dir DIR    Installation directory (default: /usr/local/bin)
#   --dry-run            Download and verify but do not install
#
# Environment variables:
#   VERSION              Same as --version
#   INSTALL_DIR          Same as --install-dir
#   DRY_RUN              Set to "true" for dry-run mode
#
# The script never modifies shell profiles.  After installation it prints
# the PATH adjustments you may need.

set -eu

# ── Constants ────────────────────────────────────────────────────────────────
REPO="danieljustus/OpenPass"
BINARY="openpass"
PROJECT="OpenPass"
GITHUB_API="https://api.github.com"
GITHUB_DOWNLOAD="https://github.com/${REPO}/releases/download"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Print to stderr so piped usage doesn't break.
info()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$*" >&2; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*" >&2; }
error() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; }
fatal() { error "$*"; exit 1; }

# Detect whether a command exists.
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Require cosign to be installed for signature verification.
require_cosign() {
    if ! has_cmd cosign; then
        fatal "cosign not found — required for checksums.txt signature verification.
  Install cosign from https://docs.sigstore.dev/cosign/installation/
  or use: brew install cosign (macOS) / apt install cosign (Linux)."
    fi
}

# Download a URL to stdout.  Prefers curl, falls back to wget.
download() {
    if has_cmd curl; then
        curl -fsSL "$1"
    elif has_cmd wget; then
        wget -qO- "$1"
    else
        fatal "Neither curl nor wget found.  Install one of them and retry."
    fi
}

# Download a URL to a file.  Prefers curl, falls back to wget.
download_to() {
    if has_cmd curl; then
        curl -fsSL -o "$1" "$2"
    elif has_cmd wget; then
        wget -qO "$1" "$2"
    else
        fatal "Neither curl nor wget found.  Install one of them and retry."
    fi
}

# ── Platform detection ───────────────────────────────────────────────────────

detect_os() {
    os="$(uname -s)"
    case "$os" in
        Linux*)  echo "linux"  ;;
        Darwin*) echo "darwin" ;;
        *)       fatal "Unsupported operating system: $os" ;;
    esac
}

detect_arch() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "amd64" ;;
        arm64|aarch64)  echo "arm64" ;;
        *)              fatal "Unsupported architecture: $arch" ;;
    esac
}

# ── Version resolution ───────────────────────────────────────────────────────

resolve_latest_version() {
    info "Fetching latest release version..."
    api_url="${GITHUB_API}/repos/${REPO}/releases/latest"
    # GitHub API requires User-Agent header.
    if has_cmd curl; then
        response=$(curl -fsSL -H "Accept: application/json" \
                        -H "User-Agent: openpass-installer" \
                        "$api_url")
    elif has_cmd wget; then
        response=$(wget -qO- --header="Accept: application/json" \
                           --header="User-Agent: openpass-installer" \
                           "$api_url")
    fi

    # Extract tag_name.  Works with both busybox and GNU sed/awk.
    tag=$(printf '%s' "$response" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//;s/".*//')
    if [ -z "$tag" ]; then
        fatal "Could not determine latest release version."
    fi
    echo "$tag"
}

# ── SHA-256 verification ─────────────────────────────────────────────────────

# Portable sha256sum check: tries sha256sum (Linux), then shasum (macOS).
sha256() {
    if has_cmd sha256sum; then
        sha256sum "$@"
    elif has_cmd shasum; then
        shasum -a 256 "$@"
    else
        fatal "Neither sha256sum nor shasum found.  Cannot verify checksums."
    fi
}

verify_checksum() {
    archive="$1"
    checksums="$2"
    archive_basename="$(basename "$archive")"

    # Look for the archive in the checksum file.
    expected=$(grep "$archive_basename" "$checksums" | awk '{print $1}')
    if [ -z "$expected" ]; then
        fatal "Checksum for $archive_basename not found in checksums file."
    fi

    actual=$(sha256 "$archive" | awk '{print $1}')
    if [ "$expected" != "$actual" ]; then
        fatal "Checksum verification failed for $archive_basename.
  Expected: $expected
  Got:      $actual"
    fi
    info "Checksum verified for $archive_basename."
}

# ── Cosign signature verification ────────────────────────────────────────────

# Cosign-verify the checksums file before trusting its SHA-256 hashes.
# Downloads .sig and .pem sidecar files from the same release URL.
verify_checksums_signature() {
    checksums_path="$1"
    sig_url="$2"
    pem_url="$3"

    require_cosign

    sig_path="${checksums_path}.sig"
    pem_path="${checksums_path}.pem"

    info "Downloading checksums signature..."
    download_to "$sig_path" "$sig_url"

    info "Downloading checksums certificate..."
    download_to "$pem_path" "$pem_url"

    info "Verifying cosign signature on checksums.txt..."
    cosign verify-blob \
        --certificate "$pem_path" \
        --signature "$sig_path" \
        --certificate-identity-regexp 'https://github.com/danieljustus/OpenPass/.github/workflows/release.yml@refs/tags/v.*' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$checksums_path" >/dev/null 2>&1 || fatal "Cosign signature verification failed for checksums.txt.
  The checksums file may have been tampered with.
  See: https://docs.sigstore.dev/cosign/overview/"

    info "Cosign signature verified on checksums.txt."
}

# ── Archive extraction ───────────────────────────────────────────────────────

extract_archive() {
    archive="$1"
    dest="$2"
    case "$archive" in
        *.tar.gz)
            tar -xzf "$archive" -C "$dest"
            ;;
        *.zip)
            if has_cmd unzip; then
                unzip -qo "$archive" -d "$dest"
            else
                fatal "unzip not found.  Install unzip and retry."
            fi
            ;;
        *)
            fatal "Unknown archive format: $archive"
            ;;
    esac
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    # Defaults (overridable via env or flags).
    version="${VERSION:-}"
    install_dir="${INSTALL_DIR:-/usr/local/bin}"
    dry_run="${DRY_RUN:-false}"

    # Parse flags.
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                version="$2"; shift 2 ;;
            --version=*)
                version="${1#*=}"; shift ;;
            --install-dir)
                install_dir="$2"; shift 2 ;;
            --install-dir=*)
                install_dir="${1#*=}"; shift ;;
            --dry-run)
                dry_run="true"; shift ;;
            --help|-h)
                cat <<'USAGE'
OpenPass installer

Usage:
  install.sh [OPTIONS]

Options:
  --version X.Y.Z      Install a specific version (default: latest)
  --install-dir DIR     Installation directory (default: /usr/local/bin)
  --dry-run             Download and verify but do not install
  -h, --help            Show this help message

Environment variables:
  VERSION               Same as --version
  INSTALL_DIR           Same as --install-dir
  DRY_RUN               Set to "true" for dry-run mode
USAGE
                exit 0
                ;;
            *)
                fatal "Unknown option: $1 (try --help)"
                ;;
        esac
    done

    # Resolve version.
    if [ -z "$version" ]; then
        version="$(resolve_latest_version)"
    fi
    # Strip leading 'v' if present for file naming (GoReleaser uses bare version).
    version_no_v="${version#v}"
    info "Installing OpenPass ${version}..."

    # Detect platform.
    os="$(detect_os)"
    arch="$(detect_arch)"
    info "Detected platform: ${os}/${arch}"

    # Build download URLs.
    archive_name="${PROJECT}_${version_no_v}_${os}_${arch}"
    if [ "$os" = "windows" ]; then
        archive_ext="zip"
    else
        archive_ext="tar.gz"
    fi
    archive_file="${archive_name}.${archive_ext}"
    checksums_file="${PROJECT}_${version_no_v}_checksums.txt"

    archive_url="${GITHUB_DOWNLOAD}/${version}/${archive_file}"
    checksums_url="${GITHUB_DOWNLOAD}/${version}/${checksums_file}"
    checksums_sig_url="${checksums_url}.sig"
    checksums_pem_url="${checksums_url}.pem"

    # Create temp workspace.
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    # Download checksums.
    info "Downloading checksums..."
    checksums_path="${tmpdir}/${checksums_file}"
    download_to "$checksums_path" "$checksums_url"

    # Verify cosign signature on checksums before trusting its hashes.
    verify_checksums_signature "$checksums_path" "$checksums_sig_url" "$checksums_pem_url"

    # Download archive.
    info "Downloading ${archive_file}..."
    archive_path="${tmpdir}/${archive_file}"
    download_to "$archive_path" "$archive_url"

    # Verify checksum.
    info "Verifying checksum..."
    verify_checksum "$archive_path" "$checksums_path"

    # Extract.
    info "Extracting archive..."
    extract_dir="${tmpdir}/extract"
    mkdir -p "$extract_dir"
    extract_archive "$archive_path" "$extract_dir"

    # Find the binary inside the extracted archive.
    # GoReleaser wraps files in a directory by default.
    binary_path=$(find "$extract_dir" -name "$BINARY" -type f | head -1)
    if [ -z "$binary_path" ]; then
        fatal "Binary '${BINARY}' not found in archive."
    fi

    if [ "$dry_run" = "true" ]; then
        info "[DRY RUN] Would install ${BINARY} to ${install_dir}/${BINARY}"
        info "[DRY RUN] Binary verified successfully.  Skipping installation."
        exit 0
    fi

    # Install.
    # Use sudo if the target directory is not writable.
    sudo_cmd=""
    if [ ! -w "$install_dir" ]; then
        if has_cmd sudo; then
            sudo_cmd="sudo"
            warn "Need elevated permissions to write to ${install_dir}."
        else
            fatal "Cannot write to ${install_dir} and sudo is not available."
        fi
    fi

    $sudo_cmd mkdir -p "$install_dir"
    $sudo_cmd cp "$binary_path" "${install_dir}/${BINARY}"
    $sudo_cmd chmod +x "${install_dir}/${BINARY}"

    info "OpenPass ${version} installed to ${install_dir}/${BINARY}"

    # PATH guidance.
    case ":$PATH:" in
        *":${install_dir}:"*)
            # Already in PATH — nothing to do.
            ;;
        *)
            printf '\n'
            warn "${install_dir} is not in your PATH."
            printf 'Add it to your shell profile:\n\n'
            printf '  # For bash/zsh (~/.bashrc, ~/.zshrc):\n'
            printf '  export PATH="%s:$PATH"\n\n' "$install_dir"
            printf '  # For fish (~/.config/fish/config.fish):\n'
            printf '  fish_add_path %s\n\n' "$install_dir"
            ;;
    esac

    # Verify installation.
    if has_cmd "$BINARY"; then
        installed_version=$("${BINARY}" version 2>/dev/null || echo "unknown")
        info "Installed version: ${installed_version}"
    fi

    info "Done!"
}

main "$@"
