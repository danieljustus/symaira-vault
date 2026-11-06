# Distribution Channels

Symaira Vault is distributed through multiple channels to support different platforms and workflows.

## Supported Platforms

The product targets Apple Silicon macOS, iOS and Web where applicable. Linux
remains a supported CLI/server and CI platform. Windows and Intel Macs are
unsupported and receive no new CI or release artifacts, and FreeBSD has been
dropped. See [#1550](https://github.com/danieljustus/symaira-vault/issues/1550).

| OS | Arch | Formats |
|----|------|---------|
| Linux | amd64, arm64 | tar.gz, deb, rpm, apk, mcpb |
| macOS | arm64 | tar.gz, Homebrew, mcpb |
| NixOS / Nix | amd64, arm64 | Nix flake |

## First-Class Channels

### GitHub Releases (Primary)

Pre-built binaries are published to GitHub Releases on every tagged release.

**Download:** https://github.com/danieljustus/symaira-vault/releases/latest

Each release includes:
- `symaira-vault_<version>_<os>_<arch>.tar.gz` (Linux/macOS)
- `symvault_<version>_<os>_<arch>.deb` (Debian/Ubuntu)
- `symvault_<version>_<os>_<arch>.rpm` (Fedora/RHEL)
- `symvault_<version>_<os>_<arch>.apk` (Alpine)
- `symvault_<version>_<os>_<arch>.mcpb` (MCP Bundle for Claude Desktop)
- `symaira-vault_<version>_checksums.txt` (SHA-256 checksums)

### Homebrew (macOS/Linux)

Install from the official tap:

```bash
brew tap danieljustus/tap
brew install symvault
```

Or install in one line:

```bash
brew install danieljustus/tap/symvault
```

The formula is rendered by `scripts/homebrew-formula.sh` and published to `danieljustus/homebrew-tap`.

### Linux Packages

#### Debian/Ubuntu (.deb)

```bash
# Download the .deb for your arch
curl -LO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_linux_<arch>.deb

# Install
sudo apt install ./symvault_<version>_linux_<arch>.deb   # resolves the git dependency (dpkg -i would not)
```

#### Fedora/RHEL (.rpm)

```bash
# Download the .rpm for your arch
curl -LO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_linux_<arch>.rpm

# Install
sudo dnf install ./symvault_<version>_linux_<arch>.rpm   # resolves the git dependency
```

#### Alpine (.apk)

```bash
# Download the .apk for your arch
curl -LO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_linux_<arch>.apk

# Install
sudo apk add --allow-untrusted symvault_<version>_linux_<arch>.apk
```

### Binary Archives

Download and extract the archive for your platform:

```bash
# Linux/macOS
tar xzf symaira-vault_<version>_<os>_<arch>.tar.gz
sudo mv symaira-vault_<version>_<os>_<arch>/symvault /usr/local/bin/

```

### Nix Flake

Symaira Vault provides a Nix flake for NixOS and Nix users:

```bash
# Run directly (no install needed)
nix run github:danieljustus/symaira-vault

# Or add as a flake input in your flake.nix:
#   inputs.symvault.url = "github:danieljustus/symaira-vault";
```

> **Note:** The flake builds the Rust CLI with `rustPlatform.buildRustPackage` from `Cargo.lock` (no vendor hash to maintain; the one git dependency is fetched by its locked rev). It needs a nixpkgs whose `rustc` satisfies the workspace `rust-version` (1.98); if the build reports `requires rustc 1.98`, run `nix flake update nixpkgs`.

### MCP Bundle (.mcpb)

Symaira Vault can be installed as an MCP Bundle for Claude Desktop and other MCP clients that support the `.mcpb` format.

```bash
# Download the MCP bundle for your platform
curl -fLO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_<os>_<arch>.mcpb

# Install (copy to Claude Desktop config directory)
mkdir -p ~/Library/Application\ Support/Claude/mcp-bundles
cp symvault_*.mcpb ~/Library/Application\ Support/Claude/mcp-bundles/
```

Available MCPB platforms: `darwin-arm64`, `linux-amd64`, `linux-arm64`.

For detailed installation instructions, see [docs/mcpb-install.md](mcpb-install.md).

### Cargo Install

```bash
cargo install --locked --git https://github.com/danieljustus/symaira-vault --tag <release tag> symvault-cli
```

### Runtime dependency: git

`symvault` shells out to the `git` executable (vault history and sync), so
`git` must be on `PATH`. The deb/rpm/apk packages declare `git` as a hard
dependency; the archives, install script and `cargo install` do not install it
for you. On macOS, `git` comes with the Xcode Command Line Tools
(`xcode-select --install`, prompted on first use) or Homebrew. Rationale:
[ADR 0033](adr/0033-git-binary-runtime-dependency.md).

### Build from Source

```bash
git clone https://github.com/danieljustus/symaira-vault
cd symaira-vault
make rust-cli   # cargo build --release --locked -p symvault-cli --bin symvault
sudo install -m 0755 target/release/symvault /usr/local/bin/symvault
```

## Code Signing and Notarization Policy

To protect users against supply-chain attacks and avoid operating system warnings, Symaira Vault evaluates and implements code signing for its releases.

### macOS (Notarization)
- **Status:** Unsigned (Self-Hosted/Core)
- **Detail:** macOS notarization requires an active Apple Developer Program membership ($99/year). Because the self-hosted core is maintained as a free and open-source project without commercial backing, the binaries are currently distributed unsigned.
- **Workaround:** When installing via curl or manual download, users on macOS may encounter Gatekeeper quarantine blocks. To bypass:
  ```bash
  xattr -d com.apple.quarantine /usr/local/bin/symvault
  ```
- **Recommended Channel:** Homebrew installations via `brew install` automatically handle quarantine settings and do not trigger Gatekeeper warnings.

### Linux and Cross-Platform (Sigstore/Cosign)
- **Status:** Enabled (Automated)
- **Detail:** All release artifacts are transparently signed during the GitHub Actions release workflow using [Cosign](https://github.com/sigstore/cosign). This provides SLSA-compatible provenance and allows users to verify that the binaries were built from this specific GitHub repository.
- **Verification:** See [Cosign Signature Verification](#cosign-signature-verification) below.

## Build Pipeline

All artifacts are built by [GoReleaser](https://goreleaser.com/) (Rust builder) via the release workflow (`.github/workflows/release.yml`). No Go toolchain is involved.

The pipeline:
1. Runs the Rust gates (rustfmt, Clippy with `-D warnings`, nextest and doctests)
2. Runs the security gates (`cargo audit`, `cargo deny`) and the release-contract checker self-test
3. Builds the binaries with cargo (static musl via cargo-zigbuild on Linux, native cargo on macOS arm64)
4. Creates archives (tar.gz)
5. Creates Linux packages (deb/rpm/apk) via nfpms
6. Generates Homebrew formula
7. Publishes GitHub Release with all artifacts and checksums

## Release Verification

### Checksum File

Every release includes `symaira-vault_<version>_checksums.txt` containing SHA-256 hashes of all artifacts.

### Verifying a Download

```bash
# Download the checksum file
curl -LO https://github.com/danieljustus/symaira-vault/releases/latest/download/symaira-vault_<version>_checksums.txt

# Verify a specific artifact
sha256sum -c symaira-vault_<version>_checksums.txt --ignore-missing
```

### Cosign Signature Verification

Release artifacts are signed using [Cosign](https://github.com/sigstore/cosign) for SLSA-compliant supply-chain security. To verify the signature of a downloaded archive (e.g., `symaira-vault_<version>_linux_amd64.tar.gz`):

1. Install Cosign: https://docs.sigstore.dev/cosign/system_config/installation/
2. Download the artifact's certificate and signature:
   ```bash
   curl -LO https://github.com/danieljustus/symaira-vault/releases/latest/download/symaira-vault_<version>_linux_amd64.tar.gz.pem
   curl -LO https://github.com/danieljustus/symaira-vault/releases/latest/download/symaira-vault_<version>_linux_amd64.tar.gz.sig
   ```
3. Verify the blob:
   ```bash
   cosign verify-blob \
     --certificate symaira-vault_<version>_linux_amd64.tar.gz.pem \
     --signature symaira-vault_<version>_linux_amd64.tar.gz.sig \
     --certificate-identity-regexp "https://github.com/danieljustus/symaira-vault" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     symaira-vault_<version>_linux_amd64.tar.gz
   ```



Or manually:

```bash
# Compute hash of downloaded file
sha256sum symaira-vault_<version>_linux_amd64.tar.gz

# Compare against the value in symaira-vault_<version>_checksums.txt
```

### Verifying Binary Metadata

Symaira Vault embeds build metadata in the binary:

```bash
symvault version
# symvault v1.2.3 (commit: abc1234, built: 2025-01-15T10:30:00Z)
```

The `commit` value should match the git tag's commit SHA on GitHub.

## Smoke Test Matrix

The following matrix shows which distribution channels have automated vs. manual smoke tests:

| Platform | Format | Status | Notes |
|----------|--------|--------|-------|
| Linux amd64 | tar.gz | Automated | `smoke-test-linux` job |
| Linux amd64 | deb | Automated | `smoke-test-deb` job |
| Linux amd64 | rpm | Manual | See manual procedure below |
| Linux amd64 | apk | Manual | Alpine package |
| Linux arm64 | All | Manual | Cross-compile target |
| macOS arm64 | tar.gz | Automated | `smoke-test-macos` job |
| macOS | Homebrew | Manual | Tap-based install |

### Automated Smoke Tests

Release workflow runs automated smoke tests for the primary targets:
- Linux amd64 archive (`smoke-test-linux`)
- Linux amd64 deb package (`smoke-test-deb`)
- macOS arm64 archive (`smoke-test-macos`)

See `.github/workflows/release.yml` for test implementation.

### Manual Smoke Test Procedure

After installing Symaira Vault from any channel, verify:

```bash
# 1. Binary is in PATH and executable
symvault version

# 2. Help output is correct
symvault --help | head -5

# 3. Can initialize a test vault
SMOKE_DIR=$(mktemp -d)
SYMVAULT_VAULT="$SMOKE_DIR/test-vault" \
  SYMVAULT_PASSPHRASE=synthetic-smoke-passphrase \
  symvault init --auth passphrase
# Inspect the isolated test vault, then remove only this disposable directory
rm -rf "$SMOKE_DIR"
```

`init` has no `--non-interactive` flag. It reads a passphrase from a TTY or
from `SYMVAULT_PASSPHRASE` (at least 12 characters). The example uses only a
synthetic test passphrase; subsequent non-interactive unlocks also require
`SYMVAULT_ALLOW_ENV_PASSPHRASE=1`. Do not use the sample for real credentials.

For package-based installs, also verify:

```bash
# Debian/Ubuntu
dpkg -s symvault | grep Status

# Fedora/RHEL
rpm -q symvault

# Alpine
apk info symvault
```

## Docker

Symvault Vault is available as a Docker image on GitHub Container Registry:

**Image:** `ghcr.io/danieljustus/symvault`

### Quick Start

```bash
# Pull the image
docker pull ghcr.io/danieljustus/symvault:latest

# Run a one-off command
docker run --rm -v "$HOME/.symvault:/home/symvault/.symvault" \
  ghcr.io/danieljustus/symvault version

# Initialize a new vault
docker run --rm -it -v "$HOME/.symvault:/home/symvault/.symvault" \
  ghcr.io/danieljustus/symvault init
```

### MCP HTTP Server with Docker

Run the MCP HTTP server behind a TLS proxy:

```bash
# Start the MCP server
docker run -d --name symvault \
  -v "$HOME/.symvault:/home/symvault/.symvault" \
  -p 8080:8080 \
  ghcr.io/danieljustus/symvault mcp --port 8080
```

### Remote Gateway Deployment

For production deployments with HTTPS, use the provided `docker-compose.yml`:

1. Clone the repository:
   ```bash
   git clone https://github.com/danieljustus/symaira-vault
   cd symaira-vault
   ```

2. Place your TLS certificates in `docker/certs/`:
   ```bash
   cp /path/to/server.crt docker/certs/
   cp /path/to/server.key docker/certs/
   ```

3. Update `docker/caddy/Caddyfile` with your domain.

4. Start the services:
   ```bash
   docker compose up -d
   ```

The compose setup provisions:
- **Caddy** — TLS termination and reverse proxy
- **Symvault** — MCP server behind the proxy
- **vault_data** — Persistent volume for vault data

### Multi-Architecture

The Docker image supports both `linux/amd64` and `linux/arm64`:

```bash
# Inspect the image for supported architectures
docker manifest inspect ghcr.io/danieljustus/symvault:latest
```
