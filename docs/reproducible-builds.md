# Reproducible Builds & Signed Releases

This document describes how to create reproducible builds and cryptographically signed releases of OpenPass.

## Overview

Reproducible builds ensure that anyone can independently verify that the distributed binary was built from the claimed source code. Signed releases provide authenticity guarantees through cryptographic signatures.

## Prerequisites

- Go 1.26 or later
- Git
- GnuPG (for release signing)
- `shasum` or `sha256sum`
- Docker (optional, for containerized builds)

## Reproducible Builds

### Why Reproducible Builds Matter

Reproducible builds protect against:
- **Supply chain attacks**: Verification that distributed binaries match source
- **Build environment compromise**: Independent verification catches tampering
- **Accidental build differences**: Ensures consistent output across environments

### Build Environment Standardization

To achieve reproducible builds, we standardize:

1. **Go version**: Specified in `go.mod`
2. **Build flags**: Deterministic `-ldflags` with explicit timestamps
3. **Module proxy**: Use `GOPROXY=https://proxy.golang.org,direct`
4. **CGO**: Disabled (`CGO_ENABLED=0`) for maximum portability
5. **Architecture**: Explicit `GOOS` and `GOARCH`

### Build Process

#### Local Build

```bash
# Clean module cache to ensure fresh dependencies
go clean -modcache

# Download dependencies
go mod download

# Set reproducible build parameters
export CGO_ENABLED=0
export GOFLAGS="-trimpath"
export BUILD_TIME=$(git log -1 --format=%ct)
export BUILD_COMMIT=$(git rev-parse HEAD)
export BUILD_VERSION=$(git describe --tags --always)

# Build for current platform
go build -trimpath -ldflags "\
  -s -w \
  -X main.version=${BUILD_VERSION} \
  -X main.commit=${BUILD_COMMIT} \
  -X main.buildTime=${BUILD_TIME} \
  -buildid=" \
  -o openpass \
  ./cmd/openpass
```

#### Cross-Platform Builds

```bash
# Build script for all supported platforms
#!/bin/bash
set -euo pipefail

VERSION=$(git describe --tags --always)
COMMIT=$(git rev-parse HEAD)
BUILD_TIME=$(git log -1 --format=%ct)
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME} -buildid="

PLATFORMS=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

mkdir -p dist

for platform in "${PLATFORMS[@]}"; do
  GOOS=${platform%/*}
  GOARCH=${platform#*/}
  output="dist/openpass-${VERSION}-${GOOS}-${GOARCH}"
  
  if [ "$GOOS" = "windows" ]; then
    output="${output}.exe"
  fi
  
  echo "Building for ${GOOS}/${GOARCH}..."
  GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 \
    go build -trimpath -ldflags "$LDFLAGS" \
    -o "$output" ./cmd/openpass
done
```

#### Docker Build (Fully Reproducible)

```bash
# Build in a controlled environment
docker build -f Dockerfile.build -t openpass-builder .
docker run --rm -v "$(pwd)/dist:/dist" openpass-builder
```

`Dockerfile.build`:
```dockerfile
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=0

ENV CGO_ENABLED=0
ENV GOFLAGS=-trimpath

RUN go build -trimpath -ldflags "\
  -s -w \
  -X main.version=${VERSION} \
  -X main.commit=${COMMIT} \
  -X main.buildTime=${BUILD_TIME} \
  -buildid=" \
  -o /dist/openpass \
  ./cmd/openpass

FROM scratch
COPY --from=builder /dist/openpass /openpass
ENTRYPOINT ["/openpass"]
```

### Verifying Reproducibility

After building, verify reproducibility by comparing hashes:

```bash
# Build once
./scripts/build.sh
mv dist dist-first

# Build again with clean environment
./scripts/build.sh

# Compare
for f in dist-first/*; do
  name=$(basename "$f")
  hash1=$(sha256sum "dist-first/$name" | cut -d' ' -f1)
  hash2=$(sha256sum "dist/$name" | cut -d' ' -f1)
  
  if [ "$hash1" = "$hash2" ]; then
    echo "✓ $name: reproducible"
  else
    echo "✗ $name: DIFFERS"
    echo "  First:  $hash1"
    echo "  Second: $hash2"
  fi
done
```

## Release Signing

### GPG Key Setup

1. **Create or import release signing key**:
   ```bash
   # Generate a new dedicated release signing key
   gpg --full-generate-key
   # Select: RSA and RSA, 4096 bits, no expiration
   # Use: OpenPass Release Signing Key <releases@openpass.dev>
   ```

2. **Export public key**:
   ```bash
   gpg --armor --export releases@openpass.dev > openpass-release-key.asc
   ```

3. **Publish public key**:
   - Upload to keyservers: `gpg --send-keys KEYID`
   - Add to repository: `cp openpass-release-key.asc docs/`
   - Publish on website and in release notes

4. **Configure Git to use signing key**:
   ```bash
   git config --global user.signingkey KEYID
   git config --global commit.gpgsign true
   ```

### Release Process

1. **Prepare release**:
   ```bash
   # Update version
   export VERSION=v1.2.3
   
   # Create release branch
   git checkout -b release/${VERSION}
   
   # Update CHANGELOG.md
   # Update version in cmd/version.go or main.go
   
   # Commit and tag
   git add -A
   git commit -S -m "release: ${VERSION}"
   git tag -s ${VERSION} -m "Release ${VERSION}"
   ```

2. **Build release artifacts**:
   ```bash
   # Clean build environment
   go clean -cache
   rm -rf dist/
   
   # Build all platforms
   ./scripts/build-release.sh ${VERSION}
   
   # Generate checksums
   cd dist
   sha256sum openpass-* > checksums.txt
   cd ..
   ```

3. **Sign release artifacts**:
   ```bash
   cd dist
   
   # Sign each binary
   for f in openpass-*; do
     gpg --detach-sign --armor "$f"
   done
   
   # Sign checksums file
   gpg --detach-sign --armor checksums.txt
   
   cd ..
   ```

4. **Verify signatures**:
   ```bash
   cd dist
   
   # Verify checksums signature
   gpg --verify checksums.txt.asc checksums.txt
   
   # Verify all binaries
   for f in openpass-*; do
     if [ -f "${f}.asc" ]; then
       gpg --verify "${f}.asc" "$f"
     fi
   done
   
   cd ..
   ```

5. **Create GitHub release**:
   ```bash
   # Create release with artifacts
   gh release create ${VERSION} \
     --title "OpenPass ${VERSION}" \
     --notes-file CHANGELOG-${VERSION}.md \
     dist/*
   ```

### Release Artifact Structure

```
dist/
├── openpass-v1.2.3-darwin-amd64
├── openpass-v1.2.3-darwin-amd64.asc
├── openpass-v1.2.3-darwin-arm64
├── openpass-v1.2.3-darwin-arm64.asc
├── openpass-v1.2.3-linux-amd64
├── openpass-v1.2.3-linux-amd64.asc
├── openpass-v1.2.3-linux-arm64
├── openpass-v1.2.3-linux-arm64.asc
├── openpass-v1.2.3-windows-amd64.exe
├── openpass-v1.2.3-windows-amd64.exe.asc
├── checksums.txt
└── checksums.txt.asc
```

## Automated Release Pipeline

### GitHub Actions Workflow

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - goos: darwin
            goarch: amd64
          - goos: darwin
            goarch: arm64
          - goos: linux
            goarch: amd64
          - goos: linux
            goarch: arm64
          - goos: windows
            goarch: amd64
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      
      - name: Build
        env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          CGO_ENABLED: 0
          GOFLAGS: -trimpath
        run: |
          VERSION=${GITHUB_REF#refs/tags/}
          COMMIT=$(git rev-parse HEAD)
          BUILD_TIME=$(git log -1 --format=%ct)
          
          output="openpass-${VERSION}-${GOOS}-${GOARCH}"
          if [ "$GOOS" = "windows" ]; then
            output="${output}.exe"
          fi
          
          go build -trimpath -ldflags "\
            -s -w \
            -X main.version=${VERSION} \
            -X main.commit=${COMMIT} \
            -X main.buildTime=${BUILD_TIME} \
            -buildid=" \
            -o "$output" ./cmd/openpass
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: openpass-${{ matrix.goos }}-${{ matrix.goarch }}
          path: openpass-*

  sign:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Download artifacts
        uses: actions/download-artifact@v4
        with:
          path: dist
          pattern: openpass-*
          merge-multiple: true
      
      - name: Import GPG key
        uses: crazy-max/ghaction-import-gpg@v6
        with:
          gpg_private_key: ${{ secrets.GPG_PRIVATE_KEY }}
          passphrase: ${{ secrets.GPG_PASSPHRASE }}
      
      - name: Generate checksums
        run: |
          cd dist
          sha256sum openpass-* > checksums.txt
      
      - name: Sign artifacts
        run: |
          cd dist
          for f in openpass-* checksums.txt; do
            gpg --detach-sign --armor "$f"
          done
      
      - name: Upload signed artifacts
        uses: actions/upload-artifact@v4
        with:
          name: signed-dist
          path: dist/*

  release:
    needs: sign
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Download signed artifacts
        uses: actions/download-artifact@v4
        with:
          name: signed-dist
          path: dist
      
      - name: Create release
        uses: softprops/action-gh-release@v1
        with:
          files: dist/*
          generate_release_notes: true
```

### Required Secrets

Configure these in GitHub repository settings:

- `GPG_PRIVATE_KEY`: Full ASCII-armored GPG private key for release signing
- `GPG_PASSPHRASE`: Passphrase for the GPG signing key

## Verification by Users

### Verifying Signatures

Users should verify downloaded binaries before use:

```bash
# Import the release signing key
gpg --import docs/openpass-release-key.asc

# Download binary and signature
curl -LO https://github.com/danieljustus/OpenPass/releases/download/v1.2.3/openpass-v1.2.3-linux-amd64
curl -LO https://github.com/danieljustus/OpenPass/releases/download/v1.2.3/openpass-v1.2.3-linux-amd64.asc

# Verify signature
gpg --verify openpass-v1.2.3-linux-amd64.asc openpass-v1.2.3-linux-amd64

# Expected output: Good signature from "OpenPass Release Signing Key"
```

### Verifying Checksums

```bash
# Download checksums and signature
curl -LO https://github.com/danieljustus/OpenPass/releases/download/v1.2.3/checksums.txt
curl -LO https://github.com/danieljustus/OpenPass/releases/download/v1.2.3/checksums.txt.asc

# Verify checksums signature
gpg --verify checksums.txt.asc checksums.txt

# Verify binary against checksums
sha256sum -c checksums.txt --ignore-missing
```

### Reproducing the Build

Advanced users can reproduce the build independently:

```bash
# Clone the repository at the release tag
git clone https://github.com/danieljustus/OpenPass.git
cd OpenPass
git checkout v1.2.3

# Build with the same flags
export VERSION=v1.2.3
export COMMIT=$(git rev-parse HEAD)
export BUILD_TIME=$(git log -1 --format=%ct)
export CGO_ENABLED=0
export GOFLAGS=-trimpath

go build -trimpath -ldflags "\
  -s -w \
  -X main.version=${VERSION} \
  -X main.commit=${COMMIT} \
  -X main.buildTime=${BUILD_TIME} \
  -buildid=" \
  -o openpass-reproduced ./cmd/openpass

# Compare with downloaded binary
sha256sum openpass-reproduced
sha256sum openpass-v1.2.3-linux-amd64
```

## Security Considerations

1. **Signing key protection**: The GPG private key must be stored securely (HSM or encrypted offline storage)
2. **Build environment integrity**: Use isolated build environments (Docker or GitHub Actions with minimal privileges)
3. **Supply chain verification**: Pin all dependencies with `go.sum` and verify module checksums
4. **Key rotation**: Plan for periodic signing key rotation and key revocation procedures
5. **Audit trail**: Maintain logs of all releases with signatures and checksums

## Related Documents

- [docs/distribution.md](/docs/distribution.md) - Distribution channels and installation
- [docs/macos-notarization.md](/docs/macos-notarization.md) - macOS-specific signing requirements
- [SECURITY.md](/SECURITY.md) - Security policy
- [CHANGELOG.md](/CHANGELOG.md) - Release history
