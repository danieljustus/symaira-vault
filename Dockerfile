# syntax=docker/dockerfile:1
# Symaira Vault container image: the static musl Rust `symvault` CLI on Alpine.
#
# The build stage runs on the *build* platform and cross-compiles to the target
# architecture with cargo-zigbuild, i.e. the same recipe GoReleaser's rust
# builder uses for the Linux release archives (static musl, cargo-auditable so
# the dependency list is embedded in the binary). That keeps multi-arch builds
# off QEMU for the compile step.
#
# Tool versions are pinned; keep them in sync with .github/workflows/release.yml.
ARG RUST_VERSION=1.98.0
ARG ZIG_VERSION=0.17.0
ARG CARGO_ZIGBUILD_VERSION=0.23.4
ARG CARGO_AUDITABLE_VERSION=0.7.5

# Build stage
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-bookworm AS build
ARG RUST_VERSION
ARG TARGETARCH
ARG ZIG_VERSION
ARG CARGO_ZIGBUILD_VERSION
ARG CARGO_AUDITABLE_VERSION
# SYMVAULT_VERSION is the only stamp the Rust CLI reads (option_env! in
# crates/symvault-cli/src/main.rs). Release builds pass the tag version.
ARG SYMVAULT_VERSION=dev

# The image's own toolchain is the pinned one; do not let rust-toolchain.toml
# download extra components (clippy, rustfmt, llvm-tools) into the build.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

# Zig comes from the pinned `ziglang` wheel; cargo-zigbuild finds it as
# `python3 -m ziglang` when no `zig` is on PATH.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/zig \
    && /opt/zig/bin/pip install --no-cache-dir "ziglang==${ZIG_VERSION}"
ENV PATH="/opt/zig/bin:${PATH}"
RUN cargo install --locked "cargo-zigbuild@${CARGO_ZIGBUILD_VERSION}" "cargo-auditable@${CARGO_AUDITABLE_VERSION}"

WORKDIR /src
COPY . .
RUN set -eu; \
    case "${TARGETARCH}" in \
        amd64) triple=x86_64-unknown-linux-musl ;; \
        arm64) triple=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${triple}"; \
    SYMVAULT_VERSION="${SYMVAULT_VERSION}" cargo auditable zigbuild \
        --release --locked --target "${triple}" -p symvault-cli --bin symvault; \
    install -D "target/${triple}/release/symvault" /out/symvault

# Final stage. git is a hard runtime dependency
# (docs/adr/0033-git-binary-runtime-dependency.md).
FROM alpine:3.21

RUN apk add --no-cache ca-certificates git tzdata

RUN addgroup -S symvault && adduser -S symvault -G symvault -h /home/symvault

COPY --from=build /out/symvault /usr/bin/symvault

RUN mkdir -p /home/symvault/.symvault && chown -R symvault:symvault /home/symvault/.symvault

USER symvault

VOLUME ["/home/symvault/.symvault"]

LABEL org.opencontainers.image.title="Symvault Vault"
LABEL org.opencontainers.image.description="Modern CLI password manager with age encryption"
LABEL org.opencontainers.image.url="https://github.com/danieljustus/symaira-vault"
LABEL org.opencontainers.image.source="https://github.com/danieljustus/symaira-vault"
LABEL org.opencontainers.image.licenses="MIT"

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["symvault", "version"]

ENTRYPOINT ["symvault"]
CMD ["--help"]
