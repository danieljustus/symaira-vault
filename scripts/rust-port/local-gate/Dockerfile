# Native Linux (arm64 on Apple Silicon) image for scripts/rust-port/local-gate.sh.
# Mirrors the ubuntu jobs "Rust", "Rust Miri" and "Rust port contract" in
# .github/workflows/ci.yml. Keep the pins in sync with that workflow.
# ponytail: Debian bookworm/arm64 instead of ubuntu-24.04/x86_64; the final
# hosted CI run on the closing PR remains the x86_64 evidence.
FROM rust:1.98-bookworm

ARG GO_VERSION=1.26.10
ARG NIGHTLY=nightly-2026-09-03

RUN apt-get update \
 && apt-get install -y --no-install-recommends git gnupg2 perl python3 sudo ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
    | tar -C /usr/local -xz

RUN useradd -m -u 1000 -s /bin/bash dev \
 && echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dev

USER dev
ENV PATH=/usr/local/go/bin:/home/dev/go/bin:/home/dev/.cargo/bin:/usr/local/cargo/bin:$PATH \
    CARGO_HOME=/home/dev/.cargo \
    RUSTUP_HOME=/home/dev/.rustup

RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.0 \
      --component clippy,rustfmt,llvm-tools-preview \
 && rustup toolchain install "${NIGHTLY}" --profile minimal --component miri,rust-src \
 && curl -fsSL https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
 && cargo binstall --no-confirm --locked \
      cargo-nextest@0.9.143 cargo-deny@0.20.2 cargo-audit@0.22.2 \
      cargo-hack@0.6.45 cargo-llvm-cov@0.9.0 cargo-fuzz@0.13.2 \
 && git config --global safe.directory '*' \
 && mkdir -p /home/dev/.cargo/registry /home/dev/go /home/dev/target
