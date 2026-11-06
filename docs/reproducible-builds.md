# Reproducible Builds & Signed Releases

Current releases use the tracked [release workflow](../.github/workflows/release.yml)
and [GoReleaser configuration](../.goreleaser.yml), including Cosign signing.
For download verification, use [the distribution guide](distribution.md#cosign-signature-verification).

## Current Build Inputs

The shipped binary is the Rust CLI (`crates/symvault-cli`, binary `symvault`).
Use the toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml)
(currently Rust 1.98.0) and the committed [`Cargo.lock`](../Cargo.lock); every
build uses `--locked`. The only build stamp the CLI reads is the
`SYMVAULT_VERSION` environment variable (compile-time `option_env!`); no commit
hash or build timestamp is embedded. To compare builds, keep the source
revision, toolchain, platform, target triple, cargo flags and `SYMVAULT_VERSION`
identical. Release reproduction must match the values and flags of the actual
release build (see [`.goreleaser.yml`](../.goreleaser.yml), which builds through
`scripts/cargo-auditable.sh`).

For a local repeatability comparison from the repository root:

```bash
export SYMVAULT_VERSION=$(git describe --tags --always)
cargo build --release --locked -p symvault-cli --bin symvault
cp target/release/symvault symvault-first
cargo clean -p symvault-cli --release
cargo build --release --locked -p symvault-cli --bin symvault
cp target/release/symvault symvault-second
shasum -a 256 symvault-first symvault-second
```

This is a comparison procedure, not evidence that all release artifacts are
reproducible: cargo embeds build-host paths and the zig and Apple linkers are
not verified deterministic here (see the comments in `.goreleaser.yml`).

## Verifying a Release

Release assets carry SHA-256 checksums and Cosign signatures; follow
[the distribution guide](distribution.md#cosign-signature-verification) to
verify a download. macOS-specific signing and notarization requirements are in
[macos-notarization.md](macos-notarization.md).

## Security Considerations

1. **Signing identity**: releases are signed by the release workflow's Cosign
   identity, not by a long-lived personal key; verify the certificate identity,
   not only the signature.
2. **Build environment integrity**: the release workflow builds on hosted runners
   with pinned actions; keep the toolchain pin and `Cargo.lock` under review.
3. **Supply chain**: every build uses `--locked`; dependency changes arrive as
   reviewed `Cargo.lock` diffs (see [dependency-updates.md](dependency-updates.md)).
4. **Audit trail**: keep the checksums and signatures of every release with the
   GitHub release.

## Related Documents

- [distribution.md](distribution.md) - Distribution channels and installation
- [macos-notarization.md](macos-notarization.md) - macOS-specific signing requirements
- [SECURITY.md](../SECURITY.md) - Security policy
- [CHANGELOG.md](../CHANGELOG.md) - Release history
- [archive/reproducible-builds-go-era.md](archive/reproducible-builds-go-era.md) - the superseded Go-era proposal, kept for history only
