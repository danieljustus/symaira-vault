#!/usr/bin/env bash
# Build the vault core framework consumed by the iOS client.
#
# Default (SYMVAULT_VAULTCORE=rust): the Rust core, crates/symvault-ffi, as
# SymvaultFFI.xcframework (ios-arm64, ios-arm64-simulator, macos-arm64;
# ADR 0031). client/Package.swift links it as the `CSymvaultFFI` binary target
# and wraps it with the SymvaultFFI Swift module. The framework is built by
# scripts/rust-port/build-ffi-xcframework.sh and copied to
# client/.build/mobilecore (git-ignored). Needs the pinned Rust toolchain
# (rust-toolchain.toml) and full Xcode with the iOS SDK; the Apple targets are
# added with rustup when rustup is on PATH.
#
# The framework is written below client/.build/mobilecore and rebuilt on every
# run (cargo is incremental, so an unchanged core costs seconds), so a changed
# core can never be shipped stale.
#
# Environment:
#   SYMVAULT_VAULTCORE   rust (default and only supported mode)
#   CARGO_TARGET_DIR     Cargo output root for the Rust build (default <repo>/target)
#   CARGO                cargo launcher for the Rust build (default `cargo`)
#
# Usage: scripts/build-vaultcore.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode-beta.app ]]; then
  export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
fi

OUT_DIR="client/.build/mobilecore"
mode="${SYMVAULT_VAULTCORE:-rust}"

case "$mode" in
  rust)
    FRAMEWORK="$OUT_DIR/SymvaultFFI.xcframework"

    if command -v rustup >/dev/null 2>&1; then
      rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim ||
        echo "warning: rustup target add failed; the build needs these targets installed" >&2
    fi

    target_dir="${CARGO_TARGET_DIR:-target}"
    case "$target_dir" in /*) ;; *) target_dir="$REPO_ROOT/$target_dir" ;; esac
    CARGO_TARGET_DIR="$target_dir" scripts/rust-port/build-ffi-xcframework.sh

    built="${SYMVAULT_XCFRAMEWORK_OUT:-$target_dir/xcframework}/SymvaultFFI.xcframework"
    [[ -d "$built" ]] || { echo "build-vaultcore: missing $built" >&2; exit 1; }
    mkdir -p "$OUT_DIR"
    rm -rf "$FRAMEWORK.tmp" "$FRAMEWORK.old"
    cp -R "$built" "$FRAMEWORK.tmp"
    # `mv tmp existing-dir` would move tmp *into* the old framework; swap the
    # old one aside first so the replacement is a rename.
    if [[ -e "$FRAMEWORK" ]]; then mv "$FRAMEWORK" "$FRAMEWORK.old"; fi
    mv "$FRAMEWORK.tmp" "$FRAMEWORK"
    rm -rf "$FRAMEWORK.old"
    echo "Built $FRAMEWORK"
    ;;
  *)
    echo "build-vaultcore: SYMVAULT_VAULTCORE must be rust (got: $mode)" >&2
    exit 2
    ;;
esac
