#!/bin/sh
# GoReleaser's Rust builder runs `<tool> <command> ...` with one token per field,
# so `cargo auditable zigbuild` needs this one-token shim. cargo-auditable embeds
# the locked dependency list in the binary (.dep-v0 section, survives strip), which
# is what syft reads to produce SBOM components for the Rust binaries.
exec cargo auditable "$@"
