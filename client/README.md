# Symvault for macOS

Native SwiftUI client for the public, self-hosted `symvault` runtime. The
client is split into `SymvaultKit` (CLI contract) and `SymvaultFeature`
(reusable UI). Under [PB-2026-09-09](../docs/product-boundaries.md), normal credential management moves to Brain. This app remains supported until replacement and security/rollback gates pass; Symaira Hub is not a target.

## Build

```bash
cd ..
make build
bash scripts/build-vaultcore.sh
cd client
xcodegen generate
xcodebuild -project Symvault.xcodeproj -scheme Symvault -scmProvider system build
```

The package manifest requires `client/.build/mobilecore/SymvaultFFI.xcframework`
(the Rust vault core, `crates/symvault-ffi`; ADR 0031) even when resolving the
macOS packages. Generate it from the repository root with
`bash scripts/build-vaultcore.sh` before package resolution or builds; this
requires the pinned Rust toolchain with the `aarch64-apple-ios` and
`aarch64-apple-ios-sim` targets and full Xcode with the iOS SDK. The framework
has arm64 slices only, so building needs an Apple silicon Mac (Intel Macs and
the x86_64 simulator are not supported). The Swift
wrapper (`Sources/SymvaultFFI`) is a symlink to
`crates/symvault-ffi/swift/Sources/SymvaultFFI`.

The former gomobile core (`Vaultcore.xcframework`) is only built with
`SYMVAULT_VAULTCORE=gomobile bash scripts/build-vaultcore.sh`; the Swift code
at this revision uses `SymvaultFFI`, so shipping gomobile means building from
the commit before the client switched.

For the reusable packages and unit tests (from `client/`, after that step):

```bash
swift build
swift test
```

The Xcode build embeds the locally built `symvault` binary in the app bundle.
During package development, the client can also discover `symvault` beside the
executable, on `PATH`, or in the standard Homebrew prefixes.
