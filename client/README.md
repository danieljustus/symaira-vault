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

`scripts/build-vaultcore.sh` builds only the Rust `SymvaultFFI.xcframework`.
The former gomobile core (`Vaultcore.xcframework`) is historical (Go era) and
is no longer buildable from this repository; it remains available from the
git history before the client switched to `SymvaultFFI`.

For the reusable packages and unit tests (from `client/`, after that step):

```bash
swift build
swift test
```

The Xcode build embeds the locally built `symvault` binary in the app bundle.
During package development, the client can also discover `symvault` beside the
executable, on `PATH`, or in the standard Homebrew prefixes.

## Interface

The macOS app uses the shared Symaira workspace from
[`symaira-corekit`](https://github.com/danieljustus/symaira-corekit) (`SymairaTheme`,
pinned exactly in `Package.swift`) and follows its interface guidelines
(`swift/GUIDELINES.md` in CoreKit). The sidebar has three destinations:

| Destination | Shortcut | Purpose |
| --- | --- | --- |
| Overview | ⌘1 | Entry, group and type counts, runtime details |
| Entries | ⌘2 | Sortable table with a detail column; secrets stay masked until revealed |
| Import | ⌘3 | Review-gated credential intake (files from Finder, drag and drop, ⇧⌘I) |

Until the vault is unlocked, every destination shows the gate (connect,
install hint, unlock, or the runtime error). Other commands: New Entry ⌘N,
Refresh ⌘R, Lock Vault ⇧⌘L, Copy primary secret ⇧⌘C, Find ⌘F, Delete removes
the selected entry after confirmation. Settings (⌘,) hold the appearance
(System, Light, Dark; key `symvault.appearance`) and the runtime details.
Copied values leave the clipboard after 30 seconds.

The app is in English and German and follows the system language (System
Settings, General, Language & Region; per app under Applications). Every
interface text goes through `L("...")` (`Sources/SymvaultFeature/Strings.swift`)
and needs a German entry in `Sources/SymvaultFeature/Resources/Localizable.xcstrings`;
`python3 -I scripts/check-client-strings.py` (repository root, also in CI)
fails on a missing or unused entry. Messages written by the `symvault` process
itself stay in English.

## Service for selected text

The app registers the macOS service "Add to Symaira Vault" (`NSServices`
in `project.yml`, handler `IntakeAppDelegate.addSelectionToVault`). Select text
in any app, right click, Services, "Add to Symaira Vault": once the vault is
unlocked, the app opens a sheet with the entry path (prefilled with the host of
the first web link) and the field names the runtime recognized. "Save Entry"
stages the text with `symvault intake --stdin-as <entry>` and promotes the
batch. The text stays in the app process and reaches the bundled CLI on stdin
only; the sheet never shows a value. The service needs a `symvault` with
`--stdin-as`, so the app must run the CLI it was built with. macOS lists the
service after the app was started once (System Settings, Keyboard, Keyboard
Shortcuts, Services, Text).
