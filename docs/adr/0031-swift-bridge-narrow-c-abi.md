# ADR 0031: The Swift bridge is a narrow hand-written C ABI, not UniFFI

Status: accepted for the FFI-001 candidate, 2026-11-01. Affects contract row
FFI-001 and implementation-plan Task 12. FFI-002 (real-device RSS budget) and
the switch of `client/` (`MobileVaultCore.swift`, `Package.swift`,
`project.yml`), `release.yml` and `scripts/build-vaultcore.sh` to the Rust
framework are **not** decided here.

## Context

`pkg/mobilebind` (re-exporting `internal/mobilebind`) is the gomobile bridge:
13 functions, every argument a `string`, `[]byte` or `bool`, every structured
payload JSON (ADR 0006 D2), every failure one `error` whose text the iOS client
shows or matches. `docs/rust-port/architecture.md` fixes the boundary:
`symvault-ffi` depends on `core`, `crypto` and `store` only and exposes a
narrow JSON/string/byte API.

## Options compared

| | Narrow C ABI (chosen) | UniFFI (`mozilla/uniffi-rs`) |
|---|---|---|
| Generated API surface | None generated. 13 `extern "C"` functions plus `symvault_buf_free` and `symvault_ffi_abi_version` in one 120-line header; the Swift wrapper (`SymvaultFFI`, ~190 lines) is reviewed source. | A scaffolding crate, a UDL or proc-macro description of the 13 functions, and a generated Swift file plus module map produced by `uniffi-bindgen`. Every change to the description regenerates Swift. |
| Error texts | `Err(String)` crosses as the exact bytes; Swift throws `SymvaultFFIError.go(text)`. Nothing re-words it. | A `[Error]` type is generated; keeping Go's free-form texts byte-exact means one string-carrying error variant, so the typed-error feature is unused. |
| Secrets | Caller passes `(ptr, len)`; results come back in a Rust-owned buffer that `symvault_buf_free` zeroizes. No intermediate copies in generated glue. | Arguments and results are serialized through `RustBuffer`; the generated Swift builds `String`/`Data` copies the library cannot zeroize. |
| Panics | Every call runs under `catch_unwind`; status 2 reports a contained bug. | Generated scaffolding also catches panics. |
| New dependency | **None.** Reuses `age`, `zeroize`, `serde_json`, already in `Cargo.lock`. `Cargo.lock` only gains the `symvault-ffi` package entry. | `uniffi` 0.32.x and its tree (`uniffi_core`, `uniffi_macros`, `uniffi_bindgen`, `uniffi_meta`, …) in the shipped supply chain, plus a `uniffi-bindgen` binary in the build. |
| License | Apache-2.0 like the repository. | `uniffi` is **MPL-2.0** (crate metadata and `LICENSE` upstream). `deny.toml` allows only Apache-2.0, BSD-3-Clause, ISC, MIT, MIT-0, NCSA, Unicode-3.0 and Zlib, so adoption needs a licence exception and a review of MPL file-level obligations for a statically linked iOS binary. |
| Build complexity | `cargo build -p symvault-ffi --profile ffi` yields `libsymvault_ffi.a`; the Swift package links it with `-lsymvault_ffi`. No second tool. | Cargo build, then `uniffi-bindgen generate` pinned to the same version as the runtime, with checksum/contract-version symbols checked at load time. |
| Size | Measured (`make ffi-xcframework`, 2026-11-01, `ffi` profile, `strip = true`, thin LTO): `libsymvault_ffi.a` 48.0 MB per iOS slice (device 48,027,088 B, simulator 48,022,888 B), 48.3 MB macOS; XCFramework 144.3 MB of archives. That archive is a build input holding every dependency object; an app pays the dead-stripped link: **about 2.2 MB per slice** (see Consequences). | Not measured; I did not add the dependency to spike it. Generated glue and the `RustBuffer` runtime add code on top of the same core. |
| Fit | The API is flat: strings, bytes, one bool, one error string. | UniFFI earns its cost for records, enums, objects, callbacks and async. None of those exist here. |

The Task 12 plan asked for a measured spike of both options. What was
measured: the C-ABI XCFramework sizes above and green Swift runs on macOS and
the iOS Simulator. What was **not**: a UniFFI build, its XCFramework size, and
host-app / extension RSS (the last is FFI-002 and needs a real device).

## Decision

Use the narrow C ABI.

- `crates/symvault-ffi` builds as `staticlib` + `rlib`. The Swift-facing
  contract is `swift/Sources/CSymvaultFFI/include/symvault_ffi.h`; the
  `header_declares_every_exported_symbol` test fails if an export is missing
  from it. `symvault_ffi_abi_version()` (currently 1) is bumped on any signature
  change.
- Status codes: 0 success, 1 Go-compatible failure (text in `*err`), 2 contained
  panic, 3 unusable arguments (null with a length, invalid UTF-8). `*out`/`*err`
  are reset before anything else; buffers are released with `symvault_buf_free`,
  which zeroizes.
- A dedicated Cargo profile `ffi` (`inherits = "release"`, `panic = "unwind"`)
  builds the static library. The `release` profile uses `panic = "abort"`,
  under which `catch_unwind` cannot contain anything; the process would abort
  instead of unwinding into Swift, which is safe but not what the ABI
  documents.
- Behaviour is pinned by `testdata/port/ffi/mobilebind.json`, recorded from the
  real Go functions by `scripts/rust-port/cmd/mobilebindgen`, replayed by Rust
  through the exported `extern "C"` functions and by Swift through the wrapper,
  and cross-checked against the live Go code (`mobilebindgen --drive`) in both
  directions (Go-written vaults read by Rust and the reverse; ciphertexts both
  ways).

## Consequences

- The Swift wrapper is maintained by hand. A second consumer (Android, a
  desktop app) would write its own thin layer over the same header.
- Revisit UniFFI if the bridge grows records, callbacks, streaming or async.
  Then the licence exception and dependency review above become a real
  decision with a real spike.
- **iOS slices (built and measured 2026-11-01).** With the Rust targets
  `aarch64-apple-ios` and `aarch64-apple-ios-sim` installed for the pinned
  toolchain (1.98.0), `make ffi-xcframework`
  (`scripts/rust-port/build-ffi-xcframework.sh`) builds the `ffi` profile for
  `aarch64-apple-darwin`, `aarch64-apple-ios` and `aarch64-apple-ios-sim`
  and joins them with `xcodebuild -create-xcframework` (header plus a
  `CSymvaultFFI` module map in every slice) below
  `$CARGO_TARGET_DIR/xcframework/`, never in the tracked tree. Measured with
  Xcode 27.2 / SDK 27.2 (cold build of the three cargo slices: 270 s real by
  `time -p`):

  | Slice | `libsymvault_ffi.a` (bytes) | linked stub, `-dead_strip`, all 15 exports kept (bytes) |
  |---|---|---|
  | `ios-arm64` (device, min iOS 16.0) | 48,027,088 | 2,230,288 |
  | `ios-arm64-simulator` (min iOS 16.0) | 48,022,888 | 2,232,472 |
  | `macos-arm64` (min macOS 13) | 48,252,800 | 2,233,248 |
  | total (sum of archives) | 144,302,776 (140,968 KiB on disk, `du -sk`) | |

  The linked column is a C `main()` calling `symvault_ffi_abi_version` and linked
  with `clang -O2 -Wl,-dead_strip -Wl,-u,_<symbol>` for each of the 15 exported
  symbols plus `-liconv` (same script, step 5; stub code is a few KiB). It is the
  closest number to what an app binary gains for the ffi code, but it is not an
  App Store thin size and not RSS (FFI-002). The earlier "8.97 MB" figure did not
  reproduce from `cargo build -p symvault-ffi --profile ffi` at this revision
  (48.25 MB for the macOS archive) and is withdrawn; it is not comparable to the
  archive numbers above.
- **Swift package consumption.** `swift/Package.swift` keeps the default
  (`-L $SYMVAULT_FFI_LIB_DIR -lsymvault_ffi`, the macOS path of
  `ffi-differential`). With `SYMVAULT_FFI_XCFRAMEWORK=<path to
  SymvaultFFI.xcframework>` it swaps the C shim target for a `binaryTarget`
  named `CSymvaultFFI`, for any platform the framework has a slice for (the
  manifest turns the absolute path into the relative path SwiftPM requires).
  Verified on macOS with `swift test` in that mode (548 steps). A consumer
  `Package.swift` for the app (`client/`) is not switched here.
- **iOS Simulator replay: passed, `xcodebuild test` route blocked.** The 548
  steps run green inside an iOS 18.6 Simulator (arm64) against the XCFramework's
  `ios-arm64-simulator` slice: `make ffi-ios-simulator-test`
  (`scripts/rust-port/ffi-ios-simulator-test.sh`) runs `xcodebuild
  build-for-testing -destination generic/platform=iOS Simulator ARCHS=arm64`,
  then `simctl boot` and `simctl spawn <udid> .../iPhoneSimulator.platform/
  Developer/Library/Xcode/Agents/xctest SymvaultFFITests.xctest`; 2 tests, 0
  failures, `FFI-001 swift replayed 548 steps over 462 cases` in 21.5 s; the
  fixture is read through the host path (`#filePath`), which a Simulator
  process can open. `xcodebuild test -destination 'platform=iOS Simulator,id=…'`
  does **not** work on this host: Xcode 27.2 reports "CoreSimulator is out of
  date. Current version (1174.9.2) is older than build version (1174.21.0)",
  disables simulator device support and lists no scheme. The installed
  CoreSimulator component is older than Xcode 27.2 expects; Xcode's `simctl`
  wrapper tries to update it with `xcodebuild -runFirstLaunch`, which hangs
  (evidence in `docs/rust-port/resumption.md`). Nothing in this repository can
  fix that, so the `xcodebuild test -destination` route is left as an
  environment wall.
- **Not verified: a physical iPhone.** The `ios-arm64` slice is built, the
  linked stub carries `platform IOS`, but no test ran on a device (needs
  hardware and code signing; FFI-002).
- Residual differences from Go that this bridge carries (not hidden; the replay
  asserts them):
  1. X25519 ciphertexts from `EncryptWithPublicKey` are 8 to 200 bytes longer
     than Go's: rust-age appends a random `*-grease` stanza to every X25519
     header, Go's age does not. They are valid age files that Go decrypts
     (proved in both directions); only an exact length cannot match.
  2. `OpenVaultWithPassphrase` on a config whose top level is not a mapping
     returns the config loader's wording instead of yaml.v3's
     `unmarshal errors` text (`testdata/port/ffi/known-divergences.json`, owner:
     the `symvault-core` config loader).
  3. `symvault-store`'s `prepare_entry` keeps an `Entry.path` that Go's
     `cloneEntry` drops; the bridge clears it before writing so stored and
     returned JSON match Go. The store still differs for other callers.
  4. A stored number written by Go as the integer literal `-0` reads back as
     `0` (serde_json folds the sign of an integer literal); `-0.0` is kept.
     Entries the bridge writes itself use `-0.0`.
