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
| Size | Measured: `libsymvault_ffi.a` 8.97 MB (arm64 macOS, `ffi` profile, `strip = true`, thin LTO). The XCFramework slice size is **not** measured here (needs the iOS targets; see Consequences). | Not measured; I did not add the dependency to spike it. Generated glue and the `RustBuffer` runtime add code on top of the same core. |
| Fit | The API is flat: strings, bytes, one bool, one error string. | UniFFI earns its cost for records, enums, objects, callbacks and async. None of those exist here. |

The Task 12 plan asked for a measured spike of both options. What was
measured: the C-ABI static library size above and a full green Swift run. What
was **not**: a UniFFI build, its XCFramework size, and host-app / extension RSS
(the last is FFI-002 and needs a real device).

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
- **iOS is not verified.** Only `aarch64-apple-darwin` is installed; the
  `aarch64-apple-ios` and `aarch64-apple-ios-sim` Rust targets are missing, so
  no iOS slice, XCFramework or simulator test was built. The package declares
  `iOS 16` and has no macOS-only API in the binding, but that is unproven.
  Needed: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`, then a
  `swift test`/`xcodebuild test` on a simulator destination and an
  `xcodebuild -create-xcframework`.
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
