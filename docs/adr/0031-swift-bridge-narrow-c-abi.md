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
| Generated API surface | None generated. 14 `extern "C"` functions (13 Go-bridge calls plus `symvault_set_backup_dir`) plus `symvault_buf_free` and `symvault_ffi_abi_version` in one header; the Swift wrapper (`SymvaultFFI`, ~190 lines) is reviewed source. | A scaffolding crate, a UDL or proc-macro description of the 13 functions, and a generated Swift file plus module map produced by `uniffi-bindgen`. Every change to the description regenerates Swift. |
| Error texts | `Err(String)` crosses as the exact bytes; Swift throws `SymvaultFFIError.go(text)`. Nothing re-words it. | A `[Error]` type is generated; keeping Go's free-form texts byte-exact means one string-carrying error variant, so the typed-error feature is unused. |
| Secrets | Caller passes `(ptr, len)`; results come back in a Rust-owned buffer that `symvault_buf_free` zeroizes. The library adds no generated glue and zeroizes its own intermediates (bech32 groups, the entry parse tree, result payloads). Copies made by the caller are outside its control: the Swift wrapper takes `String`/`Data` and returns `String`/`Data`, and Swift does not zeroize those. | Arguments and results are serialized through `RustBuffer`; the generated Swift builds `String`/`Data` copies the library cannot zeroize. |
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
  Verified on macOS with `swift test` in that mode (674 steps). A consumer
  `Package.swift` for the app (`client/`) is not switched here.
- **iOS Simulator replay: passed, `xcodebuild test` route blocked.** The 674
  steps run green inside an iOS 18.6 Simulator (arm64) against the XCFramework's
  `ios-arm64-simulator` slice: `make ffi-ios-simulator-test`
  (`scripts/rust-port/ffi-ios-simulator-test.sh`) runs `xcodebuild
  build-for-testing -destination generic/platform=iOS Simulator ARCHS=arm64`,
  then `simctl boot` and `simctl spawn <udid> .../iPhoneSimulator.platform/
  Developer/Library/Xcode/Agents/xctest SymvaultFFITests.xctest`; 2 tests, 0
  failures, `FFI-001 swift replayed 674 steps over 553 cases` in 27.4 s; the
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
- Differences from Go that this bridge carries. The replay asserts every one
  of them; there is no silent case. An entry in
  `testdata/port/ffi/known-divergences.json` pins the exact path-normalized
  text Rust returns (`expected_rust`); the Rust and Swift replays fail when the
  text is anything else, and when the case starts matching Go.
  1. X25519 ciphertexts from `EncryptWithPublicKey` are 8 to 200 bytes longer
     than Go's: rust-age appends a random `*-grease` stanza to every X25519
     header, Go's age does not. They are valid age files that Go decrypts
     (proved in both directions); only an exact length cannot match.
  2. (closed by CONFIG-LOAD-001) `OpenVaultWithPassphrase` on a config whose
     top level is not a mapping used to return the config loader's wording
     instead of yaml.v3's `unmarshal errors` text (`config-type-mismatch`). The
     `symvault-core` loader now runs the typed decode first and the case
     matches Go; its entry is gone from `known-divergences.json`.
  3. **D-SYMLINK, approved by the owner 2026-11-01.** `symvault-store` never follows a
     symlink inside the vault tree (`O_NOFOLLOW` traversal, STORE hardening);
     Go follows them. 24 recorded cases (`symlink-hardening`: symlinked
     `identity.age`, `config.yaml`, `manifest.age`, an entry, the `entries`
     directory or a subdirectory of it, dangling and outside-root targets) end
     in `vault path is a symlink: <path>` where Go succeeds or fails later with
     a different text. Rust's refusal is deliberately stricter: a symlink
     planted in a vault directory can redirect a read or an atomic write to a
     file outside it. This is a security choice made by the STORE rows, not an
     FFI decision. The owner accepted the stricter behaviour on 2026-11-01;
     the mobile bridge keeps the STORE hardening. The legacy-mode config
     rewrite in `OpenVaultWithPassphrase` leaves a symlinked `config.yaml`
     untouched so the refusal still happens, and `Config::save_to` writes
     through a unique, exclusively created temporary file, so a planted
     symlink cannot redirect that write either.
  4. `symvault-store`'s `prepare_entry` keeps an `Entry.path` that Go's
     `cloneEntry` drops; the bridge clears it before writing so stored and
     returned JSON match Go. The store still differs for other callers.
  5. **D-BACKUP (decision D1, DIST-005).** Go's `pkg/mobilebind` never took a
     backup. Rust takes a verified backup of a vault without a `.symvault-rust`
     marker before the first mutation and then writes the marker. An iOS app has
     no `$HOME`/`$XDG_STATE_HOME`, so `symvault_set_backup_dir` (Rust-only,
     additive, ABI revision stays 1) names the directory; an empty path restores
     the environment default, a relative path is refused, and with no directory
     at all the first mutation is refused before anything is written. The
     backup holds the same encrypted files as the vault, so the client
     (`MobileVaultCore`, `MobileVaultBackup`) creates
     `Application Support/symaira-vault-backups` (`0700`; not `Caches`, which the
     system may purge), sets `isExcludedFromBackup`, reads the flag back and
     only then calls `SymvaultFFI.setBackupDir`, before every call that opens or
     writes the vault; if any step fails the call fails and the vault is not
     touched. The thread-scoped form (`withBackupDirectory`) uses three more
     additive exports, `symvault_push_thread_backup_dir`,
     `symvault_pop_thread_backup_dir` and `symvault_unwind_thread_backup_dir`
     (and `symvault_set_thread_backup_dir` to replace a thread's value
     outright). A push returns a process-unique, never-reused scope token bound
     to the pushing thread; a pop restores exactly the displaced value and
     refuses, changing nothing, any token that is not that thread's innermost
     open scope (already closed, out of order, or from another thread: a bare
     stack depth would have accepted those whenever depths coincided). If a pop
     is refused the Swift scope unwinds to the value that scope saved (dropping
     leaked inner scopes, like the Rust guard) and asserts in debug builds,
     rather than leaving the scoped directory installed. These are side effects, not error texts, so they are recorded under
     `side_effects` in `known-divergences.json` (four `data-safety-backup`
     entries, each naming the tests that pin it; `tests/backup_dir.rs` fails on
     a missing pin or an unrecorded test). Verified on macOS (`swift test`
     of the client package, Rust ABI tests); the exclusion flag is honoured by
     iCloud/iTunes backup on a device, which was not run (FFI-002).
- Fixed by the FFI-001 review (no longer divergences, each with fixture cases
  recorded from the live Go functions):
  - **Nesting.** `WriteEntryJSON` parses iteratively; Go answers `vault
    resource limit exceeded` at depth 5000 and a json error beyond 10 000
    levels. Depths 33, 129, 5000, 9999, 10000 and 10001 for objects and arrays
    are replayed, also on a 256 KiB thread stack (`fixture_replay.rs`). The
    store's value limits (nesting > 32, string > 1 MiB, > 1024 array items,
    too many fields) map to Go's `resource limit` text like `ResourceLimit`.
  - **Missing `config.yaml`.** `ListEntriesJSON`, `WriteEntryJSON` and
    `VerifyManifestIntegrity` use default settings and never read
    `identity.age` (`Store::open_lenient`), as Go does; `OpenVaultWithPassphrase`
    and `ReadEntryJSON` keep their own behaviour. The config rewrite that
    `Vault.Open` performs (Go rewrites an init-style or section-less config to
    the full default config) is replayed, including the untouched case when
    legacy mode is set.
  - **Stored `-0`.** A Go-written integer literal `-0` (and `-0.0`) is read
    back as Go reads it and written back as `-0`; the replay asserts it
    (`ReadEntryJSON/stored-minus-zero`, `WriteEntryJSON/numbers-minus-zero-forms`).
    The earlier claim that it read back as `0` is withdrawn.
  - **Paths.** Errors under a nested directory name the path once
    (`entries/a/b.age`), not `entries/entries/a/b.age`.
  - **Writes.** Temporary names in the atomic write are unique per call, so
    concurrent writers to one target cannot collide (unit test with threads).
- **Secrets.** The intermediates the library controls are zeroized: bech32
  5-bit groups, the identity key, the entry parse tree, decoded entry data on
  every return path (a drop guard, including values replaced by a duplicate
  key), the store's `-0` rewrite copy, and result payloads, including one the
  caller ignores. Not covered: reallocation leftovers inside Rust collections
  and `serde_json`, entry metadata strings, and copies on the Swift side
  (`String`, `Data`) or in the host app. The caller owns every returned
  `SvBuf` and frees each exactly once.

- **C check.** `tests/c_abi.rs` compiles `tests/c/abi_check.c` with the system
  C compiler against the public header and runs it against the static library:
  struct layout, argument order and widths, buffer ownership, and passphrases
  as raw bytes (invalid UTF-8 and NUL accepted, as in Go) are checked from C.
