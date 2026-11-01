# Rust migration handover — 2026-09-09

## CLI-005c review fixes: unlock order and failed passphrase prompts, 2026-11-01

Independent review of `58460a10..d7c01a1c` (REQUEST_CHANGES) found two defects that the
corpus could not see: every earlier scenario ran with the environment passphrase, so no
prompt ever reached EOF, and no scenario started from a vault with only one of
`config.yaml` / `identity.age`. The corpus now has an `unlock_states` section
(`errtaxgen/unlockstates.go`, 60 Go-recorded scenarios, oracle `0cc78062`) and the native CLI
follows Go's `UnlockVault` order (`internal/cli/unlock.go`).

| Finding | Before | Now |
|---|---|---|
| `device pair` with only one vault file (`device.rs`) | either file missing was taken as proof that the identity is absent: with an identity but no `config.yaml` it reported `open vault: read identity file: ...`; with a `config.yaml` that disables the environment passphrase and no identity it used the passphrase from the environment | resolves the real `config.yaml` (missing = default), obtains the passphrase under its policy, then reads `identity.age`, then loads `config.yaml`: `open vault: load config: open <path>: no such file or directory` for an identity without a config, `open vault: read identity file: ...` for a config without an identity |
| EOF at the passphrase prompt (`migrate pseudonymize`, and every command that unlocks) | printed once, exit 1 | `Error: read passphrase: read Passphrase: EOF` twice, the locked hint (the Touch ID flavour for `unlock`), exit 4 (`report_failed_passphrase_read`, called by every `finish_*` function and by `intake`) |
| Interactive unlock with `security.disable_env_passphrase` and `SYMVAULT_PASSPHRASE` set (`device_input.rs`) | error `environment passphrase is disabled; ...`, exit 1 | warning `SYMVAULT_PASSPHRASE is set but ignored: ...`, then the prompt, like `resolveUnlockPassphrase` |

Scenarios per state (`UNLOCK_STATES` in `tests/error_taxonomy.rs`): `locked` 18 (settled vault,
no `SYMVAULT_PASSPHRASE`: `device pair`, `list`, `find`, `add`, `delete`, `edit`, `verify`,
`unlock`, `migrate pseudonymize` with and without `--yes`, `recipients add|remove`, `run`,
`file use`, `import review list|promote`, `intake`), and 7 each (`device pair` with and without a
positional, `list`, `verify`, `unlock`, `migrate pseudonymize` with and without `--yes`) for
`identity_only`, `config_only`, `identity_only_locked`, `config_only_locked`,
`config_only_env_disabled` and `env_disabled`. Native output before the fix, same fixture: 27 of
the 60 differed (`locked` 16, `identity_only` 2, `config_only_env_disabled` 2,
`env_disabled` 7); after: 0.

**Not covered, still different from Go (found while sweeping every runnable command in the
`locked` state):** `get` (Go takes the non-interactive path: `vault locked: this build cannot
share ...`; Rust prompts), `set` (Go asks for the username first), `file get|add`
(missing-flag errors), and a `config.yaml` that fails to parse (Go: exit 6,
`configuration is invalid`, interactive editor offer; Rust: `load config: ...`, exit 1).
These predate this branch and are not claimed.

## CLI-005c: 18 of the 28 pinned body divergences closed, 2026-11-01

Branch `local/cli-005c` (base `ee263740`), one commit per class, each removing its
pins from `KNOWN_BODY_DIVERGENCES` and re-recording
`error-taxonomy-known-divergences.json` with the ignored `record_known_divergences`
(the 10 remaining entries are byte-identical to the previous file). Every closed scenario
now matches the Go oracle `0cc78062` byte for byte (exit code, stdout, stderr).

| Class (scenarios) | Rust change |
|---|---|
| `auth rotate-passphrase` (2) | `read_passphrase` keeps the prompt label: `read Current passphrase: EOF` (Go's `ReadHiddenInput`) |
| `unlock` without OS keyring (2) | `session cache is memory-only` is printed by cobra and `ExecuteRoot`, followed by the unlock flavour of the locked hint (Touch ID) |
| `migrate pseudonymize` (2) | unlocks (env-passphrase warning, prompt) before the `(y/N)` confirmation; a failed confirmation read is reported twice |
| `device pair` (3) | no initialization gate: prompt `Passphrase: `, ExitLocked `read passphrase: read Passphrase: EOF` twice + `Unlock with ...` hint, exit 4; an initialized vault is unchanged |
| `agent list` (3) | `load config: open <path>: no such file or directory` (new `go_load_config_error`) |
| `migrate v4` (3) | same wording, reported twice (`finish_vault_result_doubled`) |
| `migrate kdf` (3) | `read vault identity (<path>): open <path>: no such file or directory`, reported twice |

Side effects of the label fix: the unlock prompt (device and session paths) is now
`Passphrase: ` like Go's `resolveUnlockPassphrase` instead of `Enter passphrase: `, and the
`read passphrase:` wrapper of a failed prompt read matches Go's ExitLocked error.

**Still open (10 scenarios): `dynamic generate` (5) and `setup` (5).** Both are not native
subcommands (only their help pages are frozen). Matching the corpus needs only the clap
argument errors (`required flag(s) "engine", "role" not set`) and the non-TTY guard of
`setup` (`setup needs a TTY; ...`), but a command that fails correctly in the corpus and
then does nothing on a TTY (`setup` wizard) or with both flags (`dynamic generate`
engines `postgres` and `aws-sts`, leases) would claim a port that does not exist, so the
pins stay until the commands are ported.

Evidence (local gate at `ad3d35a4`, clean tree, `MAKE_PREFIX=dev-external`, receipts in
`builds/symaira-vault/local-gate-cli005c/receipts.jsonl`): `macos` exit 0 (1581 tests, 0
failed; includes `config-cli-differential`, hence the `agent_list`, `auth`, `migrate kdf`
Go differentials), `linux` exit 0 (1569 tests; `port-contract` incl.
`error-taxonomy-cli-differential`). The first `linux` receipt for the same SHA is exit 2:
the Docker VM ran out of disk (`No space left on device` while compiling); the obsolete
shared volume `symvault-gate-target` (44.6 GB, unused since the per-worktree volumes)
was removed and `linux` rerun, which overwrote that log (exit 0). Local-only evidence;
`PASS (local)` is not claimed for the CLI-005 row, which stays TODO.

## CLI-005b: host tools in the error-taxonomy corpus, 2026-11-01

Branch `local/cli-005b` (base `18f7cd20`). Two defects of the extra-positional corpus:

- **Linux gate failure.** The fixture is darwin's. `mcp|serve install|status` print the launchd plist path
  (`<home>/LaunchAgents/com.symvault.mcp.plist`); the native Linux build installs a systemd user unit, and its
  `systemctl --user daemon-reload` failed in the container (`Failed to connect to bus`). The local gate run at
  `18f7cd20` stopped at 2 failures of `symvault-cli::error_taxonomy`, with 11 tests cancelled; a quick Linux run of the
  whole test file after the first fix found one more host-dependent scenario, `auth status` in the initialized vault
  (`Touch ID available: true` vs `false`).
- **Host side effect.** Go's `internal/daemon` runs `launchctl unload/load/list` (and `systemctl`) resolved through
  `PATH`, and so does the native `daemon_commands.rs`. Recording the oracle and every macOS replay of `mcp install x` /
  `serve install x` therefore called the real launchctl in the developer's user domain (plist under the sandbox HOME).

Fix (both implementations resolve the tools through `PATH`, so a stand-in directory is clean):

- `errtaxgen/hosttools.go`: every sandbox gets `.host-tools/` with stand-ins for `launchctl`, `systemctl` (service
  managers) and `security`, `secret-tool`, `pbcopy`, `pbpaste`, `xclip`, `xsel`, `wl-copy`, `wl-paste`, `osascript`,
  `notify-send`, `xdotool` (refused). Each logs `tool argv...` to a file inside the sandbox (path baked into the script:
  the service managers run with a cleared or filtered environment) and exits 0. Sandbox `PATH` = stand-ins +
  `/usr/bin:/bin`. The generator reads the log after every run (all sections, not only the scenarios): a refused tool
  fails it; service-manager calls are recorded per scenario as `host_tool_calls` (20 scenarios: `launchctl unload` for
  `mcp|serve uninstall`, `unload` then `load` for `install`; `status` makes none) and must repeat across the two
  recordings. The fixture gains `generated_on`, `host_tools` and `host_dependent_commands`.
- Platform tag: the 4 commands `mcp|serve install|status` are `host_dependent_commands`; their 20 scenarios carry
  `platforms: ["darwin"]` (12 uninitialized, 8 initialized). `mcp|serve uninstall` print the same text on both platforms
  and stay untagged. The replay skips tagged scenarios on other hosts with `SKIP n ...` on stderr and asserts the exact
  skip count (12 / 8 off darwin, 0 on darwin).
- Linux `--check`: the first full Linux gate (`556009aa`) passed the 1567 nextest tests and then stopped in
  `port-contract`, where `errtaxgen --check` builds the oracle on Linux and found the darwin-recorded
  `install|status` output and `launchctl` call lists stale. On a host other than `generated_on`, `--check` takes
  exactly two platform-bound parts from the recording and byte-compares the rest against the fresh oracle run; the
  `PASS` line states the counts (`projectOnForeignHost`, negative controls in `hosttools_test.go`). Review of
  `d4a164df` found the first version too wide (it replaced the whole observation of a tagged scenario and the call
  list of any scenario with calls on either side, so a corrupted recorded `mcp install` argument or a new unrelated
  `systemctl` call would have passed Linux `--check`). Now:
  - only the `  Service file: <path>` stdout line of a tagged scenario is taken from the recording; its args, exit code,
    stderr and every other stdout line come from the fresh run and must match the recording (a changed argument, exit
    status, stderr, other stdout line, line count or line position stays stale);
  - only scenarios of the six `service_manager_commands` (`mcp|serve install|status|uninstall`, a new fixture field
    bound to the Rust test) take their call list from the recording; every other scenario must make zero host-tool
    calls on every platform: `recordScenarios` fails otherwise (`scenario … is not a service-manager command but
    called host tools`), the projection never replaces a fresh call list outside those commands, and the Rust replay
    (`host_call_failure`) fails such a call on macOS and Linux, with negative controls in both languages.
  Checked in the gate container: the Linux-built Go oracle reproduces every other recorded byte.
- `auth status`: `Touch ID available` is a hardware probe, not CLI behavior; the named normalizer `touch_id_available`
  rewrites that line to `__BOOL__` on both sides (5 scenarios).
- Replay (`error_taxonomy.rs`): same stand-ins (installed from the fixture's `host_tools`), same `PATH`, guard on every
  run, recorded `host_tool_calls` compared on darwin. Tests: `host_dependent_scenarios_are_tagged_and_counted`,
  `sandbox_path_resolves_every_host_tool_to_its_stand_in`, `stand_ins_log_their_calls_and_the_guard_flags_other_tools`
  (negative control for the guard), `darwin_service_commands_make_the_recorded_launchctl_calls`,
  `linux_service_commands_use_systemd_through_the_stand_in` (Linux smoke, not Go parity),
  `touch_id_normalizer_rewrites_only_the_availability_line`; Go: `hosttools_test.go`.
- Not redirected (documented residuals): absolute-path calls (`/bin/launchctl` of `intake watch disable` needs an
  existing plist; `/usr/bin/osascript` of the intake notification needs an import; no scenario does either) and the
  native `auth status` Touch ID probe, which runs `/usr/bin/osascript -l JavaScript` (`canEvaluatePolicy`, read-only, no
  prompt). The session cache stays in memory because the sandbox sets `CI=1`; the oracle is built without OS keyring
  support, so no run reads the developer's keychain.
- The oracle recording itself did not change a single observation: the regenerated fixture differs by the new fields,
  the touch-id placeholder and the generator digest only.

## CLI-005 partial: nil-`Args` extra positionals, 2026-11-01

Branch `local/cli-005`. Every cobra command whose `Args` validator is nil accepts
and ignores extra positionals; clap rejected them. Now fixed and pinned.

- **Inventory.** `errtaxgen` (`inventory.go`) walks `cmd.NewRootCmd()` plus
  cobra's default `help` command: 64 commands with `Args == nil`, 48 runnable
  (the sources are digest-bound, so the compiled tree is the pinned oracle's).
- **Corpus.** `testdata/port/cli/error-taxonomy.json` gains `nil_args`,
  `vault_seed` (a Go-initialized vault, recorded once and reused by `--check`;
  `--new-seed` re-records it), `extra_positionals` (138 empty-sandbox + 82
  initialized-vault scenarios; `x`, `x y`, `-- x`), `extra_positional_exclusions`
  (7 commands, each with a reason) and `run_file_use_argv` (82 + 82 `run`/`file use`
  permutations; the vault seed holds a real attachment entry `seed/cert` and a text
  field `seed/api.token`, the child is `/bin/sh -c 'printf "%s\n" "$@"'`, so flag-like
  child words `-la --timeout 5 --json --` and symvault flags before and after the
  positionals are compared for real). Every scenario ran twice against the Go binary and had to be
  deterministic; the only rewrites are `password20` (`generate`) and `key_bytes`
  (`audit rotate-key`). The pre-existing sections are unchanged.
- **Before (first 284 scenarios):** 152 of them failed in the native binary: 133 because
  clap rejected the positionals (27 command paths), 2 because `help x y` quoted its
  words differently, 17 because `run`/`file use` reported a missing program or entry
  differently. **After:** 356 of the 384 scenarios match Go byte for byte (all 164
  `run`/`file use` ones), 28 are pinned as known body divergences (below), none is a
  clap rejection. Review round 2 (seeded `run`/`file use` corpus) found and fixed four
  more native divergences: `--timeout 5` (no unit) was accepted past the flag parser
  (now pflag's `invalid argument ... flag: time: missing unit in duration`), a bare
  `--timeout 0` was rejected (`parse_go_duration` accepts it like Go), `file use`
  mapped an absent attachment field / an entry without attachment to exit 1 instead
  of 2 (with the `Try:` hint) / 9, and printed a child's non-zero exit and a timeout
  once instead of twice.
- **Fix.** `IgnoredPositionals` (hidden `num_args = 0..`) is flattened into exactly
  the nil-Args commands; commands with validators are untouched
  (`clap_still_rejects_extra_positionals_where_cobra_has_a_validator`). Also:
  `help` words are quoted like Go's `%#q`, a missing program in `run`/`file use`
  reads `exec: "x": executable file not found in $PATH`, `file use` reports a
  missing entry like Go (exit 2, doubled line, `Try:` hint), `auth status` prints its
  plain failure twice.
- **Open (28 scenarios, `KNOWN_BODY_DIVERGENCES` in `error_taxonomy.rs`):**
  `dynamic generate` and `setup` are not native subcommands; `agent list`,
  `migrate v4`, `migrate kdf` on a missing vault word the OS error differently and
  print it once; `device pair` checks the vault before asking for the passphrase;
  `auth rotate-passphrase` loses the prompt label in `read ... EOF`; `migrate
  pseudonymize` lacks the passphrase warning and the second line; `unlock` without
  an OS keyring lacks the second line and the Touch ID hint. All differ without the
  extra positionals too; fix each against its own Go-recorded cases. Host- or
  timing-dependent `doctor` and `startup-profile` and the long-running `broker`,
  `mcp`, `serve` and random-token `device pair`/`migrate v4` are not replayed in
  the initialized vault (clap acceptance only, via `nil_args_positional_tests`).
- **Pins.** The 28 divergent scenarios are no longer replayed under a substring
  check: `testdata/port/cli/error-taxonomy-known-divergences.json` holds the exact
  native exit/stdout/stderr per scenario (regenerate with the ignored test
  `record_known_divergences`, review the diff), the replay fails on any change or on a
  match with Go, and `known_divergence_pin_detects_unrelated_changes` is the negative
  control. `generator_digest` now hashes every non-test Go file of `errtaxgen`
  (`main.go`, `inventory.go`, `scenarios.go`), and
  `TestGeneratorDigestBindsEveryProductionSource` proves that changing any of them
  makes `--check` report the fixture stale.
- This is not completion of CLI-005: the broader exit/error taxonomy outside the
  recorded corpus is unproven.

## FFI-001 Swift bridge, 2026-11-01

`crates/symvault-ffi` replaces the gomobile `pkg/mobilebind` bridge: 13 Go-identical functions (`src/api.rs`) behind a
narrow C ABI (`src/abi.rs`, header `swift/Sources/CSymvaultFFI/include/symvault_ffi.h`), built only on
`symvault-crypto`/`symvault-store`/`symvault-core` (plus `age`, already pinned, for Go's exact decrypt diagnostics).
Decision and comparison: ADR 0031 (hand-written C ABI; UniFFI is MPL-2.0 and not on the `deny.toml` allowlist). No new
dependency; `Cargo.lock` only gains the `symvault-ffi` package. New root profile `ffi` (`inherits = "release"`,
`panic = "unwind"`) so `catch_unwind` can contain a bug.

Evidence (branch `local/ffi-001`, base `22c51834`):
- `scripts/rust-port/cmd/mobilebindgen` records `testdata/port/ffi/mobilebind.json` (462 cases, 548 steps) from the real
  Go functions; `--check` re-runs Go against the stored seed and fails on any byte (also green on Linux with go1.26.6);
  `--drive` answers JSON lines with raw Go results for the interop tests. Randomized outputs are pinned by shape plus an
  inverse-function round trip; the vault tree, ciphertexts and identities Go produced once are stored as `seed`.
- Rust: `cargo test -p symvault-ffi --locked` — fixture replay (548/548 steps through the C ABI), interop with live Go in both
  directions, ABI tests. Swift: `swift test` in `crates/symvault-ffi/swift` replays the same 548 steps through `SymvaultFFI`
  against `libsymvault_ffi.a` (the harness had to create names with raw POSIX calls: Foundation URLs decompose `é`, and
  Foundation's JSON reader drops a leading U+FEFF).
- `make ffi-differential` = Go `--check` + Rust tests (with the live Go driver) + (macOS) release-grade `ffi` build + Swift
  test; exit 0 on macOS and in the Linux gate image (Swift part prints `SKIP`), hence part of `port-contract`. `make
  ffi-fixtures-generate` re-records (new random seed, deliberate), `make ffi-fixtures-check` is the Go check alone.
- Negative control: one changed byte in an expected error text fails `--check` and the replay.

Differences from Go left open (all asserted with the exact Rust text, none silent): rust-age's random `*-grease` stanza
lengthens X25519 ciphertexts by 8–200 bytes; non-mapping `config.yaml` wording (`known-divergences.json`, CFG owner);
`symvault-store` `prepare_entry` keeps `Entry.path` (bridge clears it); **D-SYMLINK** (24 cases, approved by the owner 2026-11-01):
Rust refuses a symlink anywhere inside the vault tree where Go follows it (ADR 0031).

Review fixes, 2026-11-01 (independent review of `a2feae44`: REQUEST_CHANGES, F1-F8), on `local/ffi-001` after `4a04546c`:
- Fixture now 553 cases / 674 steps. New Go-recorded cases: JSON nesting depth 33/129/5000/9999/10000/10001 (objects and
  arrays, under `data`), store value limits (string > 1 MiB, > 1024 array items, > 1024 fields, nesting > 32), missing
  `config.yaml` for every vault function, Open's config rewrite, stored and written `-0`, symlink mutations (identity,
  config, manifest, entry, `entries` and subdirectories; dangling and outside-root targets).
- Red before: at `4a04546c` the deep cases abort the replay and the 256 KiB-stack test with `stack overflow` (SIGABRT);
  the missing-config cases mismatch.
- Green after: `make ffi-differential` exit 0 on macOS (Rust 14 lib + 8 ABI + 1 C ABI + 3 replay/interop + 2, Swift 2
  tests) and in the Linux gate image (Swift part SKIP); `make ffi-ios-simulator-test`; workspace clippy `-D warnings`,
  fmt, gofmt/go vet on `mobilebindgen`, `cargo test -p symvault-store`.
- `tests/c_abi.rs` builds the staticlib itself: `cargo test` never writes `libsymvault_ffi.a`, so an archive left from an
  earlier `cargo build` could be stale (first Linux run failed for exactly that reason).
- Delta review of `4a04546c..9166d365`: REQUEST_CHANGES. Blocking: the legacy-mode config rewrite went through
  `Config::save_to`, which wrote a fixed `config.yaml.tmp` following symlinks (a planted link overwrote a file
  outside the vault); fixed in `symvault-core` for every caller (unique `create_new` temporary, as Go's
  `fsutil.AtomicWriteFile`) and the rewrite skips a symlinked `config.yaml`. Medium: `keep_negative_zero` turned
  `1e-0` into invalid `1e-0.0` for every store reader; now only a leading `-0`, copy zeroized. Low: entry data
  scrubbed on every return path (drop guard), `c_abi` skips under llvm-cov. Both fixes red before (victim
  overwritten; `1e-0.0`), green after.
- Re-review of `9166d365..3f8389b0`: APPROVE (one low note: the `c_abi` skip does not see a plain `cargo test
  --target <triple>`; only the host triple works there). Merged into `local/rust-port` as `4176fc8b`; the local gate
  on the merged SHA is the integration evidence.

iOS slices, 2026-11-01 (branch `local/ffi-001`, after `a2feae44`):
- `make ffi-xcframework` (`scripts/rust-port/build-ffi-xcframework.sh`, exit 0): `ffi` profile for `aarch64-apple-darwin`,
  `aarch64-apple-ios`, `aarch64-apple-ios-sim` -> `$CARGO_TARGET_DIR/xcframework/SymvaultFFI.xcframework` with 3 slices
  (`Info.plist` `AvailableLibraries`: `ios-arm64`, `ios-arm64-simulator`, `macos-arm64`; header + `CSymvaultFFI` module map in
  each). Sizes (bytes): 48,027,088 / 48,022,888 / 48,252,800, total 144,302,776; linked and dead-stripped with all 15
  exports kept about 2.23 MB per slice (ADR 0031 has the table; the old "8.97 MB" figure did not reproduce and is withdrawn).
  `xcodebuild` is called plain there because `dev-external` appends `-derivedDataPath`, which `-create-xcframework` rejects.
- `Package.swift`: default unchanged (`make ffi-differential` still exit 0, 548 steps on macOS); with
  `SYMVAULT_FFI_XCFRAMEWORK=<xcframework>` a `binaryTarget` replaces the C shim (macOS `swift test` in that mode: 548 steps).
- `make ffi-ios-simulator-test` (exit 0): 548 steps / 462 cases replayed inside an iOS 18.6 Simulator (arm64) against the
  `ios-arm64-simulator` slice, 21.5 s. Route: `xcodebuild build-for-testing -destination generic/platform=iOS Simulator
  ARCHS=arm64`, `simctl boot`, `simctl spawn <udid> xctest SymvaultFFITests.xctest`, using the real simctl binary
  (`SIMCTL=/Library/Developer/PrivateFrameworks/CoreSimulator.framework/Versions/A/Resources/bin/simctl`). The script created and
  afterwards removed one device of its own (`symvault-ffi001-iPhone16`); no other device or service was touched.

Environment wall (CoreSimulator, this host, 2026-11-01), evidence:
- `/usr/bin/xcrun simctl list runtimes` (Xcode's `/Applications/Xcode.app/Contents/Developer/usr/bin/simctl`, a bash wrapper)
  produced no output for 1184 s (started 05:49, killed by me at 06:09; also a foreign session's identical probe, pid 23517,
  was still hung at 20 min and was left alone). `ps`: wrapper `bash simctl` -> child `xcodebuild -runFirstLaunch`; `sample`
  of the child: main thread in `mach_msg`, another in `xpc_connection_send_message_with_reply_sync`, i.e. waiting on an XPC
  reply that never came. Cause from the wrapper source: it runs `-runFirstLaunch` when
  `/Library/Developer/PrivateFrameworks/CoreSimulator.framework/.../Info.plist` `CFBundleVersion` (here `1174.9.2`) is older
  than `EXPECTED_VERSION="1174.21"`.
- The real simctl binary under that framework answers immediately (`list runtimes` 0 s): only runtime `iOS 18.6 (22G86)`
  and `watchOS 27.0`; no iOS device existed before (created one).
- `xcodebuild test -destination 'platform=iOS Simulator,id=<udid>'` fails at once: "CoreSimulator is out of date. Current
  version (1174.9.2) is older than build version (1174.21.0) ... Simulator device support disabled", then `scheme
  "SymvaultFFI-Package"` not found. So `xcodebuild test` against a simulator destination is blocked until the CoreSimulator
  component is updated (smallest human action: let `xcodebuild -runFirstLaunch` / the Xcode components installer finish with
  administrator rights, or install the matching CoreSimulator package). The simctl-spawn route above does not need it.

Client switch, 2026-11-01 (branch `local/ffi-client`, base `1fd66491`):
- `client/` now uses the Rust core: `MobileVaultCore.swift` imports `SymvaultFFI` (public API unchanged; every
  `SymvaultFFIError` becomes `MobileVaultCoreError.frameworkError(<core text>)`, the former `NSError.localizedDescription`
  surface; `fingerprint(of:)` stays non-throwing). `client/Package.swift` has the `CSymvaultFFI` binaryTarget at
  `.build/mobilecore/SymvaultFFI.xcframework` plus a `SymvaultFFI` target whose sources are the reviewed wrapper through the
  symlink `client/Sources/SymvaultFFI` (SwiftPM rejects a target path outside the package; Swift 5 language mode as the wrapper
  is written for it); `SymvaultKit` links it on iOS, `SymvaultIOS` (SwiftPM target, now also compiling `MobileVaultCore.swift`
  on macOS) and its tests use it, `project.yml` adds the `SymvaultFFI` product to `SymvaultIOSApp` and excludes `x86_64` for the
  iOS Simulator SDK (the XCFramework is arm64 only).
- `scripts/build-vaultcore.sh` builds the Rust XCFramework by default (`rustup target add`, `build-ffi-xcframework.sh`, copy to
  `client/.build/mobilecore`); `SYMVAULT_VAULTCORE=gomobile` keeps the old gomobile bind (framework only: the Swift side is not
  switchable, shipping gomobile means building the commit before the switch). `pkg/mobilebind` Go code is untouched (Go
  removal needs owner authorization). `release.yml` gui-release, `ci.yml` Vaultcore (macOS) and `codeql.yml` (swift) install the
  pinned toolchain with the three Apple targets before the script; `ci.yml` path filter also routes `crates/symvault-ffi/**`.
- Two latent `MobileVaultCore.readEntry` bugs fixed (the same under gomobile; found by the new test, red before): the core's
  entry JSON has no `path` (decoding threw `keyNotFound`, so `VaultStore.loadEntries` silently listed nothing) and field values
  were interpolated as `string("alice")`. `IntakeTests.swift` is macOS-only now (`#if os(macOS)`, the models are), which unblocked
  `build-for-testing` for iOS.
- Verified locally (macOS 27.2, Xcode, `CARGO_TARGET_DIR` under builds/): `make ffi-xcframework` exit 0;
  `scripts/build-vaultcore.sh` exit 0; `xcodegen generate` + `xcodebuild -scheme SymvaultIOSApp -destination 'generic/platform=iOS
  Simulator' CODE_SIGNING_ALLOWED=NO build` exit 0, same for `generic/platform=iOS` (device, unsigned) exit 0; `swift build` and
  `swift test` in `client/` exit 0 (`MobileVaultCoreTests` 3/3 against the real core on macOS, 21 + 9 existing tests);
  `MobileVaultCoreTests` 3/3 inside the iOS 18.6 Simulator (`build-for-testing` of the package scheme, `simctl spawn xctest
  -XCTest SymvaultIOSTests.MobileVaultCoreTests`); `make ffi-differential` exit 0 (674 steps / 553 cases; needs a `TMPDIR` that
  is not under the `/var` symlink, otherwise the Go oracle check reports `/private$ROOT` for four symlink-loop texts: environment,
  not a regression).
- Not run: the app itself (compiled and linked only; the simulator run covers `MobileVaultCore` through an XCTest bundle, not
  the SwiftUI app), the unsigned archive/IPA path of `ios-testflight.sh`, any CI job (release/ci/codeql edits checked with
  `actionlint` only).

Client switch review and merge (2026-11-01): review of `a690a4c9` REQUEST_CHANGES; fixed in `c0b5d561`
(`build-vaultcore.sh` rebuilds the Rust framework on every run and swaps an existing one aside instead of moving the new one
into it; `release.yml`/`codeql.yml` build the Rust core before the signing keychain and the appkit git token exist; ci.yml
`macos-vaultcore` path filter covers `crates/*`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`; no global `rustup
default`; numbers render exactly instead of `%g`; docs name the arm64-only requirement and that the gomobile fallback is not
linkable by this client). Delta review REQUEST_CHANGES (`-0` lost its sign), fixed in `6cf57b8c`, re-review APPROVE.
Fast-forwarded into `local/rust-port` at `6cf57b8c`; local gate macos and linux exit 0 (receipts in
`builds/symaira-vault/local-gate/receipts.jsonl`). `xcodebuild test -scheme SymvaultClient-Package -destination
'id=<iOS 18.6 Simulator>' -only-testing:SymvaultIOSTests/MobileVaultCoreTests` passed 3/3 (the generated `Symvault.xcodeproj`
must be moved aside, otherwise xcodebuild picks the project, which only has the app scheme); the CoreSimulator wall below did
not reproduce. The whole `SymvaultIOSTests` bundle unsigned: `ApprovalSessionStoreTests` fail with `-34018` (missing keychain
entitlement without a signed test host), not caused by the switch.

Not done: FFI-002 real-device RSS; a test run on a physical iPhone (needs hardware and signing; the `ios-arm64` slice is built
and linked into the unsigned device app but never executed); `x86_64-apple-ios` (Intel simulator) slice (Apple-silicon only by
design, `ARCHS=arm64`); XCFramework signing/checksum for distribution; CI evidence for the changed `release.yml`/`ci.yml`/
`codeql.yml` steps; Go removal (`pkg/mobilebind`, gomobile tooling in `go.mod`) needs owner authorization. Next action: let the
closing CI run the three macOS jobs on this branch and read the Rust-target install and XCFramework build steps there.


## Local gate after CLI-005 and the per-worktree target volume, 2026-11-01

`local/cli-005` (`9c35ff3a`..`18f7cd20`) and `local/cli-005b` (`556009aa`..`1d6d4ef4`) are fast-forwarded into
`local/rust-port`; reviews APPROVE after two REQUEST_CHANGES rounds each. The first full gate on `1d6d4ef4` failed on
Linux in `store-differential` (`symvault-store` `tests/audit.rs`: fixture `ENOENT`): every worktree shared the
`symvault-gate-target` Docker volume, so cargo reused an `audit` test binary whose compile-time `CARGO_MANIFEST_DIR`
pointed into another worktree. `ec61f76e` names the volume after the worktree path (first Linux run per worktree is a
cold build). Gate `ec61f76e`: macos exit 0, linux exit 0 (receipts in `builds/symaira-vault/local-gate/receipts.jsonl`);
no `symvault` LaunchAgent loaded afterwards. CLI-005 stays open: 28 pinned body divergences remain.

Open at session end (2026-11-01, not merged): branch `local/cli-005c` (worktree `local-cli005c`, `2c5ad3ee`, backed up
on `origin`) closes 18 of the 28 body divergences (374/384 scenarios match; `dynamic generate` and `setup` stay pinned
until ported) and, in `cc479acb`/`25a0cf13`, both findings of the review of `d7c01a1c`: Go's unlock order for partial
vaults (`device pair`, identity without config / config without identity) and Go's exit 4 plus locked hint for a failed
passphrase read (`migrate pseudonymize`, `verify`, `list`, `run`, ...); new `unlock_states` corpus, 60 scenarios, 27
differed before, 0 after. Gate `c936dd00` macos and linux exit 0 (receipts in
`builds/symaira-vault/local-gate-cli005c/receipts.jsonl`). Next: independent re-review of `d7c01a1c..2c5ad3ee`, then
fast-forward into `local/rust-port` and gate. Known, not fixed (older than the branch): locked `get` (Go non-interactive
`vault locked: this build cannot share ...`, Rust prompts), `set` (Go asks for the username first), `file get`/`file add`
missing-flag errors, unparsable `config.yaml` (Go exit 6 `configuration is invalid`, Rust exit 1). Gate disk: each
per-worktree `symvault-gate-target-*` Docker volume holds about 45 GB; volumes of removed worktrees are not cleaned up
yet (planned: let `local-gate.sh` remove orphans).

## CLI-006 positive output matrix, 2026-10-31 (review fixes 2026-11-01)

`outputmodegen` (oracle `bf7f687b`, darwin) records text, `--json`, `--output yaml`, `--output json` and
`--quiet` for the 47 gate rows that do not refuse both formats: 524 cases (470 at the first recording), 47 paths, 6 frozen seeds, in
`testdata/port/cli/output-modes.json`; `crates/symvault-cli/tests/output_modes.rs` replays them byte for byte
(stdout, stderr, exit, file-tree effect incl. permission bits). Targets: `make output-modes-cli-differential`
(re-verifies against a rebuilt oracle, then replays) and `make output-modes-regenerate` (keeps the frozen seeds).

Rust fixes the matrix forced: `get --print` writes the `expose_plaintext` audit entry with an empty agent (Go's
`emitExposureAudit`; the replay compares decoded audit fields, not presence); `auth set` refuses
`--json`/`--output` (gate rows with `valid_args: 0` are probe artefacts); `update apply|check|info` accept
`--quiet`/`--output`, apply's report goes to stderr; `template generate` `--output` is the file flag and
`required flag(s) "type"` follows cobra; `generate manpages` accepts `--quiet`, uses the XDG default config path
and the `2-Jan-2006` HISTORY date; `doctor` order (`mcp.tokens` after `recipients.recovery`), no `tags` in JSON,
migration warning not silenced by `--quiet`; `agent install --json`; intake JSON keeps Go field order and stat
errors; config `git:` writes `commit_template` first; device errors are doubled; yaml renderer shared via
`symvault-gojson::yaml`.

Review fixes (REQUEST_CHANGES, each pinned against the real Go binary):
- **Linux CI.** `check_output_modes_cli.sh` skips the Go `--check` with a visible `SKIP` on a non-darwin host
  (the corpus is darwin-recorded: `oracle.goos`); the Rust replay prints its own `SKIP`. Verified in the local
  gate image on Linux (`make output-modes-cli-differential` exit 0, both notices on stderr). The corpus therefore
  does not gate Linux/Windows: the evidence is the darwin run.
- **`config set` typed decode.** The panic on `&value[..7]` is gone (Go cuts at seven bytes; the error text carries
  the raw bytes, and U+FFFD shows up only in the fixture's reader-facing `stderr` field, the exact bytes being
  `stderr_b64`), and a scalar of the wrong YAML type for a typed field (`sessionTimeout 12` is
  `!!int` into a `Duration`) fails like Go with exit 6 instead of being written. The cases are recorded from
  the Go binary.
- **Normalization honesty.** One numbered list of 14 rules (`root`, `bin`, `dated-id`, `tmp-suffix`,
  `touch-id`, `gen-pw`, `pair-token`, `now-ts`, `man-date`, `opaque`, `encrypted-store`, `audit-fields`,
  `archive-members`, `managed-fields`) in the generator header, the fixture notes and the test header;
  `normalization_rules_are_listed_once_and_consistently` fails on any disagreement and the other tests carry a
  negative control per rule. `agent skill export` is no longer opaque: the archive is compared as decompressed
  members (the probe showed Go writes them in map order and the `managed_hash`/`managed_installed_at` lines are
  install-time values). Tree entries record the permission bits (both harnesses run the binary under umask 022).
  Touch ID stays `<BOOL>`, but on darwin `touch_id_availability_matches_go_in_the_same_sandbox` compares the live
  Go and Rust values (needs `SYMVAULT_OUTPUT_MODES_GO_BINARY`, set by the script; visible `SKIP` without it).
- **Config read errors.** `config get|set|list` on a missing, unreadable or directory config file print Go's
  `cannot load config: [cannot read config file: ]open|read <path>: <cause>` doubled with the doctor hint (exit 6)
  instead of Rust's `No such file or directory (os error 2)`; six Go-recorded cases (red before: all six).
  Mode recording also found `agent profile export` creating its file with 0600 (Go `os.Create`: 0644); fixed.
- **yaml.v3 scalars.** `symvault-gojson::yaml` now ports the yaml.v3 scalar analysis/style selection and the
  double-quoted escape rules (leading newline `|4-`, astral `\UXXXXXXXX`, U+2028 single-quoted folded, BEL `\a`,
  U+FEFF/U+0085 escapes, plain `<<`) and is pinned by a Go-recorded scalar corpus
  (`make yaml-scalar-differential`).

Verified (HEAD at commit time): `outputmodegen --check` PASS against the rebuilt-pin oracle; replay 470 cases
(>= 3 per path, all 47 paths; 524 after the delta-review follow-ups below) green; negative control (one byte of `version.text` changed) fails both `--check`
and the replay. `error_taxonomy` and `cli_device_approval` expectations moved with the fixes (`delete x`,
`device approval-revoke` now Go-exact); `empty_flow_mapping_root` became a regular `config-yaml-syntax.json` case
(94 cases, 32 open divergences, 441 comparisons). Like all 16 `accepted` cases it records `validate`,
`validate --json` and `doctor` only; `config get` on a `{}` document is not recorded anywhere (open, low).

Declared open: update apply/check/info beyond the dev-build branch, `intake watch` beyond `--once`, live
`approval`/`device approval-pair|accept|join` flows, `remote init` (the pinned Go oracle panics with a nil
pointer dereference in `enableAutoPush` when the vault has no sync config, so that branch is not pinned),
`--color`/`--theme`; `doctor` is pinned with `--no-network`. Not compared: the volatile audit fields (`ts`,
`kid`, `hmac`, the `argv_hash` digest; shape only) and read errors of the config file other than the three recorded ones. The corpus is darwin-only
(`oracle.goos`); other hosts skip it visibly. Touch ID: the worker first saw Go true and Rust false here; that
was a Rust bug, not a sandbox effect: every JXA adapter in `symvault-platform/src/macos.rs` reported through
`console.log`, which osascript writes to stderr, so `run_jxa` read an empty stdout. Fixed by ending each script in
its result expression (and asking Go's biometric-only policy 1, not 2);
`jxa_reports_through_the_last_expression_on_stdout` and `jxa_scripts_never_report_through_console_log` pin it.

## CLI-006 delta review follow-ups, 2026-11-01

Branch `local/cli006` on 22c51834, one commit per area: `config set` typed reload ported from yaml.v3's
`decode.go` (aliases, merge keys, explicit tags, duplicate keys, `time.Time`; `time.ParseError` wording in
`symvault-gojson::rfc3339`; plain `<<` written as `!!merge <<`), resolver quirks (`0b+1`, `0o-12`, `.1_0`; 7
more strings in `yaml-scalars.json`), `gen_config_schema.py` (all `internal/config` files, loud failures,
`test_gen_config_schema.py` mutation controls inside `config-cli-differential`), and `go_path_error` for config
reads and `agent profile export -o`. 54 Go-recorded cases (`output-modes.json`, text mode), 48 differ at the
base. The open classes the review listed (loader strictness, value inference and re-encode differences,
`profiles.x: null`) are recorded with probes in the CFG-003 and CLI-005 rows of the contract matrix and in
`cli-gap-inventory.md`. The one `output-modes` harness change: work files may be symbolic links (`link`).

## IO-001 invalid-byte representation, 2026-10-31

Question closed: does `ImportedEntry` (`String` paths and values) lose data against Go? Probed with the
REAL Go binary (oracle `bf7f687b`, macOS plus a `linux/arm64` container): Go keeps imported strings as
raw bytes. Paths reach dry-run/progress lines and every error text unchanged, values are re-encoded by
`encoding/json` when stored (one U+FFFD per invalid byte), the 4096-byte field limit counts raw bytes,
and creating a file with a non-UTF-8 name fails on macOS (`EILSEQ`) but succeeds on Linux (where Go then
leaves unreadable entries: collapsed manifest keys, `entry not found`).

Rust: `ImportedEntry` gains `raw_path` and `raw_value_len` (`#[serde(skip)]`, empty for UTF-8 input);
CSV/profile/pass importers keep raw bytes, de-duplicate and `path.Join` on them; the invented
`distinct CSV paths collapse` error and `ImportError::PathCollision` are gone. `import_commands::apply`
works on path bytes (new `Reporter::line_bytes`, `ApplyError(Vec<u8>)`, byte-level `go_invalid_path_text`,
`validate_field_lengths` with raw lengths; the import/replace callbacks take the raw-length map). The
write of a non-UTF-8 path runs Go's `mkdir`/`open` sequence, so macOS produces Go's exact text; a file
system that accepts the name gets an explicit refusal (ADR 0030 item 4, bounded divergence, approved by
the owner 2026-11-01).

Corpus: `importcligen` 293 -> 345 cases (52 `invalid-bytes-*`: 33 `any`, 19 `darwin`). Harness additions:
`stdout_b64`/`stderr_b64` (raw bytes; text field only readable), normalization rule 3
(`.age.tmp-<digits>` -> `.age.tmp-<N>`), platform `darwin` (other hosts keep the recorded case in
`--check`, the Rust replay skips it). Regenerate with `make import-cli-regenerate` on a macOS host only;
verified diff: the first 293 cases byte-identical, `generator_digest` and notes changed, 52 appended.

Red before: 39 of the 52 new cases differed against the pre-change binary (replayed with the same
rules). Not covered, still open: argv-borne invalid bytes (`--prefix`, `--mapping`, source path in error
text; clap rejects non-UTF-8 values Go accepts) and invalid bytes in a pass store path (Go side not
observable on macOS; Rust adapter unit-tested). Observed once or twice under heavy host load in the
replay: `e2e-csv-many-rows` failing with `failed to read .git/objects/<xx>: No such file or directory`
from the store (valid paths, not touched by this slice; reran green 20+ times, also with the pre-change
binary) - treat as a pre-existing store/Git race if it recurs.

## IO-001 pass importer against real gpg, 2026-10-31

`passgpggen` (new, oracle `fca3f894`, sources `internal/importer/{importer,pass,totp}.go`,
`internal/crypto/totp.go`, `internal/secrets/filter.go`) freezes 36 pass stores into
`testdata/port/sync/pass-gpg.json`: an armored test-only key (empty passphrase, disposable
`GNUPGHOME`), ciphertexts made by the real gpg binary, and the entries/warnings/complete error text of
the REAL Go importer (`importer.New(FormatPass)` over the opened directory). `--check` imports the
recorded key, decrypts the stored ciphertexts (never re-encrypts) and re-runs the Go importer; it keeps
the recorded `goos`/gpg version, so it is platform independent. `pass_gpg_contract.rs` imports the same
key and runs `import_pass` with the system gpg (fail closed without gpg). Gate: `make
pass-gpg-differential` = `scripts/rust-port/check_pass_gpg.sh`, part of `sync-io-differential`.

Pinned environment: `LC_ALL=C` (Go forwards LC_ALL, and gpg words its errors per locale),
`GNUPGHOME`/`HOME` disposable and short (agent socket path limit), `pinentry-program /usr/bin/false`.
What of gpg's stderr reaches Go: nothing on success; on failure `decrypt pass entry <path>: ` + the
whole trimmed stderr (key ids and creation dates are fixed by the stored ciphertext). Two narrow rules,
documented in the fixture and implemented identically in generator and test: N1 replaces
`filepath.Clean(argument)` by `@STORE` (an un-cleaned spelling stays visible); N2 applies only to three
`version_variant` cases and only when the gpg version line differs from the recorded one (gpg 2.4.4 vs
2.5.24): listed optional lines are removed and consecutive duplicates collapsed on both sides, otherwise
byte-identical. Every other case is compared byte for byte on both gpg versions.

Red before: 13 of 36 cases differed (and 54 of 121 `otpauth://` entries): store arguments `a//b`,
`./x`, `a/../x`, `.` (Go prints `path.Join`-cleaned paths), unreadable directory/root wording
(`walk pass store: open <path>: permission denied`), decrypt failure ahead of an unreadable directory
(Go decrypts while walking, Rust walked first), symlinked store root (Go's `WalkDir` lstat()s the root
and does not descend; a trailing slash resolves it), `net/url.Parse` rejections the `url` crate accepts
(`%zz` in the path) or words differently (28 entries), `%q` quoting of TOTP algorithms (Rust Debug).
Fixed at the root: `pass.rs` is a streaming `WalkDir` port (cleaned joins, root lstat, Go error text,
`exit status N`/`signal: killed` for empty stderr), plaintext stays bytes until the last per-field lossy
conversion (Go quotes invalid bytes as `\xNN` in warnings), new `importer/gourl.rs` ports `net/url.Parse`
(escape/host/port/IPv6/`netip.ParseAddr` errors, fragment, control bytes), `ParseQuery` (first value,
bad-escape/semicolon pairs dropped, 10000-parameter cap) and byte-level `strconv.Quote`; `ParseTOTP`
uses it with Go `Atoi` wording and simple-case `ToUpper`; `symvault-core` TOTP algorithm errors use
`go_quote`. Negative control: adding `--quiet` to the production gpg arguments fails 17 cases; the
source was restored byte-identically (sha256 compared).

Evidence (2026-10-31, local): macOS arm64 (gpg 2.5.24) check script green; Linux arm64 image (gpg
2.4.4) `make pass-gpg-differential` green under plain `cargo test` and `cargo llvm-cov nextest -p
symvault-sync` (163 tests); `cargo test -p symvault-sync --all-features` and `symvault-cli --test
import_command_contract --test import_commands` green; workspace clippy `-D warnings` and fmt clean;
no gpg-agent left (pgrep) on host or in the container. Gotchas: `os.Exit` skips defers, so the generator
kills agents through a cleanup list; the first Linux run caught the gpg 2.4 extra
`no valid OpenPGP data found` line for a cut armor. Residuals: non-UTF-8 store paths in error text (Rust
`Path::display` is lossy, Go prints raw bytes), signal names beyond the common set, Windows (not a
supported target). Invalid-byte API representation of `ImportedEntry` stays open.

## IO-001/IO-002 command CLIs gated, 2026-10-31

Gate `59c8c7cc` green on macOS arm64 (1477 Rust tests, 112 Go packages) and Linux arm64 (1467
tests in the test and llvm-cov stages; import 293 and export/backup/restore 173 Go re-verifications).
Gate hardening on the way: the import replay hides a system gpg (`<work>/bin` + mirrored
`/usr/bin:/bin` without `gpg*`), both replays keep `LLVM_PROFILE_FILE` after `env_clear()`, the
export `--check` keeps the recorded `goos`, and a sweep raised test-only setup deadlines in 26 files
(#1564-#1567). Residuals: IO-001 invalid-byte API representation and real GPG compatibility; IO-002
tar header residuals.

## IO-001 complete import CLI, 2026-10-31

`importcligen` (new, oracle `bf7f687b`, source files `cmd/admin/import.go` + `internal/importer` +
`internal/cli`, generator digest over `cases.go`, `main.go` and `check_import_cli.sh`) freezes 293
`symvault import <source>` cases: stdout, stderr, exit status and, through `list --json` and
`export --format json --yes` replays, the resulting vault (paths, field values, secret type and usage
hint). `import_command_contract.rs` replays them with an exact case count and collects all
differences; `make import-cli-differential` re-verifies the corpus against a rebuilt oracle first
(`make import-cli-regenerate` rewrites it deliberately). Normalization is two narrow rules, documented
in the generator and the test: sandbox paths become `@WORK`/`@ROOT`, and `import-YYYYMMDD-<8 hex>`
quarantine IDs become `import-<DATE>-<RAND>`. Red before: 273 of 293 differed (heuristic classes, a
case can be in several): per-entry progress lines missing 150, `list --json` of an empty vault 137,
error printed once instead of twice 105, dry-run report missing 36, vault state 30, exit code 25,
`usage_hint` of imported secret metadata 18, `Detected ... CSV export` line 17, repeated string flags
rejected 4, plus single cases for `.json`/`.yaml` dispatch, `filepath.Ext` dotfiles, `1pux` alias,
check order (vault before source, quarantine ID after parse), CSV parse error positions, mapping and
open/read diagnostics, pass through the command, vault path diagnostics, backslash auto-commit.
`import_commands.rs` now follows `cmd/admin/import.go` step for step (`prepare` before the vault,
`apply` inside it). Also fixed at the root: Go CSV scanner port (`GoCsvScanner`) for exact `parse error
on line N, column M` text, `path.Join` cleaning, Go `%q` in mapping errors, `UsageHintForType` in
`symvault-store`, DEL/C1 characters accepted in entry paths (Go rejects only runes below 0x20),
`list --json` `null` for an empty vault, auto-commit paths keep Unix backslashes. Negative control:
reverting the `path.Join` cleaning fails 6 prefix cases. Residual: an environment-dependent case
(case-insensitive file system, wall-clock git warning) is deliberately not in the corpus. Local gate
only (local-first mode).

## IO-001 1PUX on gojson, 2026-10-30

`import1passgen` adds the same mutation sweep as `cxfgen` (197 `onepux_mut*` cases, complete
Go error text; oracle `fca3f894` unchanged). 128 differed (15 accepted where Go rejects, 19
upper-cased keys ignored, 94 error texts). `onepux.rs` now decodes through `gojson` (new
`GoDecode for bool`); size, zip-open, read and missing-export errors use Go's text via
`ImportError::Decode`, so `symvault import` prints Go's `parse import source: <err>`.
Negative control: disabling case-insensitive key lookup fails 19 cases. Also fixed the
load-sensitive `command_runner_times_out_and_reaps_the_process_group` (#1564).
Local gate only (local-first mode).

## IO-001 CXF on gojson, 2026-10-30

`cxfgen` now records Go's complete `err.Error()` and a mutation sweep over the reference
payload (every path null / wrong scalar / array / object, upper-cased keys): 496 cases
(oracle `58d978bb` unchanged). Before, 147 differed (13 accepted where Go rejects, 12
entry/warning differences, 122 error texts). `importer/cxf.rs` decodes through `gojson`
(new: `json.Unmarshal` path, `RawMessage`, `EditableValue`, `map[string]any`); Go-verbatim
errors use `ImportError::Decode`, so the CLI keeps Go's `parse import source: <err>`.
`go_is_print`/`go_quote` (Go `strconv.Quote`) moved to `symvault-core` (table generator
path updated) and replace `{:?}` in the CXF warning and TOTP errors; CXF type matching uses
`go_to_lower` (`CXF-021`). Negative controls: array-for-struct, `to_lowercase`, `{:?}`.
Local gate only (local-first mode).

## IO-002 numeric tar header fields, 2026-10-30

Rust checked only the mode field; Go's `readHeader` rejects any malformed size, uid,
gid, mtime, USTAR devmajor/devminor or STAR atime/ctime with `archive/tar: invalid tar
header`, and a bad GNU atime/ctime silently demotes the header and prepends the USTAR
prefix field (which overlaps those bytes) to the name. `restoregen` records 19 new
`header-field/*` cases (149 total; oracle `861ad938` unchanged, only `generator_digest`
and the appended cases differ). Red before: 11 error mismatches plus the GNU-prefix tree.
`go_header` in `symvault-sync/src/archive.rs` now mirrors both; four branch mutations each
fail the corpus. Residuals in the IO-002 matrix row. Local gate only (local-first mode).

## CLI-005/006 hand-parsed `update` bool flags, 2026-10-30 (#1558)

`update apply|check|info` accept `--flag[=<ParseBool form>]`, last value wins, for
`--json`, `--quiet`, `--force` and `--dry-run`. The cobra emulation now types these
hand-parsed flags (`HAND_PARSED_BOOLS`, guarded against `command-tree.json`), so an
invalid value is reported before an extra positional and `update info --json=`
no longer hits the persistent `--json`. Go prints the `update` errors once.
`errtaxgen` gained 10 `bool_flag_update_*` cases (105 usage cases; oracle
`0cc78062` unchanged). Open: `setup` is not ported, so its two bool flags are not
either. Local gate only (local-first mode).

## CLI-005/006 local bool flags `--flag[=bool]`, 2026-10-30 (#1529)

All 69 command-local clap `SetTrue` bool flags that are pflag `BoolVar`s in Go (plus `audit -j` and
the Rust-only local `agent install --quiet`) now use the `--flag[=bool]` + `overrides_with` spelling,
so `doctor --fix=false`, `verify --rebuild=false`, `-y=false` and repeats (last value wins) behave
like Go; pre-existing `--flag[=bool]` locals gained the missing `overrides_with`, and
`auth rotate-passphrase --reencrypt` takes ParseBool forms. The cobra emulation accepts `-y=value`
for bool shorthands. `errtaxgen` records 20 more `bool_flag_local_*` usage cases (95 total; oracle
`0cc78062` unchanged, only `generator_digest` and the appended cases differ; 15 failed on the
pre-change binary). `doctor --fix=false` is guarded by in-crate tests over the whole command tree,
not by a byte replay (host-dependent report). Open: hand-parsed `update apply|check|info` and
`setup` bool flags still reject `--flag=false`; details in `cli-gap-inventory.md`.

## GIT-002 stable git locale, 2026-10-30 (#1555)

A localized git prints `Schwerwiegend: konnte nicht auf '<url>' zugreifen: ...`, which the English
offline markers (`couldn't connect`, `unable to access`) do not match, so a German session
classified an unreachable remote as `pull failed`. Red: `git_io_gaps::
pull_classifies_offline_under_a_german_locale` (re-executes itself with `LANG/LC_ALL=de_DE.UTF-8`,
`LANGUAGE=de`; skips when the host has no German git catalog) failed with that text. Fix:
`run_process_with_timeout` (the single Rust git runner) now runs every child with `LC_ALL=C` and
`LANGUAGE` removed (`pin_stable_locale`; `git::tests` assert the env deterministically without a
catalog). Probe on git 2.56: `LANGUAGE=de LC_ALL=C` prints English, so `LC_ALL=C` alone wins; the
`LANGUAGE` removal is belt-and-braces for gettext builds that honour it. `device.rs` `git clone`
(inherits stdio, output is not classified) deliberately keeps the user's locale.

Go oracle: the Go classifier has no `unable to access` marker and pulls through go-git, so only
`pushWithSystemGit` (SSH URLs) parses git text. Pinning its env needs an edit to
`internal/git/git_push.go`, a pinned source of `gitio` (`oracleCommit` `28fd3531`, which also
compares the file set): the follow-up is source fix -> merge -> advance `gitio` pin to the
merged revision -> provenance-only `make` re-freeze of `testdata/port/sync/git-io.json`
(`git-offline`/`git-winner` are unaffected). Not done on the PR branch because a pin can only
name a revision that survives the squash merge.

## IO-003 intake watch mtime zone, 2026-10-25 (#1510)

Go formats `fi.ModTime()` in `time.Local`, so `intake <file> --json` provenance `mtime` carries the host offset (`2023-11-14T23:13:20+01:00` under `TZ=Europe/Berlin`); Rust printed `Z`. The contract was previously only exercised in UTC. Red: `TZ=Europe/Berlin intake_watch_contract.py` failed on `file-env` against the pinned Go oracle. Fix: `intake_commands.rs` converts the mtime with a `localtime_r` offset (the `time` crate's `local_offset_at` refuses in the CLI's worker thread). The contract gains a `file-env-local-zone` case (`TZ=Europe/Berlin`, non-Windows; asserts `+01:00`). No Go source or fixture changed, so no pin advance was needed.

## IO-002 restore error/side-effect contract, 2026-10-22 (#1247)

**Update 2026-10-26 (#1498, mode-field spellings):** `restoregen` now freezes 130 cases (+42:
21 numeric mode-field spellings x file/dir, header block 5 patched with a recomputed checksum;
the snapshot helper opens mode-0 results so the walk can read them). Red first: 12 cases
diverged (`+`/`-` signed and embedded-NUL-tail fields: Rust `i64::from_str_radix` accepted signs
and rejected the NUL tails Go cuts). Rust `go_header_mode` now delegates to a `go_parse_octal`
that mirrors Go `parseOctal`; the oracle is unchanged (`cmd/admin/backup.go` untouched, pin
`861ad938` stays). Windows replay count is now 116 of 130. Remaining residuals: #1483
(entry-limit pre-pass inflates oversized members), #1499 (gzip multistream), uid/gid/mtime
header fields unparsed, plus the items listed below.

`scripts/rust-port/cmd/restoregen` freezes 88 production-Go `RestoreBackup`
cases (`testdata/port/sync/restore-errors.json`, oracle `861ad938`; `cmd/admin/backup.go`
is unchanged, so no oracle-pin advance or provenance re-freeze was needed). Each case records the exact
`restore failed:` text and the complete resulting tree, and
`crates/symvault-cli/tests/restore_errors_contract.rs` replays it through the
production Rust restore (`make restore-errors-differential`, part of
`make sync-io-differential`). Rust `archive::restore` now follows Go's member-name
cleaning, `SafeMkdirAll` component walk, extraction order and error wording.

Open, recorded in the IO-002 matrix row as unapproved divergences: stage-and-rename
instead of Go's in-place write (partial file on truncated members, inode replaced;
in-place fallback only for an existing writable file in a non-writable directory),
flate offset text and re-gzipped gzip-cut/corrupt replay wraps, umask for new files,
Windows `SafeMkdirAll` symlink following, the Rust-only 100,000-member limit (checked
before any write; tested in `crates/symvault-sync/tests/restore_limits.rs`), raw-byte
non-UTF-8 names (host-dependent, same test file) and unparsed uid/gid/mtime header
fields. Windows replay (follow-up to native CI): path separators, the missing-archive stat op,
mkdir-over-file and directory-open texts are expectations derived from Go source (see the
matrix row, divergence 4); 14 of 88 cases are `unix_only` with a recorded reason, so 74 run
on Windows. Native 3-OS evidence for this corpus is still pending; IO-002 stays
`in_progress`.
Next IO-002 candidates: export/backup CLI-level stdout/stderr differential
against a built Go binary, and backup-side member modes/ordering corner cases.

## SESSION-003 non-interactive half, 2026-10-22 (#1243 slice 2)

`make biometric-differential` (in `port-contract`) freezes the macOS Keychain
OSStatus contract, the no-op biometric manager and the Touch ID item layout from
the pinned Go sources (`biometricgen`, oracle `d13e5d0b`, fixture
`testdata/port/session/biometric.json`) and replays them in `symvault-core`; on
macOS `symvault-platform` additionally drives `SecurityBiometricItems`
(Security.framework, no `security` subprocess) against disposable keychains. Real
divergence fixed: the Rust Touch ID item used the go-keyring-wrapped `OsKeyring`
instead of Go's raw item. Still pending, with reasons: the LocalAuthentication
prompt (no hardware; stays JXA), the real default-keychain/access-control path
(operator keychain), CI receipt for the new native test. SESSION-001 residuals:
Go-reads-Rust-written record, Go's case-insensitive JSON field names, CLI-layer
fallback warning text.

## IO-002 restore entry-limit pre-pass is bounded, 2026-10-26 (#1483)

`check_entry_limit` (`crates/symvault-sync/src/archive.rs`) skipped member bodies by
inflating them, so an over-limit member was fully decompressed before extraction
rejected it at the header (Go rejects at the header without reading the body).
Measured on a 3 GiB zero-filled member (14 MB gzip, debug build): Rust 2.94 s -> 0.49 ms
with the identical error `archive entry entries/huge exceeds maximum file size of
1073741824 bytes`; Go `RestoreBackup` 0.42 ms. Fix: the pre-pass (`scan_entry_limit`)
returns `Ok(())` at the first regular member whose declared size exceeds the file limit
or the remaining total budget and leaves the error to the extraction pass. Regression:
`entry_limit_scan_tests` (counting reader; 64 MiB over-limit and over-budget members must
not be read, a within-limit member must still be skipped; fails against the old scan).
Residual (low, documented): the archive is still inflated twice for valid inputs and a
file swapped between passes is bounded only by the size limits.

## IO-002 gzip multistream parity, 2026-10-26 (#1499)

Restore now reads the archive with `symvault_sync::gzip_multistream::GoGzip`, which
follows Go's multistream `gzip.Reader` (members concatenate, trailing bytes are the next
header, per-member CRC/length checks, sticky errors), in both the entry-count pre-pass and
the extraction pass. `restoregen` gained `multistream.go` and a second fixture,
`testdata/port/sync/restore-gzip-multistream.json` (61 cases with the exact Go gzip bytes),
replayed by `crates/symvault-cli/tests/restore_gzip_multistream_contract.rs` as part of
`make restore-errors-differential`; limit behaviour across members is in
`crates/symvault-sync/tests/restore_gzip_multistream.rs`. No Go production source changed, so
the oracle pin (`861ad938`) is unchanged; `restore-errors.json` was regenerated only because its
`generator_digest` covers `restoregen/main.go`. Still open: native 3-OS evidence, Go's
`flate: corrupt input before offset N` text, and the PR #1515/#1516 merge (same files: see
matrix row IO-002 for the divergence list).

## Current native-prerequisite repair, 2026-10-11

Task `t_c13388cd` composes the local MCP candidate `c8376fa4` with the existing
security prerequisite `6f7864cc` and serving-budget repair `766019ad`. It repairs
isolated Go cache resolution and the ordinary generator tests without changing
historical oracle identities or their independently anchored bytes. Separate
product captures bind the composed ordered source and patched module inputs.

Local source/fixture, Go, Rust and lint evidence is retained in
`native-prerequisite-repair-handoff.json`. Independent SPEC/parity and
QUALITY/security review of the complete composition remains required. No new
native Linux/Windows acceptance, remote integration, release, cutover or Go
removal is claimed. The earlier package below remains historical context.

## Prior bounded MCP package, 2026-10-11

Task `t_22223af2` owns the local `migration/rust-final-20261011` continuation of
PR #1321 from `2b596f916bf736250b7fd3bb4d39f5f89fb20aa2`. See ADR 0016's
`mcp-anomaly-ordered-v1` section for the separate corrected reference and
unchanged historical fixture contract. No migration row is promoted here.
Local verification/review, durable publication of the corrected oracle by the
integration owner and exact-candidate native three-OS acceptance are distinct
gates. No release, tag, push, merge, cutover or Go removal is performed here.

## Current continuation checkpoint, 2026-10-03

Read [continuation-20261003.md](continuation-20261003.md) for the current
source, verified integrations, API security evidence, remaining issue gates,
public inputs and independent setup instructions. Earlier entries below are
preserved historical evidence, not current execution orders.

## Zwischenstand 2026-09-24, Teil 17 — Slice `agent setup` + `serve token*` gebaut

- **Basis/Worktree:** Branch `feat/rust-port-deprecated-stubs2` auf `main`
  `ecaf4d0c` rebasiert (Worktree `symaira-vault-wt-mig-stubs2`);
  Implementierung und Tests unabhängig nachverifiziert.
- **Slice:** die fünf verbliebenen Deprecated-Stub-Pfade — `agent setup <name>`
  (`cmd/mcp/agent.go`, `newAgentSetupCmd`) sowie `serve token`,
  `serve token create|list|revoke`. Der Oracle baut `mcp` **und** `serve` aus
  einer gemeinsamen `newMcpTokenCmd()` (`cmd/mcp/serve.go`), alle
  `serve token*`-Bytes sind deshalb identisch mit `mcp token*`. Portierung in
  neuem Modul `crates/symvault-cli/src/deprecated_stubs.rs`, Dispatch in
  `main.rs` (`AgentCommand::Setup` als Catch-all = `ArbitraryArgs`-Semantik,
  `Command::Serve` hidden + `ServeAction::Token` als Wort-Catch-all wie
  `McpAction::Token`); Wiederverwendung von `deprecated_stub_message` (vier
  Stderr-Zeilen, Exit 2, `--quiet`-ignorierend) und `deprecated_token_message`.
- **Oracle-Capture:** Go-Oracle aus dem unveränderten Go-Baum von `main`
  `ecaf4d0c` gebaut (SHA-256 `6b3dd176cdb80ce2af706d4bbce2cd870b12774aa06d6a7f9218d8d3ec49c7a5`), isoliertes HOME; alle fünf Pfade plus
  Varianten (ohne Args, Extra-Args, unbekanntes Wort, `--quiet`) liefern die
  vier Stderr-Zeilen, leeres Stdout, Exit 2. Differenzial Go↔Rust:
  **26/26 Fälle byte-identisch** (Exit, Stdout, Stderr).
- **Bekannte Differenz (bewusst, wie `update check`/`apply`):** das
  `serve`-Elternobjekt wird nur deklariert (hidden, wie der Oracle), damit die
  portierten `token`-Kinder erreichbar sind; `token` ist dessen einziges
  deklariertes Kind. Bare `serve` und `serve install|status|uninstall`
  bleiben unportiert (HTTP- bzw. launchd/systemd-Runtime). Der Oracle druckt
  `Warning: 'symvault serve' is deprecated, use 'symvault mcp' instead.` und
  startet den Server (leeres HOME: Exit 3 mit `vault not initialized`); die
  Portierung: clap `unrecognized subcommand` (Wort-Formen, Exit 1) bzw. Help
  auf Stderr (bare `serve`, Exit 1 — dieselbe Form wie bare `agent`/`policy`).
  Keine Oberfläche ohne Runtime; dokumentiert in den Modul-Docs von
  `deprecated_stubs` und als Negativ-Kontrolle in
  `tests/cli_agent_setup_serve_stubs.rs` assertiert. `symvault help` bleibt
  dokumentiertes Non-Goal.
- **Blocker-Liste korrigiert:** `agent setup` stand in Teil 13/14 noch als
  „Netzwerk-Downloads"-Blocker; der gepinnte Oracle zeigt dort nur noch den
  Deprecated-Stub (kein Netzwerk, kein Vault-Zugang) — der Pfad war fälschlich
  als blocked geführt.
- **Gates nach Rebase auf `ecaf4d0c`:** `cargo fmt --all --check` ✅,
  `cargo clippy -p symvault-cli --all-targets --all-features --locked -- -D warnings` ✅,
  `cargo test -p symvault-cli --locked` ✅ (u. a. fünf neue Kontrakt-Tests:
  Byte-Parität, `--quiet`-Ignoranz, `serve token` ≡ `mcp token`, Hidden-in-
  Help, Negativ-Kontrolle). Keine Go-Änderung, kein Tag/Cutover.

## Zwischenstand 2026-09-22, Teil 16 — Slice `update info` gemergt (28 → 24)

- **Basis:** `main` @ `d4aa2b13` (Merge `b9a48ac7` + Ledger `d4aa2b13`);
  cligap-Baseline **missing 28**, Flag-Lücken 9, Alias 0, Rust-only 1
  (Binary `f711a275b1c0`).
- **Slice gewählt: `update`-Catch-all (Import-Muster): `update` (bare,
  Help), `update info` sowie — Surface-only über die Eltern-Hilfe —
  `update check`/`update apply` (**28 → 24** messbare Pfade; Flag-Lücken
  9 → 12, weil `check --force`, `apply --force`, `apply --dry-run` jetzt
  als unportiert auftauchen — ehrlich sichtbar, Runtime bleibt blocked:
  HTTP-Check bzw. cosign).
  Komplett offline (Versions-/Build-Infos, kein Vault-Zugang), Go-Referenz
  `cmd/admin/update.go`. `update check`/`update apply` bleiben blocked-Rows
  (HTTP-Check, cosign-Verify) und werden bewusst NICHT als clap-Subcommands
  deklariert, solange die Runtime unportiert ist — Help-Erreichbarkeit
  ohne Runtime würde die cligap-Zahl schöner machen, als sie ist.
- **Worktree:** `symaira-vault-wt-update-info`, Branch `feat/update-info`
  @ `d4aa2b13`, ein Schreiber (Selbst-Bau, 429-Dispatch entfällt).
- **Gate-Reparatur parallel:** `make port-contract` scheiterte auf macOS
  lokal am Doppelslash-Paritätsbug in `agent whoami` (Go `filepath.Clean`
  vs. Rust roher Pfad; Ubuntu-CI grün, weil dort TMPDIR keinen
  Trailing-Slash hat) — Issue #1108, PR #1109 **gemergt `23dab1b9`**;
  der Baseline-Lauf läuft danach weiter bis #1111 (s. u.).
- **Fund unterwegs:** `make config-cli-differential` scheitert lokal auf
  macOS deterministisch (Go meldet `/private/var/…`, Rust `/var/…`;
  Issue #1111) — pre-existing, unabhängig von Slice und #1109, in der
  Ubuntu-CI unsichtbar; lokaler `port-contract`-Lauf endet dort,
  kanonisches Gate = CI. Windows-Clippy-Fix `b78bd4b1` (`Path`-Import
  in `update_commands` unix-gated, Platform-Gated-Import-Falle).
- **Fixture:** 13 Cases, Oracle `d4aa2b13` (`target/port/symvault-go`,
  sha256 `7b9ad076…`), Provenanz-Digest über 6 Go-Dateien +
  corekit-Pin `v0.17.1-0.20260904101640-f3d3eb79b9b1`;
  `platform: unix` für die vier Binary-Path-Cases (Windows-Fallback ist
  `build-from-source`, dort eigener cfg-Unit-Test).
- **Bewusste Nicht-Ziele:** Help-Rendering-Klasse wie zuvor (Rust zeigt
  kein Cobra-Hilfetext), CLI-005 unverändert.
- **Ergebnis (2026-09-22):** PR #1110 **gemergt `42e3218e`**
  (`65a1db83` Implementierung, `b78bd4b1` Windows-Clippy-Fix
  `Path`-Import). CI vollständig grün inkl. `Rust native
  (windows-latest)` nach Rerun eines `symvault-sync`-Flakes
  (`Access is denied` beim Git-Spawn, testunabhängig). Gates am
  integrierten HEAD `42e3218e`: build/clippy `-D warnings`/`fmt --check` ✅,
  `cargo test --workspace --all-features --locked` 0 Fehler ✅, cligap
  **missing 24**, Flag-Lücken 12, Alias 0, Rust-only 1 ✅. Lokaler
  `make port-contract` endet weiter an #1111 (`config-cli-differential`,
  macOS-only) — kanonisches Gate = Ubuntu-CI (Job `Rust port contract`
  grün, 6m21s).

## Zwischenstand 2026-09-22, Teil 15 — Slice `import review` gemergt (30 → 28)

- **Basis:** `main` @ `a226a6f7`, Checkout sauber, kein fremder WIP, keine
  Rest-Worktrees. Toolchain: Go 1.27.1, Rust/Cargo 1.98.0.
- **cligap frisch auf `a226a6f7`** (`cargo build -p symvault-cli` + `go run
  ./scripts/rust-port/cmd/cligap`, Binary sha256 `67a4a00077d4`): Oracle-Pfade
  134, Rust-Pfade 99, **fehlend 30**, Flag-Lücken 9, Alias 0, Rust-only 1 —
  deckungsgleich mit Teil 14.
- **Slice gewählt: `import review list` + `import review promote` (30 → 28).**
  Begründung: rein offline (`cli.WithVault` + `ListEntries/GetEntry/WriteEntry/
  DeleteEntry`, alles bereits portiert), deterministisch (sortierte Import-IDs),
  volle Byte-Prüfbarkeit inkl. Vault-Seiteneffekte. Go-Referenz
  `cmd/admin/import.go` ~370–478.
- **Blocked-Rows (bewusst, mit Wand):** `approval` + `approval list/decide`
  (3 Pfade, loopback-HTTP gegen laufenden Server, kein HTTP-Client im
  Workspace — dieselbe Wand wie `update check/apply`); `dynamic`/`dynamic
  generate` (2, braucht PostgreSQL/AWS-Backends); `agent setup`
  (Netzwerk-Downloads); `device approval-pair` (Server-Roundtrip);
  `update check`/`update apply` (kein HTTP-Client, cosign). Offline-Teil
  `update info` + `update`-Hilfetext bleibt freier Kandidat für den Folge-Slice.
  `CLI-005` (doppelte `Error:`-Zeilen, Exit-Dialekt) weiter offen, absichtlich
  nicht mitgefixt.
- **Dispatch:** Worktree
  `/Volumes/1TB_NVMe_SN850X/Dev/Symaira_Dev/Repos/symaira-vault-wt-import-review`,
  Branch `feat/import-review` @ `a226a6f7`, ein Worker
  (`CLI-IMPORT-REVIEW-001`), Fixed-Field-Set aus `references/worker-dispatch.md`,
  required skills `go-rust-port-parity`, `code-editing`. Koordinator alleiniger
  Schreiber von Ledger, gemeinsamen Manifests und CI.
- **Geladene Skills dieser Sitzung (nicht erneut laden):** `go-to-rust-migration`
  (SKILL.md + `references/worker-dispatch.md`), `guard-repo`,
  `go-rust-port-parity` + `references/workflow.md`, `autonomous-coding-agents`,
  `parallel-repo-agents`, `code-editing`. `contract-matrix.md`,
  `differential-testing.md`, `rust-stack.md`, `references/porting-pitfalls.md`
  noch **nicht** geladen — nur bei Bedarf nachladen.
- Kein Cutover, kein Release; Go bleibt Produktion und Oracle.

## Zwischenstand 2026-09-21, Teil 14 (nach `f80ef938`) — `agent upgrade` gemergt (#1104), 31 → 30

- **PR [#1104](https://github.com/danieljustus/symaira-vault/pull/1104) squash-gemergt
  als `f80ef938`**: `agent upgrade <name> --tier <tier>` byte-identisch zur
  gepinnten Oracle (Exits/stdout/stderr plus Datei-Baeume nach
  Label-verankerter Random-Normalisierung). Alle Checks gruen
  (`Rust`, `Rust Miri`, `Rust native` macOS+Windows, `Rust port contract`,
  `Pairing differential`, `Test (ubuntu) — PR`, `govulncheck`, `osv-scanner`,
  `Vaultcore (macOS)`, `Process tree (Windows)`). Worktree/Branch danach
  entfernt, `main`-Checkout sauber.
- **cligap auf `main` (frisch gebaut):** Oracle-Pfade 134, Rust-Pfade 98 → 99,
  **fehlend 31 → 30**, Flag-Luecken 9, Alias 0, Rust-only 1.
- **Portiert (`agent_upgrade_commands.rs`, neu):** Tier-Validierung
  (`safe`-Alias, `--tier`-Pflicht), explizite Tier-Diff-Tabelle auf stderr,
  Biometrie-Gate (`--yes` braucht `--reason`; ohne `--no-biometric` nimmt der
  Port Go's Unavailable-Branch), interaktiver Confirm (piped stdin bricht ab,
  Exit 0), Profil-Save mit Tier, optional `--rotate-token` (Revoke-all +
  Create + Token-Datei), Skill-Refresh mit dem neuen Tier.
  Contract-Test `cli_agent_upgrade.rs` (11 Tests, TempDir, Throwaway
  HOME/USERPROFILE, restricted PATH).
- **Scope-Entscheidungen (sichtbar):** `apply_tier_preset_to_profile` in
  symvault-core jetzt `pub` (Upgrade legt das Preset ueber das geladene
  Profil, wie der Install-Writer); `map_scoped_token_error` /
  `write_agent_token_file` / `PINNED_TOOL_REGISTRY_HASH` sind `pub(crate)`;
  neuer Library-Einstieg `refresh_target_with_tier` (explizites Target, kein
  Lookup).
- **Drive-by-Parity-Fix in der Skill-Library:** Refresh-Fehlertexte sind auf
  Library-Ebene jetzt nackt (das `skill refresh`-Kommando setzt das
  `refresh skill: `-Praefix nur um `agentskill.Refresh`, Empty-Target-Fehler
  bleibt praefixlos) — entspricht Go `cmd/mcp/agent_skill.go`. Bestehende
  Skill-Tests weiter gruen.
- **Differential-Befunde (alle verifiziert):** 13/14 Faelle byte-identisch.
  (1) Auf einem TouchID-Mac zeigt Go einen echten TouchID-Prompt und folgt
  ihm — der Port nimmt den Unavailable-Branch (Warnung + Confirm bzw. Fehler
  mit `--yes`); auf Linux/Windows/allen CI-Runnern identisch, Contract-Tests
  nutzen ueberall `--no-biometric`. Kein Repo-Test deckt den Pfad ab (auf
  TouchID-Macs nicht deterministisch). (2) Go `TierPresets` kennt kein
  `"safe"` — der Loader wendet bei handgeschriebenem `tier: safe` kein Preset
  an (altes `canWrite: true`); `get_preset("safe") → None` repliziert den
  Miss. (3) Registry-Keys sind zufaellige ID-Suffixe (Sortierung variiert pro
  Lauf) — Normalisierung label-verankert statt positionsbasiert; Token-`prefix`
  und Tool-Registry-Hash flach normalisiert. (4) `vault/.lock`-Leftover ist
  Pre-existing (alle Store-Writes, flock-Stil; Go kennt keine Lock-Dateien) —
  separat als Issue [#1105](https://github.com/danieljustus/symaira-vault/issues/1105)
  angelegt, Differential ignoriert die Datei.
- **Gates auf dem Branch:** `cargo fmt --check`, `cargo clippy --workspace
  --all-targets --all-features --locked -- -D warnings` (0 Fehler),
  `cargo nextest run --workspace --all-features --locked` (**816 passed**,
  4 skipped — 805 + 11 neue), Doc-Tests.
- **Naechster Slice:** naechster Oracle-Pfad aus `cligap`-missing angreifen;
  `agent setup` (Netzwerk-Downloads), `update check/apply` (kein HTTP-Client,
  cosign) und `device approval-pair` (Server-Roundtrip) bleiben blockiert.
  CLI-005 (doppelte `Error:`-Zeilen) weiter offen, absichtlich nicht mitgefixt.

## Zwischenstand 2026-09-21, Teil 13 (nach `489a3a85`) — `agent install` gemergt (#1103), 32 → 31

- **PR [#1103](https://github.com/danieljustus/symaira-vault/pull/1103) squash-gemergt
  als `489a3a85`**: `agent install` byte-identisch zur gepinnten Oracle
  (Exits/stdout/stderr, Vault-`config.yaml` stdio+http, Agent-Dateien
  YAML/JSON/TOML nach Random-Normalisierung, alle Fehler inkl.
  CLI-005-Dopplung). Contract-Test `cli_agent_install.rs` (13 Tests) gegen 12
  gefrorene Oracle-Fixtures.
- **cligap auf `main` (frisch gebaut):** Oracle-Pfade 134, Rust-Pfade 97 → 98,
  **fehlend 32 → 31**, Flag-Luecken 9, Alias 0, Rust-only 1.
- **Windows-CI-Lehren (3 Fix-Runden, alle testseitig — der Port ist Go-treu):**
  (1) `run()` setzt zusaetzlich `USERPROFILE` aufs Throwaway-Home — Go
  `os.UserHomeDir` (vom Port-`expand_tilde` gespiegelt) ignoriert `HOME` auf
  Windows, sonst entkommt der Default-`~/.hermes/...`-Skill-Pfad ins echte
  Runner-Profil. (2) `normalize()` faltet `\` → `/` (kein Fixture enthaelt
  Backslash). (3) JSON escapt `\` als `\\` — escaped-Root zuerst ersetzen,
  danach alle `//`-Runs kollabieren außer `://` (URL-sicher).
  Verlauf: 4/13 → 11/13 → 12/13 → 13/13, danach 22/22 Checks gruen.
- **Scope-Entscheidungen (sichtbar in PR/Teil 12):** `getrandom` in
  CLI-`Cargo.toml`, `PINNED_TOOL_REGISTRY_HASH`-Konstante,
  `open_nofollow_kind`-Fix (macOS `/var`), Writer `autoUnseal`-zuerst.
- **Naechster Slice:** naechster Oracle-Pfad aus `cligap`-missing angreifen;
  `agent setup` (Netzwerk-Downloads), `update check/apply` (kein HTTP-Client,
  cosign) und `device approval-pair` (Server-Roundtrip) bleiben blockiert.
  CLI-005 (doppelte `Error:`-Zeilen) weiter offen, absichtlich nicht mitgefixt.

## Zwischenstand 2026-09-21, Teil 12 — `agent install` gebaut (32 → 31), PR offen

- **Gebaut in `feat/agent-install`** (Worktree
  `symaira-vault-wt-agent-install`): `crates/symvault-cli/src/agent_install_commands.rs`
  portiert `cmd/mcp/agent_install.go`, `cmd/mcp/mcp_install.go`
  (`buildServerConfig`, `stdioArgs`, `ResolveHTTPPort`) und
  `internal/mcp/install/*` (Detect-Tabelle, YAML/JSON/TOML-Injektoren,
  `BackupConfig`, `Install`), inklusive Token-Erzeugung im Registry-Store
  (`agent-install-*`-Display-Token plus zweites gescopetes `mcp-install-*`-Token
  fuer HTTP-Bearer), `health_check` per TCP+`GET /health`, Auto-Detect
  (`install_single → (InstallResult, Result<(), String>)` wie Go) und
  Skill-Install via `install_with_tier`/`profile_tier`-Template-Var. Kein
  `toml`-Crate: der TOML-Header/Array-Injektor ist handgerollt (quote-aware
  Klammertiefe). Dazu `AgentCommand::Install` plus Dispatch in `main.rs`.
- **Scope-Entscheidungen (sichtbar):** `getrandom = "=0.3.3"` neu in
  `crates/symvault-cli/Cargo.toml` (32-Byte-Secret-Paritaet);
  `PINNED_TOOL_REGISTRY_HASH` als Konstante (Go berechnet sha256 ueber die
  kompilierten MCP-Tools in `server.init()`, der Port hat kein Aequivalent —
  Upgrade-Pfad im Kommentar); `symvault-store/src/lib.rs`: `open_nofollow_kind`
  oeffnet nur noch die finale Komponente mit `NOFOLLOW` (macOS `/var` →
  `/private/var` scheiterte sonst mit ENOTDIR — echter Port-Bug, Go nutzt
  plain `os.Open`); `config.rs`-Writer: `autoUnseal` vor `requireApproval`.
- **cligap gemessen:** Oracle-Pfade 134, Rust-Pfade 97 → 98, **fehlend 32 → 31**,
  Flag-Luecken 9, Alias 0, Rust-only 1.
- **Differential-Befunde (alle verifiziert, keine offenen Diffs):** Vault-
  `config.yaml` stdio+http byte-gleich; Agent-Dateien (YAML/JSON/TOML) byte-
  gleich nach Random-Normalisierung; alle Exits stdout/stderr gleich.
  Geklaert und dokumentiert: (1) Oracle schreibt das **volle** 64-Hex-Bearer
  in die Agent-YAML (vermeintliches `first6...last4` war ein
  Terminal-Display-Artefakt — Lehre in `porting-pitfalls.md`); (2)
  `vaultDir` im gespeicherten Config ist der Resolver-Default bzw. `vDir` bei
  frischer Config, nie `--vault`-Flag-Magie; (3) Multi-Agent-Auto-Detect-
  Reihenfolge ist in Go map-zufaellig — der Port geht deterministisch in
  Definitionsreihenfolge (Single-Agent-Faelle byte-identisch); (4) Backup wird
  auch fuer leere Seeds geschrieben (0-Byte-`.backup` plus `Backup:`-Zeile);
  (5) builtin Default-Profile zaehlen als "already exists" ohne `--force`.
- **Repo-Test:** `crates/symvault-cli/tests/cli_agent_install.rs` (13 Tests,
  nicht ignoriert, ohne Umgebungsvariablen, `tempfile::TempDir`, restricted
  `PATH=/usr/bin:/bin` wie die Captures), 12 Fixtures unter
  `crates/symvault-cli/tests/fixtures/agent-install/` (Oracle-Bytes, frisch
  re-captured: `codex` braucht Empty-Seed statt `{}`).
- **Gates gruen:** `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --all-features --locked -- -D warnings`,
  `cargo nextest run --workspace --all-features --locked` (805 passed,
  4 skipped), Doc-Tests. Session-Env-Lehre: `SYMVAULT_VAULT`-Leak im
  Terminal bricht `config_session_contract` — vor Gates `unset`ten.
- **Naechster Schritt:** committen, PR stellen, CI gruen abwarten, squash-mergen,
  Ledger-Teil-13 mit Merge-SHA.

## Zwischenstand 2026-09-21, Teil 11 (nach `e6e0dc0d`) — `agent skill*` gemergt, naechster Slice `agent install`

- **PR [#1102](https://github.com/danieljustus/symaira-vault/pull/1102) squash-gemergt
  als `e6e0dc0d`.** Alle Checks gruen im Lauf `35629952769` (`Rust`, `Rust Miri`,
  `Rust native` macOS+Windows, `Rust port contract`, `Pairing differential` und
  `Audit differential` auf drei Plattformen, `Test (ubuntu) — PR`, `govulncheck`,
  `osv-scanner`, `Process tree (Windows)`, `Flake vendorHash`, `Vaultcore (macOS)`).
  Worktree und Branch danach entfernt, `main`-Checkout sauber.
- **Stand der Luecken:** fehlende Oracle-Pfade **35 → 32**, Rust-Pfade 94 → 97,
  Flag-Luecken 9, Alias-Luecken 0, Rust-only 1 (Oracle 134).
- **Zwei CI-Funde wurden vor dem Merge behoben, beide echte Bugs im neuen Test,
  nicht Flakes:**
  1. `Rust native (windows-latest)` rot: die ueber `include_str!` gelesenen
     Fixtures waren im CRLF-Checkout konvertiert, der Renderer liefert LF.
     Fix: `.gitattributes` pinnt `crates/symvault-cli/tests/fixtures/**` auf
     `text eol=lf` **und** beide Loader normalisieren CRLF (`16919297`).
  2. `Rust native (macos-latest)` rot: der Byte-Vergleich nach einem *legitimen*
     Rewrite war zeitabhaengig, weil der Rewrite einen frischen
     `managed_installed_at`-Stempel setzt (`16:58:40` vs `16:58:41`). Fix: volle
     Byte-Gleichheit nur dort, wo **kein** Schreiben erwartet wird; sonst
     Vergleich ohne die Zeitstempel-Zeile (`b856b7dd`).
  Beide Lehren stehen jetzt in
  `symskills/library/go-to-rust-migration/references/porting-pitfalls.md`.
- **Naechster Slice spezifiziert:** `docs/rust-port/next-slice-agent-install.md`
  (`agent install`, optional `agent upgrade`; Ziel 32 → 31). Offline, setzt auf
  dem in Teil 10 gebauten Skill-Writer und dem portierten Token-Store auf;
  `agent setup` bleibt wegen Netzwerk-Downloads ausgeschlossen.
- **Verbleibende Blocker unveraendert:** `update check`/`apply` (kein HTTP-Client
  im Workspace), `device approval-pair` (kontaktiert den laufenden Server),
  `CLI-005` (Oracle druckt jeden Fehler doppelt — reproduziert, nicht behoben).

## Zwischenstand 2026-09-21, Teil 10 (nach `6649caf0`) — `agent skill*` gebaut

- **Gebaut in `feat/agent-skill-commands`** (Worktree
  `symaira-vault-wt-agent-skill`): `crates/symvault-cli/src/agent_skill_commands.rs`
  portiert `cmd/mcp/agent_skill.go` und `internal/agentskill`
  (`skill.go`, `install.go`, `manifest.go`), inklusive einer kleinen
  `text/template`-Teilmenge (`define`/`template "…" .`/`if eq`/`{{.Field}}`,
  Trim-Marker `{{-` und `-}}`), des Frontmatter-Schreibers, des `tar.gz`-Exports
  und von `refresh` (Sentinel-Pruefung, Body-Digest, `.bak`-Backup, 0750/0600,
  Traversal-Ablehnung). Dazu die sechs Template-Assets als byte-identische
  Kopien unter `crates/symvault-cli/assets/agent-skill/**`, eine `mod`-Zeile,
  `AgentCommand::Skill`/`AgentSkillCommand` und ein Dispatch-Arm in `main.rs`
  sowie `flate2`/`tar` in `crates/symvault-cli/Cargo.toml`.
- **Additiv wiederverwendet:** `agent_token_commands::display_rfc3339` ist jetzt
  `pub(crate)` und formatiert `InstalledAt` (Go nutzt dort `time.RFC3339`,
  Sekundenauflösung — der erste Versuch mit `to_rfc3339_nano` erzeugte 6–10
  Byte zu viel pro Skill-Datei und wurde im Differential gefunden).
- **cligap gemessen:** fehlende Oracle-Pfade **35 → 32**, Rust-Pfade 94 → 97,
  Alias-Luecken 0, Flag-Luecken 9, Rust-only 1 (Oracle 134).
- **Byte-Differential gegen die gepinnte Oracle: 18/19 Faelle identisch**
  in Exit-Code, stdout, stderr, Archiv-Inhalt (Mitglieder, Modi, mtime, uid,
  Nutzdaten) sowie den Bytes der geschriebenen und gesicherten Skill-Datei:
  alle fuenf Agenten, unbekannter Agent, 0/2 Argumente, `-o/--output`,
  Default-Dateiname, `--quiet`, `refresh` fuer fehlende/identische/geaenderte/
  unverwaltete/Traversal-Ziele und fehlende Config.
- **Bewusst normalisiert und benannt, nicht stillgelegt:** (1) `managed_version`,
  `managed_installed_at` und der Versionsstring in `INSTALL.md` sind build- bzw.
  zeitabhaengig (Sekundengenauigkeit und Quoting werden stattdessen im
  Repo-Test geprueft, und `managed_version` wird gegen die Version derselben
  Binary gehalten); (2) `managed_hash` deckt einen Body ab, der den Vault-Pfad
  enthaelt; (3) die Tar-Reihenfolge ist sortiert, weil die Oracle eine Go-Map
  iteriert; (4) die gzip-Stream-Bytes unterscheiden sich zwischen Go und Rust
  (Deflate-Implementierungen) — verglichen werden die extrahierten Inhalte.
- **Einzige verbleibende Abweichung:** `agent skill` ohne Subcommand druckt in
  der Oracle Cobras Hilfe und exitet 0; die Cobra-Hilfe ist ein dokumentiertes
  Nicht-Ziel dieses Ports (wie `symvault help`), also wird nur der Exit-Status
  angeglichen.
- **Repo-Test:** `crates/symvault-cli/tests/cli_agent_skill.rs` (12 Tests, nicht
  ignoriert, ohne Umgebungsvariablen, `tempfile::TempDir` statt Zeitstempel —
  Issue-#1085-Typ), Fixtures sind die Oracle-Ausgaben selbst unter
  `crates/symvault-cli/tests/fixtures/agent-skill/`. Negativprobe: falscher
  Output-Name fuer `codex` → Contract-Test rot, restauriert gruen.
- **Gates gruen:** `cargo fmt --all --check`, `cargo clippy -p symvault-cli
  --all-targets -- -D warnings`, `cargo test -p symvault-cli` (46 Suiten),
  `cargo test -p symvault-sync`.
- **Delegation-Wand:** der Worker `sa-0-eba56320` (`CLI-AGENT-SKILL-001`) lieferte
  wegen HTTP 429 (Codex-Abo-Limit, Reset in ~27 h) nichts; der Slice wurde wie
  schon beim Alias-/device-Slice vom Koordinator selbst gebaut.

## Zwischenstand 2026-09-21, Teil 9 (nach `6649caf0`) — `device approval-*` gemergt, naechster Slice gewaehlt

- **PR [#1101](https://github.com/danieljustus/symaira-vault/pull/1101) squash-gemergt
  als `6649caf0`.** Alle Checks gruen (`Rust`, `Rust Miri`, `Rust native` macOS+Windows,
  `Rust port contract`, `Pairing differential` auf drei Plattformen, `Test (ubuntu) — PR`,
  `Lint`, `govulncheck`, `osv-scanner`, `Flake vendorHash`). Worktree und Branch danach
  entfernt; `git status` im Haupt-Checkout sauber.
- **Stand der Luecken (cligap am integrierten `main`, Binary sha256 `8e21342d1835`):**
  Oracle-Pfade 134, Rust-Pfade 94, **fehlend 35**, Flag-Luecken 9, Alias-Luecken 0,
  Rust-only 1. Von 43 → 37 → 35 in zwei Slices.
- **Die 35 verbleibenden Pfade, gruppiert (aus `target/resume-evidence/cli-gap-inventory.json`):**
  `serve` 8 (inkl. `install`, `status`, `token create|list|revoke`, `uninstall`),
  `agent` 7 (`install`, `setup`, `skill`, `skill export`, `skill refresh`, `upgrade`),
  `update` 4 (`info`, `check`, `apply`, Root), `approval` 3 (`decide`, `list`, Root),
  `intake` 3 (`watch`, `watch disable`, Root), `broker`, `dynamic`, `dynamic generate`,
  `setup`, `startup-profile`, `ui`, `help`, `generate manpages`, `device approval-pair`,
  `import review list`, `import review promote`.
  Flag-Luecken: `import --quarantine`; `mcp --bind/--port/--tls-ca/--tls-cert/--tls-key`;
  `run --broker/--broker-passthrough/--broker-strict`.
- **Naechster Slice: `agent skill`, `agent skill export`, `agent skill refresh`** (35 → 32).
  Begruendung aus Evidenz: rein offline und deterministisch (Rendering eingebetteter
  Go-Templates + Hash-Vergleich, kein Netz, kein Daemon, keine Plattform), mit
  `internal/agentskill/skill_test.go` (993 Zeilen) als reicher Oracle-Fixture-Quelle.
  Die Abhaengigkeiten sind bereits im Workspace: `tar` und `flate2` liegen in `Cargo.lock`
  und werden von `crates/symvault-sync/src/archive.rs` benutzt; ein Template-Renderer
  existiert als `crates/symvault-sync/src/template.rs`. `expand_tilde` und
  Skill-Pfadauflösung sind in `crates/symvault-cli/src/agent_uninstall_commands.rs` schon
  portiert und sollen wiederverwendet werden.
  **Bewusste Grenze:** Go's `compress/gzip`-Strom ist nicht byte-vergleichbar; export
  vergleicht deshalb den **Archivinhalt** (Eintragsnamen, Modi, Nutzlast-Bytes) und nicht
  die gzip-Bytes — das wird im Test und im PR benannt, nicht verschwiegen.
  **Nicht in diesem Slice:** `agent install`, `agent setup`, `agent upgrade` (schreiben in
  `~/.symaira/bin` und mutieren damit die Maschine) und `serve`/`approval`/`broker`/`intake`
  (Dienste, TLS, Netz).

||||||| parent of 8c25ef94 (feat(cli): port `agent skill`, `agent skill export` and `agent skill refresh`)
## Zwischenstand 2026-09-21, Teil 8 (nach `09961118`) — `device approval-*` gebaut

- **Gebaut in `feat/device-approval-registry`** (Worktree
  `symaira-vault-wt-device-approval`): `crates/symvault-cli/src/device_approval.rs`
  portiert `internal/pairing/devicesession.go` (Register) und
  `cmd/device_approval.go` (`approval-list`, `approval-revoke`), plus zwei Zeilen
  Verdrahtung in `main.rs` und ein additives
  `GoTime::from_offset_datetime` in `crates/symvault-sync/src/pairing.rs`.
- **cligap gemessen:** fehlende Oracle-Pfade **37 → 35**, Rust-Pfade 92 → 94,
  Alias-Luecken 0, Rust-only 1.
- **Byte-Differential:** 12/12 Faelle identisch in Exit-Code, stdout, stderr **und**
  den Bytes der geschriebenen `device-sessions.json` (leerer Store, aktiv/revoked/expired,
  `--quiet`, `-y`, `--yes`, Abbruch `n`, `  Y  `, unbekannte ID, zwei/keine Argumente).
  Zwei Abweichungen sind dabei ausdruecklich normalisiert und benannt, nicht stillgelegt.
- **`CLI-005` erneut belegt und bewusst nicht behoben:** der Oracle-Root-Handler druckt
  jeden zurueckgegebenen Fehler **zweimal** (`Error: …` in zwei Zeilen) und formuliert
  „vault not initialized" anders; reproduziert auch bei `device revoke -y nope`, also
  querschnittlich und vorbestehend. Der Port druckt einmal. Die Fehlertexte selbst stimmen
  (`approval device "x" not found`, `accepts 1 arg(s), received N`, Exit 1).
- **Go-Map-Reihenfolge** der Liste ist kein Vertrag: der Contract-Test vergleicht Zeilen
  als Menge, die deterministische `BTreeMap`-Ordnung des Ports ist eine dokumentierte
  Abweichung.
- **Gates lokal:** `cargo fmt --all --check` 0, `cargo clippy -p symvault-cli --all-targets
  -- -D warnings` 0, `cargo test -p symvault-cli` exit 0 (45 Suiten), `cargo test -p
  symvault-sync` exit 0. Neuer Contract-Test `tests/cli_device_approval.rs` (8 Tests,
  `tempfile`-Wurzeln wegen #1085) plus 8 Unittests im Modul; Negativprobe (Meldung
  absichtlich gebrochen → 1 Test rot, restauriert → gruen).
- **Weiter offen:** `approval-pair` ruft den laufenden Server
  (`https://127.0.0.1:<port>`, Enroll-Secret) und rendert einen QR-Code — eigener
  Dependency-/Plattform-Entscheid. `Enroll`/`Validate`/`CleanupExpired` des Registers
  gehoeren auf den Server-Pfad (`internal/approval/enroll.go`, `internal/approval`), nicht
  zur CLI; `enroll` ist portiert und als ungenutzt markiert.

## Zwischenstand 2026-09-21, Teil 7 (nach `09961118`) — Alias-/Stub-Slice ist gemergt

- **PR [#1100](https://github.com/danieljustus/symaira-vault/pull/1100) squash-gemergt
  als `09961118`.** Alle Checks gruen, darunter `Rust`, `Rust Miri`,
  `Rust native (macos-latest)`, `Rust native (windows-latest)`,
  `Rust port contract`, `Pairing differential` auf allen drei Plattformen,
  `Test (ubuntu) — PR`, `Lint`, `govulncheck`, `osv-scanner`, `Flake vendorHash`.
  Lokal zusaetzlich `cargo test -p symvault-cli` (44 Suiten, exit 0), clippy und
  `cargo fmt --all --check`.
- **cligap gemessen vor/nach dem Slice:** fehlende Oracle-Pfade **43 → 37**,
  Alias-Luecken **3 → 0**, Rust-only unveraendert 1 (`mcp serve`).
- **Byte-Beleg:** 14/14 Stub-Aufrufe identisch in Exit-Code, stdout und stderr, mit
  isolierten HOME/XDG-Wurzeln; zusaetzlich Negativprobe (eine Meldung absichtlich
  gebrochen → 2 Tests rot, restauriert → gruen).
- **Flake-Beitrag vermieden:** der neue Test nutzt `tempfile::TempDir` statt
  `as_nanos()`-Namen. `vault_commands.rs` (von diesem Diff nicht beruehrt) blieb
  beim ersten Kaltstart einmal an der #1085-Kollision haengen und lief danach
  dreimal isoliert gruen — vorbestehend, keine Regression.
- **Worker-Lehre, erneut bestaetigt:** der delegierte Worker `sa-0-8a9ab152`
  (`deleg_1d28d938`) lieferte nichts. Hermes legte einen *eigenen* Worktree
  `.worktrees/subagent-sa-0-8a9ab152` an, der Bericht kam leer zurueck
  (`files_changed: []`, `branch: "main"`, `commit: 55f7023a` = Ledger-Commit),
  der Worktree war danach entfernt. Konsequenz fuer die naechste Karte: der
  absoluten Ziel-Worktree-Pfad gehoert explizit in den Prompt, und der Worker muss
  committen, sobald der erste Test gruen ist.
- **Naechster Slice, vermessen und spezifiziert:** `device approval-list` +
  `approval-revoke`, Vertrag und Acceptance in
  [`next-slice-device-approval.md`](next-slice-device-approval.md).
  `approval-pair` bleibt bewusst draussen (QR-Rendering, LAN-IPs).

## Zwischenstand 2026-09-21, Teil 6 (nach `55f7023a`) — Alias-/Stub-Slice gebaut (PR #1100)

- **Gebaut in `feat/cli-aliases-deprecated-stubs`** (Worktree
  `symaira-vault-wt-cli-aliases`, Commit `1664712f`, PR
  [#1100](https://github.com/danieljustus/symaira-vault/pull/1100)):
  (1) die drei Cobra-Aliase aus der Oracle-Baumdatei — `get` → `show`, `cat`;
  `list` → `ls` —, (2) sechs versteckte deprecated v4.0-Befehle byte-genau:
  `mcp token`, `mcp token create|list|revoke`, `mcp-config`,
  `mcp-token-rotate` (stdout leer, Exit 2, vier stderr-Zeilen).
- **Gemessen, nicht angenommen, zwei Oracle-Eigenheiten:**
  - `mcp token <unbekannt>` druckt die **Gruppen**-Meldung: Cobra hat keine
    `Args`-Schranke und fällt auf den Parent-`RunE` zurück. Deshalb ist das
    Rust-`Token` ein Catch-all mit Wort-Dispatch statt clap-Subkommandos.
  - `--quiet` unterdrückt **keine** der vier Zeilen (gleicher stderr mit und
    ohne `--quiet`).
- **Belege:** Differential gegen das gepinnte Oracle-Binary mit isolierten
  HOME/XDG-Wurzeln — **14/14** Aufrufe byte-identisch in Exit-Code, stdout und
  stderr (inkl. `--quiet`- und Argument-Varianten). `cligap`: fehlende
  Oracle-Pfade **43 → 37**, Alias-Lücken **3 → 0**, Rust-only 1 unverändert.
  Neuer, nicht ignorierter Contract-Test
  `crates/symvault-cli/tests/cli_alias_deprecated_stubs.rs` (4 Tests);
  Negativprobe: verfälschte Meldung → 2 Tests rot, restauriert grün.
  `cargo fmt --all --check` und `cargo clippy -p symvault-cli --all-targets`
  grün.
- **Bewusst nicht im Slice:** der vorbestehende Exit-Code-Dialekt bei „vault not
  initialized“ (Oracle Exit 3 + dreizeilige stderr, Rust Exit 1 + eine Zeile),
  identisch für Aliase **und** kanonische Befehle, bleibt `CLI-005` (`TODO`);
  `symvault help` bleibt dokumentierte Nicht-Zusage.
- **Worker-Ausfall, als Lehre notiert:** `deleg_1d28d938` (`sa-0-8a9ab152`)
  lieferte **nichts**. Hermes legte dem Worker einen *eigenen* Worktree
  `.worktrees/subagent-sa-0-8a9ab152` an; der Worker editierte dort, verlor die
  Orientierung (Ende in `/Users/daniel`), meldete `files_changed: []`,
  `branch: "main"` und `commit: 55f7023a` (mein Ledger-Commit) und der Worktree
  wurde beim Beenden entfernt — die Arbeit war weg, nichts war committet.
  Konsequenz: Wer in einem **vorgegebenen** Worktree dispatcht, muss dem Kind
  ausdrücklich sagen, dass es nicht in einen eigenen Worktree wechseln darf,
  und den ersten Commit verlangen, sobald ein Test grün ist (bestehende Regel,
  hier nicht eingehalten). Der Slice wurde danach vom Koordinator selbst im
  isolierten Worktree gebaut.
- **`main`-CI:** Rerun von Lauf `35610080000` (attempt 2) **success** → der
  Windows-Fehlschlag aus attempt 1 ist als Flake bestätigt
  ([#1099](https://github.com/danieljustus/symaira-vault/issues/1099),
  Kommentar am Issue).
- Kein Cutover, kein Release; Go bleibt Produktion und Oracle.

## Zwischenstand 2026-09-21, Teil 5 (nach `e30789d0`) — `migrate`-Slice integriert, Alias-/Stub-Slice ausgelagert

- **`migrate v4`/`migrate session` sind auf `main`.** PR #1098
  (`bdcdc782`) squash-gemergt als `e30789d0`; der PR war vorher vollständig
  grün (CI-Lauf `35608327679` success, `Rust pairing differential`
  `35608327529` success, alle 18 relevanten Jobs pass, `mergeStateStatus`
  CLEAN). Der Diff berührte **keine** Fixture und keinen Pin (nur
  `crates/symvault-cli/src/main.rs`, `crates/symvault-core/src/session.rs`,
  `crates/symvault-cli/tests/migrate_v4_differential.rs`, `resumption.md`) —
  es gab also nichts neu einzufrieren, und die Pin-Falle aus Teil „2026-09-21
  (nach `a28b6a09`)“ war hier nicht im Spiel. Native CI auf dem Merge-Commit:
  Lauf `35610080000` (`CI`) gestartet, `Rust pairing differential`
  `35610079785` success.
- **CLI-Lücke neu gemessen bei `e30789d0`** (`cargo build -p symvault-cli` +
  `go run ./scripts/rust-port/cmd/cligap`, Binary sha256 `18bfa533cd91`):
  **43 fehlende** Oracle-Pfade (134 Oracle, 92 Rust), 9 Flag-Lücken,
  **3 Alias-Lücken**, 1 Rust-only Pfad (`mcp serve`). Deckungsgleich mit Teil 4.
  Die 43 verteilen sich auf `agent` (6), `serve` (8), `mcp token*`/`mcp-config`/
  `mcp-token-rotate` (6), `update` (4), `approval` (3), `device approval-*` (3),
  `intake` (3), `import review` (2), `dynamic` (2), `broker`, `generate manpages`,
  `help`, `setup`, `startup-profile`, `ui` (je 1).
- **CLI-005-Beleg (neu, ohne Statuswechsel der Zeile).** Der gepinnte Oracle
  und die Rust-CLI unterscheiden sich in Exit-Code und stderr-Dialekt, wenn der
  Vault fehlt: Oracle `symvault list` → Exit **3**, stderr dreizeilig
  (`Error: …` doppelt plus `Run 'symvault init' for a quick start, or 'symvault
  setup' for the guided wizard.`); Rust → Exit **1**, eine `Error:`-Zeile.
  Bei den (noch) fehlenden Subkommandos trifft clap-Robustheit auf Cobra:
  `mcp token` → Oracle Exit **2** mit Deprecation-Warnung und `Try:`-Hinweis,
  Rust Exit **1** mit `unrecognized subcommand`. Beides bleibt unter `CLI-005`
  (`TODO`, „exit codes 0–10“); hier ist nur die Messung, keine neue Zusage.
- **Ausgelagerter Slice (koordiniert, nicht im Haupt-Checkout gebaut).**
  Worktree `/Volumes/1TB_NVMe_SN850X/Dev/Symaira_Dev/Repos/symaira-vault-wt-cli-aliases`,
  Branch `feat/cli-aliases-deprecated-stubs` auf `e30789d0`; ein Worker
  (`deleg_1d28d938`) baut: (1) die drei **Top-Level-Aliase** aus der
  Oracle-Baum-Datei — `get` → `show`, `cat`; `list` → `ls` (Cobra-Aliase wirken
  top-level, also `symvault show X` ≡ `symvault get X`; `symvault get show X`
  ist dagegen **kein** Vertrag, das Oracle lehnt es mit „accepts 1 arg(s),
  received 2“ ab), (2) die vier **deprecated, versteckten** `mcp token`-Stubs
  (`token`, `create`, `list`, `revoke`) byte-genau: stdout leer, Exit 2, vier
  stderr-Zeilen (Warnung, `Error:` doppelt, `Try:`-Hinweis); (3) neuen
  Fixture-Generator `scripts/rust-port/cmd/deprecstubgen` mit Provenance und
  Digest-Test plus einen nicht-ignorierten Rust-Contract-Test. Erwartung:
  Alias-Lücken 3 → 0, fehlende Pfade 43 → 39. Der Slice ist bewusst klein
  gewählt, weil er vollständig offline und byte-genau prüfbar ist.
- **Entscheidung (nicht portiert, begründet):** `symvault help` bleibt offen.
  Das Oracle-`help` ist Cobras eingebauter Hilfe-Befehl und gibt den
  **kompletten Go-Root-Hilfetext** aus (Exit 0, stdout). Byte-Parität würde das
  Nachbauen von Cobras Renderer verlangen; die Rust-CLI bietet stattdessen
  `--help`. Bleibt als Nicht-Zusage dokumentiert, kein stiller Skip.
- **Main-CI auf dem Merge-Commit war rot — nicht wegen des Merges.** Lauf
  `35610080000` (`e30789d0`, attempt 1) scheiterte **ausschließlich** in
  `Rust native (windows-latest)` (Job `106366704731`):
  `divergent_pull_matches_go_oracle_projection` bricht in
  `crates/symvault-sync/tests/git_io_gaps.rs:254` beim `GitRepository::init(&local)`
  mit `Io(Os { code: 5, kind: PermissionDenied })` ab; die anderen 4 Tests
  derselben Suite und alle übrigen Jobs des Laufs waren grün. Der Diff des
  Merges berührt `symvault-sync` nicht → kein Regress aus #1098. Erfasst als
  [#1099](https://github.com/danieljustus/symaira-vault/issues/1099); Rerun
  (attempt 2 desselben Laufs) gestartet, Ergebnis beim Schreiben offen. Die
  vorherigen `main`-Läufe (`71af9eb0`, `b1e1c69f`) waren alle grün, also ist
  das ein Flake-Kandidat und kein Dauerzustand.
- **Nächste Slices (geplant, noch nicht dispatcht).**
  - `update` (4 Pfade) ist **nicht** sofort baubar: der Rust-Workspace hat
    überhaupt keinen HTTP-Client (`Cargo.lock` enthält kein `reqwest`/`ureq`/
    `hyper`; `symvault-sync` spricht Git, nicht HTTP). Das Oracle nutzt
    stdlib `net/http` (`internal/update/checker.go`, `cosign.go`) plus
    cosign-Verifikation für `update apply`. Ohne neue Dependency ist nur
    `update info` (Install-Method-Erkennung aus dem Binary-Pfad) und der bare
    `update`-Hilfetext offline portierbar; `check`/`apply` sind bis zu einer
    bewussten HTTP-Transport- und Cosign-Entscheidung als `blocked` zu führen,
    nicht stillschweigend zu vereinfachen. Das ist die kleinste ehrliche
    Variante: Offline-Teil zuerst, Rest explizit blockiert.
  - `device approval-list`, `approval-pair`, `approval-revoke`
    (`cmd/device_approval.go`, ca. 300 Zeilen, dateibasiert, kein Netz) ist der
    nächste vollständig offline prüfbare Kandidat nach dem Alias-/Stub-Slice.
  - Danach der Rest der 43: `serve` (8), `agent` (6), `intake` (3),
    `approval` (3), `dynamic` (2), `import review` (2), `broker`, `ui`,
    `setup`, `startup-profile`, `generate manpages`, `help`.
- Geladene Skills dieser Sitzung: `go-to-rust-migration` (SKILL.md).
  `go-rust-port-parity` und `references/porting-pitfalls.md` wurden noch nicht
  geladen — bei der nächsten Invocation zuerst laden, nicht erneut inventarisieren.
- Kein Cutover, kein Release; Go bleibt Produktion und Oracle.

## Zwischenstand 2026-09-21, Teil 4 (nach `b1e1c69f`) — alle drei `migrate`-Subkommandos portiert

`migrate` ist in der Rust-CLI vollständig: `pseudonymize` (Teil 3), `v4` und
`session`. Die CLI-Lücke schrumpfte über beide Teile von 46 auf **43** fehlende
Oracle-Pfade; kein `migrate`-Pfad steht mehr in `missing_paths`.

- **`migrate v4`** (`crates/symvault-cli/src/main.rs`): weist Agent-Profilen ohne
  Tier-Feld ein Tier zu — `can_run_commands` → `admin`, `can_write` → `standard`,
  sonst `safe` — legt vorher eine Sicherung
  `config.yaml.v3-backup-<unix-stamp>` an und schreibt erst danach. Dry-Run
  schreibt nichts, ein zweiter Lauf meldet „All profiles already have tier
  fields." und legt keine weitere Sicherung an (idempotent).
- **`migrate session`**: aktualisiert eine zwischengespeicherte Passphrase vom
  Legacy-Klartextformat auf die verschlüsselte Form. Zwei neue
  `SessionManager`-Methoden in `crates/symvault-core/src/session.rs`:
  `has_legacy_plaintext_session` (fehlender Eintrag = „kein Legacy“, leerer
  Klartext zählt nicht) und `migrate_session` (Wrap-Key bei Bedarf, Klartext
  wird vor dem Serialisieren verworfen und per `zeroize` gelöscht,
  `max_lifetime_ns` wird auf 8 h defaulted, zweiter Lauf ist ein No-Op). Das
  Flag `--dry-run` erkennt den Legacy-Zustand und schreibt nichts.
- **Tests.** `crates/symvault-core/src/session.rs`: zwei Einheiten-Tests
  (Migration + Idempotenz + Defaulting; No-Op ohne Legacy-Eintrag) — 9/9
  Session-Tests grün. `crates/symvault-cli/tests/migrate_v4_differential.rs`
  vergleicht direkt gegen das gepinnte Go-Oracle (`SYMVAULT_GO_BINARY`).
- **Bewusste Abweichung, im Test dokumentiert:** das Oracle iteriert
  `cfg.Agents`, eine Go-Map, also ist die Reihenfolge der
  `  <name> → <tier>`-Zeilen nicht-deterministisch; Rust läuft über eine
  `BTreeMap` und ist sortiert. Byte-Parität ist dort ohne Nachbau der
  Map-Iteration nicht erreichbar, deshalb vergleicht der Test die **Menge** der
  Zuordnungen plus die stabilen Rahmenzeilen wörtlich. Verifiziert
  nicht-vakuos: ein absichtlich gebrochener `can_write`-Zweig macht den Test rot
  (`cli → safe` statt `cli → standard`), restauriert ist er grün; die
  Zuordnungsmenge wird explizit auf 7 Einträge geprüft.
- **End-to-End am Binary:** `migrate v4 --dry-run` schreibt nichts;
  der echte Lauf vergibt 7 Tiers und legt genau eine Sicherung an, die nachweislich
  die Vor-Migrations-Config ohne `tier:`-Zeilen enthält; der zweite Lauf ist ein
  No-Op. `migrate session` meldet ohne Legacy-Eintrag „No legacy plaintext
  session found. Nothing to migrate." — der Legacy-Pfad selbst ist
  cross-process nicht darstellbar, weil der Test-Keyring prozesslokal ist
  (gilt für Go genauso), und wird deshalb durch die Einheiten-Tests belegt.
- **Gate-Sweep** über alle 24 `port-contract`-Voraussetzungen: **23 PASS**;
  einziger FAIL ist weiterhin der macOS-Temp-Dir-Flake
  [#1085](https://github.com/danieljustus/symaira-vault/issues/1085), auf pristine
  `origin/main` identisch reproduziert.
- Kein Cutover, kein Release; Go bleibt Produktion.

## Zwischenstand 2026-09-21, Teil 3 (nach `71af9eb0`) — `migrate pseudonymize` portiert

Der nächste freigegebene Slice aus `RUST-009` ist gebaut: `symvault migrate
pseudonymize` existiert jetzt nativ in Rust und verhält sich wie das gefixte
Go-Oracle (`cmd/admin/migrate.go`, Order-Fix aus #1088).

- **Store-API** `Store::migrate_pseudonymize(&Identity) -> PseudonymizeSummary`
  (`crates/symvault-store/src/lib.rs`). Sie wandelt alle `entries/**/*.age` in
  HMAC-abgeleitete Pfade um. Der logische Pfad kommt aus dem Ciphertext
  (`entry.path`), nicht aus dem Dateinamen — nach der ersten Migration ist der
  Dateiname kein Identifikator mehr. Bereits abgeleitete Ziele werden
  übersprungen; würde man den abgeleiteten Namen erneut hashen, verwaiste der
  Eintrag. Die Klartextdatei wird erst entfernt, **nachdem** das Ziel bestätigt
  auf der Platte liegt; fehlt es, bricht die Migration mit Fehler ab, statt still
  zu löschen.
- **Die P0-Lehre ist jetzt strukturell abgesichert, nicht nur nachgeahmt.**
  `migrate_pseudonymize` **verweigert** die Arbeit mit `StoreError::Config`,
  solange `pseudonymize_paths` nicht gesetzt ist. Genau die umgekehrte
  Reihenfolge — Flag erst nach dem Rewrite-Loop setzen — hatte in Go jeden
  Eintrag auf seinen eigenen Klartextpfad geschrieben und dann gelöscht (#1088).
  Die CLI aktiviert das Flag deshalb **vor** dem ersten Schreibvorgang und öffnet
  den Store danach neu.
- **CLI** `crates/symvault-cli/src/main.rs`: Subkommando in der `MigrateCommand`-
  Enum, Dispatcher-Zweig und `run_migrate_pseudonymize` mit
  `-y/--yes`-Bestätigung; ohne `-y` fragt es interaktiv „Migrate all entries to
  pseudonymized paths. Make a backup first (y/N)" und bricht bei `n` mit
  „Canceled" ab — deckungsgleich mit `cli.ConfirmInteractive` im Oracle.
- **Tests** `crates/symvault-store/tests/pseudonymize_migration.rs` (3 Fälle,
  grün): Migration erhält jeden Eintrag und lässt keine klartextbenannte Datei
  zurück; zweiter Lauf ist ein No-Op (`migrated == 0`, Dateizahl unverändert);
  ohne Flag wird mit `StoreError::Config` verweigert und der Vault bleibt
  unberührt.
- **End-to-End am echten Binary** (`target/debug/symvault`, temporärer Vault):
  3 Einträge angelegt (`example.one`, `work/nested/two`, `deep/a/b/c/three`),
  migriert („Migrating 3 entries to pseudonymized paths..."), alle drei unter
  ihrem logischen Pfad lesbar, Dateizahl 3 vor und nach der Migration, zweiter
  Lauf schreibt 0 Einträge um, `list` liefert weiter alle drei. Abbruchpfad mit
  `n` verifiziert.
- **CLI-Lücke gemessen** (`scripts/rust-port/cmd/cligap`): 134 Oracle-Pfade,
  90 Rust-Pfade, **45 fehlen** (vorher 46), 9 Flag-Lücken, 3 Alias-Lücken,
  1 Rust-only Pfad. `migrate pseudonymize` ist nicht mehr in
  `missing_paths`. `CLI-002`/`CLI-003` bleiben `TODO`: Oberflächen-Erreichbarkeit
  ist keine Verhaltensparität und hebt keine Matrix-Zeile an.
- **Gate-Sweep** über alle 24 `port-contract`-Voraussetzungen: **23 PASS**. Der
  einzige FAIL ist der bekannte macOS-Temp-Dir-Flake
  [#1085](https://github.com/danieljustus/symaira-vault/issues/1085)
  (`config-cli-differential`, `Not a directory (os error 20)`) und **auf pristine
  `origin/main` identisch reproduziert** — kein Regress dieses Slices.
- Ein früherer `rust-007-fixtures-check`-FAIL war **selbstverschuldet**: ein
  exportiertes `SYMVAULT_VAULT` aus einem vorherigen E2E-Lauf erbte in
  `configgen` und backte den echten Vault-Pfad statt `/fixture/root/...` in die
  Fixture. Mit sauberer Umgebung grün; Fixtures unverändert. Lehre: nach
  E2E-Läufen `SYMVAULT_*` vollständig `unset`, bevor Fixture-Generatoren laufen.
- Kein Cutover, kein Release; Go bleibt Produktion.

## Zwischenstand 2026-09-21, Teil 2 (nach `c218771c`) — Dependency-Bumps blockieren die Pins nicht mehr

Der zuvor strukturell blockierte Dependabot-Bump ist gemergt. Zwei voneinander
unabhängige Kopplungen mussten dafür fallen — die zweite war beim ersten Anlauf
nicht sichtbar und ist der eigentliche Fund.

- **Kopplung 1 — `go.mod`/`go.sum` im erzwungenen Digest.** Der Bump ließ
  `TestManifestKeyProductionFixture` mit „production source differs from
  `3232e31f`: **go.mod**" scheitern: fünf Fixtures banden die
  Dependency-Manifeste in den *erzwungenen* Quellcode-Digest. Behoben in
  [#1094](https://github.com/danieljustus/symaira-vault/pull/1094) (`b5e5de32`):
  neuer `EnforcedSources`-Helfer, `go.mod`/`go.sum` bleiben als Provenance in
  `source_files` dokumentiert, gaten aber nicht mehr. Betroffen waren
  `mcprendergen`, `exportgen`, `manifestkeygen`, `configprofilegen` (blieb grün),
  `focus` und `mcpprompts`.
- **Kopplung 2 — Oracle-Harness parste `CombinedOutput` als JSON.** Nach dem
  Bump wurde `Rust port contract` rot, obwohl lokal alles grün war. Ursache ist
  **nicht** der Bump: `go run` schreibt Modul-Downloads und Build-Diagnostik nach
  stderr, und bei **kaltem Modul-Cache** landen diese Zeilen *vor* der
  JSON-Payload. Wer `CombinedOutput` an `json.Unmarshal` gibt, liest dann
  `go: downloading …` als Dokument und stirbt mit
  `invalid character 'g' looking for beginning of value`. Ein Bump erzwingt
  genau diesen kalten Pfad — deshalb sah es wie ein Bump-Regress aus.
  `syncgen`, `storegen` und `cxfgen` trennen die Ströme jetzt
  (`cmd.Output()` plus erfasstes `stderr` für die Fehlermeldung). Reproduziert
  wurde der Fehler absichtlich mit `GOMODCACHE=$(mktemp -d) go test ./...`.
- **Folge: drei Fixtures provenance-only neu eingefroren.** `syncgen`,
  `storegen` und `cxfgen` führen ihre **eigene** `main.go` in
  `generator_files`; jede Änderung an ihnen bewegt den `generator_digest`.
  Betroffen: `testdata/port/{sync/sync,import/cxf,store/store}.json` — je genau
  eine Zeile (`generator_digest`), Bodies und `source_digest` byte-identisch.
  Kein Full-Re-Freeze: der würde zusätzlich Eintrags-Zeitstempel und
  Encryption-Nonces umschreiben (#1015 bleibt dafür offen).
- **Gemessen auf `00f42edb` (PR [#1095](https://github.com/danieljustus/symaira-vault/pull/1095),
  Squash-Merge `c218771c`).** CI: 18/18 relevante Jobs grün, keine Failures —
  inklusive `Rust port contract` (pass, 7m5s), `Test (ubuntu) — PR` (pass, 5m6s),
  `Rust native (windows-latest)` (pass, 7m58s), `Flake vendorHash` (pass) und
  `Rust` (pass). Lokal mit kaltem Modul-Cache: 24 von 26 `port-contract`-Targets
  grün; `rust-gates-core` grün.
- **Vorbestehend rot bleibt ausschließlich** `config-cli-differential` (#1085,
  macOS-Temp-Dir-Kollision, `os error 20`, dreimal sequenziell reproduziert,
  auch mit kaltem Cache); der Job läuft in CI auf ubuntu und ist dort grün.
  `Rust native (windows-latest)` traf den bekannten #1071-Timeout in einer
  früheren Runde und war danach grün — `symvault-sync` ist von diesem Branch
  nicht berührt.
- **Issues geschlossen:** [#1058](https://github.com/danieljustus/symaira-vault/pull/1058)
  (durch #1095 ersetzt) und [#1093](https://github.com/danieljustus/symaira-vault/issues/1093).
  Pin `3232e31f` hat den Squash erneut überlebt (`merge-base --is-ancestor` ✓).
- **Regel für die Zukunft:** Wer einen Generator anfasst, der seine eigene
  Quelldatei in `generator_files` führt, muss die Fixture-Digests im **selben**
  PR nachziehen und den Re-Freeze provenance-only halten. Vor dem Editieren
  `generator_files` aller `testdata/port/**/*.json` gegen die eigene Diff-Liste
  prüfen. In `references/porting-pitfalls.md` festgehalten (zwei Einträge).
- Go bleibt Produktion; kein Cutover, kein Release. Nächster Slice unverändert
  `migrate pseudonymize` (RUST-009; in Rust noch nicht vorhanden).

## Zwischenstand 2026-09-21 (nach `a28b6a09`) — P0 gefixt, Squash-Pin behoben

- **Native CI beobachtet.** `0a123084` → Lauf `35539515206` grün;
  Merge `3232e31f` (PR #1089, Squash) → Lauf `35569092279` **rot**.
- **Squash-Merge hat die Pins zerstört** (eigener Fehler): die Fixtures waren auf
  Branch-Commits (`fd55bb73`, `c7309b0f`) eingefroren. Der Squash entfernte diese
  Objekte; danach schlug auf `main` jedes Gate fehl, das den Pin auflöst
  (`Rust storage differential`, `make port-fixtures-check` — „command-tree fixture
  is stale“), weil `git ls-tree <pin>` ins Leere greift. Ursache ist nicht der Fix,
  sondern die Pin-Wahl.
- **Behoben und wieder grün:** PR
  [#1090](https://github.com/danieljustus/symaira-vault/pull/1090), Squash-Merge
  `a28b6a09`. Alle 19 Pin-Stellen zeigen jetzt auf `3232e31f` — die Revision, die
  dauerhaft auf `main` erreichbar ist (`git merge-base --is-ancestor 3232e31f
  origin/main` ✓). Fixtures erneut eingefroren, weiterhin **provenance-only**.
  Kein Oracle-Quellcode in diesem Fix, deshalb bleibt der Pin inhaltlich korrekt.
- **Native CI für den Merge beobachtet:** `a28b6a09` → `CI` Lauf `35571433190`
  **success**, keine Fehler; `Rust storage differential` `35571433195` und
  `Rust pairing differential` `35571433199` success. Lokal auf `main` zusätzlich
  `port-fixtures-check`, `store-metadata-fixtures-check` (8 Vektoren),
  `cxfgen -check` (19 Cases) und `cargo test -p symvault-store -p symvault-mcp`
  (32 Suites ok) grün.
- **Regel für den nächsten Merge:** Ein Fixture-Pin darf nur eine Revision nennen,
  die von der Basis-Branch dauerhaft erreichbar ist, und das Re-Freeze muss **im
  selben PR** landen. Vor jedem Merge `git merge-base --is-ancestor <pin>
  origin/main` prüfen; schlägt das fehl, ist der Pin eine Zeitbombe. In
  `references/porting-pitfalls.md` festgehalten.
- Go bleibt Produktion; kein Cutover, kein Release. Kein Branch-/Tag-Ereignis.
- **Korrektur früherer Fehleinordnungen** (eigene Fehler, ausdrücklich richtiggestellt):
  - `rust-007-fixtures-check` ist **nicht** vorbestehend rot. Er ist auf `c60e3be5`
    (alte Basis) und auf `f034f061` (jetzt) grün — der ursprüngliche „`config/contract.json`
    is stale"-Befund war ein Fehlschluss aus einem `git stash`-Test, der nichts
    zurückgesetzt hat, weil die Arbeit bereits committet war. `rust-007-differential`
    (6 Fälle) ebenfalls grün, `config-profile-fixtures-check` 62 Cases PASS.
  - `auth_commands` (2 Fälle) ist **nicht** vorbestehend rot. Vollständiger Lauf:
    auf `c60e3be5` 3 passed/0 failed, auf `f034f061` 3 passed/0 failed, dreimal
    sequenziell reproduzierbar grün. Der frühere Fehlschlag war eine
    Parallel-Last-Erscheinung, kein Vertragsproblem und kein Baseline-Rot.
- **Bestätigt vorbestehend rot** ist nur `config-cli-differential`:
  auf `c60e3be5` reproduziert mit `os error 20` (Temp-Dir-Kollision in
  `agent_token_mutations_differential`, Mikrosekunden-Takt aus #1085; allein
  ausgeführt grün). Das ist die einzige rote Baseline, die ich behaupten darf.

## Zwischenstand 2026-09-20, Teil 4 (nach `c60e3be5`) — P0 im Oracle, Slice pausiert

**Der nächste geplante Slice (`migrate pseudonymize`) ist als Oracle unbrauchbar:
die Go-Produktion löscht dabei den ganzen Vault.** Gefunden bei der
Voruntersuchung des Slice, gemeldet als
[#1088](https://github.com/danieljustus/symaira-vault/issues/1088), Fix in
[PR #1089](https://github.com/danieljustus/symaira-vault/pull/1089).

Gemessen mit dem gepinnten Oracle-Build (`target/port/symvault-go`), isoliertes
`HOME`, Memory-Keyring, 2 Einträge:

- `migrate pseudonymize -y` meldet „Migrating 2 entries… / Migration complete.“
  und **Exit 0**, danach existiert **keine einzige Eintragsdatei** mehr:
  `find entries -name '*.age'` → 0, `list` leer, `get` → not found,
  `config.yaml` trägt `pseudonymize_paths: true`.
- Ursache: `cmd/admin/migrate.go` ruft `enablePseudonymizeConfig` **nach** der
  Schleife. `WriteEntry` lädt die Config selbst, `entryStoragePath()` liefert den
  HMAC-Pfad nur bei gesetztem Flag — also schreibt jede Iteration auf
  `entries/<plain>.age` zurück und das folgende `os.Remove` löscht sie.

Drei weitere Defekte derselben Stelle beim Fix gefunden und mitbehoben:
Pfadableitung aus dem Dateinamen (zweiter Lauf hasht den HMAC-Namen erneut),
`PrepareEntryForWrite(pseudonymize=false)` (logischer Pfad landet nie im
Ciphertext), und `ReadEntry`/`readEntryInner` ohne Fallback auf
`entries/<plain>.age` (Vault mit Flag und Plaintext-Namen liest sich als leer —
genau der Zustand nach einem fehlerhaften Lauf).

- Fixture-Pins vorgerückt. Der Fix berührt zwei Dateien, die Generatoren als
  gepinnte Oracle-Quelle binden und gegen den Working Tree vergleichen:
  `internal/vault/entry_readwrite.go` (manifestkeygen, storemetagen, 6
  MCP-Generatoren, `cxfgen` über den ganzen `internal/vault`-Closure) und
  `cmd/admin/migrate.go` (`portgen` bindet jede Nicht-Test-Datei unter `cmd/`).
  Betroffene Fixtures neu eingefroren — **alle nur Provenance geändert**, alle
  Vektoren/Cases byte-identisch: `store/metadata.json` (8), 
  `store/manifest-keys.json` (16), `mcp/tools-{delete-entry,generate-totp,
  get-value,list-entries,search-fetch,set-entry}.json`, `import/cxf.json` (19),
  `cli/command-tree.json` (135 Kommandos). Rust-Seite nachgezogen:
  `symvault-store/{src/metadata.rs,tests/manifest_keys.rs}` und die sechs
  `symvault-mcp/tests/tools_*.rs` (inkl. `source_hash`).
  `portgen`/`cxfgen` vergleichen gegen den Pin, konnten also nur eine Revision
  mit sauberem Tree nennen und wurden zusammen mit dem Re-Freeze vorgerückt.
  Geprüft und **unberührt**: `storegen`, `store004gen` (lesen gepinnte Blobs,
  nicht den Working Tree), `configclicasesgen`, `exportgen`, `import1passgen`,
  `importcsvgen`, `mcprendergen`, `sessiongen`, `gitio` (`internal/git`).
- **Vorbestehende, nicht durch diesen Fix verursachte rote Gates** (auf
  pristine `origin/main` bestätigt): `config-cli-differential`
  (Temp-Dir-Kollision in `agent_token_mutations_differential`, der
  Mikrosekunden-Takt aus #1085; allein ausgeführt grün).
  **Korrektur:** `rust-007-fixtures-check` wurde hier ursprünglich mit
  „`config/contract.json` is stale“ als vorbestehend rot geführt. Das war falsch
  und ist oben richtiggestellt: das Gate ist auf der alten wie der neuen Basis grün.
- **Slice-Entscheidung:** `migrate pseudonymize` nicht portieren, solange das
  Oracle den Defekt trägt. Byte-identische stdout/stderr-Fixture hätte die
  Datenlöschung als Vertrag eingefroren. #1089 ist inzwischen gemergt (`3232e31f`)
  — der Slice ist damit **wieder freigegeben**, die Voruntersuchung unten gilt
  weiter, und der Fix selbst muss noch verifiziert werden (die Akzeptanzpunkte
  unten nennen „zweiter Lauf ist ein No-op", was der Fix erst herstellt).
- Go bleibt Produktion; kein Cutover, kein Release.
- **Native CI für `0a123084` inzwischen beobachtet: grün** (Lauf `35539515206`).
  Der Merge-Lauf `35569092279` war rot, weil der Squash die Pins zerstörte; das ist
  oben behoben und mit `a28b6a09` (Lauf `35571433190`, success) belegt.

## Zwischenstand 2026-09-20, Teil 3 (nach `72c14890`)

**Gemessen: die macOS-Testflakes sind eine Uhr-Auflösung, kein Vertragsproblem.**

- `SystemTime::now().as_nanos()` liefert auf macOS Mikrosekunden-Schritte. Messung
  (Wegwerf-Test, 2026-09-20): 30 Samples → 9 verschiedene Werte, **alle** enden auf
  `000`; vier synchron per `Barrier` gestartete Threads bekamen 3 verschiedene
  Werte, zwei denselben. Tests **eines** Binaries benennen ihre Temp-Ordner so und
  landen beim Start im selben Verzeichnis.
- Folge: doppeltes `git init` in einem Ordner → `fatal: cannot copy
  '.../git-core/templates/info/exclude' … File exists`, Exit 128. Das traf am
  2026-09-20 dreimal `Rust native (macos-latest)` (`history_commands.rs:27` und
  `:89`), jeweils ohne Bezug zur geprüften Änderung: Issues #1082, #1085.
- **Behoben:** `crates/symvault-cli/tests/history_commands.rs` nutzt jetzt eine
  `tempfile::TempDir`-Wache plus nicht existierenden Wurzelpfad (PR #1084, Fixes
  #1082). **Offen:** dasselbe Muster in 21 weiteren Dateien unter
  `crates/symvault-cli/tests/` (Liste in #1085) — solange das offen ist, kann der
  macOS-Rust-Job jederzeit ohne Codebezug rot werden; ein Rerun hilft, ist aber
  kein Vertragssignal.
- **Nicht-Vertrag:** `Rust Miri` und `Rust native (macos-latest)` sind die
  langsamsten Jobs (~20 min bzw. ~6 min) und die einzigen, die in dieser Sitzung
  unabhängig von Änderungen rot wurden. Bewertung: natives Gate bleibt Pflicht,
  Flakes werden als Flakes behandelt und nicht als Evidenz.

**Nächster Slice: `symvault migrate pseudonymize`.** Voruntersuchung abgeschlossen,
Implementierung noch nicht begonnen:

- Der Rust-Store kann die Arbeit bereits: `Store::write_entry_at(..., pseudonymize)`,
  `Store::configured_entry_path`, `Store::delete_entry`, `symvault_crypto::pseudonymize_path`,
  Manifest-Pflege — alles vorhanden (`crates/symvault-store/src/lib.rs:1897-2141`).
  Zu portieren ist also die CLI-Schicht, nicht der Kern.
- Go-Oracle: `cmd/admin/migrate.go:46-153`. Vertragspunkte: Abbruch ohne `--yes` gibt
  `Canceled` auf stderr und Exit 0; leerer Vault gibt „No entries to migrate.
  Enabling pseudonymize_paths in config.“ und setzt den Config-Schalter trotzdem;
  sonst „Migrating N entries to pseudonymized paths...“, Fortschritt `\r`-Zeilen auf
  stderr, danach „Migration complete. All entries now use pseudonymized paths.“;
  jede Datei wird gelesen, mit `pseudonymize_paths` neu geschrieben und die
  Plaintext-Datei entfernt; `config.yaml` bekommt `vault.pseudonymize_paths: true`.
- Vorlage für die Rust-Seite: `crates/symvault-cli/src/migrate_kdf_commands.rs`
  (Mutation-Grenze) und die Verdrahtung in `main.rs` (`run_migrate_kdf`, um Zeile 3104).
- **Befund:** `crates/symvault-cli/tests/migrate_kdf_differential.rs` ist
  `#[ignore]` und braucht `SYMVAULT_GO_BINARY`; **kein** Makefile-/Workflow-Ziel setzt
  diese Variable (geprüft). Der Go↔Rust-Vergleich für `migrate kdf` läuft also nur
  manuell und ist kein Gate. Für `migrate pseudonymize` deshalb einen Fixture-Weg
  bauen, der ohne Umgebungsvariable läuft: Generator unter
  `scripts/rust-port/cmd/` (Muster `sessiongen`/`portgen`, Ziel
  `testdata/port/cli/migrate-pseudonymize.json`), Provenance-Digest-Test wie bei
  `sessiongen`, und ein nicht-ignorierter Contract-Test in
  `crates/symvault-cli/tests/`. Oracle-Binary bauen:
  `make port-contract`-Mechanik (`make`-Ziel baut `target/port/symvault-go` aus dem
  Checkout, `PORT_GO_BINARY`), dann den Generator dagegen laufen lassen.
- Akzeptanz für den Slice: (1) Fixture aus dem gepinnten Oracle mit Digest-Bindung,
  (2) Rust-CLI gibt byte-identischen stdout/stderr-Text wie das Fixture, (3) nach dem
  Lauf liegen alle Einträge unter HMAC-Pfaden und kein Plaintext-Name bleibt übrig,
  (4) `config.yaml` trägt `pseudonymize_paths: true`, (5) zweiter Lauf ist ein
  No-op mit der Leer-Vault-Meldung, (6) Abbruch ohne `--yes` lässt Vault und Config
  unverändert, (7) `cargo test -p symvault-cli` und `cargo fmt/clippy` grün.
- Kein Cutover, kein Release: Go bleibt Oracle und Produktion.

## Zwischenstand 2026-09-18 (nach `56e0c83c`, ersetzt nichts darunter)

- **Gepusht:** `56e0c83c` auf `migration/rust-batch-20260916`, Draft PR #1069.
- **Drei native CI-Fehler von `dce458bf` root-cause-behoben** (`d9bc4f0f`):
  Windows-XDG-Pfad parität zu Go komponentenweise gejoint (`xdg_base`/`xdg_root`),
  `share revoke`-Differential sortiert jetzt (Go iteriert eine Map: 3 verschiedene
  Reihenfolgen in 12 Läufen des gepinnten Oracles, also kein Vertrag), macOS
  `ShareStore::read_verified` gegen Symlink-Präfix kanonisiert (Reproduktion:
  Fehler `ENOTDIR` mit Symlink-`TMPDIR`, identisch zum CI-Fehler).
- **Human-TTY-Approval portiert** (`e89a633c`, `bc44b3b6`): `crates/symvault-platform/src/approval.rs`
  mit Prompt-Renderer, Go-Duration-Text, Timeout, Raw-Mode-Restore und
  `/dev/tty`-Zugriff über `rustix` (Crate bleibt `#![deny(unsafe_code)]`).
  Review hat drei Abweichungen gefunden und korrigiert: Enter kommt im Raw-Mode als
  `\r` (nicht `\n`), Cooked-Mode wird vor dem Acknowledge wiederhergestellt,
  Zeilen werden nach Runen (nicht Bytes) gepolstert.
- **MCP `approve_share` verbunden** (`0d5abe96`): menschliche Bestätigung
  verpflichtend, Selbstfreigabe vor dem Prompt verweigert, fehlende TTY fail-closed,
  Grant wird unter Sperre erneut geprüft, Nicht-Bestätigung lehnt ab (wie Go).
  8 neue Protokolltests; Workspace 655/655 grün.
- **CI-Laufzeit gemessen und halbiert** (`56e0c83c`): Der Job `Rust` war mit 33,7 min
  der kritische Pfad, davon ~22 min Miri. Miri läuft jetzt als eigener paralleler
  Job; `make rust-gates` behält seine Bedeutung (`rust-gates-core` + `rust-miri`).
  Basis: `docs/rust-port/ci-runtime.md`. Erwartung ~22 min; nächster Hebel ist die
  Per-Test-Messung der Miri-Laufzeit (läuft).
- **CLI-Lückeninventur erzeugt** (`docs/rust-port/cli-gap-inventory.md`): 11 von 45
  Top-Level-Gruppen fehlen komplett, dazu 30+ Subkommandos und 11 Flag-Lücken.
  Zwei Worker-Lanes laufen dagegen: Agent-Token-Mutationen (`new`/`revoke`/`rotate`)
  und `auth set`/`auth rotate-passphrase`/`audit rotate-key`/`config validate`.
- **Offene, bewusste Lücke:** Windows-TTY-Approval fehlt (fail-closed „deny“,
  `ponytail:`-Kommentar nennt den Upgrade-Pfad `CONIN$`/`CONOUT$` + `SetConsoleMode`).
- Verbleibend: 13 von 35 MCP-Tools ohne Handler (davon 7 GUI-/Biometrie-abhängig),
  HTTP/OAuth/Broker, native Biometrie/Session, Swift-Bridge, Rest-CLI/TUI,
  Release-/Value-/Rollback-Gates. Go bleibt Produktion; kein Cutover/Release.

## Zwischenstand 2026-09-20 (nach `1d534410`)

- **`main` war rot**: CI-Lauf 35505824525 (`1d534410`) scheiterte in
  `Test (macos-latest)` und `Test (windows-latest)`, beide im Go-Testcode der
  Migration, nicht im Produktcode.
  - macOS: `entry_writer_crosslang_test.go:36: build Rust writer: context deadline
    exceeded` — der kalte Cargo-Build der Store-Beispieladapter lief in das
    2-Minuten-Limit des Adapter-Helfers. Alle vier Build-Aufrufe teilen jetzt
    `crosslangBuildTimeout` (15 min); die 2 Minuten bleiben für das Ausführen
    bereits gebauter Adapter.
  - Windows: `sessiongen` legte ein Vault-Verzeichnis `special-<&>-U+2028` an,
    das Windows ablehnt (`mkdir ... syntax is incorrect`). Der Generator entfernt
    dort jetzt `<` und `>` genau wie `fixture_path` im Rust-Differential und
    behält `&`/U+2028, weil darauf der JSON-Escaping-Vertrag beruht.
- Fixture `testdata/port/cli/session.json` wurde bewusst mit dem gepinnten
  Oracle `fca3f894` neu erzeugt; nur `generator_digest` ändert sich. Ein neuer
  Test bindet diesen Digest, weil kein Make- oder Workflow-Ziel `sessiongen`
  ausführt — die Datei konnte bisher unbemerkt veralten.
- Kein Cutover, kein Release; Go bleibt Produktion. Native CI für den neuen Head
  steht aus.

## Zwischenstand 2026-09-20, Teil 2 (nach `622ec619`)

- `main` war rot (`Test (macos-latest)` und `Test (windows-latest)`). Ursache und
  Fix in PR [#1078](https://github.com/danieljustus/symaira-vault/pull/1078),
  gemergt als `622ec619`: das 2-Minuten-Limit des Adapter-Helfers traf kalte
  Cargo-Builds, und `sessiongen` legte unter Windows einen unzulässigen
  Verzeichnisnamen an. Native Abnahme im Dispatch-Lauf 35507740116 auf dem
  PR-Head (beide Jobs grün). Die `main`-CI auf dem Merge-Commit `622ec619`
  (Lauf 35509590715) bestätigt `Test (windows-latest)` und
  `Test (macos-latest)` als erfolgreich; `Test (ubuntu-latest)` und `Rust Miri`
  liefen zum Zeitpunkt dieser Notiz noch.
- CLI-Oberfläche neu und reproduzierbar gemessen: `scripts/rust-port/cmd/cligap`
  vergleicht die Rust-CLI gegen den gepinnten Oracle-Baum
  (`testdata/port/cli/command-tree.json`, `a518124f`) und braucht dafür kein
  Oracle-Binary; Report in `target/resume-evidence/cli-gap-inventory.json`.
  Ergebnis bei `1d534410`: 134 Oracle-Pfade, 89 Rust-Pfade, **46 fehlen**,
  9 Flag-Lücken, **3 Alias-Lücken** (`get show`, `get cat`, `list ls`) und ein
  Rust-only Pfad (`mcp serve`, eine Re-Pin-Entscheidung).
  `docs/rust-port/cli-gap-inventory.md` ist damit ersetzt; `CLI-002`/`CLI-003`
  zitieren die Messung und bleiben beide `TODO`.
- Zwei delegierte Worker lieferten **keinen verwertbaren Beitrag**. Lane 1 schrieb
  vier CLI-Module mit erfundenen Store-/Session-APIs, ohne Fixture und ohne
  Differential (nicht kompilierbar); Lane 2 ein Werkzeug, das Hilfetexte als
  Kommandopfade zählte (Go-Pfade 1, Rust-Pfade 44136). Beides lag ungepusht als
  WIP auf den damaligen Worker-Branches (`subagent-sa-0-cebb4232` und
  `-sa-1-52b3faea`) und gilt ausdrücklich nicht als Fortschritt. Diese Branches
  wurden am 2026-09-20 entfernt; die Inhalte liegen als `git bundle` unter
  `…/recovery/symaira-vault-cleanup-20260920/` (Commits `a6f58fc6`, `df87dadf`).
  Lehre: Worker-Artefakte am Branch prüfen, nicht am Abschlussbericht.
- Kein Cutover, kein Release; Go bleibt Produktion.

## Candidate and provenance

- **Integration candidate before this handover document:** `542175e09d40c2f06a0e1ab2cd0fb412fd8db50b`; it is based on `origin/main` `81210de2720ee000fa26adda4da4080daae01677`.
- The candidate reconciles the reviewed storage-recovery sequence from stale PR [#1020](https://github.com/danieljustus/symaira-vault/pull/1020) and the clean current-main search-index sequence from draft PR [#1025](https://github.com/danieljustus/symaira-vault/pull/1025). Neither source PR is itself claimed as merged by this document.
- The original local `47562eda7610db7d6f854f219023f6b97d90f503` is only a source reference for index-wire behavior. Its direct application conflicts with current main; the candidate uses the complete #1025 acceptance sequence instead.
- During reconstruction a separate checkpoint object (`43010ab28d4fb0448e0b2f3250390d6268dcaa55`) containing other parallel WIP was observed. Its local ref was subsequently absent from the original checkout; do not assume it remains reachable. It is not an input to this candidate and any recovered contents must be reconciled independently, not replayed blindly.
- Product contract PB-2026-09-09 revision 2 was used as an operational constraint: Vault remains standalone-first; no product, repository, module, Swift, release, or deployment migration is included. The local product-boundary commit `d3df9ee9de4ccecf4f6146993414a41f0d2d0e23` was not asserted to be on `main` and was not modified here.

## Integrated bounded scope

The candidate restores and tests the currently commissioned **RUST-005 storage slice**: persisted entry metadata, configured-recipient write behavior, rooted publication/deletion with fault paths, manifest sequencing, deterministic reopen handling, and encrypted search-index wire parity. Relevant public Go consumers remain `internal/vault/entry_readwrite.go`, `manifest.go`, `manifest_updater.go`, and `search.go`; the Rust implementation boundary is `crates/symvault-store` with test-only adapters under `crates/symvault-store/examples/`.

Data ownership remains the existing vault filesystem: encrypted entry files, manifest metadata, and encrypted search indexes. No productive vault was opened or migrated during verification; all contract tests create isolated temporary roots. There is no new public Rust CLI/MCP/HTTP entry point. The shipped Go CLI/service remains the executable reference and rollback implementation.

Native helpers and permissions remain outside this slice: `crates/symvault-platform`, macOS keychain/UI/clipboard/LaunchAgent behavior, Windows locking/reparse semantics, and the Swift `client/` bridge are not migrated or changed. This keeps the current boundary compatible with later Brain integration without enlarging MCP privileges or moving master keys.

## Verification at the candidate source

Executed on **macOS arm64**, Go `1.26.6`, Rust `1.98.0`, with `GOWORK=off`:

| Command | Result | Evidence scope |
| --- | --- | --- |
| `go test -v -timeout=15m -skip 'TestFlow|TestBinaryE2E|Integration' ./...` | PASS | Go CLI, MCP/error handling, filesystem and process-lifecycle suites; no productive vault paths used. |
| `go test ./internal/vault -run '^(TestEntryWriterGoRustLiveAcceptance|TestManifestSequenceGoRustDifferential|TestManifestSequenceJSONTransportControls|TestEncryptedIndexGoRustLiveAcceptance)$' -count=1 -timeout=20m -v` | PASS | Live Go↔Rust writer, manifest, transport-control, and encrypted-index contracts. |
| `go test ./cmd -run '^(TestCmdRun_BrokerWiring|TestCmdRun_WorkingDir)$' -count=1 -v` and `go test ./cmd/crud -run '^TestEditCommand_UpdatesEntry$' -count=1 -v` | PASS | Nested CLI/process output and safe temporary-filesystem behavior. |
| `cargo test -p symvault-store --all-targets --all-features --locked` | PASS | Rust store unit, audit, root-mutation, and adapter targets. |
| `cargo nextest run --workspace --all-features --locked` | PASS: 203 tests | Workspace implementation suite. |
| `make port-contract` | PASS | Frozen Go fixture generation, command/tree and core/crypto differential checks, bounded fuzz smoke. |
| `make rust-security` | PASS | `cargo audit` plus both workspace and fuzz `cargo deny` checks; duplicate-license warnings were non-fatal. |
| `make rust-fuzz-smoke rust-miri rust-features rust-coverage rust-version-contract` | PASS | Pinned fuzz smoke, Miri, feature combinations, coverage summary, and all 10 version differential cases. |
| `golangci-lint run --new-from-rev=origin/main` | PASS: 0 issues | No candidate-introduced Go lint finding. |
| `go run github.com/securego/gosec/v2/cmd/gosec@v2.22.0 -exclude-generated -exclude-dir=testdata ./...` | PASS: 0 issues | CI-pinned Go SAST version; resolved `google.golang.org/grpc` is `v1.83.2`. |
| [Rust storage differential #34369625689](https://github.com/danieljustus/symaira-vault/actions/runs/34369625689) | PASS | Native Ubuntu, macOS, and Windows Go↔Rust storage/publication and live writer/manifest/index checks for PR #1027 head `7ea1cbfb1d1d6350eb7dcbc30545d34dbbda506c`; the preceding source commit is `542175e09d40c2f06a0e1ab2cd0fb412fd8db50b`. |
| [Rust audit differential #34369681055](https://github.com/danieljustus/symaira-vault/actions/runs/34369681055) | PASS | Native Ubuntu, macOS, and Windows audit-differential workflow for the same PR head. |

The current local `golangci-lint run` and locally installed gosec `2.29.0` report pre-existing whole-repository findings outside this candidate. They are not treated as new migration regressions; CI uses pinned `gosec v2.22.0` and remains the authoritative protected gate.

## Deliberate non-claims and blockers

- `RUST-005` remains **in_progress** in `work-items.json`. The above proves bounded native Ubuntu/macOS/Windows storage behavior; it does not prove all read/list/index/legacy-migration paths, cross-process writer behavior, or full transactionality on every supported platform.
- Native Ubuntu, macOS, and Windows storage/audit evidence is recorded above. FreeBSD and iOS runtime evidence is still required for rows that claim those platforms; cross-compilation does not substitute for it.
- RUST-006 audit, RUST-007 platform/config/session, RUST-008 sync/import/export/intake, and all CLI/MCP/HTTP/FFI/distribution/cutover work remain at their ledger states. Do not promote their matrix rows from the presence of a compiled crate or a fixture projection.
- The existing Go fallback is mandatory. Reproducible rollback is: start from pinned `origin/main` `81210de2720ee000fa26adda4da4080daae01677`, build the Go CLI with Go 1.26.6, and operate a copy of a Rust-written test vault only after the future `DIST-005` compatibility gate passes. No Go deletion, release, tag, deployment, or productive-store migration is authorized by this checkpoint.

## Handover operating notes

- Work only from a clean, named candidate branch; retain the Go reference and use the checked-in fixture generators rather than copied behavior.
- Record each native CI run against its exact head SHA before changing matrix status. A configured workflow is not evidence of execution.
- Preserve any re-discovered parallel worktrees/branches and the checkpoint object above. Do not reset, clean, delete, or bulk-commit them.
- **Conclusion at this checkpoint:** `STABILER TEILSTAND, MIGRATION NOCH OFFEN`. The storage/index candidate has native Ubuntu/macOS/Windows evidence and is a bounded behavior-preserving module-move input; it is not release-, cutover-, or consolidation-ready while the listed RUST-005 and later-slice gaps remain.

## Continuation checkpoint: 2026-09-18, HEAD `f929e819`

The active integration branch is `codex/vault-rust-resume-20260917`; the pushed PR branch is `migration/rust-batch-20260916`, PR #1069 remains Draft. Agent profile edit, token listing, audit display, read-only `agent doctor`, signed pending share requests, share lifecycle persistence, and the grant-signing-key loader are connected. `agent doctor` checks the configured profile, skill path, YAML frontmatter, `managed_by: symaira` sentinel, and body SHA-256 drift without modifying files.

The prior general CI failure was reduced to a Clippy `write_literal` warning in the token-table heading. Commit `f929e819` fixes that warning; local workspace Clippy, three focused doctor tests, token/audit differential tests, and 22 sharing tests pass. New CI for `f929e819` must still be observed at the exact head before claiming native acceptance.

Next bounded work: implement the human TTY approval primitive and wire MCP `approve_share` only after safe terminal/timeout tests; then continue remaining agent token mutations and MCP/HTTP/Broker slices. Keep Go production and preserve rollback. Estimated total migration progress remains 50–55% by effort, not an acceptance percentage. All local build/test/cache/temp paths remain on the external NVMe.
