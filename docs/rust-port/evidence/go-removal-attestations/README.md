# Go-removal attestations (CAP-PROC-OTHER)

Reverse checks are the places where the Go oracle *consumes or verifies what Rust wrote*. Go cannot be
replayed from a recording there, so each was run once with Go and the verdict recorded as
`NAME.<goos>.json`: sha256 of every Rust artifact the Go side saw, the Go verdict (command, exit code,
output digest), Go version, oracle commit and the Rust commit that produced the artifacts.

**An attestation is a static, historical claim**, not a re-check: "at oracle `ORACLE_COMMIT`
(`scripts/rust-port/go_observations_common.py`, a fixed commit like the other contracts' pins), built from
`rust_commit`, live Go accepted these artifacts". Nothing re-runs Go. The Go-free make targets run the Rust
halves live and call `go_observations_common.py verify-attestation NAME`, which prints
`attestation ok (static, historical; Go is NOT re-run)` and fails (never skips) when the file is missing,
malformed, for another OS, for another oracle than the pin, records a rejected verdict, holds artifact labels
other than the expected per-attestation list (`EXPECTED_ARTIFACTS`), or names a `rust_commit` that is not an
ancestor of `HEAD` (a foreign file or a shallow clone: fetch the full history). The recorded artifact digests
are provenance of the attested build, not a pin on later builds.

| attestation | Go side | make target that verifies it |
|---|---|---|
| `audit-differential` | `cmd/auditverify` validates the audit log Rust wrote | `audit-differential` |
| `crypto-differential` | `cmd/cryptoverify` validates the age/KDF output Rust emitted | `crypto-differential` |
| `reencrypt-journal-differential` | `TestReencryptJournalGoRustIntegration` drives the Rust binary (Rust-written journal, Go recovers) | `reencrypt-journal-differential` |
| `ffi-differential` | live Go `mobilebind` driver decrypts Rust-produced vault data (`symvault-ffi` interop test; recorded with `SKIP` forbidden in its output) | `ffi-differential` |
| `kdf-go-rust-integration` | Go CLI creates vaults, Rust migrates KDF policy, Go reads back | `kdf-resource-policy-contract` |
| `pairing-oracle` | live Go and Rust CLIs interleaved on shared vaults (`area_pairing_oracle.sh`) | `pairing-oracle-contract` |
| `data-safety-contract` | the 11 *reverse* Go calls of the data-safety contract (`ffi-seed#0-4`, `go-init#3-7`, `zero-key#2`): Go reads, verifies and writes vaults Rust has just changed. Each entry holds the call, its exit code, the digest of its stdout and the digest of the Rust-written vault tree Go was shown | `data-safety-differential` |
| `native-keyring-interop` | Go `NewOSKeyring` writes a native item, Rust updates it, Go reads and deletes it. **linux**: local live-Go run in a throwaway gate container with gnome-keyring. **darwin**: `source: ci-run`, hosted macOS run 41481364542 job 125400227618 at bf5bd120 (live Go three-stage step, passed); valid only while `crates/symvault-platform/src/{os_keyring,macos_keychain}.rs` have the digest recorded in the file | `native_closeout.py keyring` (disposable runners) |

`data-safety-differential` is the replay of `data_safety_contract.py`: the Go-created *seed* vaults are
replayed byte for byte from `scripts/rust-port/fixtures/go-observations/data-safety-contract.<goos>.json`,
and the run states in its output that the 11 reverse verdicts are attested by the file above and are not
re-checked (earlier the recording simply returned the recorded exit code and stdout, which proved nothing
about what Rust wrote).

`ffi-differential`: `crates/symvault-ffi/tests/interop.rs` is a Go-free replay of
`testdata/port/cli-observations/ffi_interop.json` and prints no `SKIP`; the attestation (recorded with SKIP
forbidden) remains the record of the live Go run of the same test and is verified in the same target.

`native_closeout.py keyring` on a workstation is refused (it needs a disposable runner); on darwin its Go
attestation is the CI-run record. The darwin `tui-contract` has **no** attestation: it is an
`ACCEPTED_GAPS` entry printed by `make tui-harness-check` (text in `go_observations_common.py`).

Re-recording: **check out tag `legacy/go-oracle`** (the last pre-delete commit that contains every capture
tool; see [go-oracle-archive.md](../../go-oracle-archive.md)) and run the old commands there: `make
go-attest-other` on each OS (Linux through `scripts/rust-port/go-observations-capture-linux.sh NAME 'make
go-attest-other'`), `data_safety_contract.py --capture-go` for `data-safety-contract` together with its seed
observation, `go_observations_common.py attest-ci` for a CI-run attestation. This tree has none of those modes
(P40c-2 removed them); it only runs `verify-attestation`. A CI-run attestation is accepted only with run URL, job id,
commit and a digest of the exercised sources that matches the tree.

Go observations that replay Rust live against recorded Go output are in
`scripts/rust-port/fixtures/go-observations/`; only the capture tools at tag `legacy/go-oracle` write them. They
record no host paths: temporary roots are stored as `@TREE_ROOT@` / `@WORK@` and restored on replay, and
`make go-observations-selftest` scans this directory and `docs/rust-port/evidence` (decoding base64) for
operator workstation paths (macOS volume, user-home, per-user temp and private-var roots; the regex is
`OPERATOR_PATH` in `go_observations_common.py`) and mkdtemp directories below the Linux temp root. The README
therefore does not spell those prefixes out.

## Oracle build harness checks (P40c-3, cap-proc)

Still in this tree and still allowlisted (they build a Go oracle from the old tree; see
[go-oracle-archive.md](../../go-oracle-archive.md), "Scripts that still drive Go"):

- `mcp-oracle-controls` (`test_build_timeout.py`, `test_mcp_oracle.py`, `test_mcp_compiler_adapter.py`) - tests the
  oracle build/timeout harness.
- `test_oracle_build.py` (run by the area target at Makefile `AREA_ORACLE`) - oracle build harness selftest.
- `scripts/rust-port/build_timeout.py`, `oracle_build.py`, `mcp_oracle.py`, `mcp_compiler_adapter.py` - the Go
  oracle compile budget and builder, used by the HTTP and MCP process contracts.

Retired in P40c-2: the `GoOracle` live mode of `data_safety_contract.py` (the data-safety *reverse* checks exist only
as the attestation above), `reencrypt_journal_fixture.py` and its one-time Go capture of the frozen crash states
(`testdata/port/store/reencrypt-journal.json`; `reencrypt_journal_probe.go.txt` stays as frozen text),
`manual_path_probe.py`, and the `scripts/rust-port/cmd/cligap` Go tool (`cligap.py` is its Python port).

## Go-only tests dropped from make targets

| Go test | was run by | covered by |
|---|---|---|
| `TestStartAutoClearSignalRouterProcessContract` (`internal/clipboard`) | `mcp-clipboard-signals-differential` | Rust `approval::tests::stdio_clipboard_signal_router_process_contract` (still run by that target); the Go child-process half is **not** replayed — the Rust test has no Go comparison |
| `TestTTYReadStringRuneEditing` (`internal/secureui`) | `mcp-secure-input-differential` | Rust `approval::tests::secure_input_matches_go_rune_editing_and_printable_filter` (prefix `approval::tests::secure_input_`) plus the `secure-input-unicode` observation of the Go printable table |
| `TestPrompt_TTYBackend_SignalCancel` (`internal/secureui`) | `mcp-secure-input-differential` | Rust `approval::tests::stdio_prompt_signal_cancel_maps_to_go_context_canceled`, now run by exact name in that target |
| `TestReencryptJournalGoRustIntegration` | `reencrypt-journal-differential` | direction Rust-writes/Go-recovers: the attestation. Direction Go-writes/Rust-recovers: `crates/symvault-store/tests/reencrypt_journal_go_fixture.rs` over frozen Go-written crash states |

## Divergence found while freezing the crash states (closed: Go parity)

Go recovers the state "replacement staged, backup not yet journaled" (journal digest = staged ciphertext and
temp path, no backup, target = original) by keeping the original and deleting the temp file. Rust used to
refuse to open the vault (`re-encryption target changed without an original backup`), leaving journal, temp
file and original in place, so the vault could not be opened after such a crash. Rust now rolls back exactly
as Go does; `reencrypt_journal_go_fixture.rs` asserts Go's post-recovery tree for the `staged` scenario (the
only remaining difference is the already-pinned `config.yaml` rewrite on Go's `Open`). Both implementations
journal the backup path before the original is moved, so a target that is not the staged digest and has no
journaled backup is still the untouched original. A journal entry with a digest but neither a staged temp nor
a backup has no provenance: a changed target there is still refused and nothing is changed
(`tests::recovery_without_backup_rolls_back_only_with_staged_provenance`).

## Windows scope lost with the Go-free replay (recorded, not covered)

- PowerShell completion run through `pwsh` (was part of `cli_artifacts_contract.py` on Windows).
- The device-list Windows job supervisor (`windows_job_guard` was dead code and is deleted; the script refuses
  native Windows).
- No replayed contract in this directory was captured or run on Windows.

## Converted in CAP-PROC-OTHER-RESID

- `mcp-secure-input-fixtures-check`: `secure-input-unicode` observation (`go run secure_input_unicode` accepted
  `go_unicode_print_15.rs`; the file keeps those bytes). Its prerequisite `mcp-ordered-fixtures-check` is the MCP
  fixture regeneration owned by the MCP packet (still live Go here until `local/cap-proc` lands).
- `native_closeout.py` (Go-free; the former `--live-go` hosted-CI runs, `--capture-go` and `--attest-go` are removed):
  - `portable`: `native-closeout-policy.<goos>.json` records that native Go `policygen` regeneration
    (+ `--check`) reproduced `testdata/port/core/policy-contract.json` byte for byte; darwin and linux captured.
  - `keyring`: see the table above.
- `tui_contract.py` / `tui_mutation_test.py` (`make tui-contract`, linux; `make tui-harness-check`, macOS):
  the Go `tuifixture` helper is gone from the Rust runs. `tui_driver.py` (stdlib pty/termios) is the console
  wrapper and fixture editor, the `tui-snapshot` example of `symvault-store` reads the encrypted store, the Go
  side is `tui-contract.<goos>.json` (normalized rows + the Go-made seed vaults), and
  `tui-driver-equivalence.<goos>.json` records that the Python driver produced identical Rust-side rows
  (15 cases, 84 store snapshots, config readbacks, exit/console/editor facts) to the Go helper on the same Rust
  binary and seeds. The tag `legacy/go-oracle` re-records both (`make go-observations-capture-tui` there); editing `tui_driver.py`,
  `tui-snapshot.rs` or the observation makes `tui_driver_equivalence.py check` fail, and the proof can no longer
  be repeated in this tree (the Go helper and the proof mode are gone).
  Only **linux** is captured; darwin is the accepted gap named above.

## Not converted (still need Go, or a Go-built helper)

- `crypto-fuzz-smoke` fuzzes the Go implementation only and was dropped from `crypto-differential`.
- Windows `tui-contract` observation (disposable hosts only).
- `mcp-ordered-fixtures-check` (the prerequisite of `mcp-secure-input-fixtures-check`): `local/cap-proc` converts it.
