# Go-removal attestations (CAP-PROC-OTHER)

Reverse checks are the places where the Go oracle *consumes or verifies what Rust wrote*. Go cannot be
replayed from a recording there, so each was run once with Go and the verdict recorded as
`NAME.<goos>.json`: sha256 of every Rust artifact the Go side saw, the Go verdict (command, exit code,
output digest), Go version, oracle commit and the Rust commit that produced the artifacts. The Go-free
make targets run the Rust halves live and call `go_observations_common.py verify-attestation NAME`, which
fails (never skips) when the file is missing, malformed, for another OS or oracle commit, or records a
rejected verdict. The recorded artifact digests are provenance, not a replay input: the Rust side is
re-tested live.

| attestation | Go side | make target that verifies it |
|---|---|---|
| `audit-differential` | `cmd/auditverify` validates the audit log Rust wrote | `audit-differential` |
| `crypto-differential` | `cmd/cryptoverify` validates the age/KDF output Rust emitted | `crypto-differential` |
| `reencrypt-journal-differential` | `TestReencryptJournalGoRustIntegration` drives the Rust binary | `reencrypt-journal-differential` |
| `ffi-differential` | live Go `mobilebind` driver decrypts Rust-produced vault data (`symvault-ffi` interop) | `ffi-differential` |
| `kdf-go-rust-integration` | Go CLI creates vaults, Rust migrates KDF policy, Go reads back | `kdf-resource-policy-contract` |
| `pairing-oracle` | live Go and Rust CLIs interleaved on shared vaults (`area_pairing_oracle.sh`) | `pairing-oracle-contract` |

Regenerate (needs Go, built Rust): `make go-attest-other` on each OS (Linux in the local-gate image).
Go observations that replay Rust live against recorded Go output are in
`scripts/rust-port/fixtures/go-observations/`; `make go-observations-capture-other` rewrites them.

## Oracle build harness checks to retire with Go (not deleted here)

- `store004-isolation-check` (`test_store004_isolation.py`) – tests the Go oracle build isolation.
- `mcp-oracle-controls` (`test_build_timeout.py`, `test_mcp_oracle.py`) – tests the oracle build/timeout harness.
- `test_oracle_build.py` (run by the area target at Makefile `AREA_ORACLE`) – oracle build harness selftest.

## Converted in CAP-PROC-OTHER-RESID

- `mcp-secure-input-fixtures-check`: `secure-input-unicode` observation (`go run secure_input_unicode` accepted
  `go_unicode_print_15.rs`; the file keeps those bytes). Its prerequisite `mcp-ordered-fixtures-check` is the MCP
  fixture regeneration owned by the MCP packet (still Go there until that lands).
- `native_closeout.py` (Go-free by default; `--live-go` keeps the hosted-CI runs):
  - `portable`: `native-closeout-policy.<goos>.json` records that native Go `policygen` regeneration
    (+ `--check`) reproduced `testdata/port/core/policy-contract.json` byte for byte; darwin and linux captured.
  - `keyring`: `native-keyring-interop` attestation = a live three-stage run (Go `NewOSKeyring` write, Rust update,
    Go read/delete) in a disposable keyring; the Rust half (`native_keyring_rust_half_set_update_read_delete`)
    runs live. **linux** is attested (gate image + gnome-keyring in a throwaway container). **darwin is not**: the
    stages create a private keychain and change the user keychain search list, which is only authorized on a
    disposable runner (`make go-attest-native-keyring` there); until it exists `native_closeout.py keyring` fails on
    macOS with a missing attestation, never skips.
- `tui_contract.py` / `tui_mutation_test.py` (`make tui-contract`, linux; `make tui-harness-check`, macOS):
  the Go `tuifixture` helper is gone from the Rust runs. `tui_driver.py` (stdlib pty/termios) is the console
  wrapper and fixture editor, the `tui-snapshot` example of `symvault-store` reads the encrypted store, the Go
  side is `tui-contract.<goos>.json` (normalized rows + the Go-made seed vaults), and
  `tui-driver-equivalence.<goos>.json` records that the Python driver produced identical Rust-side rows
  (15 cases, 84 store snapshots, config readbacks, exit/console/editor facts) to the Go helper on the same Rust
  binary and seeds. `make go-observations-capture-tui` (Go, Xvfb) re-records both; editing `tui_driver.py`,
  `tui-snapshot.rs` or the observation without re-proving makes `tui_driver_equivalence.py check` fail.
  Only **linux** is captured: the darwin/windows contract drives the real native clipboard and is only allowed on a
  disposable host, so those observations (and `rust-tui.yml`) still need a capture there.

## Not converted (still need Go, or a Go-built helper)

- `crypto-fuzz-smoke` fuzzes the Go implementation only and was dropped from `crypto-differential`.
- darwin `native-keyring-interop` attestation and darwin/windows `tui-contract` observation (disposable hosts only).
