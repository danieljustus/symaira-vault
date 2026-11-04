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

## Not converted (still need Go, or a Go-built helper)

- `tui_contract.py` / `tui_mutation_test.py`: the Go `tuifixture` helper is the PTY console driver and the
  store snapshotter for the Rust runs too, so it needs a Rust/Python replacement before Go can go.
- `native_closeout.py`: native keyring interop (Go writes, Rust updates, Go reads) and `policygen`.
- `mcp-secure-input-differential` still depends on `mcp-secure-input-fixtures-check` (`go run secure_input_unicode`).
- `crypto-fuzz-smoke` fuzzes the Go implementation only and was dropped from `crypto-differential`.
