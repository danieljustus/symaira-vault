# ADR 0036: Go removal (Rust-only cutover)

Status: **Accepted** 2026-11-04 (maintainer order: complete Go removal, no Go
fallback, no observation window; see ADR 0035 and `docs/rust-port` commit
`2c42c915`).

## Decision

The Go implementation is deleted from the working tree. Symaira Vault is
Rust-only: build, test, lint, fuzz, packaging (Nix, GoReleaser's Rust builder),
CI and release no longer use a Go toolchain, and no Go fallback is kept.

The last tree that still contains Go is archived at the tag
**`legacy/go-oracle`** (created at push time by the coordinator at the last
pre-delete commit `ccaf3bdc`). The frozen fixtures, the recordings under
`testdata/port/**`, the `*.go.txt` detached oracle programs and the
`FROZEN.sha256` / `FROZEN.oracle.json` manifests stay in the tree;
`make fixtures-verify` and `make oracle-reachability-check` prove they are
unchanged and that the pinned oracle commits stay reachable
([go-oracle-archive.md](../rust-port/go-oracle-archive.md)). Regenerating a
fixture or recapturing a recording needs a worktree of the tag.

## What is no longer verified

* **Reverse oracles (plan risk R4).** Go no longer verifies Rust-written data:
  `audit-differential` (Go `auditverify` of a Rust audit log),
  `crypto-differential` (`cryptoverify`), `reencrypt-journal-differential`
  (Go test driving the Rust binary), FFI interop for Rust-sealed ciphertext
  decrypted by Go, and the store/manifest cross-language tests. Replay still
  covers Go-written data read by Rust. "Old Go clients can read Rust-written
  vaults" is no longer tested.
* **Backend test volume (R8).** 4723 Go test, fuzz and benchmark functions
  of the backend (`cmd/`, `internal/`, `pkg/`, root) are gone; the Rust workspace
  replaced them with the crates' own tests plus replays of frozen Go
  recordings. The package to crate mapping (derived from the contract matrix
  rows and from `internal/...`/`cmd/...` citations in `crates/`; a package may
  have only partial coverage in its crate) is below. Packages marked "none
  found" have no Rust counterpart that cites them and are **untested after
  removal** unless a CLI-level replay happens to cover them. The 280 test
  functions of the fixture generators under `scripts/rust-port/` are retired
  with the generators.
* **Fuzz coverage loss (R14).** The Go fuzzers `FuzzCSVImporterParse`,
  `FuzzBitwardenImporterParse`, `FuzzOnePUXImporterParse`, `FuzzParsePassEntry`,
  `FuzzNormalizePath`, `FuzzParseMapping`, `FuzzParseArgon2idParams` and
  `FuzzDecryptAgeEnvelope` are gone. Rust keeps `fuzz/fuzz_targets/age_envelope.rs`
  (`make rust-fuzz-smoke`). The seed corpus of `FuzzNormalizePath` is kept in
  `fuzz/corpus/go_importer_normalize_path/`. Follow-up: add cargo-fuzz targets
  for the Rust importers.
* **Platforms.** Windows and FreeBSD legs and `install.ps1` are dropped
  (the Windows sync-oracle exception stays a recorded historical contract).
* **Darwin-only recordings.** The output-modes corpus and the Touch ID
  observation were recorded on Darwin; other hosts replay them with a visible
  `SKIP`/attestation, not a re-measurement.
* **Capture side.** `SYMVAULT_ORACLE=capture` of `common/go_oracle.rs` and
  `go_oracle_ext.rs` is removed from the Rust tests (replay-or-fail). Recapture
  = check out `legacy/go-oracle`, build the oracle, run the old capture command
  there.
* **Harness self-tests** of the Go build (`differential-go-selftest`,
  `rust-version-contract`, `store004-isolation-check`; `mcp-oracle-controls`
  stays with its owned script until P40c-2), Go lint/security/fuzz/
  coverage gates (golangci-lint, gosec, govulncheck) and the Go-only scripts
  (`run_go_tests.py`, `check-go-coverage.sh`, `go-fuzz-target.sh`,
  `test_go_toolchains.py`, `gen_config_schema.py`) are retired.
* Everything in the "Retired / not replayable" list of
  [go-oracle-archive.md](../rust-port/go-oracle-archive.md) stays unverified.
* Residual divergences accepted before removal: ADR 0032, 0034, 0035.

## Still reading the Go oracle (P40c-2)

Python contract scripts owned by in-flight packets still build or run Go from
the old tree. They are allowlisted in
`crates/symvault-cli/tests/no_go_oracle_refs.rs` and are converted to replay
by P40c-2; until then their `make` targets fail without the archived tree.

## Package to crate mapping

| Go package | Go test functions | Rust home |
|---|---|---|
| `internal/mcp` | 1084 | symvault-mcp (+ symvault-cli `mcp` commands) |
| `internal/vault` | 600 | symvault-store, symvault-sync |
| `cmd/(root)` | 546 | symvault-cli (command tests) |
| `internal/crypto` | 261 | symvault-crypto |
| `internal/config` | 237 | symvault-core, symvault-cli |
| `internal/git` | 164 | symvault-sync |
| `internal/cli` | 162 | symvault-cli |
| `internal/audit` | 155 | symvault-store |
| `internal/session` | 153 | symvault-core, symvault-cli |
| `internal/policy` | 96 | symvault-core, symvault-mcp |
| `internal/health` | 93 | symvault-cli |
| `internal/ui` | 82 | symvault-cli, symvault-platform |
| `internal/update` | 82 | symvault-cli |
| `internal/secureui` | 75 | symvault-cli |
| `cmd/mcp` | 73 | symvault-cli, symvault-mcp |
| `internal/secrets` | 65 | symvault-mcp |
| `cmd/crud` | 63 | symvault-cli |
| `internal/dynamicsecret` | 63 | symvault-cli |
| `internal/importer` | 46 | symvault-cli, symvault-sync |
| `internal/pairing` | 45 | symvault-mcp, symvault-sync |
| `internal/fsutil` | 43 | symvault-core, symvault-cli |
| `internal/intake` | 40 | symvault-sync, symvault-cli |
| `internal/approval` | 37 | symvault-mcp |
| `cmd/auth` | 36 | symvault-cli |
| `cmd/admin` | 32 | symvault-cli |
| `internal/agentskill` | 32 | symvault-cli |
| `internal/metrics` | 28 | symvault-mcp (thin) |
| `internal/template` | 27 | symvault-sync |
| `internal/errors` | 26 | symvault-core, symvault-cli |
| `internal/broker` | 25 | symvault-mcp |
| `internal/redact` | 25 | symvault-core |
| `cmd/file` | 24 | symvault-cli |
| `internal/anomaly` | 21 | symvault-mcp |
| `internal/exporter` | 19 | symvault-cli, symvault-sync |
| `internal/agentctx` | 18 | none found |
| `internal/daemon` | 18 | symvault-cli |
| `internal/ssrf` | 17 | symvault-mcp |
| `internal/autotype` | 16 | symvault-platform |
| `cmd/intake` | 14 | symvault-cli |
| `internal/clipboard` | 14 | symvault-platform, symvault-mcp |
| `internal/payment` | 14 | symvault-mcp |
| `internal/authguard` | 11 | symvault-cli, symvault-mcp |
| `internal/logging` | 9 | symvault-core, symvault-mcp |
| `internal/quotas` | 8 | symvault-core, symvault-mcp |
| `internal/i18n` | 6 | none found |
| `cmd/passlint` | 5 | none found |
| `internal/notify` | 5 | symvault-platform |
| `internal/manpages` | 3 | symvault-cli |
| `internal/mobilebind` | 2 | symvault-ffi |
| `(root)` | 1 | none (beta smoke test) |
| `internal/secureedit` | 1 | symvault-cli |
| `pkg/mobilebind` | 1 | symvault-ffi |

Packages without a Rust counterpart: `internal/agentctx`, `internal/i18n`, `cmd/passlint`, `(root)`.
