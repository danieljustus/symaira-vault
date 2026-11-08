# ADR 0036: Go removal (Rust-only cutover)

Status: **Accepted** 2026-11-04 (maintainer order: complete Go removal, no Go
fallback, no observation window; see ADR 0035 and `docs/rust-port` commit
`2c42c915`).

## Decision

The Go implementation is deleted from the working tree. Symaira Vault is
Rust-only: build, test, lint, fuzz, packaging (Nix, GoReleaser's Rust builder),
CI and release no longer use a Go toolchain, and no Go fallback is kept.

The last tree that still contains Go is archived at the tag
**`legacy/go-oracle`**: the last pre-delete commit that contains every capture
tool (integ8 plus the cap-proc merge), created by the coordinator before push. The frozen fixtures, the recordings under
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
  for the Rust importers. 2026-11-08: restored as `fuzz/fuzz_targets/import_*.rs`
  (CSV, CSV mapping, Bitwarden, 1PUX, CXF, pass entry + TOTP, path normaliser),
  all run by `make rust-fuzz-smoke`/`rust-fuzz`. `FuzzParseArgon2idParams` and
  `FuzzDecryptAgeEnvelope` live on in `age_envelope`; the pass directory walk
  (`import_pass`, needs gpg and a filesystem) and the safepath write/remove
  fuzzers are not restored.
* **Platforms.** Windows and FreeBSD legs and `install.ps1` are dropped
  (the Windows sync-oracle exception stays a recorded historical contract).
* **Darwin-only recordings.** The output-modes corpus and the Touch ID
  observation were recorded on Darwin; other hosts replay them with a visible
  `SKIP`/attestation, not a re-measurement. Rust tests that replay a darwin
  transcript are ignored off Darwin with the reason `SKIP (darwin recording):
  replays on macOS only`; `gate_area_check.py log-ok` accepts exactly those
  ignored tests, counted and printed, and only on a non-Darwin host. Linux
  replays darwin observations where the output is host-independent; host-bound
  lines (OS/Arch, symlink modes, the GUI-dependent Touch ID warning) are
  projected onto the replay host by the test, not skipped.
* **Capture side.** `SYMVAULT_ORACLE=capture` of `common/go_oracle.rs` and
  `go_oracle_ext.rs` is removed from the Rust tests (replay-or-fail). Recapture
  = check out `legacy/go-oracle`, build the oracle, run the old capture command
  there. P40c-2 and P40c-3 removed the same modes from the Python side: the capture,
  attest and live-Go subcommands of `go_observations_common.py`, every
  `--capture-go` / `--live-go` / `--attest-go` / `--generate` mode of the
  contract scripts, and the capture-only scripts. Lost with them:
  * re-generating an attestation or a go-observation from this tree (replay and
    `verify-attestation` stay; the files are static, historical claims);
  * the live-Go branch of `native_closeout.py` (portable policy regeneration,
    keyring write/verify) and of `manual_path_contract.py` (Go/legacy-Go/Rust
    three-binary manual comparison, `manual_path_probe.py`);
  * the re-proof of `tui_driver_equivalence` (Python driver vs the Go helper) and
    of the data-safety reverse reads; the darwin `tui-contract` gap is now
    permanent, not "closes when rust-tui.yml passes";
  * byte checks of the retired generator scripts: `frozen_generator_replay.py
    replay` no longer hashes the script files `kdf_policy_fixtures.py` and
    `refresh-read-policy-fixtures.py`. Still recomputed from git blobs of the
    pinned commits: the update `generator_digest` (blob of
    `refresh-update-fixtures.py` at `58d978bb`, `042a20f4...`), the read-policy
    `generator_digest` and the source digests of all three kinds. **Not
    verified any more**, only pinned by the frozen fixture bytes: the KDF
    fixture's `driver_digest` (its blob lives at the tag `legacy/go-oracle`, not
    at the oracle commit) and the script bytes themselves;
  * `mcp_authz_matrix.py --generate` (the matrix is verified, not regenerated).
* **Harness self-tests** of the Go build (`differential-go-selftest`,
  `rust-version-contract`, `store004-isolation-check`; `mcp-oracle-controls` is
  now the tamper controls of the Go-free fixture replay, P40c-3), Go lint/security/fuzz/
  coverage gates (golangci-lint, gosec, govulncheck) and the Go-only scripts
  (`run_go_tests.py`, `check-go-coverage.sh`, `go-fuzz-target.sh`,
  `test_go_toolchains.py`, `gen_config_schema.py`) are retired.
* Everything in the "Retired / not replayable" list of
  [go-oracle-archive.md](../rust-port/go-oracle-archive.md) stays unverified.
* Residual divergences accepted before removal: ADR 0032, 0034, 0035.

## HTTP / MCP process contracts (P40c-3: converted, allowlist empty)

P40c-3 converted the 24 scripts that still built or drove a Go oracle from the
old tree. The `ALLOWLIST` of `crates/symvault-cli/tests/no_go_oracle_refs.rs` is
now empty and asserted empty; the lint also fails on argv-form Go calls
(`['go', 'build', ...]`, `[GO, "build"]`), `Command::new(go)`, absolute `.../bin/go`
paths, `shutil.which('go')`, `exec go`, `$(GO)`/`$(AREA_GO)`/`$(GO_TOOLCHAIN)`
and recipe lines that start with `go`, `go_compiler`, `pinned_go(`, the
`oracle_build` harness, `go.mod`/`go.sum` and Go source trees read from scripts,
`.github/` or the Makefile, so a new script cannot start Go unnoticed. The one
exemption mechanism, `LINE_ALLOW`, is per file and per whole trimmed line.

* `http_{drain,framing,head,oauth,origin,process,replay,slow_peer,timeout,tls,
  token,write}_contract.py`, `mcp_process_contract.py`,
  `toolhash_process_contract.py`, `mcp_http_shutdown_go_tests.py` and
  `test_http001init_isolation.py` replay the committed Go observation and run
  the Rust binary live with the unchanged comparison. No capture mode, no
  `--signals`/`--go-cli`/`--go-seed`, no oracle worktree.
* `mcp_fixture_contract.py` replays the recorded lanes (historical, corrected
  `approval-lifetime-v1`, product-source) of the 26 MCP fixtures: anchor over the
  fixtures and the generator inputs still held in the tree, recorded step
  verdicts, historical captures equal to the anchored bytes, corrected and
  product-source captures equal to the historical fixtures in every field except
  oracle identity, each bound to its lane commit. It creates no git worktree.
  `mcp-oracle-controls` is `test_mcp_oracle.py` (tamper controls).
* Deleted: `oracle_build.py`, `build_timeout.py`, `mcp_compiler_adapter.py`, their
  tests, `go-observations-capture-http` and the dead workflow path filters.
* Restored (they only parse replayed rows): `gate_area_check.py go-json` and
  `go-text-pass`, which seven Makefile area targets read.

**No longer verified** (recapture and re-proof need tag `legacy/go-oracle`):

* the live Go-vs-Rust signal suite of `mcp_process_contract.py --signals` and
  `http_process_contract.py --signals` (the recorded signal observation of
  `signal-process-contract` stays);
* `validate_reference` (the corrected oracle's parent and exact changed-file set,
  read from the Go tree) and the working-tree equality of the product source with
  `58d978bb`; `make oracle-reachability-check` still keeps the pins reachable;
* the byte identity of the 32 fixture generator sources that lived under
  `internal/` and `scripts/rust-port/cmd/` (deleted with the Go tree; their
  digests stay in `historical-inputs.json`, the other 12 inputs are held as
  `historical/**.txt`), the source and generator digests of the overlaid oracle
  trees, the compiler adapter evidence and the Windows timeout-child admission:
  the recorded Go step verdicts are replayed instead;
* the oracle build budget and worktree-cleanup harness.

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
