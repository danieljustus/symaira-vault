# Symaira Vault Rust Migration Implementation Plan

> **For Hermes:** Use subagent-driven-development to implement independent work
> items, but keep parity-sensitive cascading slices under one coordinator. Work
> strictly in dependency order from `work-items.json`.

**Goal:** Replace the Go backend and gomobile bridge with an idiomatic, safe Rust
implementation without changing observable behavior or vault data.

**Architecture:** Keep Go as a black-box oracle while Rust crates are added only
when their first vertical slice starts. Every slice adds Go-generated fixtures,
Rust tests, and a differential case before expanding scope. Cutover is dual-
binary and reversible; Go removal is a later release step.

**Tech stack:** Rust 1.98 / edition 2024, Cargo workspace, clap, serde, age,
zeroize/secrecy, candidate rmcp/keyring/gix adapters, nextest, proptest, insta,
llvm-cov, audit, deny, Miri, cargo-fuzz, native CI.

---

## Global execution protocol

For every task:

1. Re-read `git status --short --branch` and the affected Go implementation/tests.
2. Add or regenerate the Go-oracle fixture first; prove the drift test fails if
   the source contract changes.
3. Add the smallest Rust behavior that consumes the same fixture.
4. Run the focused Rust test and Go↔Rust differential case.
5. Run `cargo fmt`, `cargo check`, Clippy, affected nextest/doctests, and affected Go tests.
6. Update `contract-matrix.md` only when evidence is executable in CI.
7. Update exactly one item in `work-items.json`; do not mark downstream work ready
   before all dependencies pass.
8. Commit one coherent slice when explicitly operating on a task branch. Never
   commit or push from `main`.

No task may read the real keychain or vault. Use fresh HOME/XDG roots, fixed UTC,
fixed locale, generated identities, local-only remotes, and loopback servers.

### Task 1: Freeze the oracle and create the neutral harness

**Objective:** Make CLI, filesystem, process, and protocol comparisons data-driven.

**Files:**
- Create: `scripts/rust-port/cmd/portgen/`
- Create: `scripts/rust-port/cmd/diffharness/`
- Create: `scripts/rust-port/internal/diff/`
- Create: `testdata/port/cli/command-tree.json`
- Create: `testdata/port/cli/cases.json`
- Create: `testdata/port/filesystem/`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Steps:**
1. Pin the Go oracle commit/release in fixture metadata.
2. Generate the full Cobra tree including hidden commands, aliases, groups,
   argument rules, local/persistent flags, defaults, annotations, and help.
3. Implement a harness that captures raw streams, status/signal, recursive
   file manifests, modes, hashes, and timeouts under isolated HOME/XDG.
4. Add deterministic normalizers only for temp roots and explicitly fixed fields.
5. Add `make port-fixtures-check` and `make differential-go-selftest`.
6. Prove the harness detects an intentional local mismatch, then revert it.
7. Run `GOTOOLCHAIN=go1.26.6 make test-fast docs-check port-fixtures-check`.

**Expected:** Go self-comparison passes; a modified golden fixture fails loudly.

### Task 2: Initialize the Rust workspace and `version` slice

**Objective:** Establish a fully gated Rust repository with one byte-exact command.

**Files:**
- Create: `rust-toolchain.toml`
- Create: `Cargo.toml`
- Create: `Cargo.lock`
- Create: `deny.toml`
- Create: `crates/symvault-core/Cargo.toml`
- Create: `crates/symvault-core/src/lib.rs`
- Create: `crates/symvault-cli/Cargo.toml`
- Create: `crates/symvault-cli/src/main.rs`
- Create: `crates/symvault-cli/tests/version.rs`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Steps:**
1. Pin Rust 1.98 with rustfmt and Clippy; set workspace resolver 3, edition 2024,
   `rust-version = "1.98"`, Apache-2.0, and `#![deny(unsafe_code)]`.
2. Add only `symvault-core` and `symvault-cli`; no empty future crates.
3. Write failing byte-parity tests for `version`, `--version`, JSON, and errors.
4. Implement the minimal clap entrypoint and build metadata injection.
5. Add standard Cargo gates, nextest, doctests, audit, and deny to Make/CI.
6. Measure release binary/startup as an early signal, clearly labelled partial.

**Expected:** Go remains production; Rust `version` matches byte-for-byte and all
Rust gates pass on macOS, Linux, and Windows.

### Task 3: Port pure core contracts

**Objective:** Move deterministic logic without I/O into `symvault-core`.

**Files:**
- Create/modify: `crates/symvault-core/src/{error,secret_ref,redact,policy,quota,password,totp,types}.rs`
- Create: `crates/symvault-core/tests/fixtures.rs`
- Create: `testdata/port/core/`

**Steps:**
1. Freeze exit taxonomy, secret-reference parsing, redaction, policy/tier rules,
   quotas, type inference, password policies, and fixed-clock TOTP vectors.
2. Add failing Rust fixture/property tests per module.
3. Implement explicit enums/newtypes; use `secrecy`/`zeroize` for secret-bearing values.
4. Fuzz parsers and path/reference normalization.
5. Run core Rust gates and focused Go oracle tests.

**Expected:** CLI-independent core contracts pass without Tokio, clap, HTTP,
keyring, git, or TUI dependencies.

### Task 4: Prove age and KDF interoperability

**Objective:** Port credential cryptography before any Rust storage writes.

**Files:**
- Create: `crates/symvault-crypto/`
- Create: `testdata/port/crypto/`
- Extend: `scripts/rust-port/cmd/diffharness/`

**Steps:**
1. Generate safe fixed X25519 identity/fingerprint vectors and scrypt/argon2id
   fixtures through Go production helpers.
2. Add Go-encrypt→Rust-decrypt and Rust-encrypt→Go-decrypt tests.
3. Cover multi-recipient add/remove, malformed headers, wrong passphrases,
   parameter limits, zero-key healing, and KDF migration detection.
4. Ensure secret types do not implement revealing `Debug`/`Display` and wipe buffers.
5. Add property/fuzz tests for untrusted envelope/KDF parsing and run Miri on pure code.

**Expected:** Existing copied test vaults are mutually readable; no Rust code writes
production data yet.

### Task 5: Port read-only storage, then write paths

**Objective:** Make Rust open, inspect, search, and finally mutate isolated vaults.

**Files:**
- Create: `crates/symvault-store/`
- Create: `testdata/port/store/`
- Extend: `scripts/rust-port/cmd/diffharness/`

**Steps:**
1. Freeze entry YAML, metadata, layout, legacy roots, recipients, manifests, and index formats.
2. Port read-only open/list/get/find/verify paths first.
3. Add filesystem type/mode/hash comparisons and plaintext-leak scans.
4. Port atomic write/delete/re-encrypt and interruption/rollback semantics.
5. Add symlink, traversal, read-only, concurrent, and corrupt-file tests.
6. Run Go↔Rust round trips in both write directions.

**Expected:** Rust-written test vaults reopen in Go with identical semantic state,
and vice versa.

### Task 6: Port the audit chain

**Objective:** Preserve the keyed tamper-evidence model exactly.

**Files:**
- Create: `crates/symvault-store/src/audit/`
- Create: `testdata/port/audit/`

**Steps:**
1. Generate fixed-key/fixed-clock canonical JSON and HMAC chain vectors in Go.
2. Port `kid`, previous-HMAC linking, chain-reset detection, rotation archive,
   multi-key verification, retention, redaction, and exports.
3. Add mutation tests for reordering, truncation, insertion, key mismatch, and reset.
4. Byte-compare canonical entries and exported evidence.

**Expected:** Go and Rust verify each other's audit logs and reject the same attacks.

### Task 7: Port configuration and platform session adapters

**Objective:** Preserve unlock/session behavior and OS integrations behind injected traits.

**Files:**
- Extend: `symvault-core` config types
- Create: `crates/symvault-platform/`
- Create: `testdata/port/config/`, `testdata/port/session/`

**Steps:**
1. Freeze YAML defaults/precedence/legacy paths and exact writer behavior.
2. Port config parsing/validation without UI dependencies.
3. Define full side-effect traits for keyring, clock, Touch ID, clipboard,
   autotype, secure UI, notifications, and daemon lifecycle.
4. Port memory/injected implementations first; then explicit native backends.
5. Verify service/account names, session idle/max TTL, non-refreshing probes,
   unavailable/cancel behavior, and no secret exposure.

**Expected:** native smoke tests pass without weakening headless behavior.

### Task 8: Port git, reconciliation, import/export, and intake

**Objective:** Complete the storage lifecycle against isolated infrastructure.

**Files:**
- Create: `crates/symvault-sync/`
- Create: `testdata/port/{git,import,export,intake}/`

**Steps:**
1. Spike `gix` against all GIT matrix rows; record gaps before choosing it.
2. Port repository init/commit/remotes/push/pull and deterministic reconciliation.
3. Port backup/restore with traversal defense and exact archive manifests.
4. Port importer/quarantine/export behavior from Go-generated fixtures.
5. Port intake watch/disable with fake-clock and filesystem-event adapters.
6. Fuzz import and archive parsers; run local bare-remote differential cases.

**Expected:** all storage lifecycle rows pass on native OS jobs.

### Task 9: Port the complete CLI and TUI

**Objective:** Make Rust cover every non-MCP command while Go remains production.

**Files:**
- Extend: `crates/symvault-cli/`
- Create: `crates/symvault-cli/tests/cli_contract.rs`
- Create: `testdata/port/tui/`

**Steps:**
1. Build the full clap tree from frozen inventory, preserving hidden aliases.
2. Port commands by vertical family: auth/admin, CRUD/file, recipients/device,
   policy/share, template/run, sync/remote, update/doctor, then TUI.
3. For each family, write failing black-box cases before handlers.
4. Generate and compare completions/manpages; classify only unavoidable framework text differences.
5. Add PTY tests for prompts, editor flows, cancellation, and TUI key behavior.

**Expected:** every non-MCP CLI case passes through Rust with exact stream/exit behavior.

### Task 10: Port MCP stdio

**Objective:** Preserve all 35 tools and raw protocol behavior with zero stdout pollution.

**Files:**
- Create: `crates/symvault-mcp/`
- Create: `testdata/port/mcp/`
- Extend: `scripts/rust-port/cmd/diffharness/`

**Steps:**
1. Snapshot tool definitions for each agent tier/runtime availability combination.
2. Spike `rmcp` 3.2.0 against raw line/framed behavior; keep it only behind a
   compatibility adapter and only if all required hooks exist.
3. Port initialize/list/call, notifications, cancellation, bounds, aliases,
   scope enforcement, approval, redaction, and structured content.
4. Add raw-byte differential cases, property tests, and fuzzing.
5. Assert stderr-only diagnostics and scan all outputs for generated fixture secrets.

**Expected:** stdio transcripts match and no tool can bypass list-time/call-time authorization.

### Task 11: Port HTTP/SSE, OAuth, broker, and command execution

**Objective:** Complete network and process boundaries without broadening exposure.

**Files:**
- Extend: `crates/symvault-mcp/`
- Create: `testdata/port/{http,oauth,broker}/`

**Steps:**
1. Freeze HTTP routes/status/headers/SSE, bearer/scoped-token storage, OAuth
   discovery/DCR/PKCE/refresh, origin checks, request limits, and shutdown.
2. Port HTTP/SSE and auth against loopback transcript fixtures.
3. Port run/broker/API template behavior with injected process and HTTP adapters.
4. Test process-tree cancellation, PTY behavior, SSRF/path policy, TLS, timeout,
   and complete secret redaction on every error path.
5. Run MCP conformance plus Symaira-specific raw differential tests.

**Expected:** network and broker matrix rows pass without real external services.

### Task 12: Replace gomobile with the Rust Swift bridge

**Objective:** Ship one Rust crypto/storage implementation to macOS and iOS clients.

**Files:**
- Create: `crates/symvault-ffi/`
- Modify: `client/Package.swift`
- Modify: `client/project.yml`
- Modify: `client/Sources/SymvaultKit/VaultClient.swift`
- Modify: `scripts/build-vaultcore.sh`
- Create: Swift integration tests matching every `pkg/mobilebind` function

**Steps:**
1. Freeze the current string/bytes/JSON bridge API and errors.
2. Spike UniFFI and a narrow C ABI; measure generated API, license impact,
   XCFramework size, host-app RSS, and credential-extension RSS.
3. Choose and document one bridge, then implement all FFI rows.
4. Build macOS and iOS simulator/device frameworks; run Swift tests.
5. Verify Go and Rust frameworks produce mutually readable test vaults.

**Expected:** clients no longer require gomobile for candidate builds; real-device
budget evidence is recorded before cutover.

### Task 13: Value gate and dual-binary prerelease

**Objective:** Decide whether the representative Rust implementation earns cutover.

**Files:**
- Create: `scripts/rust-port/cmd/valuegate/`
- Create: `docs/rust-port/value-gate-<date>.json`
- Modify: release workflow and packaging only after the gate passes

**Steps:**
1. Build release Go and Rust binaries from clean caches and warm caches on the same host.
2. Run at least 100 startup and representative command samples after warmups.
3. Measure size, RSS, startup p95, CRUD/search/MCP p95, and full gate duration.
4. Fail unless the threshold in `baseline-20260905.json` passes.
5. If it fails, keep Go production and optimize or stop; do not redefine the metric.
6. If it passes, ship a prerelease containing Rust `symvault` plus `symvault-go`.
7. Verify archives, packages, signatures, SBOMs, provenance, notarization,
   Homebrew/Scoop/Docker/Nix/MCPB, and rollback by public artifact readback.

**Expected:** a reversible prerelease with measured value and complete parity.

### Task 14: Stable cutover and delayed Go removal

**Objective:** Finish without destroying rollback.

**Files:**
- Modify: `AGENTS.md`, `ARCHITECTURE.md`, `README.md`, build/release docs and workflows
- Remove Go source only in a separate post-stable change

**Steps:**
1. Run native macOS/Linux/Windows suites and FreeBSD artifact smoke.
2. Run signed/notarized macOS app and iOS device smoke against copied test data.
3. Release stable Rust primary with the Go fallback still packaged.
4. Operate one stable release without unexplained parity defects.
5. Tag the final dual-binary rollback point and document exact rollback commands.
6. In a separate reviewed change, remove Go source, go.mod/go.sum, Go CI,
   GoReleaser-only assumptions, and the current-release fallback.
7. Verify zero tracked backend Go files while preserving Swift/editor sources,
   release names, data compatibility, and immutable rollback artifacts.

**Expected:** Rust is the sole backend source; the final dual release remains a
verified external rollback point.
