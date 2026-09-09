# Rust migration handover — 2026-09-09

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

The current local `golangci-lint run` and locally installed gosec `2.29.0` report pre-existing whole-repository findings outside this candidate. They are not treated as new migration regressions; CI uses pinned `gosec v2.22.0` and remains the authoritative protected gate.

## Deliberate non-claims and blockers

- `RUST-005` remains **in_progress** in `work-items.json`. The above proves bounded macOS storage behavior; it does not prove all read/list/index/legacy-migration paths, cross-process writer behavior, or full transactionality on every supported platform.
- Native Windows, Linux, FreeBSD, and iOS runtime evidence is still required. `.github/workflows/rust-store.yml` schedules native Ubuntu/macOS/Windows storage differentials after a push; cross-compilation does not substitute for them.
- RUST-006 audit, RUST-007 platform/config/session, RUST-008 sync/import/export/intake, and all CLI/MCP/HTTP/FFI/distribution/cutover work remain at their ledger states. Do not promote their matrix rows from the presence of a compiled crate or a fixture projection.
- The existing Go fallback is mandatory. Reproducible rollback is: start from pinned `origin/main` `81210de2720ee000fa26adda4da4080daae01677`, build the Go CLI with Go 1.26.6, and operate a copy of a Rust-written test vault only after the future `DIST-005` compatibility gate passes. No Go deletion, release, tag, deployment, or productive-store migration is authorized by this checkpoint.

## Handover operating notes

- Work only from a clean, named candidate branch; retain the Go reference and use the checked-in fixture generators rather than copied behavior.
- Record each native CI run against its exact head SHA before changing matrix status. A configured workflow is not evidence of execution.
- Preserve any re-discovered parallel worktrees/branches and the checkpoint object above. Do not reset, clean, delete, or bulk-commit them.
- **Conclusion at this checkpoint:** `STABILER TEILSTAND, MIGRATION NOCH OFFEN`. The storage/index candidate is suitable as a behavior-preserving module-move input only after its native CI matrix passes; it is not release-, cutover-, or consolidation-ready.
