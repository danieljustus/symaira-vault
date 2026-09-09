# Migration resumption checkpoint

## Active revision and ownership

- Active verification candidate: branch `migration/storage-recovery-verified`, worktree `.worktrees/storage-recovery-verified`. The original `.worktrees/store-writer-resume-20260908` WIP is preserved unchanged.
- Base: `e912fcacc9bb4500b579f62a4cc034c0e3ab9859` plus uncommitted changes. Root checkout is preserved.
- `work-items.json` and `contract-matrix.md` now incorporate the reopened storage statuses from `.worktrees/resume-ledger-20260908`; that worktree retains historical investigation notes, not a competing queue.
- Tracking: https://github.com/danieljustus/symaira-vault/issues/1019
- Historical command history: [resumption-evidence.json](resumption-evidence.json). Fresh candidate source hashes and gate results: [storage-recovery-verification.json](storage-recovery-verification.json). Historical evidence does not certify changed source.

## Verified bounded implementation

Configured recipients, dotted/nested paths, pseudonymized storage, and eight persisted Go metadata vectors have executable coverage. Single-recipient entry encryption remains distinct from all-recipient entry encryption; manifests use configured recipients.

Independent final review `deleg_39090a20` approved the bounded Unix root-acquisition race detector and post-acquisition entry write/delete confinement. The detector compares a no-follow metadata snapshot's device/inode with the opened handle before config parsing. It does not authenticate pathname identity before the snapshot. Replacement holds the parent capability through exclusive temp creation, rename, cleanup and fsync; deletion uses root-relative traversal and unlink. Deterministic regressions cover replacement roots and rejected special targets.

After integration, the coordinator reran the full Rust workspace all-target/all-feature tests, strict workspace Clippy, Go `internal/vault` tests, formatting and diff checks successfully. Store tests also passed with eight test threads. Windows GNU strict Clippy establishes compilation only, not native runtime behavior.

## Open scope and next task

`RUST-005` remains `in_progress`; its dependent audit/platform/sync and later work remain blocked in the task DAG. Existing implementations are preserved, not discarded.

The recovered **RUST-005-MANIFEST-SEQUENCE** implementation now passes the live Go/Rust comparator on macOS: ten cases in both configured layouts, including missing/malformed manifests and integer boundaries. The live writer and encrypted-index acceptance tests also pass. The config-authoritative layout regression passes with conflicting request flags. Fresh workspace tests pass (193 tests, no failures or ignored tests), strict workspace Clippy passes, and Go `internal/vault` tests pass. These are dirty-snapshot diagnostic results, not release acceptance. Next: finish independent final review, address any actual findings, and execute remaining platform/fault-injection gates before promoting RUST-005.

Reference paths: `internal/vault/entry_readwrite.go`, `manifest.go`, `manifest_updater.go`; Rust `publish_prepared_entry`, `delete_entry`, and manifest helpers in `crates/symvault-store/src/lib.rs`.

Remaining non-claims: complete cross-platform read/list/index/legacy-migration confinement; cross-process writer and cleanup/fsync fault-injection coverage; native Windows, Linux, FreeBSD and iOS evidence; downstream CLI/MCP/HTTP/FFI/value/package/rollback gates. Pseudonymized deletion and manifest bookkeeping have bounded live macOS differential coverage, not a transactionality guarantee: the Go high-level writer deliberately tolerates certain bookkeeping failures. Do not remove Go or publish a release.

## Recovery discipline

Rejected wrong-base artifacts `b02f1a93` and `3e7c8a8` were not integrated. Acquisition worker commit `3d8d7f9857e923785a7b05da7b9971d4457fc4c2` was created contrary to its no-commit instruction; the coordinator did not cherry-pick it, and integrated only the inspected revised delta. Coordinator changes remain uncommitted.

Use `GOTOOLCHAIN=go1.26.6`, `GOWORK=off`, and an explicit `CARGO_TARGET_DIR` pointing to `.worktrees/storage-recovery-verified/target`. Pass the absolute candidate Cargo manifest path; never inherit a different worker's target directory. Verify current branches, source hashes and tests before continuing; recorded results are not native evidence for other targets.
