# Go-to-Rust migration record

> **Status:** accepted for staged implementation
> **Go oracle:** commit `caadd5e`, release `v0.22.1`
> **Scope:** the Go backend and mobile bridge; Swift clients and editor plugins stay in their current languages

## Decision

Symaira Vault will be migrated in-place from Go to Rust through reversible,
contract-first vertical slices. The Go implementation remains runnable and is
the executable oracle until every contract row is green on Rust. There is no
flag-day rewrite and no cross-repository Cargo workspace.

This repository is a difficult first-class security port: 782 Go files and
191,021 lines, an age-compatible credential format, 35 MCP tools, stdio and
HTTP/SSE transports, OAuth, OS keyrings, Touch ID, a TUI, git-backed sync,
release signing, and a gomobile bridge. A mechanical translation would be
reckless. Each slice must be independently executable and compared against Go.

## Why Rust

The intended gain is memory-safe handling of untrusted MCP, HTTP, importer,
archive, path, and secret-processing inputs without a garbage-collected runtime,
while retaining native binaries and the existing local-first model. Rust is not
a benefit by declaration, so the port has an early value gate.

The migration continues past the first representative slices only if a
release-profile Rust candidate demonstrates at least one of:

- at least 20% lower maximum RSS; or
- at least 20% smaller release binary;

while startup p95 and representative command latency regress by no more than
10%. Security and contract parity remain mandatory even if the performance gate
passes. The measured Go baseline is in
[`baseline-20260905.json`](baseline-20260905.json).

## Non-negotiable constraints

1. Existing vaults remain readable and writable without migration or re-encryption.
2. The byte formats of age files, manifests, audit JSONL/HMAC chains, config,
   tokens, pairing data, exports, and release archives remain compatible.
3. MCP stdout contains only protocol frames; diagnostics stay on stderr.
4. Secret values never enter logs, errors, snapshots, fixtures, or benchmark data.
5. Go remains buildable and testable until a stable Rust release has operated
   without unexplained parity defects. Removal is a separate final change.
6. `#![deny(unsafe_code)]` is the default. Any exception requires a documented
   invariant, focused tests, Miri where applicable, and review.
7. macOS, Linux, Windows, and the currently shipped FreeBSD artifacts stay in
   scope unless a separate compatibility decision explicitly removes one.
8. Swift clients continue using Symaira AppKit. TypeScript/editor code is not
   rewritten merely to make the repository “all Rust”.
9. The Apache-2.0 self-hosted and standalone-first product boundary does not change.

## Prepared artifacts

- [`architecture.md`](architecture.md) — target crate boundaries and dependency choices.
- [`contract-matrix.md`](contract-matrix.md) — acceptance map for observable behavior.
- [`implementation-plan.md`](implementation-plan.md) — ordered, reversible execution plan.
- [`work-items.json`](work-items.json) — machine-readable dependency graph for autonomous execution.
- [`baseline-20260905.json`](baseline-20260905.json) — measured Go reference metrics.
- [`value-signal-version-20260905.json`](value-signal-version-20260905.json) — non-representative first-slice measurements.

## Implementation progress

- `RUST-001` passed: the 131-command Go contract fixture and neutral differential harness are executable in CI.
- `RUST-002` is locally green: the pinned Rust workspace and byte-exact
  `version` slice passes all ten Go↔Rust cases plus format, Clippy, nextest,
  doctest, feature, coverage, audit, and deny gates. Native CI remains the
  completion gate.

The tiny release-built version slice measured 577,104 bytes, 2,277,376 bytes
maximum RSS in one sample, and 2.576 ms startup p95 over 120 runs after 20
warmups on macOS arm64. These numbers are promising but deliberately marked
non-representative; they do not justify product cutover before representative
crypto/storage/MCP slices pass.

## Execution rule

On the next implementation turn, start at the first `ready` item in
`work-items.json`, complete its tests and gates, update its status and contract
rows, then continue only when the item is green. Never skip ahead across a
failed parity or value gate.

## Reuse assessment

Current reconnaissance supports reuse rather than reinvention:

- `age` 0.12.1 from `str4d/rage` is the interoperable Rust age implementation.
- `clap` 4.6.6 is the CLI parser candidate, with Cobra help/error behavior
  frozen by black-box fixtures rather than assumed equivalent.
- `rmcp` 3.2.0 is the official Apache-2.0 Rust MCP SDK. It may be used behind
  an adapter only after raw-frame, HTTP/SSE, OAuth, redaction, and cancellation
  parity is demonstrated; framework defaults are not the contract.
- `keyring` 4.2.0 supports native macOS, Windows, and Unix stores.
- `gix` 0.87.1 is the pure-Rust git candidate; adoption depends on executable
  parity for separate-git-dir, auth, push/pull, and conflict behavior.
- `zeroize` 1.9.0 and `secrecy` 0.10.3 are candidates for secret memory handling.
- UniFFI 0.32.0 is the leading Swift bridge candidate, but its MPL-2.0 license,
  generated binding shape, iOS binary size, and extension RSS must be reviewed
  before adoption.

No existing Rust password-manager repository matches Symaira Vault's complete
CLI/MCP/storage contract. The correct strategy is crate-level reuse plus our
own language-neutral fixtures, not adopting another product as a base.
