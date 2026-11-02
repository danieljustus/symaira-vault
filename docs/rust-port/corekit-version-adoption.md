# CoreKit Rust version adoption evidence

Issue #995 adopts the shared `symaira-core-version` contract from CoreKit's
RUST-005 work without changing the staged Vault CLI's observable version
behavior.

## Exact pin

Both Rust crates consume the same exact git revision through the workspace
manifest:

```toml
symaira-core-version = { version = "=0.0.0", git = "https://github.com/danieljustus/symaira-corekit", rev = "27177f25f551cecefa7bd6c4524abf175b3a75c7", package = "symaira-core-version" }
```

`Cargo.lock` records the same source and revision:

```text
git+https://github.com/danieljustus/symaira-corekit?rev=27177f25f551cecefa7bd6c4524abf175b3a75c7#27177f25f551cecefa7bd6c4524abf175b3a75c7
```

The dependency is used by both `symvault-core` (compatibility wrappers) and
`symvault-cli` (the executable path). The CLI now constructs CoreKit's `Info`
payload and uses CoreKit's `json()`/`write()` implementation; the existing
`render_version_text` and `render_version_json` public functions remain as
thin compatibility wrappers.

## Duplicate source removed

The old local `VersionDocument` declaration and local `serde_json` payload
construction are gone from `crates/symvault-core/src/lib.rs`:

- **12 nonblank duplicate payload/serialization source LOC deleted**: six
  lines for the local document declaration and six lines for its construction
  and serialization.
- The now-unused local `serde::Serialize` import was also removed.
- The text and JSON compatibility wrappers remain, but delegate to CoreKit;
  no local version payload schema or serializer remains.

## Dependency and feature closure

Observed with `cargo tree --workspace --all-features -e features`:

- `symaira-core-version` has only its `default` feature; it declares no
  consumer-selectable feature flags.
- Its locked runtime closure is only `serde` and `serde_json`; CoreKit removed
  the prior `thiserror` derive so adopters do not pay for an extra proc-macro
  dependency in clean builds.
- The reverse dependency tree contains exactly the two Vault consumers:
  `symvault-cli` and `symvault-core`.
- No local replacement, path dependency, or unpinned CoreKit source is used.

## Native verification

All commands below were run in this macOS arm64 checkout.

| Command | Result |
|---|---|
| `cargo fmt --all --check` | passed |
| `cargo check --workspace --all-targets --all-features --locked` | passed |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | passed |
| `cargo nextest run --workspace --all-features --locked` | 95 passed, 0 skipped |
| `cargo test --workspace --doc --all-features --locked` | 1 doctest passed |
| `cargo test --workspace --all-features --locked` | passed; 95 tests and doctests reported by the run |
| `make rust-version-contract` | all 10 selected Go/Rust version cases passed |
| `GOTOOLCHAIN=go1.26.6 make build` | passed |
| `GOTOOLCHAIN=go1.26.6 make test-fast` | passed |
| `GOTOOLCHAIN=go1.26.6 make test` | passed |
| `make vet` | passed |
| `make fmt-check` | passed |
| `GOTOOLCHAIN=go1.26.6 make lint` | passed; 0 issues |

Standalone smoke was also run against the built Rust binary for no arguments,
`version`, `version --json`, and `version --output json`; all four cases
returned the expected status, stdout, and empty stderr. The Go native binary's
text and JSON version outputs were likewise checked for matching payloads.

## Performance evidence boundary

A real post-adoption release-build smoke was run with the same
`v0.0.0-port` version string. Over 50 subprocess launches of `version --json`:

| Binary | Size | Median startup | p95 startup |
|---|---:|---:|---:|
| `target/port/symvault-go-release` | 21,720,354 bytes | 7.717 ms | 8.118 ms |
| `target/release/symvault` | 577,312 bytes | 2.683 ms | 3.114 ms |

These are real local observations, not a CoreKit value-gate claim: the Go
binary is the full Vault CLI while the Rust binary is only the staged version
slice, so their sizes and startup times are not a like-for-like product
comparison. No RSS result, clean/warm build distribution, or before/after
performance improvement is claimed here.

## CoreKit v0.19.0 (Rust-only) assessment

CoreKit `v0.19.0` (tag commit `c214f67f7ab2fbc720e0eda898238844849a9b5a`,
released 2026-11-02) removes the Go library from CoreKit `main` (CoreKit ADR
0005). Assessment for this repository, with no code change:

- **Rust pin stays at `27177f25f551cecefa7bd6c4524abf175b3a75c7`.** The GitHub
  compare `27177f2...v0.19.0` touches no file under
  `rust/symaira-core-version/`, the only CoreKit crate Vault consumes, so the
  pinned contract is identical to the released one. Raise the pin together
  with the first additional CoreKit crate adoption, not on its own.
- **Go stays on `v0.18.x`.** `go.mod` keeps `v0.18.2`; tags after `v0.18.x`
  contain no Go packages. `v0.18.3` carries `golang.org/x/net` v0.62.0 /
  `golang.org/x/sys` v0.49.0 security updates and an `mcpserver` stdout-failure
  fix; take it only if another Go release ships before the Rust-only cutover.
- **New shared Rust crates** (`symaira-core-exit`, `-fs`, `-log`, `-update`,
  `-mcp`, `-config`, `-env`, `-secretref`, `-sqlite`, `-llm`, `-mcpcfg`) are
  candidates for post-cutover deduplication, slice by slice with parity
  evidence. They are not adopted mid-migration. The removed Go-only packages
  (`auditkit`, `evidencekit`, `domkit`, `vectorkit/turboquant`, `ollamakit`)
  have no shared Rust crate; any Vault use stays consumer-local.
