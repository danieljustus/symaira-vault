# Rust port architecture

> **Status:** accepted
> **Produces:** staged Rust implementation beside the Go oracle

## 1. Why this shape

The current Go package tree is optimized around package visibility and Cobra,
not around independent port slices. Mirroring it would produce dozens of crates
and preserve accidental coupling. The Rust design instead follows externally
testable capabilities: domain, crypto, storage, platform adapters, CLI, MCP,
and FFI.

The highest-risk current areas by production size are `internal/mcp/server`
(8,527 lines), `internal/vault` (7,628), `cmd/` (7,234 across root and
subpackages), `internal/config` (2,926), `internal/audit` (2,351),
`internal/session` (2,257), `internal/health` (2,352), `internal/crypto`
(1,832), and `internal/git` (1,752). These boundaries drive the slice order.

## 2. Must support

| Capability | Why |
|---|---|
| Existing age/X25519, scrypt, and argon2id data | Existing vaults are the primary contract |
| CLI tree, flags, streams, help, and exit codes 0–10 | Scripts and clients depend on them |
| 35-tool MCP registry plus stdio and HTTP/SSE | Agent integration is a core product surface |
| OAuth 2.1/PKCE/DCR and scoped tokens | Existing HTTP clients depend on it |
| YAML config, XDG and legacy paths | No forced user migration |
| HMAC-chained audit log and key rotation | Security property stronger than corekit audit |
| Keyring, Touch ID, clipboard, autotype, secure UI | Native credential workflow |
| Git, remote sync, conflict copies, import/export/intake | Existing storage lifecycle |
| macOS/Linux/Windows and shipped FreeBSD binaries | Distribution compatibility |
| Swift bridge replacing gomobile | iOS/mobile core must not remain Go-only forever |

## 3. Out of scope

| Capability | Reason |
|---|---|
| Rewriting Swift clients | They are native UI, not part of the Go backend port |
| Rewriting editor plugins | TypeScript/JavaScript is appropriate there |
| New vault format or crypto suite | A rewrite and a format migration cannot be debugged safely together |
| New MCP tools or product features | Prevents scope drift during parity work |
| Hosted accounts, billing, tenants, SSO/SCIM | Forbidden by the product boundary |
| Replacing Symaira AppKit | Existing shared GUI foundation remains authoritative |
| Cross-repository Rust workspace/corekit rewrite | Violates repository independence and standalone-first |

## 4. Delivery model

Rust lands in this repository beside Go. The production `symvault` remains Go
until the release cutover stage. During dual implementation:

- Go binary: `./symvault-go` in differential/release snapshots.
- Rust binary: `target/release/symvault`.
- User-facing release binary before cutover: still named `symvault` and built
  from Go.
- Prerelease cutover: Rust is `symvault`; the archive also carries the last
  known-good `symvault-go` fallback.
- Stable cutover: Rust remains primary after all gates and native smoke tests.
- Go removal: separate change after one stable Rust release has operated cleanly;
  the final dual-binary release remains immutable rollback.

## 5. Crate boundaries

Create crates only when their first vertical slice starts. Do not add empty
architecture crates.

| Crate | Responsibility | Initial source seams |
|---|---|---|
| `symvault-core` | Domain types, error taxonomy, policy, quotas, redaction, secret references, deterministic generators | `internal/errors`, `policy`, `quotas`, `redact`, `secrets`, pure parts of `vault` |
| `symvault-crypto` | age interoperability, X25519 identities, scrypt/argon2id envelope, TOTP, zeroization | `internal/crypto`, crypto parts of `session` and `mobilebind` |
| `symvault-store` | Entry layout, manifests, recipients, encrypted index, atomic filesystem, audit chain | `internal/vault`, `audit`, `fsutil` |
| `symvault-sync` | git repository adapter, remotes, reconciliation, backup/restore, import/export/intake | `internal/git`, `vault/sync`, `importer`, `exporter`, `intake` |
| `symvault-platform` | keyrings, Touch ID, clipboard, autotype, notifications, secure UI, daemon | `session`, `clipboard`, `autotype`, `secureui`, `notify`, `daemon` |
| `symvault-mcp` | protocol models, registry, auth, stdio, HTTP/SSE, OAuth, approval, broker adapters | `internal/mcp`, `approval`, `authguard`, `broker`, `dynamicsecret` |
| `symvault-cli` | clap command tree, output rendering, TUI composition, process exit mapping | `cmd`, `internal/cli`, `internal/ui`, binary entrypoint |
| `symvault-ffi` | narrow JSON/string/byte API for Swift/iOS and XCFramework packaging | `pkg/mobilebind`, `internal/mobilebind` |

### Dependency direction

```text
symvault-cli      -> core + crypto + store + sync + platform + mcp
symvault-mcp      -> core + crypto + store + platform + sync interfaces
symvault-sync     -> core + crypto + store
symvault-store    -> core + crypto
symvault-platform -> core + crypto
symvault-ffi      -> core + crypto + store
symvault-crypto   -> core
symvault-core     -> no adapter crates
```

The binary crate owns composition only. Core crates never depend on clap,
Tokio, HTTP, keyring, TUI, git, or Swift binding crates.

## 6. Framework and dependency choices

| Area | Candidates | Decision | Constraint |
|---|---|---|---|
| age format | `age` 0.12.1 vs custom crypto | Start with `age`; custom format code rejected | Must decrypt Go fixtures and produce Go-readable ciphertext |
| CLI | `clap` 4.6.6 vs hand parser | `clap`, wrapped and snapshot-tested | Cobra defaults are not assumed equivalent |
| MCP | `rmcp` 3.2.0 vs own protocol layer | Spike `rmcp` behind adapter; keep only if parity holds | Existing HTTP/SSE/OAuth/redaction behavior wins over SDK defaults |
| Keyring | `keyring` 4.2.0 vs shell-outs | `keyring`, with explicit per-platform features | Same service/account names and failure taxonomy |
| Git | `gix` 0.87.1 vs git CLI vs `git2` | Spike `gix`; fall back to bounded git CLI if behavior is incomplete | No libgit2/CGO-style native build burden without evidence |
| Secret memory | `zeroize` + `secrecy` | Use at domain boundaries | No accidental `Debug`, clone, or error exposure |
| Async runtime | Tokio vs sync threads | Tokio only in MCP HTTP/SSE and cancellation boundaries | Keep file/crypto/CLI core synchronous |
| Swift bridge | UniFFI vs narrow C ABI | Spike both; choose from measured iOS/RSS/binding evidence | Preserve the existing JSON bridge contract |
| TUI | ratatui/crossterm vs minimal port | Decide when TUI slice begins | Existing keyboard/render/accessibility behavior is the oracle |

All dependency versions are exact-pinned in `Cargo.lock`. Application crates use
`edition = "2024"`, `rust-version = "1.98"`, and `#![deny(unsafe_code)]`.

## 7. Contract and test architecture

The neutral harness launches both binaries with identical argv, stdin, cwd,
environment allowlist, locale, timezone, fixed clocks/seeds where supported,
and isolated HOME/XDG trees. It captures:

1. exit status or signal;
2. raw stdout and stderr;
3. recursive filesystem type/mode/hash manifests;
4. decrypted semantic entry snapshots only inside the isolated test process;
5. audit/config/token bytes;
6. git refs/status/log and conflict copies;
7. HTTP exchanges and OAuth state transitions;
8. raw MCP frames and tool schemas.

Golden data is generated by the production Go implementation at the pinned
oracle commit. Real vaults, host keychains, and developer configuration are
never read. Random ciphertext is compared by cross-decryption and parsed age
semantics, not byte equality; deterministic headers, schemas, manifests, JSON,
and command output use byte equality unless the contract matrix says otherwise.

## 8. Security gates

- `cargo fmt --all --check`
- `cargo check --workspace --all-targets --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo nextest run --workspace --all-features`
- `cargo test --workspace --doc --all-features`
- `cargo hack check --workspace --each-feature --no-dev-deps`
- `cargo llvm-cov nextest --workspace --all-features`
- `cargo audit`
- `cargo deny check`
- nightly Miri for suitable core code
- nightly fuzzing for importers, paths, age/KDF parsing, MCP frames, OAuth, and archives
- native CI on macOS, Linux, and Windows; FreeBSD build plus smoke evidence

## 9. Cutover invariants

Cutover is blocked unless every contract-matrix row is `PASS`, the value gate
passes, release archives are equivalent, Swift clients run against the Rust
bridge, and rollback has been exercised from Rust back to the frozen Go binary
without changing vault data. Failure at any point leaves Go as production.
