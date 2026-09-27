# CLI surface gap (measured)

Measured on **2026-09-27** against the Rust CLI built from candidate
`8ec623b6` and the pinned Go command tree in
`testdata/port/cli/command-tree.json` (oracle `3232e31f`, release
`unreleased`), depth 3. This supersedes the 2026-09-20 report below: the rebuilt
candidate has a different command surface.

The probe pins the binary: SHA-256
`bc3c6e73183b001714b843ab0fc1daba80b198dbdb23886fc6a2721abcca5412`, modified
`2026-09-27T08:03:49Z`.

The source-tree `cligap` probe uses the pinned Go command-tree fixture; it does
not need a Go oracle binary. Build the CLI after checking external build storage
with `~/.local/bin/dev-external --status`, then run `cligap` against the binary
produced by that build:

```sh
~/.local/bin/dev-external cargo build --manifest-path crates/symvault-cli/Cargo.toml --locked
GOTOOLCHAIN=go1.26.6 go run ./scripts/rust-port/cmd/cligap --binary <built-symvault-path>
```

The report records the exact binary path, hash and modification time. These are
surface probes only. Reachability and displayed flags do not prove behavior,
output bytes, exit codes or side effects; the behavioral rows remain separate.

## Summary

| | count |
| --- | --- |
| oracle command paths (depth ≤ 3) | 134 |
| Rust command paths (walked from its own help) | 100 |
| oracle paths **missing** in Rust | **24** |
| oracle flags missing from probed paths | **11** (on 4 paths) |
| oracle aliases missing on reachable commands | **0** |
| Rust paths not present in the pinned tree | 1 |

## Missing command paths (24)

| cluster | count | paths |
| --- | --- | --- |
| `agent` | 1 | `setup` |
| `approval` | 3 | `approval`, `approval decide`, `approval list` |
| `broker` | 1 | `broker` |
| `device` | 1 | `approval-pair` |
| `dynamic` | 2 | `dynamic`, `dynamic generate` |
| single | 2 | `generate manpages`, `help` |
| `intake` | 3 | `intake`, `intake watch`, `intake watch disable` |
| `serve` | 8 | `serve`, `serve install`, `serve status`, `serve uninstall`, `serve token`, `serve token create`, `serve token list`, `serve token revoke` |
| single | 3 | `setup`, `startup-profile`, `ui` |

The measurement above predates the current candidate. The Rust CLI now exposes
the top-level `help` route through Clap's generated help subcommand, including
`symvault help config validate`; its success and usage path are checked against
the Go command in `cli_help_subcommand.rs`. This is route-level evidence only:
help text formatting remains part of CLI-004 and is not claimed byte-identical.

## Alias gaps (0)

The latest binary accepts all three aliases recorded by the pinned tree:
`show` and `cat` for `get`, and `ls` for `list`. The 2026-09-20 alias-gap
finding is resolved in the current candidate.

## Rust-only path (1)

`symvault mcp serve` is reachable in Rust and absent from the pinned tree. The
tree predates it; this is a re-pin decision, not a defect claim. `mcp install`,
`status` and `uninstall` are present on both sides.

## Deliberate non-claims

- Argument-count probes from the oracle tree are not replayed. Clap and Cobra
  report argument errors with different exit codes and text, so the comparison
  would measure parser error style, not the contract.
- Clap prints inherited global flags in every subcommand's options section while
  the tree records only each node's own flags, so additional Rust entries are
  not called divergences; only oracle flags missing in Rust are listed.
- Hidden commands stay invisible to both `--help` walks. They are not covered.
- A path counted as present is only a help/parser-surface result. `update check`
  and `update apply` are recognized by `update_commands::run`, but this does not
  imply full runtime parity: `apply --dry-run` previews release metadata,
  unsupported installation methods fail closed before network access, and
  direct-download apply verifies the signed checksum bytes, archive digest,
  extracted executable, and post-install version before deleting its rollback
  backup. Ignored live smokes passed against signed public release `v0.22.1`
  on macOS arm64. The Rust smoke verified Cosign/checksum handling, isolated
  installation, `version`, and rollback after an injected validation failure.
  A paired Go 1.26.6/Rust `0.0.1` run with `update apply --force --json`
  produced matching normalized outcomes, installed identical bytes
  (`85c6e54b867ec8c497395f1afccfd4e8f1bfe2bebd668d88dcf015049ec67248`), and
  left only `symvault` in each isolated install directory. The paired smoke is
  repeatable with `SYMAIRA_VAULT_GO_SMOKE_BINARY` and
  `SYMAIRA_VAULT_RUST_SMOKE_BINARY`; both live tests require public GitHub access
  and the external `cosign` CLI.

## Missing flags on probed paths

| Path | Missing flags |
| --- | --- |
| `mcp` | `--bind`, `--port`, `--tls-ca`, `--tls-cert`, `--tls-key` |
| `run` | `--broker`, `--broker-passthrough`, `--broker-strict` |

`import --quarantine` is implemented. The `mcp` and `run` flags belong to
unported HTTP/TLS and broker behavior. Update flags are recognized only where
the corresponding checker/preview path consumes them; do not add
accepted-and-ignored flag scaffolding.

## `symvault doctor` check coverage (2026-09-27)

The command group exists in Rust, but only part of Go's check registry is ported.
Measured with `--json --no-network` against the pinned Go oracle
(`parent-doctor-matrix.py`, fixtures `empty`, `corrupt`, `env` and `initialized`):
Go runs **35** non-network checks, Rust **34**. For the 34 shared IDs the
name/status/message/hint/fixable fields are byte-identical on a missing vault, on a
missing vault with the env-passphrase variables set, and on an oracle-initialized
vault (**0 field deviations**). The remaining ID is **not implemented** and is
therefore *absent* from the output rather than reported as OK — a missing check may
never look like a passing one.

### Known deviation: config-loader syntax-error dialect (not yet parity)

On parser-invalid `config.yaml` inputs, five shared IDs can diverge in the
`message` field: Go renders go-yaml's syntax error while the Rust loader renders
serde_yaml's detail and source location. A source-bound differential now covers
the stable multiple-document rejection across all five IDs; that message matches
Go exactly. Scanner-generated syntax errors remain open.
The prefixed part (`config.yaml parse error: `, `failed to load config: `,
`cannot load config: `) is identical, so only the parser dialect differs:

- `vault.config.parses`, `vault.config.validates`, `auth.passphrase.rotation`,
  `mcp.dynamic.engines`, `mcp.agents` (all five share the one root cause)

This is a **pre-existing** divergence of the Rust config loader shared by the whole
CLI, not introduced by the doctor port, and general parser-message parity is **not**
claimed. The checks ported in wave 2a quote no parser error, so they match on the
corrupt fixture as well (`differential_doctor_session_tooling_checks`); the two MCP
config checks from wave 2b quote parser errors and are pinned for the missing and
initialized fixtures only (`differential_doctor_mcp_config_checks`).

Ported IDs (37 in the registry, 34 of them without network):

`vault.initialized`, `vault.config.parses`, `vault.config.validates`,
`vault.identity.encrypted`, `vault.permissions`, `auth.method`, `session.cache`,
`git.repo`, `git.remote`, `git.gitignore.protects`, `git.lastsync.fresh` (network),
`recipients.count`, `recipients.recovery`, `audit.log`, `audit.keyring.orphans`,
`update.available` (network), `vault.size`, `vault.stale_temp_files`,
`vault.conflict_files`, `vault.search_index.persistence`, `crypto.kdf.modern`,
`vault.manifest.intact`, `auth.passphrase.rotation`, `tooling.autotype.backend`,
`tooling.clipboard.backend`, `daemon.status`, `mcp.approval.tls`, `tooling.secureui`,
`tooling.precommit`, `session.keyring`, `password.strength`, `password.reuse`,
`security.env_passphrase`, `mcp.dynamic.engines`, `mcp.agents`,
`mcp.server.reachable` (network), `mcp.tokens`.

Still open (1): `crypto.scrypt.benchmark`. The network-tagged
`mcp.server.reachable` check now uses a controlled loopback HTTP fixture and is
differentially covered for HTTP 200 (with and without a token file), HTTP 503,
and an unreachable port. The Go implementation at oracle commit
`fca3f89401833b5e14ec4ec74ef736b0f63bca74` is source-identical for
`internal/health/doctor_mcp.go` (blob `81d0d6581bf3b1d81a5c9c4a18c96caaa3bcff8a`).

### Branch limitations of the ported checks (documented, not hidden)

These branches are unreachable in the fixture matrix but exist in Go, so they are
explicitly listed instead of being silently simplified:

- `session.keyring`, `audit.keyring.orphans`: the non-test/non-CI branches need the
  OS keyring layer. Outside test/CI `session.keyring` reports Go's **fail** branch
  (the Rust session cache really has fallen back to memory), and
  `audit.keyring.orphans` reports `warn` instead of a false "no orphans".
- `vault.manifest.intact`: the branch with an existing `manifest.age` needs the
  identity/session to verify and uses Go's `msgSessionNeeded` text; additionally the
  hint points at `symvault verify --rebuild`, which is **not implemented in Rust
  yet** — the check must stay byte-identical anyway, so this is a documented hole.
- `security.env_passphrase`: the **pinned oracle** reports `not set` for every
  measured fixture, even with `SYMVAULT_PASSPHRASE` set in the environment; the
  current Go *tree* source would warn in that case. The port follows the pinned
  binary (the contract), never reads the variable's value, and this divergence
  between oracle and tree is recorded here.

`auth.method` now checks Touch ID availability on macOS through the existing
`MacOsTouchId` platform adapter and retains Go's unavailable branch elsewhere.
The differential test uses the host's non-prompting availability probe, so the
active/inactive result follows the machine running the test. The Go oracle's
`internal/session/touchid_darwin.go` matches current source at pinned commit
`fca3f89401833b5e14ec4ec74ef736b0f63bca74` (blob
`cbd27b9bfc4caefaa811f88e14376c0263f944b3`).

The remaining open check was implemented at some point, measured against the oracle
and then **withdrawn again** because it cannot be byte-pinned — do not re-add it
without a new decision:

- `crypto.scrypt.benchmark`: Go embeds a *measured* duration and its recommended work
  factor for this machine in the message (the argon2id branch *is* stable, the scrypt
  branch is not).

`mcp.tokens` is now ported. A disposable differential checks an existing registry
without changing its bytes or sibling legacy-token file, and tests both legacy-token
migration and fresh-token initialization. Go and Rust results match; the generated
registry bytes are compared after normalizing the random ID and creation time (and
the random hash/prefix for fresh tokens), both registry files are mode `0600`, the
migrated raw token is absent, and the token-specific paths match. Go runs all checks
before applying `--only`, so `mcp.approval.tls` also initializes
`.symvault/device-sessions.json`; Rust now calls the shared device-session store,
which initializes missing files and migrates legacy raw-token keys using the
store's no-follow reads and atomic writes. Pinned-oracle differentials check empty
JSON bytes and Unix modes (`0700` directory, `0600` file), legacy-key migration,
zero-expiry counting, and read-only existing stores. Rust publishes the final
hashed token registry atomically without writing a generated raw token to the
temporary legacy-token path used by Go.

`mcp.dynamic.engines` and `mcp.agents` were in that group too and are now **ported**:
their missing-vault branch is byte-exact (`cannot load config: open <path>: no such
file or directory`) and their loadable-config branch is deterministic per fixture
(`no dynamic providers configured` / the agent list from the vault's own config), so
they are pinned for the missing and initialized fixtures — with the same documented
dialect exception on a corrupt config as `auth.passphrase.rotation`. The withdrawn
attempt had reported `ok` where Go reports `warn`; the ported version reproduces the
oracle's status.

The `mcp.server.reachable` check now has a controlled loopback HTTP differential
fixture; its internet connectivity and external-host branches are not exercised.

`crypto.scrypt.benchmark` stays out unless a shape-only comparison is explicitly
accepted as such.

Oracle behaviours the port must keep (verified 2026-09-19): text output goes to
stderr and JSON to stdout; `--output json` is **rejected** with exit 9 and
`Error: output format "json" is not supported by 'symvault doctor' …`, only the
deprecated `--json` flag produces JSON; without `--strict` the exit code stays 0
even with failures (8 = at least one fail, 7 = warnings only); `--only 'config.*'`
matches nothing because the IDs are `vault.config.parses`/`vault.config.validates`.

### Superseded first extraction (kept as history)

| Node | Missing flags |
| --- | --- |
| `file` | `--cert`, `--field`, `--from`, `--out`, `--shred` |
| `file use` | `--cert` |
| `get` | `--digest`, `--length`, `--metadata` |
| `import` | `--quarantine` |
| `mcp` | `--bind`, `--port`, `--tls-ca`, `--tls-cert`, `--tls-key` |
| `migrate` | `--dry-run` |
| `remote` | `--push` |
| `run` | `--broker`, `--broker-passthrough`, `--broker-strict`, `--workdir` |
| `set` | `--totp-account`, `--totp-issuer`, `--totp-secret` |
| `share` | `--status` |
| `template` | `--name`, `--prefix` |

Go reference entry points for the clusters that are self-contained enough to
port without the platform/broker slices: `cmd/auth/auth.go`,
`cmd/auth/auth_rotate.go`, `cmd/admin/audit.go`, the `cmd/config*.go` validate
path, `cmd/agent*.go`/`cmd/mcp/agent_install.go`, and `cmd/update*.go`.
