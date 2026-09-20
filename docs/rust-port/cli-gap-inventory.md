# CLI surface gap (measured)

Measured on **2026-09-20** against the Rust CLI at `1d534410` and the pinned Go
oracle command tree in `testdata/port/cli/command-tree.json` (`a518124f`,
release `unreleased`), depth 3. The previous inventory in this file walked a
different Rust revision by hand and is superseded below.

Reproduce (no Go oracle binary required — the frozen tree is the oracle side):

```sh
cargo build -p symvault-cli
go run ./scripts/rust-port/cmd/cligap
```

The tool writes `target/resume-evidence/cli-gap-inventory.json` and is
deterministic: same tree, same binary, same report.

**These are surface numbers only.** A reachable command is not a ported command.
Behaviour, output bytes, exit codes, side effects and flag semantics stay with
the behavioural rows (`CLI-005`..`CLI-007` and every non-CLI row); nothing here
promotes a contract row.

## Summary

| | count |
| --- | --- |
| oracle command paths (depth ≤ 3) | 134 |
| Rust command paths (walked from its own help) | 89 |
| oracle paths **missing** in Rust | **46** |
| oracle flags missing on reachable commands | **9** (on 3 commands) |
| oracle aliases missing on reachable commands | **3** |
| Rust paths not present in the pinned tree | 1 |

## Missing command paths (46)

| cluster | count | paths |
| --- | --- | --- |
| `agent` | 6 | `install`, `setup`, `skill`, `skill export`, `skill refresh`, `upgrade` |
| `serve` | 8 | `serve`, `install`, `status`, `uninstall`, `token`, `token create`, `token list`, `token revoke` |
| `approval` | 3 | `approval`, `decide`, `list` |
| `device` | 3 | `approval-list`, `approval-pair`, `approval-revoke` |
| `intake` | 3 | `intake`, `watch`, `watch disable` |
| `migrate` | 3 | `pseudonymize`, `session`, `v4` |
| `update` | 4 | `update`, `apply`, `check`, `info` |
| `mcp` | 6 | `token`, `token create`, `token list`, `token revoke`, `mcp-config`, `mcp-token-rotate` |
| `dynamic` | 2 | `dynamic`, `dynamic generate` |
| `import` | 2 | `review list`, `review promote` |
| single | 6 | `broker`, `generate manpages`, `help`, `setup`, `startup-profile`, `ui` |

## Alias gaps (3)

Cobra declares these aliases; the Rust parser rejects them. This was not
reported by the previous inventory.

| oracle node | missing alias |
| --- | --- |
| `symvault get` | `show` |
| `symvault get` | `cat` |
| `symvault list` | `ls` |

## Rust-only path (1)

`symvault mcp serve` is reachable in Rust and absent from the pinned tree.
The tree predates it; this is a re-pin decision, not a defect claim. `mcp
install`, `status` and `uninstall` are present on both sides.

## Deliberate non-claims

- Argument-count probes from the oracle tree are not replayed. Clap and Cobra
  report argument errors with different exit codes and text, so the comparison
  would measure parser error style, not the contract.
- Clap prints inherited global flags in every subcommand's options section while
  the tree records only each node's own flags, so additional Rust entries are not
  called divergences; only oracle flags **missing** in Rust are listed.
- Hidden commands stay invisible to both `--help` walks. They are not covered.


## Missing flags on commands that exist

**Corrected 2026-09-18:** the first extraction scanned the whole `--help` text, so
flags named only in prose or in a nested command's section were counted as gaps.
Re-extracted from the local `Flags:`/`Options:` section only, comparing Go's flag
definitions against Rust's:

| Node | Really missing |
| --- | --- |
| `import` | `--quarantine` |
| `mcp` | `--bind`, `--port`, `--tls-ca`, `--tls-cert`, `--tls-key` |
| `run` | `--broker`, `--broker-passthrough`, `--broker-strict` |

Everything else the first pass reported is already covered: `file`, `file use`,
`share`, `share list`, `migrate`, `remote`, `set`, `template`, `get` and
`migrate kdf` show no local-flag difference, and `share list --status` (which the
first pass listed under `share`) exists in both. `migrate --dry-run` exists only
in `import`; `migrate`'s flag section defines nothing but `--help`.

All three real gaps belong to feature slices that are not ported yet (broker,
HTTP/TLS, quarantine rules), so they must be recorded as blocked rather than
implemented as accepted-and-ignored flags.

**Confirmed by the 2026-09-20 measurement:** exactly these nine flags (three on
`import`, five on `mcp`, three on `run`) are missing on reachable commands — no
more and no fewer. The correction above was right; it was made by hand, this one
is reproducible.

**Superseded:** the "missing top-level groups (10 of 45)" and "missing
subcommands" tables that used to stand above this section came from a different
walk of a different Rust revision and over-counted both directions: they listed
`audit rotate-key`, `auth set`, `config validate`, `mcp install/status/uninstall`
and `completion` as missing although those paths exist and are reachable now,
and they omitted the alias gaps. Do not reinstate them; the measured summary at
the top of this file replaces them.

## `symvault doctor` check coverage (2026-09-19)

The command group exists in Rust, but only part of Go's check registry is ported.
Measured with `--json --no-network` against the pinned Go oracle
(`parent-doctor-matrix.py`, fixtures `empty`, `corrupt`, `env` and `initialized`):
Go runs **35** checks, Rust **33**. For the 33 shared IDs the
name/status/message/hint/fixable fields are byte-identical on a missing vault, on a
missing vault with the env-passphrase variables set, and on an oracle-initialized
vault (**0 field deviations**). The remaining 2 IDs are **not implemented** and are
therefore *absent* from the output rather than reported as OK — a missing check may
never look like a passing one.

### Known deviation: config-loader error dialect (not yet parity)

On a *corrupt* `config.yaml` three shared IDs diverge in the `message` field, all
through the same root cause: Go renders go-yaml's error text (`yaml: line 1: …`)
while the Rust loader renders its own (`parse config: … at line 3 column 1`).
The prefixed part (`config.yaml parse error: `, `failed to load config: `,
`cannot load config: `) is identical, so only the parser dialect differs:

- `vault.config.parses`, `vault.config.validates`, `auth.passphrase.rotation`,
  `mcp.dynamic.engines`, `mcp.agents` (all five share the one root cause)

This is a **pre-existing** divergence of the Rust config loader shared by the whole
CLI, not introduced by the doctor port, and it is **not** claimed as parity. The checks
ported in wave 2a quote no parser error, so they match on the corrupt fixture as well
(`differential_doctor_session_tooling_checks`); the two MCP config checks from wave 2b
do quote it and are therefore pinned for the missing and initialized fixtures only
(`differential_doctor_mcp_config_checks`).

Ported IDs (35 in the registry, 33 of them without network):

`vault.initialized`, `vault.config.parses`, `vault.config.validates`,
`vault.identity.encrypted`, `vault.permissions`, `auth.method`, `session.cache`,
`git.repo`, `git.remote`, `git.gitignore.protects`, `git.lastsync.fresh` (network),
`recipients.count`, `recipients.recovery`, `audit.log`, `audit.keyring.orphans`,
`update.available` (network), `vault.size`, `vault.stale_temp_files`,
`vault.conflict_files`, `vault.search_index.persistence`, `crypto.kdf.modern`,
`vault.manifest.intact`, `auth.passphrase.rotation`, `tooling.autotype.backend`,
`tooling.clipboard.backend`, `daemon.status`, `mcp.approval.tls`, `tooling.secureui`,
`tooling.precommit`, `session.keyring`, `password.strength`, `password.reuse`,
`security.env_passphrase`, `mcp.dynamic.engines`, `mcp.agents`.

Still open (2): `mcp.tokens`, `crypto.scrypt.benchmark` (plus the network check
`mcp.server.reachable`, which needs a controlled local HTTP fixture).

### Branch limitations of the ported checks (documented, not hidden)

These branches are unreachable in the fixture matrix but exist in Go, so they are
explicitly listed instead of being silently simplified:

- `auth.method`: the `touchid` branch needs `session.BiometricAvailable()` from the
  native platform slice; until then it always reports Go's degraded branch
  (`warn`, "configured as Touch ID but biometric not available on this system").
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

The two open IDs were each implemented at some point, measured against the oracle and
then **withdrawn again** because they cannot be byte-pinned — do not re-add them
without a new decision:

- `crypto.scrypt.benchmark`: Go embeds a *measured* duration and its recommended work
  factor for this machine in the message (the argon2id branch *is* stable, the scrypt
  branch is not).
- `mcp.tokens`: Go's message depends on token-registry side effects inside the
  (synthetic) vault path and contains a non-deterministic temp-file name; on an
  initialized vault it reports the *user's* token count.

`mcp.dynamic.engines` and `mcp.agents` were in that group too and are now **ported**:
their missing-vault branch is byte-exact (`cannot load config: open <path>: no such
file or directory`) and their loadable-config branch is deterministic per fixture
(`no dynamic providers configured` / the agent list from the vault's own config), so
they are pinned for the missing and initialized fixtures — with the same documented
dialect exception on a corrupt config as `auth.passphrase.rotation`. The withdrawn
attempt had reported `ok` where Go reports `warn`; the ported version reproduces the
oracle's status.

`mcp.server.reachable` (network-tagged) needs a controlled local HTTP fixture to
become pinnable.

`mcp.tokens` and `crypto.scrypt.benchmark` stay out unless a shape-only comparison is
explicitly accepted as such.

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
