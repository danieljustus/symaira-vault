# CLI surface gap (measured)

## Current help surface, 2026-10-04

At candidate 9178a3e6 (PR #1293), the source-tree cligap probes all 134 frozen
oracle paths at depth three and reports zero missing help paths, flags or
aliases. Its actual candidate binary SHA-256 is
0c674bb386c1462601672cbd3aa80d65b5f618b8f071efd0bafcc18c707aec63.
The repaired grouped-help walker discovers 119 visible paths, including the
root; it excludes generated help/completion helpers and hidden parents.
Direct probes also cover hidden oracle paths. The earlier walker counted only
one path when fed Go's grouped root help; a regression test now reads the real
generated artifact instead of assuming a Clap-only layout.

The Rust CLI preserves the public Go documentation, including commands whose
runtime is still incomplete. These zero help gaps therefore do not complete
CLI-002 or CLI-003. #1236 now implements shared serve/mcp launch flags,
locked/unlocked stdio and service children, with actual source-bound Linux
Go/Rust launch/protocol/private-file/TLS comparisons and mandatory native
Linux/macOS/Windows receipt jobs. The old bare-serve negative control is
replaced by the real initialized-vault guard; ADR 0013 records decisions and
measured HTTP differences. Serve native acceptance, broker flags/runtime, TUI,
broad argument diagnostics and whole output-mode acceptance remain open. CLI-004
has actual local Go/Rust artifact and completion evidence, with native
Linux/macOS/Windows acceptance pending. See ADR 0011 and the contract matrix.

The measurements below are historical snapshots, retained with their original
candidate and binary identity; their gap counts are not current status.

## CLI-005 / CLI-006 slice 2, 2026-10-22

`crates/symvault-cli/src/cobra_usage.rs` reproduces cobra's command resolution
(`stripFlags`, `Find`, legacy root-argument check), pflag's flag parse and the
argument validators before clap parses, so Go's usage errors, arity errors and
the output-format gate are produced byte for byte; anything it does not reject
falls through to clap unchanged. Evidence: `testdata/port/cli/error-taxonomy.json`
(40 usage cases, 116 arity rows, 116 gate rows, 29 not-initialized cases; the
follow-up below raises this to 63 usage cases and adds 23 argv shapes),
`make error-taxonomy-cli-differential`.

Measured before the change (28 hand-picked probes of the pinned Go binary against
the native one): 21 differed, typically clap wording and exit 1 for what Go
prints as a doubled `Error:` line, exit 9 for the format gate and exit 3 plus a
hint for an uninitialized vault. Not fixed and recorded: `delete` prompts before
the vault check; `run`/`file use` need `--` natively; `device approval-pair` and
`device revoke` word the failure differently; Go's `auth set|status|
rotate-passphrase` keep exit 1 for the same text (kept, covered by
`auth_commands.rs`).

### Follow-up: `device join --pairing-file` and flag types

Review of slice 2 found `device join --pairing-file <path> <token>` falsely
rejected: the emulation treated `--pairing-file` as a boolean (a leftover
override table), but Go declares it a string flag. With a non-empty value Go
wants exactly one positional (the token) and prints `with --pairing-file, pass
only the pairing token: ...` otherwise; without it exactly two, with the
`accepts between 1 and 2 arg(s)` message. Fixed by deleting the override table
and making the `device join` rule depend on whether the flag is set; flag types
now come only from clap, and `flag_types_match_the_command_tree` compares every
shared flag with `command-tree.json` so the class cannot return. The
`COMMANDS`/`GROUPS` tables are compared with the tree in both directions, and
`generate --length` now parses like `strconv.ParseInt(s, 0, 64)` (`0x10`, `0o17`,
`0b101`, `1_0`, range errors; the clap value parser is the same function).
`errtaxgen` records the new rows in `testdata/port/cli/error-taxonomy.json` (73
usage cases, 23 `argv_shapes`) and `device join` now prints its errors twice like Go. `agent skill` (bare) is byte-replayed through the
`group_help_agent_skill` row. Left open: a pairing file that is not JSON (Go's
decoder wording vs serde), the success path of `device join` (passphrase prompt),
and int flags other than `generate --length`.

Review follow-up (repeated booleans): pflag assigns a bool on every occurrence,
so `--json --json=false` leaves the flag unset and the last value wins. The
emulation only ever set `json_flag`, so `--json --json=false --output xml
startup-profile` named `json` instead of `xml` (exit 9 either way) and
`--json --json=false lock` was refused where Go reaches the command. The gate
now assigns the parsed value on every occurrence, and the global `--json`,
`--quiet` and `--no-pipe-warning` clap flags are `--flag[=bool]` with
`overrides_with` (Go's `ParseBool` forms, last value wins) instead of
`SetTrue`, which rejected `--quiet=false` and any repeat. Ten Go-recorded usage
cases (`bool_flag_*`) pin it. The command-local bool flags were left as
`SetTrue` at that point; #1529 below closes them.

### Local bool flags accept `--flag[=bool]` (#1529)

Every Go bool flag is a pflag `BoolVar`: `--flag`, `--flag=<ParseBool form>`,
`-x=<form>` and repeats (last value wins) are all valid. The Rust CLI still
declared the command-local ones as clap `SetTrue`, so `symvault doctor
--fix=false` and `symvault verify --rebuild=false` failed with `unexpected value
'false'` where Go succeeds. The enumeration is scripted from the recorded Go
command tree (`testdata/port/cli/command-tree.json`): 98 non-help bool flags on
runnable non-root commands (plus 14 shorthand forms). 82 have a clap arg at the
same path and 69 of those were `SetTrue` (`add`, `set`, `get`, `delete`,
`doctor`, `verify`, `sync`, `unlock`, `backup`, `import`, `export`, `generate`,
`file add`, `recipients add|remove`, `remote init`, `device
add|revoke|approval-revoke`, `approval decide`, `audit`, `audit export`, `agent
install|uninstall|upgrade`, `auth rotate-passphrase`, `config validate`,
`migrate kdf|pseudonymize|session|v4`, `template generate`). All 69, plus the
`audit -j` shorthand and the Rust-only local `agent install --quiet` (Go has
only the persistent flag, which accepts `=false`), now use the global flags'
`--flag[=bool]` spelling (`ArgAction::Set`, optional `require_equals` value,
`intake_commands::parse_bool`) with `overrides_with` on themselves, so a repeat
is last-value-wins. Of the other 16 Go flags, six are `--json` locals served by
the global flag (`audit`, `auth status`, `config validate`, `doctor`, `intake`,
`intake watch`), `import review promote --overwrite` is `import`'s clap
`--overwrite`, and nine belong to hand-parsed commands (below). Already-converted local
flags (`ui`, `completion`, `mcp`, `broker`, `run`, `recipients`/`auth`
`--reencrypt`) gained the missing `overrides_with` (a repeat such as
`--reencrypt --reencrypt=false` was rejected as "cannot be used multiple
times") and `auth rotate-passphrase --reencrypt` now takes Go's ParseBool forms
instead of only `true|false`. The cobra emulation also accepts `-y=value` for a
bool shorthand like pflag (previously it read `=` as an unknown shorthand: `sync
-f=false` printed `unknown shorthand flag: '=' in -=false`); `-y=maybe` is Go's
`invalid argument "maybe" for "-y, --yes" flag` and a bare `-y=` still reports
the `=` as unknown.

Evidence: 20 Go-recorded `bool_flag_local_*` usage cases in
`testdata/port/cli/error-taxonomy.json` (now 95 usage cases; `errtaxgen`
regenerated at the unchanged oracle `0cc78062`, only `generator_digest` and the
appended cases differ) cover `verify --rebuild=false|true|F|t|maybe|`, repeated
forms, `--rebuild-only=false`, `get -p -p=false`, `sync -f=false|maybe|`,
`sync --force=false`, `unlock --check=false`, `get --metadata=false` and
`recipients remove --yes=false --no-reencrypt=false`. 15 of them failed on the
pre-change binary. `doctor --fix=false` cannot be byte-replayed (its report
depends on keyring and host state), so its corpus case ends at `--help`, which
Rust decides before clap parses the value and therefore does not guard clap;
that is covered instead by two in-crate tests that run on every Go bool flag
of the tree: `go_bool_flags_accept_an_explicit_value` (structural: the clap arg
is the `--flag[=bool]` spelling, long and short) and
`clap_parses_explicit_values_of_every_go_bool_flag` (behavioral: `--f=false`,
`--f --f=false`, `--f=false --f`, `--f=F --f=1`, `-x=false` parse). Not
covered: the nine bool flags of the hand-parsed commands `update
apply|check|info` (7) and `setup` (2, not probed: interactive wizard); they are
not clap `SetTrue` and their parsers reject the `=value` form (measured: `update
check --force=false` exits 1 with `unknown command "--force=false"` where Go
exits 0). Also uncovered: the `delete` prompt-before-vault-check gap (`delete -y=false x` prompts), and
clap still rejecting `--flag false`-style extra positionals that cobra's
`legacyArgs` accepts (listed above).

### Review correction: NoArgs versus legacyArgs and bare dash

The regenerated corpus has 75 usage cases and 236 rejected arity probes across
116 runnable paths. The generator now records cobra's `unknown command` argument
validator family, exposing 48 previously misclassified `NoArgs` rejections on
12 paths. All are byte-replayed through the native binary; the three `update`
children preserve Go's single error line (`SilenceErrors`), while the other
NoArgs paths print two lines, without a usage hint. Root resolution errors,
not NoArgs validation errors, carry the usage hint. Bare `-` is skipped by
cobra's command-discovery `stripFlags`, but is positional in pflag's later
parse: `- get x` and `config - get x` now report two arguments for `get`.

Acceptance is bounded to recorded rejections, not every argument validator's
whole-binary behavior. cobra `legacyArgs` accepts arbitrary arguments on
non-root commands with no explicit validator (even when they have subcommands).
The emulator correctly proceeds; clap still rejects extra positionals there.
Measured examples (not exhaustive): `lock`, `verify`, `unlock`, `generate`,
`share list`, `policy list`, `agent list`, `agent whoami`, `approval list`,
`audit`, `audit rotate-key`, `auth rotate-passphrase`, `auth status`,
`device approval-pair`, `doctor`, `migrate kdf`, `migrate pseudonymize`,
`migrate session`, `migrate v4` and `recipients list`. Clap likewise still
rejects the accepting bare-dash shapes `- list`, `share - list` and
`-- get x`. These CLI-005/006 acceptance gaps remain open; accepting arity
probes test only the emulator.
Other command-body diagnostics remain per-command, except that
`finish_vault_result` and the code-3 callers of `finish_session_result` render
a message starting with `vault not initialized` with doubled error lines and
the init hint (including approval/file commands). `auth status` (code 1) and
`finish_vault_result_exit_1` keep a single error line.

## Historical measurement, 2026-09-27

Measured on **2026-09-27** against the Rust CLI built from candidate
`9628016f` and the pinned Go command tree in
`testdata/port/cli/command-tree.json` (oracle `3232e31f`, release
`unreleased`), depth 3. This supersedes the 2026-09-20 report below: the rebuilt
candidate has a different command surface.

The probe pins the binary: SHA-256
`7ce681026ae465dd52a7112471f89b795eddae77c93a1c43edfa03490838bb2f`, modified
`2026-09-27T13:47:54Z`.

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
| oracle paths rejected by the `--help` probe | **26** |
| oracle flags missing from probed paths | **8** (on 2 paths) |
| oracle aliases missing on reachable commands | **0** |
| Rust paths not present in the pinned tree | 0 |

## Paths rejected by the `--help` probe (26)

| cluster | count | paths |
| --- | --- | --- |
| `agent` | 1 | `setup` |
| `approval` | 3 | `approval`, `approval decide`, `approval list` |
| `broker` | 1 | `broker` |
| `device` | 1 | `approval-pair` |
| `dynamic` | 2 | `dynamic`, `dynamic generate` |
| single | 1 | `help` |
| `intake` | 3 | `intake`, `intake watch`, `intake watch disable` |
| `serve` | 8 | `serve`, `serve install`, `serve status`, `serve uninstall`, `serve token`, `serve token create`, `serve token list`, `serve token revoke` |
| single | 3 | `setup`, `startup-profile`, `ui` |
| `update` | 3 | `update apply`, `update check`, `update info` |

The `cligap` probe appends `--help` to every path. Rust accepts `symvault help`
and nested `symvault help config validate`, but Clap rejects `help --help`.
The catch-all `update` runner recognizes `apply`, `check` and `info`, but rejects
their `--help` form. Those four entries are help-path gaps, not unreachable
runtime commands. `cli_help_subcommand.rs` compares the generated help route
semantically with Go; rendered text is not byte-identical.

## Alias gaps (0)

The latest binary accepts all three aliases recorded by the pinned tree:
`show` and `cat` for `get`, and `ls` for `list`. The 2026-09-20 alias-gap
finding is resolved in the current candidate.

## Rust-only paths (0)

The current help walk found no Rust-only path at depth 3.

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
Go and Rust each run **35** non-network checks. For the original 34 shared IDs the
name/status/message/hint/fixable fields are byte-identical on a missing vault, on a
missing vault with the env-passphrase variables set, and on an oracle-initialized
vault (**0 field deviations**). The Scrypt benchmark now runs for legacy vaults;
its measured duration and recommended factor are host-dependent, so the added
differential compares the Argon2id branch exactly and the legacy branch's result
shape and warning hint.

### Config-loader syntax-error dialect (bounded corpus at parity, known gaps recorded; #1241)

Go renders `config.yaml` failures with go-yaml (`gopkg.in/yaml.v3`): `yaml: line N: <problem>`
for scanner and parser failures, `yaml: <problem>` for reader failures and first-line marks. The
Rust loader used to render serde_yaml's `<problem> at line L column C, while …` behind a
`parse config:` prefix. Both front ends are ports of libyaml, so problem strings and marks agree;
`crates/symvault-core/src/go_yaml.rs` converts the second form into the first (Go's `parser.fail`
line rule: context mark first, `+1` only for scanner errors, no line on the first line, none for
reader errors; the single spelling difference is yaml.v3's `hexdecimal`). The loader checks the
first document's syntax before decoding it, as Go does, and `config get`/`config set` run the same
gate before their lossless editor, so a failing load leaves the file untouched. Three more Go
loader rules are reproduced: an alias to an undefined anchor reads `yaml: unknown anchor 'x'
referenced` (yaml.v3 names the anchor; the name is read back from the alias token), a later
document counts as a second document only when it decodes (a syntax error in it, or in text after
a `...` marker, leaves a single-document stream), and a config that is only Unicode white space
(`unicode.IsSpace`: `\v`, U+0085, U+00A0, U+3000, …, not only ASCII) serves the defaults. The five
shared doctor IDs are `vault.config.parses`, `vault.config.validates`,
`auth.passphrase.rotation`, `mcp.dynamic.engines` and `mcp.agents`.

Evidence: `testdata/port/cli/config-yaml-syntax.json` freezes the pinned Go binary's (`0cc78062`)
exit status, stdout and stderr for **93** inputs (9 reader, 38 scanner, 22 parser, 8 node-builder
(undefined anchor), 1 loader and 15 accepted controls, among them the Unicode white-space configs
and the later-document syntax errors; at least 38 distinct go-yaml problem strings) over
`config validate`, `config validate --json`, `config get`, `config set` (config left unchanged),
the five doctor checks above and, for five representative failures, `agent list`.
`crates/symvault-cli/tests/config_yaml_syntax.rs` replays all **438** comparisons against the
native CLI byte for byte (the count is asserted); `make yaml-syntax-cli-differential` rebuilds the
oracle, re-verifies the fixture and runs the replay. The multiple-document rejection also matches
on `config validate` (it no longer carries the `parse config:` prefix). This is parity for that
corpus, **not** for YAML syntax errors in general: the next paragraph is the part that is not.

Open divergences, recorded in the fixture's `open_divergences` (**33** inputs, each with the Go
bytes of the commands it shows on, a `kind` and a reason; the replay asserts each still differs
in the way its kind says, so a fix has to move it into `cases`):

- *Scanner look-ahead (root cause of the largest family).* yaml.v3 keeps a two-token scanner
  look-ahead behind the parser (`yaml_parser_fetch_more_tokens`, for comment association);
  libyaml fetches a token only when the parser asks for it. When the parser rejects a token and a
  scanner failure sits in the next two tokens, Go reports the scanner failure (`mapping values are
  not allowed in this context`, with its own line) and the Rust loader reports the parser failure
  (`did not find expected key`). Same-line trailing tokens after a closed value are the common
  trigger: `a: "x" b: 1`, `a: [1] b: 2`, `a: {b: 1} c: 2`, `a: &x [1] c: 2`, `b: *x c: 2`,
  `a: {} b: 1`, a multi-line flow sequence followed by `b: 3` and more (11 `trailing_token_*`
  entries plus `- [] b: 1`, where libyaml is also in a different parser state, and the existing
  `%YAML` directive without `---`). An ad-hoc sweep of 1,020 generated inputs (quoted, flow,
  anchored, tagged and alias values followed by a second key, at four nesting positions) found 514
  that differ between the two CLIs: 495 in this wording, 16 in the sequence-root decode text below
  and 3 on a custom tag. No bounded rule reproduces it without the scanner state after the
  rejected token, which `serde_yaml_ng` does not expose and a safe re-implementation of
  yaml.v3's scanner would be needed for, so the class is recorded, not approximated. Exit status
  and the effect on the file agree for each recorded entry of the family (`kind: wording`). The look-ahead also
  reaches across documents: `a: 1\n---\n"x\n` is rejected by Go and accepted natively, and
  `a: 1\n---\nb: 2\n---\n"x\n` accepted by Go and rejected natively (`kind: behavior`).
- *Later documents.* `a: 1\n---\nb: *nope\n` (Go decodes the second document with anchors shared
  across the stream and fails, so it sees no trailing document; the native loader scopes anchors
  per document and rejects the stream as multi-document) and `config get`/`config set` on
  `a: 1\n---\n[\n` (Go reads only the first document; get reports the key and set succeeds, the
  native commands parse the whole stream and refuse).
- *Not libyaml.* A lone UTF-16 BOM stream (yaml.v3 decodes it), a UTF-8 BOM after the first line
  (yaml.v3 skips it), an alias to a scalar used for a string field (`vaultDir: *x`, accepted by
  Go, so validate, doctor, `agent list` and a nested `config set` succeed there; natively they
  fail, and `config set` rewrites the file before its post-update load fails) and a local tag on a
  value (`a: !t x`, accepted by Go) all differ in acceptance.
- *yaml.v3 decode and node layers.* A scalar or sequence root, `agents: x`, a root made of one
  zero-width space, and `config get`/`config set` (and `agent list`) on `null`, `---`, `{}`,
  comment-only, empty, spaces-only, NBSP-only and BOM-only configs fail on both sides with the
  same exit status and file effect (a failing load leaves the file untouched; `agents: x` is
  rewritten on both sides before the post-update load fails) and different text: yaml.v3 says
  `yaml: unmarshal errors: … cannot unmarshal !!str … into config.Config`, `parent is a scalar
  node, not a mapping`, `root node is a scalar, not a mapping`, `unknown(0) node`; the native CLI
  says `invalid type: string …`, `missing YAML document`, `document has no root to descend into`.
  The `config get` key-not-found text (Go appends its cause) is likewise not covered.

The checks ported in wave 2a quote no parser error (`differential_doctor_session_tooling_checks`);
the two MCP config checks from wave 2b are additionally pinned for the missing and initialized
fixtures (`differential_doctor_mcp_config_checks`).

Ported IDs (38 in the registry, 35 of them without network):

`vault.initialized`, `vault.config.parses`, `vault.config.validates`,
`vault.identity.encrypted`, `vault.permissions`, `auth.method`, `session.cache`,
`git.repo`, `git.remote`, `git.gitignore.protects`, `git.lastsync.fresh` (network),
`recipients.count`, `recipients.recovery`, `audit.log`, `audit.keyring.orphans`,
`update.available` (network), `vault.size`, `vault.stale_temp_files`,
`vault.conflict_files`, `vault.search_index.persistence`, `crypto.scrypt.benchmark`
(slow), `crypto.kdf.modern`,
`vault.manifest.intact`, `auth.passphrase.rotation`, `tooling.autotype.backend`,
`tooling.clipboard.backend`, `daemon.status`, `mcp.approval.tls`, `tooling.secureui`,
`tooling.precommit`, `session.keyring`, `password.strength`, `password.reuse`,
`security.env_passphrase`, `mcp.dynamic.engines`, `mcp.agents`,
`mcp.server.reachable` (network), `mcp.tokens`.

The network-tagged `mcp.server.reachable` check uses a controlled loopback HTTP fixture and is
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

The earlier `crypto.scrypt.benchmark` attempt was withdrawn because its measured
duration and recommended work factor cannot be byte-pinned. This slice adopts
an explicit shape-only comparison for the legacy Scrypt branch: both binaries
must run the check, emit a valid status and explain any below-target warning;
pure branch tests pin the exact text for fixed inputs. Argon2id and `--quick`
remain exact comparisons. This does not claim identical measurements.

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
