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
hint for an uninitialized vault. Not fixed and recorded then: `delete` prompts
before the vault check (since fixed by CLI-006: `delete x` is Go-exact and no
longer in `OPEN_NOT_INITIALIZED`); `run`/`file use` need `--` natively; `device
approval-pair` and `device revoke` word the failure differently (these four are
the cases `open_not_initialized_cases_are_still_open` still pins: 25 of the 29
not-initialized cases replay, four stay open); Go's `auth set|status|
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
`testdata/port/cli/error-taxonomy.json` (95 usage cases at that point; `errtaxgen`
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
covered: the two bool flags of `setup` (`--keep-on-error`, `--no-resume`),
because the native CLI has no `setup` command yet (`unrecognized subcommand`;
only its help text is ported).

The seven bool flags of the hand-parsed `update apply|check|info` follow pflag
since #1558: `update_commands` assigns `--flag[=<ParseBool form>]` with the last
occurrence winning, and the cobra emulation (`HAND_PARSED_BOOLS`, checked
against `command-tree.json`) rejects an invalid value before argument
validation and lets the local `update info --json` shadow the persistent flag.
Go prints these errors once (`SilenceErrors`). Evidence: 10 Go-recorded
`bool_flag_update_*` cases (105 usage cases, oracle `0cc78062` unchanged).
Before the fix the native CLI rejected `update check --force=false` with
`unknown command "--force=false"`, printed `update info --json=` doubled and
reported `update check extra --force=maybe` as an unknown command. Also uncovered then: the `delete` prompt-before-vault-check gap (`delete -y=false x`
prompted; closed by CLI-006, `delete` is no longer open), and
clap still rejecting `--flag false`-style extra positionals that cobra's
`legacyArgs` accepts (listed above).

### CLI-003/CLI-005: typed-flag and required-flag diagnostics (P2)

pflag parses every typed flag while it parses the flags, so a bad value is a usage
error before the argument validator, the output-format gate, the required-flag check
and any vault precondition. The cobra emulation (`cobra_usage.rs`) now does that for
**every** typed flag of `command-tree.json` instead of `generate --length` and three
durations: `INT_FLAGS` (`add --length`, `agent audit --limit`, `audit --tail`,
`file add --max-size`, `generate --length`, `intake --batch-limit|--max-files`,
`mcp|serve --port`, `startup-profile --count|--top`; `ParseInt(s, 0, 64)` wording,
`invalid syntax` / `value out of range`), `DURATION_FLAGS` (also `intake watch
--debounce|--interval`, `unlock --ttl`; `time.ParseDuration` wording) and the new
`STRING_SLICE_FLAGS` (`agent token new|rotate --tools`, `broker --passthrough`,
`doctor --only|--exclude`, `run --broker-passthrough`): pflag reads a `stringSlice`
value as one `encoding/csv` record, so `go_csv_error` ports `Reader.readRecord`
(bare `"`, unterminated quote, multi-line `record on line N; parse error on line M`,
blank lines = `EOF`, `\r\n` folding). `stringArray` flags (`run --env|--env-file|
--passthrough`) cannot fail. The labels carry the shorthand like Go
(`-n, --tail`, `-n, --count`, `-t, --timeout`). `REQUIRED_FLAGS` gained
`profile add` (`--vault`; `--vault=` is set, so Go's own `--vault is required` comes
from the body, recorded as the `profile_add_empty_vault` argv shape). The six clap
`i64` flags that lacked it (`add --length`, `audit --tail`, `startup-profile`
`--count|--top`, `mcp|serve --port`, `agent audit --limit`, `intake --max-files|
--batch-limit`) now parse with `parse_go_int` and accept a leading `-`, so a value
the emulation lets through (`0x10`, `-5`) is not rejected by clap afterwards.

Guard: `typed_flag_tables_cover_every_typed_flag_of_the_command_tree` fails when the
tree has an int/int64/duration/stringSlice flag in no table (or in the wrong one) or
when `REQUIRED_FLAGS` differs from the tree's `MarkFlagRequired` flags.
Evidence: 54 Go-recorded `typed_*` / `required_flag_*` usage cases plus one argv
shape in `testdata/port/cli/error-taxonomy.json` (159 usage cases, 24 argv shapes;
`errtaxgen` regenerated at the unchanged oracle `0cc78062`, only `generator_digest`
and the appended cases differ). Negative control: dropping `unlock --ttl`,
`intake --max-files`, `doctor --only` and `profile add`'s required `vault` fails 14
corpus cases plus both unit guards.

### CLI-003 residuals: int64 `--max-size`, `stringSlice` CSV, re-read durations (`local/cli003-resid`)

The three residuals the typed-flag work above left open are closed with a new section
`typed_flags` of `testdata/port/cli/error-taxonomy.json` (140 Go-recorded scenarios:
132 in the initialized vault, 8 in an uninitialized one; oracle `0cc78062` unchanged,
`errtaxgen` regenerated, only `generator_digest` and the new section differ; the
sandbox accepts `files` in nested directories for it, and a `token_values` normalizer
rewrites the random token id, expiry and raw token).

- **`file add --max-size` is an `int64`.** The clap field was a `u64`, so a negative or
  base-prefixed value that Go accepts was rejected by clap after the emulation let it
  through. It now parses with `parse_go_int` (`ParseInt(s, 0, 64)`: `0x`/`0o`/`0b`/
  leading-`0` prefixes, `_` separators, a sign), takes a dash-leading word as its value
  like pflag, and keeps the last of a repeated flag (`args_override_self`). A negative
  limit rejects every file (`source file is 100 bytes, exceeds the -1 byte limit`, exit 9,
  printed twice); `-9223372036854775808` and `0x7fffffffffffffff` are accepted, `0x8000…`
  and `±99999999999999999999` are the recorded range errors. Making the value observable
  exposed that `file add` ran its whole front end after the vault unlock: Go checks
  `--field` and `--from` (exit 9: `--field is required`, `--from is required`), stats the
  source (exit 1, `cannot stat source file: stat <path>: no such file or directory`), applies
  the size limit (exit 9) and reads the file (exit 1, `read <dir>: is a directory`) **before**
  it resolves the vault, so none of them needs an initialized vault. `--field` and `--from`
  were clap-required arguments with clap wording and exit 1. `file_commands::read_source`
  now does Go's checks in Go's order before `resolve_vault`/unlock; the bounded read (a
  source that grows past the limit after the stat is still refused) is kept.
- **`stringSlice` flags are one CSV record per occurrence.** `go_csv_record` (port of
  `encoding/csv` `readRecord`, the same code `go_csv_error` now derives its message from)
  returns the elements pflag stores: a quoted comma stays in one element, `""` inside
  quotes is a quote, empty elements are kept, only the first record is read (a second line
  is ignored), leading blank lines are skipped, an empty value is an **empty slice, not the
  default**, the first occurrence replaces the default and later ones append
  (`string_slice_flag`). Native clap split on `,` instead (`value_delimiter`), which kept
  quotes, kept a lone empty element for `--only ""` (so the filter matched nothing where Go
  filters nothing), appended `x,y` + `""` as an empty element and rejected a dash-leading
  value. `doctor --only|--exclude`, `agent token new|rotate --tools` (default `*`, an empty
  result is `at least one tool must be specified`), `broker --passthrough` and `run
  --broker-passthrough` take the raw occurrences (`allow_hyphen_values`) and split them
  with the shared function; the private CSV parser of `broker_commands` is gone.
  `go_csv_record_equals_pflag_string_slice` compares 45 occurrence lists with real pflag
  v1.0.10 (12 are errors).
- **Durations commands re-read.** The cobra emulation already validated the syntax; what
  was left is what the commands do with a value Go accepts. Differences found and fixed:
  a dash-leading value (`run --timeout -5s`, `file use -t -5s`, `unlock --ttl -5s`) was
  rejected by clap; `file use` rejected a repeated `-t`/`--timeout` (pflag keeps the last);
  a timeout that has already expired when the process would start is not started by Go
  (`exec.Cmd.Start` checks the context: `failed to run command: context deadline exceeded`,
  `run --timeout 1ns`) while Rust started and killed it (`command timed out after 1ns`);
  and `file use` printed that error once instead of Go's two lines. Accepted forms
  (`+5s`, `.5s`, `1.s`, `1µs`/`1μs`, compound units, `0`, `-0s`, the largest int64
  nanoseconds, a negative value meaning no timeout) were already identical and are now
  recorded for `run`, `file use`, `unlock --ttl`, `intake watch --once --interval|--debounce`
  and `dynamic generate --ttl`.

Evidence: `native_cli_matches_go_typed_flags_{uninitialized,initialized}` replay all 140
scenarios (8 + 132, zero skipped); `typed_flag_section_records_every_residual_class` and
the Go test `TestTypedFlagInputsCoverEveryResidualClass` fail when a class disappears;
negative controls: restoring `u64`, the old comma split and the missing deadline check each
fail the replay (see the receipt in the packet result).

Still open after this packet (not flag parsing):

- `broker --passthrough` and `run --broker-passthrough` hand the slice to the egress proxy;
  `broker` prints it only after it listens, so no terminating Go run shows it. The values
  are covered by the shared `go_csv_record` corpus and the usage errors, not by a recorded
  broker run.
- The text `Watching <dir> (interval X, debounce Y). Ctrl-C to stop.` of the always-on
  `intake watch` for unusual literals needs a signal-ended run (IO-003's contract covers
  `--interval 1h`; `--once` with zero/negative values is covered there and here).
- A timeout of roughly a microsecond to a millisecond races Go's process start against the
  deadline (`run --timeout 1us` printed `command timed out after 1µs` in one run and the
  expired-context error in another), so it is not recorded; Rust uses Go's rule (deadline
  already past before the start), which makes the outcome equally timing-dependent there.
- `unlock --ttl` only shows the effective TTL on a persistent session cache; the sandbox
  keeps the cache in memory (`CI=1`), so the recorded runs prove acceptance, not the value.
  `dynamic generate --ttl` is accepted and ignored: the pinned oracle registers no engine.
- Deliberate deviation: a source that grows past `--max-size` between the stat and the
  read is refused by Rust (bounded read) where Go would store it.

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
`migrate session`, `migrate v4` and `recipients list`. The accepting
bare-dash shapes `- list`, `share - list` and `-- get x` are closed (CLI-005,
local/cli005-plat001: `cobra_usage::clap_arguments`, the root help and the help
topic walk; 83 Go-recorded `bare_dash` scenarios). The other CLI-005/006
acceptance gaps remain open; accepting arity probes test only the emulator.
Other command-body diagnostics remain per-command, except that
`finish_vault_result` and the code-3 callers of `finish_session_result` render
a message starting with `vault not initialized` with doubled error lines and
the init hint (including approval/file commands). `auth status` (code 1) and
`finish_vault_result_exit_1` keep a single error line.

## CLI-006 delta review follow-ups, 2026-11-01

Fixed, each pinned against the real Go binary (oracle `bf7f687b`) in
`testdata/port/cli/output-modes.json` (524 cases now; 54 added, 48 of them differed before):

- `config set` reload: aliases (the error names the anchor's line), `<<` merge keys (own keys win, a
  sequence of maps, a non-mapping operand aborts), explicit tags (`!!str 12` stays a string, `!!int abc`
  aborts with `yaml: cannot decode …`), duplicate keys, and `time.Time` fields (`vault.last_rotated`
  takes a mapping, a plain timestamp and RFC 3339 text; anything else aborts with Go's
  `parsing time … as "2006-01-02T15:04:05Z07:00": …`). Core `Config::load` treats a `last_rotated` mapping
  as the zero time.
- yaml.v3 resolver: `0b+1`, `0b-1`, `0o-12`, `0o+12` are ints, `.1_0`, `.5_6`, `.5e1_0` floats, so Go quotes
  them (`yaml-scalars.json`, 306 values).
- `gen_config_schema.py` reads every non-test `internal/config` file and stops on a field it cannot model.
- Config reads and `agent profile export -o` print ENOTDIR, ELOOP, ENAMETOOLONG (and every other
  create failure) as Go's `open <path>: <cause>`.

Still open (probed, not fixed; see the CFG-003 and CLI-005 rows of the contract matrix; the `vault.authMethod` and `sessionTimeout: null` rows that stood here are closed, see CONFIG-LOAD-001 below; the seven `Config::load` rows on float and YAML 1.1 scalars, custom tags and unread keys are closed too, see CONFIG-SECTIONS-001 below):

| Class | Go | Rust |
| --- | --- | --- |
| nesting depth | stops at 10000 open flow collections and at 10000 nested block collections (two separate counters, scanner problem `exceeded max depth of 10000`, `line N:` only past the first line) | **loader fixed**: `Config::load`, `config validate`, `doctor` and the gate of `config get`/`config set` accept exactly what Go accepts and refuse level 10001 with Go's text (`symvault_core::go_yaml_depth`; 26 Go-recorded `nest_*` cases in `config-yaml-syntax.json`). **Still open:** `config get`/`config set` read and rewrite the tree with `yaml_edit`, which refuses beyond 256 flow levels, so 257-10000 levels validate but cannot be read or edited (open divergences `nest_get_set_flow_sequence_257`/`_10000`); the read stops at the depth violation, so 100k `[` are refused in 0.5 s (debug build `config validate`; 35 s before the read stopped there, Go 0.02 s), and a 400 KB config with 11000 keys plus a 300 KB run of blanks validates in 5.3 s (debug; not finished after 120 s while every blank rescanned the run, Go 0.35 s). |
| `profiles:\n  x: null` | nil pointer panic, exit 2 | parse error, exit 6 |
| `config set x 1e3` / `y` / `2026-10-31` | writes `1000` / `"y"` / `2026-10-31T00:00:00Z` | `1000.0` / `y` / `2026-10-31` (ADR 0034 item 3, maintainer decision pending) |
| `config set x 010` / `017` / `0b11` / `0b101` / `1_000` (ADR 0034 item 4) | writes `8` / `15` / `3` / `5` / `1000` | **fixed**: same. A plain scalar that `symvault_gojson::resolve` resolves to `!!int` is written as its decimal value (also inside flow sequences and mappings; a quoted `"010"` stays a string). Before: `10` / `17` / `"0b11"` (an int key then failed the reload) / `"0b101"` / `1_000`. Pinned by 25 Go-recorded `config-set-int-*` cases in `output-modes.json` (oracle `bf7f687b`, `post` `config get` shows the stored number) |
| `config set x '<<'` | writes `!!merge <<` | writes `"<<"` |
| re-encode of the rest of the file | CRLF becomes LF; flow sequences get `, ` spacing (`[x,x]` becomes `[x, x]`); timestamp scalars in flow mappings are quoted (so a later error says `!!str`, not `!!timestamp`); anchor comments move behind the collection (changing reported lines); explicit keys, `\u00e9` escapes, verbatim and `!` tags, `!!int &a 12` order, tagged block sequence indent are normalised | kept as written |
| root that is not a mapping | `root node is a scalar, not a mapping` (or `a sequence`) | `document has no root to descend into` |
| typed decode, anchors | the preceding definition of a redefined anchor; the anchor's line even behind a comment | the last definition; the collection's line |
| typed decode, `!!binary` into `time.Time` | raw decoded bytes in the `parsing time` text | lossy UTF-8 (U+FFFD) for a non-UTF-8 payload |

## CONFIG-LOAD-001: loader and validator parity, 2026-11-02

`config validate` reproduced six divergences from `config.Load` / `Config.Validate` (found while
reviewing `--fix`; every one also showed without `--fix`). All six were one root cause each in the
shared core loader (`crates/symvault-core/src/config.rs`), so every command that loads a config
changed, not only `config validate`:

| Input | Go (oracle `0cc78062`) | Native before | Now |
| --- | --- | --- | --- |
| `vaultDir: ''` (or `null`) | valid: the merge keeps the resolved default (an empty text is not a value) | `vaultDir: must not be empty` | valid; the message survives only where no default resolves (no home, no `SYMVAULT_VAULT`) |
| `promptInjectionMode: weird` | load error `agent "x": invalid promptInjectionMode "weird" (valid: off, log-only, wrap, deny)` (after the `approvalMode` loop, which wins) | accepted | same load error |
| `audit.maxSizeMb: abc` | load error `yaml: unmarshal errors:\n  line 2: cannot unmarshal !!str `abc` into int64` | accepted | same |
| `logging.level: [1]` | load error `... cannot unmarshal !!seq into string` | accepted | same |
| `authMethod: bogus` | loads and validates: the merge drops a method that does not normalize, but the key still counts as written (`useTouchID: true` then selects nothing); `vault.authMethod: bogus` loads and `Validate` rejects it, quoting it as written | load error `invalid authMethod` | same as Go, including the non-string spellings (`5`, `true`) |
| `sessionTimeout: 0s` | `sessionTimeout: must be greater than 0, got 0s (default: 15m, ...)`; both durations are reported (joined by `\n`); `null` decodes to `0s`; an integer is a typed-decode error | no `, got 0s`; first field only; `null` was `must be a string` | same as Go (`go_duration_string` is `time.Duration.String`) |

Root causes: (1) the typed decode of yaml.v3 into `config.Config` — which Go runs over the whole
first document before it merges anything — only existed in the CLI (`config set`'s post-write reload).
`config_typed.rs` and the generated `config_schema.rs` moved into `symvault-core`
(`scripts/rust-port/gen_config_schema.py` now writes `crates/symvault-core/src/config_schema.rs`;
`symvault-core` gained the `yaml-edit` and `symvault-gojson` dependencies, `Cargo.lock` moved by those
two edges only) and `Config::load_from_bytes` calls it right after the syntax and multiple-document
checks. The sections the port does not model (`audit`, `logging`, `security`, `scan_patterns`, ...)
are therefore type-checked like Go. This also closed `agents_scalar` (an open divergence, now the
`decode`-class case) and the FFI `OpenVaultWithPassphrase/config-type-mismatch` pin. (2) The merge
rules above. (3) `ConfigError::Parse` / `::Invalid` carried the prefixes `parse config:` /
`invalid config:`; Go returns its causes bare and each caller adds its own wrapper (`cannot load
config from <path>: X: X`, `load config: X`, `config load failed: X`), so the variants now render bare
(the `go_text` stripper of the `--fix` flow is gone).

Evidence: `testdata/port/cli/config-yaml-syntax.json` (now 128 cases, 31 open divergences, 554
comparisons; the 94 earlier cases and 30 of the 32 earlier open divergences are byte-identical to the
previous fixture) gained 32 `load_*` cases, the `decode`-class `agents_scalar` and the promoted
`alias_value_for_string_field`, all recorded from the pinned
Go binary through `yamlsyntaxgen` (`config validate` text and `--json`, `doctor`'s five loader checks
and, for 9 cases, `agent list` — the "normal command"; `internal/config/config_merge.go` and
`config_validate.go` joined the digest-bound sources). `make yaml-syntax-cli-differential` re-verifies
and replays them; core contract tests that used to accept substrings of the Rust text now compare the
recorded Go diagnostic exactly (`config_session_contract`), and the eight `ADJUDICATED_STRICTER`
authMethod entries of `config_sections_contract` are gone (the loader matches Go on all of them).

### Intentional deviations (decided, not gaps)

| Where | Go | Native | Pinned by |
| --- | --- | --- | --- |
| `config validate --fix` with `clipboard.copyByDefault: false` | `CopyByDefault bool` is `omitempty`, so `SaveTo` drops the key and the next load reads the default `true`: an unrelated repair silently turns the opt-out into an opt-in | the writer prints `copyByDefault: false`, so the opt-out survives; everything else the repair writes is byte-identical | `intentional_deviation_copy_by_default_false_survives_fix` (recorded Go bytes, plus the live oracle when `SYMVAULT_GO_BINARY` is set) and its negative control `copy_by_default_deviation_is_exactly_one_line` in `config_fix_differential.rs` |
| several agent profiles that are all invalid | `validateAgents` ranges over a map, so which profile is named is random (the `approvalMode` loop still runs before the `promptInjectionMode` loop) | profiles are checked in name order | not pinned (Go is nondeterministic); `load_agent_enum_order` pins the one deterministic fact |

### Residuals (probed, not fixed)

- The doctor check `vault.config.validates` calls only the typed `Config::validate`, so it reports
  `config.yaml passes validation` for `audit.maxSizeMb: 0` where Go warns about `audit.maxFileSize`
  (`config validate` itself agrees; recorded as the open divergence `load_audit_max_size_mb_zero`, which
  replaced the two entries `agents_scalar` and `alias_value_for_string_field` that this change closed).
  (Closed by CONFIG-RESID: the typed config carries the audit size, so the doctor check agrees.)
- A typed-decode error whose quoted value is cut inside a multi-byte character is rendered with
  U+FFFD by the loader (`String::from_utf8_lossy`); `config set` still prints Go's raw bytes.
- A non-string scalar in a string field decodes to its text in Go. (Closed by CONFIG-SECTIONS-001:
  every string field reads the source text, so `vault.authMethod: 0x10` is quoted as `"0x10"`.)

## CONFIG-SECTIONS-001: the section parsers read what yaml.v3 decoded, 2026-11-02

The CONFIG-LOAD-001 review swept 1,316 generated field-table configs plus 62 syntax variants through
both CLIs (`config validate`, `config validate --json`, `agent list`) and found 109 inputs Go accepts
and the native loader rejected. They shared one cause: the per-section parsers in `config.rs` read the
`serde_yaml_ng` value of the first document and re-implemented, field by field, what yaml.v3's typed
decode does to a scalar, so every scalar that decode coerces (and `serde_yaml_ng` does not) was refused.

| Class (Go decode of the field type) | Example | Before | Now |
| --- | --- | --- | --- |
| string field takes any scalar as its source text | `vault.path: 5`, `mcp.bind: 1.5`, `git.commit_template: true`, `agents.x.skillPath: 0x10`, `tier: 5`, `[5, true]` in a `[]string` | `must be a string` | text kept (`"5"`, `"1.5"`, `"0x10"`) |
| int field truncates a float, reads YAML 1.1 ints | `mcp.port: 1.5` / `1e3` / `1_000` / `017`, `argon2id_time: -1.5` | `must be an integer` | `1` / `1000` / `1000` / `15` |
| `*bool`, `*int`, `*string`, `*time.Duration` take `null` as nil | `agents.x.canWrite: null`, `max_reads_per_hour: null`, `tier: null`, `skillPath: null` | `must be a boolean/an integer/a string` | field left alone (`tier: null` still counts as written, so the profile is not made to expose the value tools) |
| negative durations in the sections | `mcp.approval_timeout: -1s`, `vault.listing_cache_ttl`, `update.cache_ttl`, `git.auto_pull_interval`, `agents.x.approvalTimeout` | `has a negative duration` | accepted; kept as zero (see below) |
| `agents: null`, `agents.x: null` | | `top-level YAML document must be a mapping` | nil map / zero profile (the profile still exposes the value tools) |
| null item in a `[]string` | `allowedPaths: [null, '[']` | `must be a string` | item dropped, so the bad glob is entry 0 as in Go |
| non-string `approvalMode` | `approvalMode: 5` | `approvalMode must be a string` | Go's `invalid approvalMode "5" (valid: none, deny, prompt)` |
| rendering of a coerced number | `vault.authMethod: 0x10`, `defaultAgent: 0x10`, `promptInjectionMode: 0x10`, `1.50`, `True` | quoted as `"16"` / `"1.5"` / `"true"` (serde's rendering) | source text |
| custom tag `a: !t x`, second-document syntax error | | rejected by serde (tag), or typed decode skipped | accepted like Go (open divergence `custom_tag_on_value` promoted to a case) |

Design: one source of coercion truth. `config_typed.rs` (the port of yaml.v3's `decode.go` that already
validates the whole first document) now also produces the *decoded* tree
(`config_typed::coerced_document`): each scalar is converted by the Go type of its field (string = the
source text, bool = the decoded boolean incl. `y/yes/on/n/no/off`, int = the truncated int, duration = its
nanoseconds, null = null, null items of a `[]string` dropped, struct fields the Go type does not name
dropped, `<<` merges filled in behind the mapping's own keys with the earliest operand first). Every
struct/map mapping reached without an alias or merge also carries the list of keys it wrote itself
(under a non-string mapping key, `own_keys_key()`, so no YAML string key such as a double-quoted `"\0own"`
can collide with it; a key is listed by its node's text, which for an alias is the anchor name, and an alias
that resolves to another text credits its fields to a name nothing looks up), the view Go's `loadSectionFields`/`loadAgentFields`/`loadTopLevelFields` walk the node tree
for. `config.rs` then merges exactly as `config_merge.go`: a section field only when the section wrote it,
`*T` agent fields whenever the decoded value is not nil (a merged `promptInjectionMode: weird` is
rejected, a merged `approvalMode: bogus` is ignored because that field is gated on being written), the
`sync` block and the `approval_required` warning regardless. The vault merge feeds the top-level method
from the *decoded* `useTouchID` (`raw.UseTouchID`, merged keys included) when no `authMethod` was written,
while `vault.useTouchID` itself keeps only a key the section wrote. The per-field special cases
(`text_scalar`, `boolean`, `integer`, `duration`, `duration_allowing_negative`, `present`,
`ProfileFields`/`ProfileYaml`) are gone. `yaml_edit` now parses with `YamlFile::parse(..).tree()` so a
syntax error in a later document (which Go never reads) no longer hides the first document from the
typed decode. `migrate kdf --allow-legacy-kdf` (`migrate_resource_policy`) wraps its config stages like
`prepareResourceMigrationConfig`: `read migration config: …`, `load migration config: …`,
`validate migration config: …` (the validate stage is new), `migration config vault must be a mapping`.
The scrypt path (`migrate_kdf`, `prepare_config_update`) has no Go counterpart that re-reads the config
(`vault.MigrateKDF` works on the already loaded one and ignores the save error), so its `load config` /
`validate rendered config` texts are left as they were.

Evidence: `testdata/port/cli/config-yaml-syntax.json` (now 183 cases, 33 open divergences at that time (29 now), 737
comparisons; the 128 earlier cases and 30 of the 31 earlier open divergences are byte-identical, the
31st, `custom_tag_on_value`, matches Go now and became a regular case) gained 47 `load_*` cases recorded
from the pinned Go binary (`yamlsyntaxgen`, oracle `0cc78062`): every coercion class above with its
accepted and rejected siblings, chosen so the coerced value shows in Go's message where it prints one
(`invalid authMethod "0x10"`, `argon2id_time: 1 is below minimum floor of 2`, `allowedPaths[0]`), plus
the merge gates. The CONFIG-SECTIONS-001 fix round added seven more (`load_vault_use_touch_id_via_merge`
and its inline-flow sibling, `..._merged_then_overridden`, `load_agent_name_alias_fields_unwritten`,
`load_vault_section_alias_fields_unwritten`, `load_vault_field_alias_named_by_anchor`,
`load_agent_name_nul_own`) and two new optional observations: `auth_method` (the `Auth method:` line of
`auth status`, the only command that shows the method the vault merge resolved) and `agent_list` for the NUL
agent; the 176 earlier cases are byte-identical. `section_coercions_are_pinned_to_what_go_prints` names the pinned outcomes and mutates
three expectations (a wrong coercion must fail the replay). Core unit tests cover the decoded tree and the
loader (`coerced_*`, `sections_read_the_values_yaml_v3_decodes`, `agents_take_nulls_and_non_string_scalars_like_go`,
`merged_values_follow_the_gates_of_the_go_merge`, `coerced_values_show_in_the_loader_and_validator_messages`).
Re-measured with the review's sweep (1,316 generated + 190 + 62 + 2 + 19 hand-written configs, three
commands each): Go accepts and native rejects **109 → 0** in the generated set (118 → 0 over all 1,589
configs; 344 of 4,767 comparisons before).

### Residuals (probed, not fixed)

- (All of the following except `profiles: {p: null}` are closed by CONFIG-RESID, below.) The sweep's 59
  remaining differences are all outside the section parsers: 41 inputs Go rejects and
  native accepts — `paymentPolicies` (Config.Validate's instrument / limit / agent-reference checks are
  not ported: the native `Config` has no `paymentPolicies` section; open divergences
  `load_payment_policy_without_instrument`, `load_agent_payment_policy_unknown`) and `audit.maxSizeMb:
  null` (Go validates a zero maximum size; `config validate` reads the numeric value only, open divergence
  `load_audit_max_size_mb_null`; `load_audit_max_size_mb_zero` stays open for the doctor check) — 17 inputs
  that differ only in stderr because the CLI does not print the loader's three deprecation warnings
  (`envWhitelist`, `mcp.approval_required`, `clipboard.printByDefault`; `Config::load_from_bytes_with_warnings`
  returns them, no command shows them) and `profiles: {p: null}` (Go dereferences the nil profile and
  panics with exit 2; native refuses with exit 6, deliberately).
- Negative durations are not representable in the unsigned `Duration` of the native config; they are kept
  as zero. The Go consumers read `vault.listing_cache_ttl`, `update.cache_ttl` and `git.auto_pull_interval`
  only when positive (`vault.go:231`, `update.go:35`, `sync.go:27`), the MCP network timeouts and `oauth`
  TTLs are positive-only overrides, and an agent's `approvalTimeout` of zero or below falls back to the default approval timeout
  (`approval_helper.go:77-81`; the native `store_adapter.rs` falls back too), so zero says the same in each
  case. What is not modelled is the display: `agent profile show` / `agent profile export` print a negative
  `approvalTimeout` as Go does (`-1s`) and omit a `null` one, while the native CLI prints `0h0m0s` for both
  (`agents.x.approvalTimeout: -1s` and `null`); `config get`/`config list` style output of a negative value
  is not modelled either.
- Go credits an alias key's fields to the anchor name; when that name is itself a different section (or
  agent) name, Go attributes the written fields to that other section. The native tree only withholds them
  from the section the alias resolves to (the case Go's own lookup reaches), so a second, real section named
  like the anchor does not inherit them.
- `agents.*.perToolRedactFields`, `dynamicProviders`, `pre_call_hooks`, `post_call_hooks`,
  `scan_patterns`, `mcp.perplexity` are decoded and type-checked but not carried by the native
  `AgentProfile`/`McpConfig` (unchanged; `paymentPolicy` and `paymentPolicies` are carried since
  CONFIG-RESID).
- A key written both as an integer and as the same text under a merge (`1: a` own, `"1"` merged) is one
  key here and two in Go's `mergedFields` (interface-typed keys).
- An explicitly empty or null `vault.authMethod` loads as `""` in Go and `passphrase` in Rust. No command
  shows it (delta review probed 6 configs across `config get vault.authMethod`/`authMethod`, `config list`,
  `auth status [--json]`, `config validate`, `agent list`, `doctor --no-network`): Go's
  `EffectiveAuthMethod` reads `Vault.AuthMethod` only when the top-level method is empty. It could only
  surface in file text after a save when the top-level method is touchid, and the top-level key wins on
  reload; no save path was exercised.
- `agent profile show/export` still read the raw YAML (`agent_profile_commands.rs`), so a duplicate agent
  key reached through an alias (`&a x: {...}` then `*a : {...}`) fails there with `agents: duplicate entry
  with key "x"` (exit 1) where Go loads it (exit 0); `config validate` and `agent list` agree with Go.
- `get`/`set` observations of `custom_tag_on_value` (node layer, `textCommands`) are no longer recorded
  with the promoted case; they were never part of the `accepted` class.

## CONFIG-RESID: audit and paymentPolicies validation, deprecation warnings, 2026-11-02

Closes the residuals the CONFIG-SECTIONS-001 sweep left (136 differences over its 1,589 configs x 3
commands = 4,767 comparisons: 82 inputs Go rejects and native accepted, 51 that differed only in
stderr, 3 `profiles: {p: null}`).

- **`Config::validate` checks `audit` and `paymentPolicies`.** `Config` now carries
  `audit_max_file_size` (`maxSizeMb` x 1 MiB in wrapping `int64`, present only when the file has an
  `audit` mapping; a written `maxSizeMb` that is `null` or empty decodes to zero, as in Go),
  `payment_policies` and `AgentProfile::payment_policy`, all read from the yaml.v3-coerced tree
  (`parse_audit_max_file_size`, `parse_payment_policies`). The checks, their texts and their order are
  `validatePaymentPolicies` / `validateDecimalString` / `validateAgentPaymentPolicies` of
  `config_validate.go`, placed where Go's `Validate` puts them (audit before clipboard; payment policy,
  then agent reference, before Argon2id). `config validate`, `--json`, the doctor check
  `vault.config.validates` and the KDF migration all go through the one validator;
  `config_fix.rs` no longer inserts the audit error itself and keeps the audit size in the core config
  in step when `--fix` repairs it. Go ranges over the policy and agent maps in random order and returns
  the first failing entry; the native validator reports the first in name order (like the existing
  agent loops), and no recorded case has two failing entries in one map.
- **Deprecation warnings reach stderr.** `symvault_core::config::set_warn_hook` is Go's
  `config.SetWarnFunc`; the CLI installs `config::warn_sink` (Go's `cliout.Warnf`: the message plus a
  newline on stderr, colour 220 only when stderr and stdout are terminals and `NO_COLOR` is empty) after
  argument parsing. With a sink installed `Config::load` / `Config::load_from_bytes` emit each warning
  in load order (`envWhitelist`, then `mcp.approval_required`, then `clipboard.printByDefault`, the last
  once per process) **even when the load then fails**, as Go does. Without a sink (library users, unit
  tests) the loaders still drop them. Recorded Go behaviour that is easy to get wrong: `--quiet` does
  **not** silence them (Go hands `ctx.QuietMode` to `cliout` before cobra parses the flags, so the
  persistent flag never reaches `cliout.Warnf`; `--color` does not either), a null `envWhitelist` and
  `approval_required: false` do not warn, a merged `approval_required: true` does, a rejected or
  undecodable document warns about nothing it did not reach.
- **Warning count per command (local/plat-pins, probed against the pinned Go binary with an instrumented build):** Go prints the `envWhitelist` line once per `config.Load`, and loads at more seams than Rust. For `list`, `get`, `find` and `verify` Go prints 3 times (4 when its background index build wins the race with process exit) when the vault is given by `--vault`/`SYMVAULT_VAULT` and 5 (6) with a vault in the default `~/.symvault`; Rust prints 2 / 3 (`get`: 3 / 4). The missing prints are Go's second global read (`PersistentPreRunE` and the command's `VaultPath`) and its per-operation `loadVaultConfig`. `recipients list`, `lock` and `generate` print 2/2/1 in the default location (Rust 1/1/0), `agent list` matches. Recorded as `loader_warning_counts` in `config-yaml-syntax.json` (bounds over repeated runs) and pinned natively by `native_loader_warning_counts_are_pinned_against_go`. Not ported: matching the counts means repeating loads whose only effect is another identical deprecation line.
- **Deliberate deviation: `profiles: {p: null}`.** Go dereferences the nil `*Profile` in
  `mergeTopLevel` (`config_merge.go:106`) and crashes: `panic: runtime error: invalid memory address or
  nil pointer dereference [signal SIGSEGV ...]` in `config.mergeTopLevel` <- `LoadFromBytes`
  (`config_load.go:189`) <- `Load`, exit 2 with a goroutine trace on stderr. The native CLI refuses the
  document (`profiles.p: profile must not be null`, exit 6, `agent list` exit 1). A crash is not
  behaviour to reproduce and the trace is not a stable byte contract (it carries build paths), so no
  fixture records it; the refusal is pinned by the core unit test of the loader.

Evidence: `testdata/port/cli/config-yaml-syntax.json` (now 249 cases, 29 open divergences, 957
comparisons; the 183 earlier cases are byte-identical, only `oracle.generator_digest` changed; the four
open divergences `load_audit_max_size_mb_zero`, `load_audit_max_size_mb_null`,
`load_payment_policy_without_instrument` and `load_agent_payment_policy_unknown` became cases) gained 66
cases recorded from the pinned Go binary (`resid_*`: the audit and payment-policy checks and every
message of `validateDecimalString`, the validation order, Go's integer coercions for `maxSizeMb` and
policy names, and the warnings on `config validate`, `--json`, `--quiet`, `agent list` and `doctor`).
`config_resid_outcomes_are_pinned_to_what_go_prints` names the outcomes and mutates three expectations
to prove the replay notices a missing check or warning. Re-measured with the CONFIG-SECTIONS sweep
(1,589 configs x 3 commands = 4,767 comparisons, plus 353 adversarial inputs x 3 and the 26 fix-round
inputs x 3): **0** Go-rejects/native-accepts, **0** stderr-only differences, the only remaining
difference is `profiles: {p: null}` (3 comparisons, above).

### Residuals (probed, not fixed)

- (Closed by CONFIG-WRITER.) `symvault doctor` printed every warning 8 times where Go printed it 9 times:
  Go's `checkPasswordStrength` makes one more config load (`vault.List`), now mirrored. Commands with a
  single load (`agent list`, `agent profile show`, `config set`'s post-update reload, `config validate`) match.
- (Closed by CONFIG-WRITER.) `doctor --fix` and `config validate --fix` dropped `paymentPolicies` and an
  agent's `paymentPolicy`, and the doctor fixer lacked Go's fixes for `audit.maxFileSize` and
  `clipboard.autoClearDuration`; see the CONFIG-WRITER section for the writer, the fixes and the declared
  deviation (Go itself drops `paymentPolicies`).

## CONFIG-WRITER: Rust config rewrites keep what Go keeps, 2026-11-02

Review of CONFIG-RESID found that every `save_to` caller (`agent install`/`upgrade`/`uninstall`, `remote`,
`doctor --fix`, the `config validate --fix` renderer) lost data on rewrite. Measured: `agent uninstall other
--yes` on a config with `agents.bot.paymentPolicy` dropped the policy, `skillVersion` and the whole `audit`
section; Go kept them.

- **The typed `Config` now models and writes `audit`, `logging`, `security`, `scan_patterns` and the full
  `paymentPolicies`** (`AuditConfig`, `LoggingConfig`, `SecurityConfig`, `ScanPattern`, `PaymentPolicy`),
  parsed from the same yaml.v3-coerced tree as the other sections. `config_fix.rs` lost its private `Extras`
  carrier and its own renderer: `Config::to_yaml_bytes` is the one writer. `Config::audit_max_file_size`
  became `Config::audit` (`max_file_size` in bytes, `max_backups`, `max_age_days`).
- **Agent profile writer in Go's struct order:** `skillVersion`, then `exposePaymentValues`, then
  `paymentPolicy` close the block (`exposePaymentValues` used to sit after `exposeValueTools`); the fields the
  writer never emitted are now written: `perToolRedactFields`, `approvalTimeout`, `allowed_tools`,
  `max_reads_per_hour|day`, `max_secrets_in_session`, `dynamicProviders`, `allowedEnvVars` (all but
  `perToolRedactFields` and `dynamicProviders` were already parsed; those two are parsed now, with Go's merge
  rule), `promptInjectionMode`. A dropped `allowed_tools` list widens an agent's
  permissions on the next load, so this was a security-relevant loss and not only a cosmetic one.
- **Declared Rust-safer deviation:** Go's `SaveTo` copies a fixed field list into a fresh struct, so it
  *drops* the top-level `paymentPolicies` and `security`; after `doctor --fix` an agent's `paymentPolicy`
  then dangles and the next load fails validation. Rust keeps both sections (`paymentPolicies` last, `security`
  between `logging` and `vaultDir`, the struct positions). Go evidence: the recorded bytes of
  `testdata/port/config/rewrite.json` and the live oracle in `config_rewrite_differential.rs`. Entry 1 and 2
  of `upstream-go-bugs.md`.
- **Evidence (Go-recorded, byte level):** `scripts/rust-port/cmd/configrewritegen` records real Go
  `Load` -> mutation -> `SaveTo` runs (21 in the first round, 47 after the fix round) (oracle `690647c5`, source digest enforced) into
  `testdata/port/config/rewrite.json`; `config_rewrite_contract.rs` requires the Rust bytes minus exactly the
  two declared sections to equal Go's, checks the declared sections survive, and carries negative controls
  (dropping `paymentPolicy`, `skillVersion`, the `audit` block or reordering fields is rejected). Live:
  `config_rewrite_differential.rs` runs `agent uninstall` (two agents) and `doctor --fix` on the Go binary and
  on Rust and compares stdout, stderr, exit status and the resulting `config.yaml`. Gate:
  `make config-rewrite-differential` (`scripts/rust-port/check_config_rewrite.sh`; generation is the explicit
  `make config-rewrite-fixtures-generate`, `--check` never writes).
- **Doctor fixer:** `fix_config_validation` gained Go's fixes 3 and 4 (`audit.maxFileSize <= 0` -> 100 MiB,
  `clipboard.autoClearDuration < 0` -> 0). Go prints nothing for them, so there is no report line to mirror;
  the live differential repairs both and compares the file.
- **Doctor warning count:** `check_password_strength` mirrors Go's extra `vault.List` -> `loadVaultConfig`
  load (the reuse check shares it through Go's mtime-keyed cache). A `doctor` run now prints each deprecation
  warning 10 times (default) / 9 times (`--no-network`) on both sides.
- **`__complete`** installs the warning sink with the rest of startup, so completion prints loader warnings.
- **`config validate`** (text and `--json`) and the doctor message split the joined validation errors on
  `'\n'` like Go (`resid_payment_policy_name_newline`; the fixture is `config-yaml-syntax.json`, now 250
  cases / 960 comparisons, the 249 earlier cases byte-identical, only `oracle.generator_digest` changed after
  the two comment fixes in `yamlsyntaxgen`: `--quiet` does **not** silence the loader warnings).

### CONFIG-WRITER fix round (review of e74bdd9c: REQUEST_CHANGES)

- **Scalars and keys are emitted by the yaml.v3 emitter port** (`symvault-gojson` `yaml::string_in_mapping`,
  `string_in_sequence`, `mapping_key`), at the depth the writer puts them. Before, `yaml_scalar` handed a
  multi-line string to `serde_yaml_ng`, which wrote a block scalar at the wrong indentation: the rewritten
  `config.yaml` no longer loaded in Go or Rust (`scan_patterns[].description: |`, `allowedPaths`, `dynamicProviders`,
  `perToolRedactFields`, `paymentPolicies`, vault/git/profile strings). Quoting (`'&amp'`, `'#c'`,
  `"2026-01-02"`, `"\U0001F600"`), the `? key` / `:` form of a multi-line key and `[]` for an empty list under
  `perToolRedactFields`/`dynamicProviders` now follow yaml.v3 byte for byte.
- **Durations** are `time.Duration.String()` (`90s` -> `1m30s`, `1.5s` -> `1.5s`), also `sessionTimeout`,
  `sessionMaxLifetime`, the mcp timeouts and `oauth` TTLs.
- **`McpConfig` models `otlp_endpoint`, the trusted-proxy allowlist `trusted_proxy_ips`,
  `approval_tls_cert_file` and `approval_tls_key_file`** and writes them in Go's order (`port`, `bind`,
  `httpTokenFile`, `otlp_endpoint`, `stdio`, timeouts, `rate_limit`, `trusted_proxy_ips`,
  `metrics_auth_required`, `tls_*`, `approval_tls_*`, `mtls_enabled`, `allow_insecure_bind`). A rewrite used to
  disable approval mTLS and the trusted-proxy allowlist silently. `mcp.oauth` is kept (Go drops it:
  `upstream-go-bugs.md` 8).
- **A true capability is always written** (`canManageConfig`, `canUseClipboard`, `canUseAutotype`,
  `canReadValues`, `autoUnseal` on a custom profile were dropped, which turned them off on the next load).
- **`approvalTimeout: 0s`** is modelled (`AgentProfile::approval_timeout_zero_set`, the loader records a written
  zero) and written back; it reloaded as the 5 minute default before.
- **`vault.last_rotated`** is printed like `time.Time.Format(RFC3339Nano)` for every timestamp shape yaml.v3
  reads (`2026-1-2`, `2026-01-02 03:04:05`, fractions, offsets); a quoted string made Rust's own loader reject
  the file.
- **Evidence:** the recorded fixture now has 47 Go cases (multi-line description, multi-line list items and keys
  in every position, full mcp fields, stdio + httpTokenFile, oauth, durations, quoting, emoji, date-like
  strings, empty lists, `approvalTimeout: 0s`, tier-only profiles, false/zero values, timestamps) plus the
  **field-coverage probe** in `configrewritegen`: it walks every yaml key of Go's `Config` by reflection and
  fails unless some case input sets it, and unless the set of keys Go reads but `SaveTo` does not write back
  equals `droppedBySaveTo` (`dropped_by_save_to` in the fixture, `agents.*.pre_call_hooks|post_call_hooks`,
  `clipboard.printByDefault`, `envAllowlist|envWhitelist`, `git.author|email`, `mcp.approval_required|oauth|perplexity*`,
  `paymentPolicies*`, `security*`, `vault.listing_cache_ttl|manifest_generation|sync*`). The Rust contract proves
  the probe case writes every key outside that set. `config_rewrite_differential.rs` additionally runs
  `agent uninstall` on a multi-line config and on a full-mcp config against the live Go binary and loads the
  file Rust wrote with **both** `symvault config validate` binaries.

### Residuals (probed; every difference below is a `declared_line_differences` entry of `rewrite.json`
with its reason, or a byte-level residual named here)

- **Rust writes, Go drops (declared, `rust_adds`):** `mcp.oauth` (Go: TTLs fall back to defaults);
  `git.auto_push: false` / `auto_pull: false` and `clipboard.copyByDefault: false` (Go's `omitempty` drops them
  and the loader default `true` turns the opt-out into an opt-in: the older CONFIG-LOAD-001 deviation);
  `mcp.port: 0`, `read_timeout: 0s`, `rate_limit: 0`, `metrics_auth_required: false` (Go drops them and the
  defaults 8080 / 10s / 60 / true replace them); the top-level `paymentPolicies` and `security`.
- **Go writes, Rust omits (declared, `go_only`):** an explicit `false` for `canRunCommands`, `canManageConfig`,
  `canUseClipboard`, `canUseAutotype`, `canReadValues`, `autoUnseal`, `exposePaymentValues` on a *custom*
  profile (Go's `*bool` is set; Rust's `bool` omits it, which reloads as the same `false`). Tiered and built-in
  profiles write their full preset set on both sides (cases `tier_only_profiles`, `tier_with_overrides`).
- **Double-quoted where yaml.v3 is unsafe (declared, `go_saved_faithful: false`):** a string that starts with a
  line break (yaml.v3 drops the break) and a string that starts with a space inside a sequence item or a
  mapping nested in one (yaml.v3's `|4` indicator is wrong there and the file does not parse back):
  `upstream-go-bugs.md` 9. Cases `leading_break_*`.
- **Other explicit zeros still unwritten:** `max_reads_per_hour: 0`, `max_reads_per_day: 0`,
  `max_secrets_in_session: 0`, `skillVersion: ''`, `paymentPolicy: ''`, `exposePaymentValues: false`, an explicit
  `5m` / `off` on a built-in preset; no non-zero value is lost and each reloads as its default.
- **Kept by Rust, dropped by Go (declared, `rust_adds`):** `git.author`/`email`, `mcp.perplexity` (its `api_key`
  too), `mcp.approval_required`, `clipboard.printByDefault` (`upstream-go-bugs.md` 10); an explicit empty
  `allowedExecutables` and `approvalMode: null` of a tiered profile, which Go's rewrite turns into the tier
  preset's grant (`upstream-go-bugs.md` 11); `canWrite: false` of a custom profile that never set it.
- **Not modelled in Rust, dropped like Go:** `agents.*.pre_call_hooks|post_call_hooks`,
  `envAllowlist|envWhitelist`, `vault.sync`/`listing_cache_ttl`/`manifest_generation`
  (`upstream-go-bugs.md` 3, 4, 6).
- Go loads the global config once at startup for every `__complete` and for `completion <shell>`; Rust's
  completion path loads only what the completer needs, so Go prints a loader warning twice / once where Rust
  prints it once / not at all (`__complete get ''`, `completion bash`). Ordinary commands match. Pinned by the open entry `completion_loader_warnings` (ADR 0034 item 9, `config-yaml-syntax.json`).

## SET-003 fix round: vault-open errors, hidden reads, piped input

Fixed, each pinned against the Go oracle in `crates/symvault-cli/tests/set_differential.rs` (228 piped
cases, 28 prompt-driven terminal cases):

- The `open vault: load identity: …` text follows Go's chain (`identity_error.rs`): an Argon2id envelope
  goes through `trustedZeroKeyAuthorities` first (`recipients.txt` missing, symlinked, a directory or
  unreadable: `requires a trusted recipients.txt`; empty, garbled, comment-only:
  `requires valid recipients.txt authority`; valid: `zero-key recovery failed: decryption failed`); any
  other envelope is `decryption failed: ` plus the age header parser's message (quoting the bytes, base64
  offsets, scrypt stanza checks, `identity did not match any of the recipients: …`). An empty passphrase is
  `open vault: passphrase is empty`, before the identity is read.
- `get`, `list`, `find`, `add`, `delete` and `edit` print a returned error twice (cobra, then `ExecuteRoot`)
  like `set`; `vault locked:` errors add the locked hint and exit 4. `get` unlocks without prompting once
  stdin is not a terminal (`WithVaultForScripting`).
- A hidden terminal read ends its line on stderr (Go's `fmt.Fprintln(os.Stderr)`), not on the terminal; the
  read is `term.ReadPassword` on stdin (echo off, no `ECHONL`).
- `--no-pipe-warning` suppresses the pipe warning on every prompting path.
- Piped prompt values are bytes: each invalid UTF-8 byte is stored as U+FFFD, like Go's JSON encoding.
- Go's `bufio.Reader` over stdin (the one `set` hands to its prompts) takes what is piped, up to 4096 bytes
  per `read(2)`, so a passphrase prompt after the `set` prompts finds end of input; the Rust prompts share an
  equivalent buffer. Unbuffered `ReadLineFromStdin` reads one byte at a time.

Still open:

| Class | Go | Rust |
| --- | --- | --- |
| non-UTF-8 passphrase bytes at the unlock prompt | raw bytes are the passphrase | each invalid byte is U+FFFD |
| `%q` of exotic Unicode in the quoted intro | `strconv.Quote` | an approximation of `unicode.IsPrint` |
| Go's `bufio` fill when the writer is slower than the reader | takes one `read(2)` of whatever arrived | same model, so the same timing dependence |
| Windows hidden read | `term.ReadPassword` | `rpassword` plus the stderr line feed (no native run) |

## SET-004 fix round: legacy zero-key heal, `unlock`/`verify` errors, Go's `Open` bookkeeping

Fixed, each pinned against the non-CGO Go oracle in
`crates/symvault-cli/tests/zero_key_differential.rs` (25 heal cases, 15 header cases, 7 manifest
cases, Touch ID warning, 4 Ctrl-D prompt cases) and, for the error shape, `set_differential.rs`
(`unlock` and `verify` joined the 12 open-failure damages of the other seven commands):

- **Legacy zero-key vaults heal.** `vault.OpenWithPassphrase` calls `tryHealZeroKeyIdentity` when an
  Argon2id unwrap fails with a non-resource error. The shared implementation is
  `symvault_store::zero_key::heal_zero_key_identity` (CLI and C ABI): `recipients.txt` is read first
  (byte-exact `bufio.Scanner` rules: regular file, never a symlink, CRLF stripped, 64 KiB lines refused,
  comments/blank lines skipped, every other line a valid `age1` key, duplicates folded), the identity is
  recovered once with a zero key of the passphrase length (`recover_zero_key_identity_with_authorities`,
  Go's `RecoverZeroKeyIdentityWithAuthorities`: authorities, then the 1..=1024 length, then the unwrap),
  `recipients.txt` is re-read and must be unchanged, then `identity.age.bak` (mode 0600, atomic) receives
  the old bytes, `identity.age` is re-wrapped with Argon2id under the real passphrase (mode 0600,
  atomic), re-read and opened with the passphrase, and rolled back from the backup if that fails. Go
  prints no notice and writes no audit record for a heal (`HealedFromZeroKey` has no reader). Callers
  traced from Go's `OpenWithPassphrase` users: every unlock (`device.rs`, including the cached-session
  passphrase), `unlock`, `auth rotate-passphrase`, `auth set touchid` and the FFI; `migrate kdf` only
  reaches it for a scrypt identity (never healed) and `serve`'s OAuth consent check still verifies by
  decrypting (below).
- A heal that finds a passphrase longer than 1024 bytes reports `zero-key length is invalid` (after the
  `recipients.txt` checks, as in Go); the heal refusals and a vault healed by either binary opening in
  the other are pinned.
- `unlock` and `verify` print a wrong-passphrase failure twice as `open vault: load identity: …`, exit 1.
- The `Touch ID skipped (no GUI session); …` warning is printed by the non-interactive unlock path
  (`get`, `list`, …) when `authMethod: touchid` and no GUI session exists; `--quiet` silences it.
- An `identity.age` header over 2 MiB fails with `header exceeds 2 MiB` in the accounting of Go's
  `headerReader` (intro, stanza lines, footer line and the 3-byte footer peek are charged) and no longer
  reaches the `age` crate or the mirror parser unbounded. The `age` crate is also superlinear in the length
  of a header line (a 64 KiB argument line takes it 17 s); identity headers over 16 KiB, with a line over
  1 KiB or more than 1024 stanzas are therefore never handed to it and are reported as an identity the
  passphrase does not open (an `argon2id` stanza line that long is Go's `malformed argon2id stanza`).
  **Deliberate deviation:** a Go-valid identity with such a header cannot be opened; no vault writes one.
- Every vault open rebuilds a missing, stale (older than `manifest_generation`) or incomplete (`.age` files
  the manifest does not list) `manifest.age`, best effort, like `Vault.Open` (`Store::reconcile_manifest_on_open`),
  so `verify` on a manifest-less vault verifies instead of printing `No manifest found`, and read commands
  leave `.lock` and `manifest.age` as Go does.
- Hidden terminal input: Ctrl-D (one zero-byte read) is ignored while the terminal is open, as in
  `x/term`'s `readPasswordLine` loop; the terminal attributes are restored by a drop guard. Password and
  line buffers are `Zeroizing` with their capacity reserved (growth wipes the old allocation) and the
  consumed range of the shared 4096-byte `bufio` buffer is zeroed.
  **Deliberate deviation:** a terminal that has hung up (the zero-byte read returns at once, 64 times in a
  row) ends the read as `EOF`; Go spins at full CPU forever.
  **Signals:** both binaries are killed by SIGINT/SIGTERM/SIGHUP at the prompt without running their
  restore (`ISIG` stays on; Go's `defer` and Rust's drop guard do not run on death by signal), so both
  leave echo off. Neither installs a handler for the hidden read.

Still open:

| Class | Go | Rust |
| --- | --- | --- |
| `serve` OAuth consent passphrase check on a legacy zero-key vault | `OpenWithPassphrase` heals the file | decrypts only; a zero-key vault is refused at consent (the vault must have been unlocked once by any command) |
| `Touch ID skipped` warning on a host with a GUI session | not printed | not printed; the warning branch is only exercised against the oracle on hosts without one (unit test in the binary on others) |
| `FlushManifestUpdates`, filesystem-sync reports, git relocation of `Open` | run on open | not part of the Rust open |

## SET-004b/c fix rounds: entry-ciphertext header validation and delta-review follow-ups

Pinned against the non-CGO Go oracle (`set_differential`, `zero_key_differential`, `cli_differential`,
`auth_differential`, `edit_differential`, `add_form_differential`, `error_taxonomy`, `session_commands`,
`write_commands`). `output_modes` (the frozen manpage corpus and the live
`touch_id_availability_matches_go_in_the_same_sandbox`) is **not** pinned against that oracle: it needs the
CGO-enabled oracle that `make output-modes-cli-differential` builds with a plain `go build` (the non-CGO
binary cannot report Touch ID), and it SKIPs visibly without `SYMVAULT_OUTPUT_MODES_GO_BINARY`.

- **Entry ciphertext is untrusted; the `age` crate's header parser is superlinear in line length, stanza count
  and body lines (SET-004b/c).** A crafted `entries/w/zz-evil.age` (a git pull or rsync can drop one in) made
  `list` take 53 s in the review and 50-125 s in a debug build here; Go parses every shape below in 0.1-0.4 s.
  The crate re-parses the whole header after each line it reads, so cost is lines x bytes. Debug-build
  measurements of the bare crate: 64 KiB line about 60 s; 1000 tiny stanzas (6 KiB) 10.6 s, 2000 (12 KiB) 67 s;
  one stanza with 200 body lines 21.5 s; 32 x 1 KiB stanzas 14.9 s; a 2 MiB header over 100 s. SET-004b capped
  only the line length (1 KiB) and the 2 MiB total, which left all but the first shape open.
  **Fix:** `symvault_crypto::entry_decryptor` (used by `decrypt`, `decrypt_bounded` for entries, manifest,
  `grant_key`, doctor round trip, and both probes of the FFI `agehdr` walk) first runs the strict, one-pass
  `entry_header_extent`: exact `age-encryption.org/v1` intro, 1..=1024 stanzas (Go's `maxRecipientStanzas`) of
  only the types the vault writes (`X25519` with one 43-character argument; `scrypt` with two; `argon2id` with
  up to four; rust-age's random `*-grease` stanza with at most three body lines), opening lines of at most
  1 KiB, bodies as 64-column lines closed by a short one, a 43-character `--- ` footer, 2 MiB cap. Anything
  else is `malformed age envelope` without reaching the crate (Go would skip an unknown stanza type; the vault
  never writes one). An admitted header is then handed to the crate through `HeaderReader`, whose single
  `read_until` returns the whole header (found by that scan), so the crate parses it once. The identity-file
  paths (`decrypt_scrypt`, `decrypt_argon2id*`, `inspect_argon2id_policy`, `recover_zero_key_identity*`) keep
  their stricter `identity_header_refused` budget and now also read through `HeaderReader` via
  `linear_decryptor` (a 1000-stanza identity file within the budget used to cost 10-20 s). A 171-recipient entry
  (17 KiB header) and a 1023-recipient entry still decrypt.
  Tests: `symvault-crypto` `entry_header_validator_accepts_everything_the_vault_writes`,
  `rust_age_grease_stanzas_of_every_size_are_admitted`,
  `hostile_entry_headers_are_refused_in_microseconds_by_every_entry_decrypt` (12 shapes, one per dimension,
  each under 2 s), `identity_files_get_their_header_in_one_linear_pass`,
  `header_extent_stops_at_the_footer_and_leaves_the_payload_alone`; `symvault-store`
  `hostile_entry_headers_never_reach_the_age_parser` (open + reconcile + list + get + verify + rebuild over
  five shapes under 10 s). With the validator replaced by the SET-004b rule, the store test fails (the crafted
  header reaches the parser: `decryption failed` instead of `malformed age envelope`).
  **Measured worst case, end to end (debug Rust binary vs Go oracle, `list` / `get` on one crafted entry):**
  Rust 0.2-0.4 s for every shape, up to the 2 MiB headers, Go 0.06-0.4 s (one run per shape, wall clock
  including process start).
  **How a refused entry fails (Rust-safer deviation):** `list` exits 0 and names the file, as in Go; `get`
  exits 1 in both. Go prints `Error: cannot read entry: cannot read entry w/zz-evil: decryption failed: invalid
  X25519 recipient block: decryption failed: invalid X25519 recipient block` (Go's parser accepts the line and
  rejects the block); Rust prints `Error: cannot read entry: entry ciphertext is invalid: malformed age
  envelope`, the text of every other envelope the crate cannot parse. Exit status matches; the Go wording for
  a hostile header is not reproduced (the FFI diagnostic still produces Go's text through its own linear
  parser, and only its `age`-crate probes are guarded: an otherwise valid header the validator refuses reports
  Go's `malformed header (N bytes)` fallback instead of the key-dependent text).
- `atomic_write` in `zero_key.rs` now `fchmod`s the temporary file to the requested mode after creating it,
  like `os.CreateTemp` + `File.Chmod`: under umask 0277 `identity.age` and `identity.age.bak` end up 0600 (they
  were 0400). Pinned by `heal_files_keep_mode_0600_under_a_restrictive_umask_like_go` (fails without the
  fix). **Still open, outside this heal:** Go creates `.lock`, `.symvault-migrated` and `manifest.age` with
  the umask applied (0400 under 0277, and the next open then fails with `open lock file: permission
  denied`); Rust creates them at a fixed 0600. A restrictive umask is not a supported configuration.
- **Accepted deviation, I/O failures of the heal's atomic writes:** the text of a failing temp-file create,
  write, sync or rename in `zero_key.rs` is the errno text (`write backup: …`), where Go reports its
  `*PathError`/`*LinkError`, which names a randomly suffixed temporary file (`open /…/identity.age.bak.tmp-123456:
  …`). The random name cannot be reproduced and is not compared; the exit status and the rollback behaviour are.
- **Accepted deviation, `auth set touchid` with a cached session:** Go's `passphraseForBiometricSetup` returns
  a cached-session passphrase without opening the vault; Rust opens (and so heals) in that branch too, before
  saving the Touch ID item. Practically unreachable: a cached passphrase was verified (and healed) when it
  was cached. Only the env-variable and prompt branches open in Go.
- **FFI open reconciles the manifest.** `pkg/mobilebind` goes through `vault.Open` / `OpenWithPassphrase`, so
  every FFI call that opens a vault rebuilds a missing, stale or incomplete manifest like the CLI; the FFI
  used to rebuild only a missing one. `every_open_reconciles_the_manifest_like_go` (fails without the change).
- **Accepted deviation, non-regular `*.age` files in `entries/`:** Go's `DetectOutOfBandEntries` counts any
  non-directory ending in `.age`. A symlink makes Go's `list` ignore it and `verify` report it as unknown;
  Rust refuses the whole open with `vault path is a symlink: …` (fail closed, STORE-003). A FIFO/socket named
  `*.age` is counted by Go (whose rebuild would then `open` it, which can block); Rust skips it, so no
  rebuild is triggered. Matching Go would mean hashing through a symlink or opening a FIFO, which is the
  hazard the store's rooted walk exists to avoid.
- **`generate manpages` corpus no longer expires daily.** cobra writes its generation date into the one
  `.SH HISTORY` line it emits (`2-Nov-2026 Auto generated by spf13/cobra`, only in `symvault-version.1`), so the
  recorded sha of that page went stale every day. Normalization rule 9 (`man-date`) now also rewrites the
  date of exactly that line to `<MAN-DATE>`, in the generator (`outputmodegen`), the replay and the fixture
  notes; the fixture was re-recorded through `make output-modes-regenerate` and differs from the old one only
  in the generator digest, the rule-9 note and the five `symvault-version.1` hashes. The unit test pins the
  shapes that must not be rewritten.

## DATA-SAFETY-GATE (P30, DIST-005 / RUST-014 acceptance), 2026-11-02

Maintainer decision D1: the first vault-**mutating** operation Rust performs on a vault that carries no
Rust marker is preceded by a verified backup; reads never trigger it. Verified by
`make data-safety-differential` (`scripts/rust-port/data_safety_contract.py`, real Rust CLI + non-CGO Go
oracle, disposable HOME/XDG roots).

**Design.**

- *Marker*: `.symvault-rust` in the vault root, JSON (`schema`, `kind` = `go-vault-backup` | `rust-created`,
  `created_at`, `vault_id`, and for the former the backup `path`, `sha256`, `bytes`, `files`). Written atomically
  (temp file, fsync, rename, directory fsync, `0600`) only after the backup verified. `init` (CLI and FFI
  `InitVault`) writes `rust-created` at once; an empty directory needs no
  backup. **A marker is evidence only for the vault it was written for** (fix round 2): `vault_id` is SHA-256
  over the canonical vault path and (Unix) the inode of the vault directory; a marker with another or no id
  (`cp -r`, git clone, restore into a new directory, a recreated directory, hand-made) does not count. A
  `go-vault-backup` marker also has to prove its backup: a regular file (no symlink) with the recorded size
  and SHA-256 (hashed once per process). A `rust-created` marker must carry no backup. Anything else, or a
  marker that does not parse, means "no marker" and the vault is backed up again. `identity.age` is
  deliberately **not** part of the id: Rust rewrites it itself (KDF migration, password change, zero-key
  heal), and an id that changed under those operations made the gate fire between the identity rewrite and
  the writes that depend on it (the migrate-kdf tests caught this in the first attempt). The marker is kept out of git (`.git/info/exclude`, also on `git init`).
- *Choke points* (`symvault-store::data_safety`): `open_root_write_lock` (every store/manifest/grant/token/journal
  write; the write lock is held across backup, restore check and marker); `Store::data_safety_gate` before the
  first filesystem mutation of entry publication, `write_new_entry` and delete (Go publishes entries **outside**
  the lock, so the lock alone was not enough: the first harness run found the entry already in the backup);
  legacy-layout migration (`migrate_legacy`, a read-triggered rename of entry files) and the zero-key heal
  (`rewrite_identity`); `symvault_sync::safeio` (`write_atomic`, `open_append`, `secure_delete`, `create_dir_all`:
  recipients, device/pairing files, policies, identity rewrites; the vault is the nearest ancestor with an
  `identity.age`); `Config::save_to` through a registered pre-save hook (vault `config.yaml`); `git pull`, `git sync --force`, `GitRepository::commit` (index, `.gitignore`), `remote add` and
  `push --set-upstream` (both rewrite `.git/config`; `symvault remote init`); the audit helpers' destructive steps
  (legacy `audit-hmac-key` unlink, log rotation by rename, key/log retention deletes; plain appends stay
  ungated, they only add bytes); `restore` into an existing vault. The marker is looked up through the retained root capability, so a directory swapped in
  under the path neither satisfies nor receives the gate. Refusal is `StoreError::DataSafety` / a `Error: ...
  pre-migration backup failed, the vault was not modified: ...` message; nothing is written.
- *Backup*: the Go-faithful `CreateBackup` port moved from `symvault-cli` to `symvault_sync::backup_writer` (CLI
  `backup` re-exports it), `.git` included (Go's default; only `--exclude-git` omits it). Durability and crash
  safety (fix round 2): the archive is written as `<final>.<pid>.partial`, `fsync`ed, verified, renamed to its
  final name, and the backup directory is `fsync`ed before the receipt (and with it the marker) exists; a
  process killed halfway (SIGXFSZ, power loss) leaves a `.partial` or a `.verify-<pid>-*` scratch directory,
  never an incomplete final-named archive, and the next gate sweeps those of dead pids (live ones stay). Verification is the
  production `symvault_sync::archive::restore` into a `0700` scratch directory next to the archive, then a
  comparison of path set, file sha256/size and file mode with the live tree; the archive is removed on failure.
  `symvault-store` cannot depend on `symvault-sync`, so the store defines `PreMutationGuard`; CLI, MCP
  (`StoreReadOnlyAdapter::open`) and FFI (every open/init) call `symvault_sync::data_safety::install()`. A binary
  without the guard refuses to touch an unmarked vault (fail closed).
- *Location*: `$XDG_STATE_HOME/symvault/backups` (default `~/.local/state/symvault/backups`), file
  `pre-rust-<vault>-<hash8>-<UTC stamp>.tar.gz` (`0600`, directories `0700`, umask-proof). Go has no default
  backup directory (the `backup` command takes a path); the resolved data directory of a legacy install **is** the
  vault (`~/.symvault`), so a backup there would archive itself and, in a git-synced vault, be pushed. A backup
  directory inside the vault is refused. A host without `$HOME`/`$XDG_STATE_HOME` (the iOS app) sets the
  directory explicitly: `symvault_sync::data_safety::set_backup_dir`, FFI `symvault_set_backup_dir` /
  Swift `SymvaultFFI.setBackupDir` (additive, ABI revision stays 1). Excluding that directory from iCloud
  backup is the host's responsibility; the archive holds the same encrypted files as the vault.

**Findings recorded, not hidden.**

1. Go's restore (kept) retains only `mode & 0600` of a file and recreates directories `0700`; verification
   compares file modes through that mask and directories by presence (`.git/HEAD` 0644 restores as 0600).
2. Go's own reads create the empty `.symvault-migrated` and append to `audit-symvault.log` in the vault. They
   stay ungated (empty file / append-only, hash-chained); the harness allows exactly those two and asserts
   everything else is byte-identical. The audit appends of a mutating command can precede the backup; the backup
   then contains them and the restore comparison treats the log as a prefix-extension.
3. Not gated (derived or outside the vault): the encrypted search index, agent/config files outside the vault,
   session caches. A mutation path that writes vault files without `safeio`, the store, `Config::save_to`,
   `git pull` or `restore` would bypass the gate; the harness sweep (set, delete, file add, recipients add/remove,
   policy apply, agent token new, migrate pseudonymize, device pair, import, **remote init on a git-backed Go
   vault**) asserts "tree changed => marker + backup that restores to the pre-command tree" for the commands it
   runs. `remote init` was an ungated `.git/config` rewrite in the first round (found by review) and is now
   gated in `GitRepository::{add_remote, push, commit, force_pull}`. Not individually swept: auth
   rotate-passphrase, migrate kdf/v4, intake, `device accept`, `device approval-pair` (they pass through
   `safeio`/the store lock, same primitives as the swept `device pair`/`import`), `approval decide` (talks to
   a running server; its queue is in memory, no vault file), `share` grants (CLI has only `revoke`, which needs
   a grant that only the Rust MCP creates).
4. Test isolation (fix round 2): the first round let FFI fixture replays reach the gate for a vault dir named
   `missing` and wrote `pre-rust-missing-*` into the developer's real state directory. Every test binary that
   can reach the gate now either pre-marks its vaults or sends backups to a throw-away directory
   (`tests/common::isolate_backups` through `set_backup_dir`, which also asserts the resolved directory is
   inside the sandbox); the check is run by executing the suites with a scratch `HOME` and looking for
   `.local/state/symvault`. `test_support_pre_marked` is behind the `test-support` cargo feature, enabled only
   by the crates' `dev-dependencies`, so no production build contains it.

**Harness** (`make data-safety-differential`): seeds = frozen `mobilebind.json` vault, Go `init`+`set` vault
(has `.git`), Go zero-key identity. Per seed: read battery leaves the tree identical (marker/backup absent);
first `set` -> one backup + marker with matching sha256/size/mode; `restore` of that archive into a fresh dir
reproduces the pre-mutation tree; second `set` makes no second backup; Go reads and writes afterwards (D2).
Zero-key: `list` heals, backup precedes it and restores the zero-key identity, Go opens the healed vault. Eleven
mutators swept (including `remote init`: the live `.git/config` has the remote, the restored backup's does
not). Negative controls: unwritable backup directory (refused, tree untouched, retry succeeds);
corrupted archive through `crates/symvault-sync/examples/data_safety_probe` (refused, no marker, archive removed);
same corruption with the restore verification short-circuited (gate accepts; the harness's independent
restore comparison must fail); marker binding (a go-vault-backup marker and a rust-created marker copied from
other vaults, and a go-vault-backup marker whose backup is a foreign file / `/etc/hosts`, has a wrong sha256, a
wrong size or no vault id: each one triggers a fresh backup and a valid marker); crash leftovers (`.partial`
and `.verify-*` of a dead pid swept, a live pid's kept).

**Normalizations changed (documented D1 differences).** Go-parity tree comparisons look past the
`.symvault-rust` marker and the `home/.local/state/symvault` backup subtree: `zero_key_differential.rs`,
`export_backup_restore_contract.rs`, `output_modes.rs` (each through a local `d1_artifact`), and the FFI replay
(`tests/common/mod.rs`, marker only, seeds pre-marked). Store/MCP/sync/CLI test fixtures that build vaults with
the store API are pre-marked with `symvault_store::data_safety::test_support_pre_marked` (feature
`test-support`, dev-dependencies only); the store crate's own unit
tests run with the gate off (`cfg(test)`) except `data_safety::tests`.

## MCP-003 / HTTP-004 / CLI-007: `mcp` HTTP signal drain, 2026-11-03

Before this slice `symvault mcp` over HTTP exited 0 at once on SIGINT/SIGTERM/SIGQUIT and
aborted every request in flight, and removed only the runtime records it had published;
Go drains. Go's sequence, measured on the oracle (`cmd/mcp/serve_deps.go`,
`serverbootstrap/http_lifecycle.go`, ADR 0009):

1. The first of SIGINT/SIGTERM/SIGQUIT cancels the serving context (SIGQUIT first prints
   `Received SIGQUIT, shutting down gracefully...` on stderr). Later signals are swallowed.
2. The listener closes (new connections are refused), idle keep-alive transports close,
   `/mcp` requests that reach the handler get `403` with JSON-RPC error `-32603`
   `context canceled`, and a reply written during the drain carries `Connection: close`.
3. Requests in flight run for up to `MCP.shutdown_timeout` (5 s unless a positive value is
   configured). A tool call that ignores cancellation (`run_command`) completes normally.
4. At the deadline everything still open is force-closed; the exit does not wait for
   uncooperative callbacks (the started command keeps running).
5. `.runtime-port` and `.runtime-tls-cert` are removed unconditionally, nothing is printed
   (except the SIGQUIT warning) and the exit status is 0.

Rust now does the same through `HttpShutdown::drain` (`begin_drain`: stop admission, cancel the
request context, close idle transports; `cancel` at the deadline), wired by
`mcp_shutdown::install_http` and `serve_with_oauth_and_approval_options_until`. The CLI uses
`HttpShutdown::for_process()` (blocking socket I/O, cancelled by closing the transport) so the
data path is unchanged; Windows keeps its previous behavior because `install_http` is Unix only.
Evidence: `make mcp-http-shutdown-contract` (Go `-race` tests, then the Rust leg):
`http_drain_contract.py` runs the real Go oracle `24acdb08` and the Rust CLI through 15 signal
runs each (SIGINT and SIGTERM for idle keep-alive, in-flight command inside the window, the same
as a keep-alive request, in-flight command beyond it, partial body completed inside the window,
partial body never completed, second signal during the drain; SIGQUIT for the in-flight command)
and compares peer outcome (status, headers except `Date`, body), exit status, stdout, stderr,
listener state, started-command survival and the on-disk delta. `test_http_drain_contract.py`
rejects each mutated observation and the pre-drain behavior; the receipt profile `http-drain`
pins 15 runs per implementation. Local Darwin/arm64 only; native Linux CI is the coordinator's lane.

Residuals (probed, not fixed): the HTTP drain is Unix only; Rust removes the runtime records
unconditionally like Go (a successor's records are not protected); a drain that hits the deadline
does not report Go's `HTTPShutdownError` anywhere (Go drops it too: exit 0); Rust replies carry no
`Date` header, which the contract excludes from the comparison like the other HTTP contracts.

## MCP-AUDIT-IDS, OAUTH-EXPIRY, API-POLICY-DIAG (`local/mcp-audit`), 2026-11-03

Local evidence only; no matrix status cell changes (HTTP-002, MCP-003, HTTP-003
and BROKER-002 stay `in_progress`). Oracle is the Go tree at `ae6f8340`.

### MCP audit rows carry Go's three ids (MCP-003 / HTTP-002)

- Go's `logAudit` stamps `sess_id` (`Server.sessionID`, 16 random bytes hex,
  minted once per server = once per agent handler for HTTP, once per process
  for stdio), `req_id` (`generateRequestID`, 8 random bytes hex, minted at the
  top of `executeTool`, so *every* row of a call has it, denials included) and
  `token_id` (`auth.TokenFromContext`: only a **registry** token puts one in
  the context; the legacy bearer and stdio have none, so the key is *absent*,
  never `""`). `req_id` is **not** the JSON-RPC id.
- Rust: `StoreReadOnlyRuntime.session_id` (per runtime, `audit_identity`);
  `ProtocolHandler::set_token_id` (set by the HTTP layer from the registry
  token, cleared for the legacy bearer) and a request id minted per `tools/call`
  are installed in a thread-local `CallAuditScope` for the synchronous
  authorize + handler span; `append_audit` reads it. Rows written from another
  thread (clipboard auto-clear) or outside a protocol call carry only
  `sess_id`, like Go's `context.Background()` audit calls. The JSON layout is
  the shared `LogEntry`, so the HMAC chain covers the ids
  (`tests/audit_identity.rs::rows_with_ids_keep_a_valid_hmac_chain`, which also
  shows that stripping an id breaks verification).
- Go-recorded comparison: `scripts/rust-port/toolhash_process_contract.py`
  (explicit run, prebuilt binaries) now reads the audit log of both servers and
  compares the 8 rows of its 14 HTTP calls (`tool_registry_drift`,
  `tool_denied`, `get_metadata` ok and denied) field for field *and in field
  order* with `ts`/`hmac`/`kid` dropped, `sess_id`/`req_id` masked after
  asserting 32/16 lower-case hex and a single session per agent server, and
  `token_id` compared exactly (the registry ids are deterministic).
  `--drop-audit-ids` is the negative control (fails); a code-level control
  (blank `token_id` in `append_audit`) also fails it.
- Residuals: (1) Go's anomaly detector writes `anomaly_*` rows (`off_hours`,
  time-of-day dependent; `sess_id` only); Rust now runs the same detector
  (PLATFORM-002, ADR 0034 item 29: `anomaly_dispatch.rs`,
  `mcp_anomaly_process.rs`), the comparison still skips those rows after
  asserting they carry no `req_id`/`token_id`;
  (2) Go's `share_grant` / `share_expired` rows (`logAuditShare`: share id,
  from/to agent, share action plus the three ids) belong to the share-access
  scope override, which the Rust `scope_allows` does not implement, so there is
  no row to stamp; (3) Go's optional `tool_invocation` / `tool_scope_denied`
  hook rows are not produced by Rust; (4) the stdio transport is covered by
  `tests/audit_identity.rs` only (no Go stdio audit recording); (5) the
  thread-local scope assumes the whole call runs on the serving thread, which
  holds for every current handler (blocking runtime, `block_on`).

### OAuth expiry boundaries (HTTP-003)

Go compares with `time.Now().After(t)` throughout: authorization code
(`oauth.go:744`), DCR client lookup and sweep (`:354`, `:368`). A value is
valid at exactly its expiry and expired one nanosecond later. Rust's injected
`now` makes this testable (`oauth.rs` tests): code TTL (5 min, valid at
`TTL`, `invalid_grant` at `TTL+1ns`, single-use either way, no token minted),
browser-consent ticket (same boundary on `confirm`), the 256-ticket cap
(503 `{"error":"server_error"}\n`, still full at exactly `TTL`, purged at
`TTL+1ns`) and the DCR client `expires_at` (strict `>` in `get_oauth_client`;
`ttl_seconds` alone never expires a client, as in Go where it is metadata).
Negative controls: `>=` in the code check, ticket retention or client lookup
fails four of these tests. No Go-side unit test was added: Go reads
`time.Now()` directly, so the exact instant cannot be injected; the operator
is pinned by source reading above. **The browser ticket table and its 503 cap
have no Go counterpart** (Go's consent form is stateless and carries the
request fields), so the 503 bytes are pinned as a Rust-only hardening, not
compared with Go.

### execute_api_request entry-policy diagnostics (BROKER-002)

`check_api_entry_policy` mirrors Go's `checkPolicy` for the template's
credential entry: `policy: no matching rule (default deny)`,
`policy denied by rule %q` (audit `policy_denied`), `policy requires approval
by rule %q` (audit `policy_prompt`) and `biometric verification required by
policy by rule %q` (audit `policy_biometry`); all nine Go-recorded
`execute-api-policy.json` cases now compare the error text (previously prompt
and biometry were skipped). Every policy evaluation in `symvault-mcp` (the tool gate
`authorize_policy`, `run_command`, `execute_with_secret`, `execute_api_request`) now builds its
`EvalContext` through `symvault_mcp::policy_context::build_context`, a field-by-field mirror of
Go's `ContextProvider.BuildContext`: `ToLogicalPath(path)`, the local wall-clock `now`,
`working_dir` (`os.Getwd`, `$PWD` first), `home_dir` (`$HOME`), `env_vars` `HOME` and `GIT_BRANCH`
(git run with Go's `DefaultWhitelist` environment), and **no tool name**. Go never sets
`EvalContext.ToolName`, so an `allowed_tools` condition matches every tool there and here (see
`upstream-go-bugs.md` section 12); the tool name still feeds the separate tool-scope and catalog
checks. Pinned by the Go-recorded `testdata/port/mcp/policy-build-context.json`
(`make policy-context-differential`) and `policy_context_authorize.rs`.
Unknown actions are denied (Go proceeds), the existing fail-closed difference.

## CLI-007: `run --timeout` Ctrl-C reaches the child (ADR 0034 item 12)

A bounded `run` (`--timeout`, also `run --broker --timeout`) keeps the child in
its own process group so a timeout can kill the tree (#1199). Go's child shares
the caller's group, so a terminal Ctrl-C reached it; Rust's parent died and the
child kept running with the injected secrets and no parent left to enforce the
timeout. Fixed: `run_commands::child_group` holds the child's group
(registered before the spawn, cleared on every exit path) and the signal thread
forwards SIGINT/SIGTERM/SIGHUP/SIGQUIT to it before the parent dies exactly as
before (death by that signal; exit 2 for SIGQUIT). The `KNOWN_DIVERGENCES`
exemption of `signal_process_contract.py` is gone, so `run-timeout-group-sigint`
is compared Go against Rust like the other 32 cases.

Residuals (probed, not fixed):

| Class | Go | Rust |
| --- | --- | --- |
| signal sent to the `run --timeout` **parent only** (`kill -TERM <pid>`) | child keeps running | child group receives the same signal (a process cannot tell a tty group delivery from a direct one) |
| child that ignores or handles the forwarded signal | survives, like in Go | survives, like in Go; the parent still dies at once |
| MCP `execute_with_secret` child (own group, #1242) | receives a terminal Ctrl-C | not forwarded: the MCP server has its own shutdown path (`mcp_shutdown`) |
| secret file cleanup when the parent dies from the signal | not applicable | `file use` temporary files are not zeroed on death by signal (unchanged) |

## CLI-007: residual packet (`--allow-locked`, `ui`, armed clipboard), 2026-11-03

Measured on the real Go oracle (`45b8577e`, same as `signal_process_contract.py`), fixed in Rust, and
pinned by `make signal-process-contract` (41 compared observations per implementation, 13 Go-only: 7 from this packet plus 6 HTTP `mcp` records,
see "HTTP SIGHUP" below).

| Surface | Go (real process) | Rust before | Rust now |
| --- | --- | --- | --- |
| `mcp --stdio --allow-locked`, SIGINT/SIGTERM | exit 0, `.runtime-port` removed (`serve` subscribes before it branches on the vault) | OS default action (death by signal) | exit 0, records cleared |
| same, SIGQUIT | one `Received SIGQUIT, shutting down gracefully...`, exit 0 | death by SIGQUIT | same as Go |
| same, SIGHUP | death by SIGHUP | same | same |
| stdio `mcp` with an armed clipboard timer, SIGINT/SIGTERM | clipboard cleared, **then the server shuts down** (`serve` and the timer both subscribe), exit 0 | cleared, server kept running | cleared, shutdown requested through the stdio terminator (not when a prompt is active: the prompt's scope ends the process) |
| same, SIGHUP | cleared, server keeps serving (only the timer subscribes) | same | same |
| `ui`, SIGTERM | clean quit, exit 0, terminal restored | same | same |
| `ui`, SIGINT | `Error: ui failed: program was killed: program was interrupted` twice, exit 1, terminal restored | exit 0, silent | same as Go |
| `ui`, SIGHUP | death by SIGHUP, terminal left raw | exit 0, terminal restored (`ctrlc` `termination`) | same as Go |
| `ui`, SIGQUIT | exit 2 (goroutine dump), terminal left raw | death by SIGQUIT | exit 2, terminal left raw |
| `ui` with an armed copy (Enter, default 30 s auto-clear), SIGHUP | clipboard cleared, **`ui` keeps running** (the copy's `StartAutoClear` subscribes SIGINT/SIGTERM/SIGHUP); the next SIGHUP, with nothing armed, kills it by SIGHUP | secret left on the clipboard, death by SIGHUP (review finding: regression against the `ctrlc` build) | same as Go: `OwnedClipboardHandle::clear_if_armed` clears and `ui` shows `Clipboard cleared`; the next SIGHUP dies by SIGHUP |
| same, SIGINT/SIGTERM | cleared at signal receipt (goroutine), exit 1 (`program was interrupted`) / 0 | cleared on the exit path only: a main thread blocked in `$EDITOR` kept the secret (CLI007-LOW) | cleared by the signal thread right after the stop request (`clear_before_exit`), the exit path finds nothing left; same exit codes |
| same, SIGQUIT | exit 2, **secret left on the clipboard** (SIGQUIT is not in Go's auto-clear subscription) | secret left on the clipboard | **declared Rust-safer difference**: cleared, then exit 2 |
| `ui` with a copy kept until quit (`auto_clear_duration: 0`), SIGHUP | no subscription: death by SIGHUP, secret left | secret left | **declared Rust-safer difference**: cleared, then death by SIGHUP |
| stdio `mcp` with an armed timer, SIGQUIT | shuts down (exit 0, warning) and **leaves the secret** (the timer does not subscribe SIGQUIT) | secret left | **declared Rust-safer difference**: `clear_armed_stdio_clipboard` first, then the Go shutdown (exit 0, warning) |

CLI007-LOW follow-ups (delta review, APPROVE): (1) `OwnedClipboardHandle::clear_before_exit` marks the
owner as stopping under the clear's lock, so a `copy` racing the death-path clear on the main thread is
refused instead of putting a new secret behind it (the armed-SIGHUP `clear_if_armed` keep-running path does
not stop the owner). (2) see the SIGINT/SIGTERM row. (3) A failing backend `clear()` no longer drops the
deadline: the copy stays held and the worker retries every second; the failure reaches `Model::tick` through
`take_clear_result`, and on paths without a UI (worker shutdown, signal exit) it is written to stderr as
`warning: clipboard clear failed: ...`. (4) HTTP `mcp` **can** arm the timer: `copy_to_clipboard` and
`generate_totp` go through the same `start_clipboard_auto_clear` per request runtime, and Go's
`Server.startClipboardAutoClear` is transport-independent, so Go's armed timer clears on SIGINT/SIGTERM next
to `serve`'s shutdown. Rust only registered stdio runtimes with the signal router, so an HTTP shutdown
(drain, then exit 0) left the secret. Fixed: HTTP runtimes register in a process list
(`approval::register_process_clipboard_auto_clear`), and `install_http` clears it at signal receipt and
again after the drain (a request still in flight may copy meanwhile); SIGQUIT is cleared too (declared
Rust-safer, as in stdio). Pinned by `mcp_shutdown::tests::http_signal_shutdown_clears_an_armed_clipboard`
(real signals, injected clipboard) and `clipboard_http_signal_clear` (real `copy_to_clipboard`). Not covered
by a Go observation at that time (superseded by "HTTP SIGHUP" below).

**HTTP SIGHUP (packet HTTP-SIGHUP, 2026-11-03).** Measured on the real Go oracle `45b8577e` with fake
pasteboard tools on `PATH` (receipt `go_only`, cases `mcp-http-clipboard-*`; the Rust CLI would touch the
real pasteboard, so its leg is the injected-clipboard process tests):

| HTTP `mcp`, copy over HTTP | Go (real process) | Rust now |
|---|---|---|
| armed copy, SIGHUP | clears, keeps serving (a ping is answered); the next SIGHUP finds no timer and kills by SIGHUP | same (`http_sighup_follows_the_armed_clipboard_timer`, case `armed`) |
| nothing armed, SIGHUP | dies by SIGHUP, runtime records untouched, nothing touches the clipboard | same (case `idle`) |
| SIGHUP inherited as `SIG_IGN`, armed | the timer's `Notify` overrides the ignore: clears, keeps serving; the ignore is back afterwards (second SIGHUP survives, SIGTERM exits 0) | same (case `armed-ignored`) |
| SIGHUP inherited as `SIG_IGN`, nothing armed | ignored, no clipboard activity, SIGTERM exits 0 | same (case `idle-ignored`) |
| armed copy, SIGINT/SIGTERM | exits 0, but in 13 of 14 measured runs **before** its timer's clear reached the tool (the secret stayed); one run cleared | clears at receipt and again after the drain, exits 0 (declared Rust-safer difference) |

`install_http` gets a separate SIGHUP listener, so a SIGHUP during the drain is not queued behind it (Go's
default death applies immediately when nothing is armed). Because SIGHUP is registered unconditionally, the
listener restores the unarmed behavior itself (default action via `emulate_default_handler`, or nothing when
the disposition was inherited ignored, queried before the handler replaces it). The earlier claim that Go
"clears at receipt" for SIGINT/SIGTERM over HTTP holds in code, not reliably in a real process.

Review LOW (shutdown-path clears): `install_http` (receipt, post-drain and SIGHUP) and the stdio SIGQUIT
clear now run on a short-lived thread joined for at most 2 s (`CLIPBOARD_CLEAR_BOUND`), so a clipboard
backend that never returns neither blocks the drain, the exit nor later signals. Pinned by
`http_shutdown_bounds_a_hung_clipboard_backend` and `sigquit_shutdown_bounds_a_hung_clipboard_backend`
(a backend that sleeps 60 s; both fail when the bound is removed). Not covered: the stdio router's own
SIGINT/SIGTERM clear (`approval.rs` `clear_and_cancel_auto_clear`) still runs on its listener thread
unbounded.

The task description called the clipboard row "only clears and the server keeps running"; the
real Go process shows that this is true for SIGHUP only. Ordinary approval prompts under an armed
timer are now canceled by SIGINT/SIGTERM as well (Go cancels them through the serve context); this
combination is covered by the injected-clipboard process test, not by a Go observation.

The armed-clipboard Go observation (`go_only` in the receipt) uses fake `pbcopy`/`xclip`/... tools on a
PATH that cannot reach the real ones; the Rust CLI would use `/usr/bin/pbcopy`, so its leg is the
process test `approval::tests::stdio_armed_clipboard_signal_clears_and_requests_shutdown`. The `ui`
armed-copy Go records (`ui-clipboard-armed-*`, a pseudo-terminal sends Enter first) have the same
shape; the Rust leg is the injected-clipboard process test
`tui::tests::ui_signal_with_held_copy_process_contract` (real signals to a child process that records
clipboard events in a file), and the stdio SIGQUIT clear is held by
`mcp_shutdown::tests::sigquit_shutdown_clears_an_armed_clipboard`. A copy armed in `ui` under an
inherited `SIG_IGN` for SIGHUP is cleared as well (Go's `Notify` overrides the ignore; unit-tested in
`process_signals::tests`).

Bounded claims (no Go-vs-Rust observation, listed so they stay visible):

- `sync` / git push: Go pulls through in-process go-git and pushes through system `git` under
  `exec.CommandContext(ctx, ...)` with a plain context and no signal hook, so the Go runtime default applies.
  A hanging remote could not be staged hermetically: a local bare remote with a sleeping `pre-receive` hook
  made Go fail before the push with `pull failed: reference not found`.
- Intake spool: the idle `intake watch` spool directory is part of the compared on-disk state (removed on
  SIGINT/SIGTERM, left on SIGHUP/SIGQUIT in both implementations). A signal during an in-flight processing step is not recorded.
- `ui` is observed on a macOS pseudo-terminal for SIGINT/SIGTERM/SIGHUP/SIGQUIT only; Linux CI is pending, and
  a signal while the `$EDITOR` hand-off is running is not observed.
- Go's SIGQUIT goroutine dump (ADR 0034 item 11) remains a maintainer decision and is not reproduced.

## APPROVAL-001: frozen `approval list|decide` contract, 2026-11-03

The live differential (`approval_queue_differential.rs`) builds a Go handler seam with `go build`, so it ends with
the Go tree. `scripts/rust-port/cmd/approvalgen` freezes the same contract before removal:

- **Oracle.** The production `approval.LocalHTTPHandler` behind a TLS (optionally mTLS) listener, driven by the real Go
  CLI built from the tree. The generator refuses to run unless `cmd/approval.go`, `internal/approval/{enroll,http,local,queue}.go`,
  `internal/cli/port_utils.go` and `internal/mcp/serverbootstrap/tls.go` equal their blobs at the pinned commit
  (`8d2e5e15`); the fixture records each blob digest.
- **Determinism.** Go draws queue ids, timestamps and the port at random and reads the wall clock (no clock or nonce
  injection exists in Go). Ids become `apr-a0000000000N`, timestamps fixed values, the port `{port}`, temp paths `{vault}`/`{certs}`.
  The Go CLI is then run a second time against a stub that serves exactly the canonical responses, so every recorded
  stdout/stderr/exit is the Go CLI's own rendering of the frozen bytes. `X-Enroll-Timestamp` is validated inside the
  30 s proof window and `X-Enroll-Proof` as HMAC-SHA256 of that timestamp under the recorded secret class, never frozen as bytes.
- **What the replay asserts** (`approval_queue_replay.rs`): method, path, Host, contract headers, no `Authorization`/extra
  headers, no body, the mTLS client identity the server saw, the HMAC proof recomputed per request, the number of
  requests and connections (client-side validation failures must not touch the network, handshake failures must), and the
  CLI's stdout/stderr/exit against the Go outcome. TLS-library error text is compared by the CLI's own prefix only.
- **Accepted differences** (declared in the fixture `scope`): HTTP-library headers (`User-Agent`, `Accept`,
  `Accept-Encoding`, `Content-Length`, `Connection`) are not held to Go's choice.
- **Not covered by the replay:** stale-timestamp and non-loopback-peer rejection (server behaviour; the CLI cannot be made
  to send them without Go clock/peer injection; covered by `internal/approval` Go unit tests and, Go-free, by the `approval::tests` unit tests in `crates/symvault-mcp/src/approval.rs`:
  stale and future proofs → 401, non-loopback peer → 403),
  and the Rust listener side, which is covered by the end-to-end test below. The device-token `/api/v1/approvals` bearer endpoint is
  ported to the Rust server and has its own fixture (device-token section, below).
- **Divergence found and fixed.** `--output yaml` is a plain struct marshal in Go with no `yaml` tags: keys are the
  lower-cased Go field names, the embedded request is a nested `request` mapping, `decidedby: ""` is always written, and
  indentation is four columns. Rust printed serde's snake_case keys. `queue.rs` now emits the yaml.v3 layout
  (`symvault_gojson::yaml::string_in_mapping` for string scalars). Known residual (review, not in the fixture): a string that starts with a newline is
  written double-quoted by Rust where yaml.v3 writes `|4-` and drops the newline; `symvault_gojson::yaml` declares this as
  a deliberate deviation from a yaml.v3 defect. A scratch differential over 49 tricky reason strings matched otherwise.
- **Maintenance.** `make approval-fixtures-generate` rewrites the fixture; `make approval-fixtures-check` regenerates it
  in memory and requires byte equality; `make approval-replay` runs the Go-free replay. Fixture certificates are valid to 2126 and
  are created once with `approvalgen --init-certs` (never regenerated by the check).

### Device-token endpoint `/api/v1/approvals`, 2026-11-03

`scripts/rust-port/cmd/deviceapprovalgen` freezes the server side of the device bearer endpoint into
`testdata/port/approval/device-approvals.json` (`make device-approval-fixtures-generate|-check`, replay: `make device-approval-replay`).

- **Oracle.** The real `approval.HTTPHandler` over a real `approval.Queue` and a real `pairing.DeviceSessionStore`, registered on both
  `approval.PathApprovals` and `approval.PathApprovalAction` of an `http.ServeMux` (as `serverbootstrap` does), on a loopback listener, driven by raw
  HTTP/1.1. The generator pins `cmd/mcp/serve_deps.go`, `internal/approval/{http,queue}.go`, `internal/mcp/auth/token.go`,
  `internal/mcp/serverbootstrap/http.go` and `internal/pairing/devicesession.go` at `8d2e5e15` and checks the four mounting source lines.
- **Findings.** The Go handler never reads a body, so malformed JSON cannot yield 400: the only 400 is `missing approval request id`; a
  bad body is ignored and the decision proceeds (recorded). Authentication precedes id/action validation, but method/path mismatches are the mux 404 *before*
  authentication. Device tokens are rejected on `/mcp` and MCP legacy/scoped tokens on `/api/v1/approvals` (Rust-only assertion in the replay).
  A session with an empty device id is unauthorized (Go's `deviceFromRequest`).
- **Rust divergences found and fixed.** Body JSON was not HTML-escaped (`<`, `>`, `&` become `\u003c`, `\u003e`, `\u0026`, Go's `Encoder` default; affected the local API too);
  `pending()` ordered by RFC 3339 text, which misorders `...05.12Z` vs `...05.123Z`; an empty `decided_by` was serialized.
- **Rate limiter.** Go's per-IP limiter (one bucket shared with `/mcp` and the local API) now wraps these routes in Rust too; the recording here ran the handler on a bare mux, so the replay disables the limiter (`rate_limit: 0`) and the throttling is frozen by `http002ratelimitgen` (scenario `limit_three_device_approval_routes_share_the_bucket`, plus the `rate_limit: 0` and trusted-proxy steps).
- **Device enrollment.** `/api/v1/devices/enroll` and `/api/v1/devices/enroll-code` are ported and wrapped by the same limiter (see the section "APPROVAL-001: device enrollment" at the end of this file).
- **Not covered / residual.** The 15-minute store cleanup,
  HEAD body suppression on the generic 404, TLS/mTLS (owned by the HTTP fixtures).

## APPROVAL-001: Rust server + Rust CLI end to end, 2026-11-03

`crates/symvault-cli/tests/approval_e2e.rs` (`make approval-e2e`, no Go needed) closes the server half the replay leaves open:

- **Recorded cases against the real listener.** The production listener (`serve_with_oauth_and_approval_options_until`, `load_tls_server_config`,
  `LocalApprovalApi`, the `.runtime-port`/`.runtime-tls-cert`/`mcp-server.enroll-secret` discovery files) serves a seeded
  `ApprovalQueue` over TLS and mandatory mTLS; the real Rust CLI runs the 24 reproducible cases of `queue.json` in recorded order
  (one shared queue, one listener per case). stdout/stderr/exit must equal the Go CLI's recorded outcome after random ids and clock
  values are mapped onto the canonical ones (clock values are also checked to be well-formed and near now), and the queue must
  afterwards be exactly what the outcome implies. Cases the CLI refuses before the network, TLS-handshake refusals, bad-HMAC 401s
  (server and CLI hold different secrets), repeat 409 and unknown-id 404 are all served by the real handler, not a recording.
- **Real process.** `symvault mcp --port 0` over mTLS (fixture certificates, dedicated approval client identity in `config.yaml`):
  an MCP `tools/call set_entry_field` by an agent in `approvalMode: prompt` becomes a pending approval; the CLI lists it (json and
  table), approves one request and denies another, and the blocked MCP callers receive success / `denied by approval device`.
  A forged ownership secret is refused with the recorded 401 text.
- **mTLS settings.** `scripts/rust-port/cmd/approvaltlsgen` runs the real Go `symvault mcp` against 10 broken mTLS settings
  (missing CA setting, insecure bind + mTLS, missing/non-PEM client CA, missing/non-PEM key, missing/non-PEM certificate, mismatched
  pair, client CA checked before the key) into `testdata/port/approval/mtls_settings.json` (oracle `8d2e5e15`, pinned blobs +
  digests, `make approval-tls-fixtures-check`); the Rust process must refuse each with the same exit code, empty stdout and `Error:`
  lines. **Divergence found and fixed:** Rust reported `MCP HTTP TLS: <rustls text>` and loaded certificate, key, CA in that order;
  it now follows Go (CA read, CA parse, key pair; cause-free `load server TLS key pair failed`; `http server: ` prefix).
- **Not covered, declared.** Device-token `/api/v1/approvals` (ported and frozen separately by `deviceapprovalgen`, see the device-token section above; this e2e does not drive it); `decide_expired` (the Rust queue TTL
  is fixed at five minutes); Go's pre-failure diagnostics (listener bind + legacy-token migration happen before Go validates the
  CA/key pair; Rust validates first); non-mTLS certificate/key failure texts (Go `crypto/tls`); Windows (the settings replay is
  unix-only because the recorded errno texts are Unix's).

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
  fail, and `config set` rewrites the file before its post-update load fails) differ in acceptance (the local tag on a value, `a: !t x`, matches since CONFIG-SECTIONS-001).
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

- `session.cache`, `session.keyring`, `audit.keyring.orphans`: real checks since
  DOCTOR-KEYRING-001 (2026-11-02, `local/doctor-keyring` `f2838fed`): the OS keyring probe,
  `security dump-keychain` without `-d` (attributes only) and the orphan `--fix`.
  Byte-identical to Go in the forced-memory states (`doctor_keyring_differential`) and, opt-in,
  against the real login keychain. Remaining: a failing OS keyring probe prints the sanitized
  platform error tail instead of go-keyring's; Rust calls `/usr/bin/security` where Go
  resolves `security` through `PATH`; Linux/Windows probes are compiled and unit-tested only.
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

## Token registry decoder (HTTP-A, `go_registry`)

`symvault_store::go_registry::decode_go_registry` reproduces Go's `encoding/json`
decoding of `mcp-tokens.json` for the serving loader, the store reader and the
CLI reader (`agent list`, `agent whoami`, `agent token ls`, `doctor` MCP token
checks). Matched and covered by Go-recorded cases: case-insensitive field
binding, duplicate keys (every occurrence type-checked, last good value wins,
root `tokens` merge), per-byte invalid-UTF-8 replacement, lone `\u` surrogates
(U+FFFD), nesting up to 10000, root `null` (empty registry) and RFC3339
timestamps on the raw bytes (953 recorded Go 1.26.6 outcomes).

Reload caveat that applies to any divergence declared here: when Rust rejects a document the
live registry keeps its **last good state**, while Go (which accepts the same
document) adopts it. A Rust-stricter rejection is therefore a real behavioural
difference on reload (for example an un-applied revocation or an un-applied new
token), not only a startup refusal.

No divergence is declared. A repeated `allowed_tools` array (including one with
`null` elements) is decoded the way Go's `array()` does it: element `i` is
decoded onto the slice the earlier occurrence left, `null` keeps it (a new
position is `""`), the backing array survives truncation so a later longer
`null` array re-exposes old elements, and `[]` / `null` drop the backing array
(`GoStringSlice`). Pinned by 72 Go-recorded `documents` in
`testdata/port/auth/token-lookup.json` (`TestTokenPortFixture`, replayed by
`go_registry::tests::repeated_allowed_tools_overlay_matches_go_recorded_documents`,
incl. 12 capacity-boundary sequences up to 600 elements and 48 seeded random
ones) and by live Go/Rust cases `dup-allowed-tools-null-*` plus two reload steps
in `http_token_contract.py`.

Lone surrogates, depth (10000), root `null` and
timestamp leftovers (one-digit hour, `,` fraction, `+24:00`, `+00:60`, years
`0000`-`9999`, fraction digits beyond nine) are matched, not documented away.
Residual risk: the matched timestamp grammar is a port of `time.Parse`
(`parse_go_rfc3339`) checked against the recorded cases, not against every
possible string; re-record with `scripts/rust-port/go_timestamp_oracle.go.txt`
if Go's toolchain changes. The `time` crate is only used to hold the parsed
instant.

## APPROVAL-001: device enrollment, 2026-11-03

Go mounts two exact-path routes beside the approval transports
(`cmd/mcp/serve_deps.go`, `serverbootstrap/http.go`), both behind the shared
per-client limiter. The Rust MCP HTTP server now serves them
(`crates/symvault-mcp/src/enroll.rs`, `LocalApprovalApi::with_device_enrollment`,
wired by `crates/symvault-cli/src/mcp_commands.rs`).

- **Mint (`POST /api/v1/devices/enroll-code`).** Order of checks as in Go:
  method (anything but POST is the mux 404), loopback peer (403), HMAC proof
  over the whole-second UTC timestamp within 30 s (401), certificate
  fingerprint present (503), then a 32-character base32-hex code valid five
  minutes; the body is `{"code","expires_at","fingerprint"}`. The fingerprint is
  the SHA-256 of the vault's `mcp-server.crt`, computed once at start (Go pins
  that file even when the server presents a configured certificate).
- **Redeem (`POST /api/v1/devices/enroll`).** First JSON value of the body with
  `encoding/json` semantics, `strings.TrimSpace` on the code, a single-use
  `TokenStore` (five failures anywhere start a 30 s cooldown that also refuses
  valid codes), then `DeviceSessionStore.Enroll` with an empty public key; the
  body is `{"device_id","expires_at","token"}`; only the hash of the token is
  persisted.
- **Recording.** `scripts/rust-port/cmd/deviceenrollgen` (`make
  device-enroll-fixtures-check`) freezes 27 cases / 266 exchanges into
  `testdata/port/approval/device-enroll.json`; `crates/symvault-mcp/tests/
  device_enroll_replay.rs` (`make device-enroll-replay`) replays them against
  the Rust server, and `approval_e2e.rs` drives the real `symvault mcp` process.
  Throttling is `http002ratelimitgen` scenario
  `limit_three_device_enroll_routes_share_the_bucket`.
- **Rust divergence found by the recording and fixed.** The proof was signed
  over the timestamp text including its fraction and parsed with the `time`
  crate; Go signs the whole-second UTC text of a `time.Parse(RFC3339)` value
  (also for the local approval API, which shares `verify_proof`).
- **Declared, stricter than Go (never more permissive).** A repeated
  `X-Enroll-Timestamp`/`X-Enroll-Proof` header is refused (smuggling policy of
  `DUPLICATE_SENSITIVE_HEADERS`; Go takes the first); a body above 1 MiB is
  refused before routing; a non-UTF-8 body is refused (Go substitutes U+FFFD);
  a lone surrogate escape in the JSON is `400 malformed request body` (Go
  substitutes U+FFFD). Nesting is bounded at Go's 10000 levels by a pre-scan
  (serde_json would skip any depth in ignored values).
- **Not covered / residual.** The end of the 30 s cooldown over HTTP (injected
  clock corpus in `symvault-sync`), a non-loopback TCP peer (answered through
  the handler with a documentation-range address), HEAD on the generic 404, Go's
  15-minute `StartCleanup` (expiry is enforced on use).
