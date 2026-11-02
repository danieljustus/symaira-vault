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

Still open (probed, not fixed; see the CFG-003 and CLI-005 rows of the contract matrix):

| Class | Go | Rust |
| --- | --- | --- |
| `Config::load`: `vault.authMethod: 12` / `abc` | accepted by the typed reload | `must be a string` / `invalid authMethod` |
| `Config::load`: `mcp.port: 1.5`, `!!float 3` | accepted | `port must be an integer` |
| `Config::load`: `useTouchID: y`, `approval_required: n` | accepted (YAML 1.1 words) | `must be a boolean` |
| `Config::load`: `sessionTimeout: null` | `must be greater than 0, got 0s (default: 15m, …)` | `parse config: sessionTimeout must be a string` |
| `Config::load`: custom or non-specific tags on scalars | accepted | serde_yaml_ng enum error |
| `Config::load`: recursive alias under an unread key | accepted | `recursion limit exceeded` |
| `Config::load`: duplicate keys in an unread mapping (`m: {a: 1, a: 2}`, `"<<"` plus `'<<'`) | accepted | `duplicate entry` |
| `Config::load`: explicit tags on unread values (`d0: !!float ~`) | accepted | `expected a float` |
| `Config::load`: alias bomb under an unread key | accepted | `repetition limit exceeded` after about 0.7 s (safe refusal) |
| nesting depth | up to 10000 levels | refused beyond 256 (`yaml_edit`); 100k `[` take about 100 s to refuse |
| `profiles:\n  x: null` | nil pointer panic, exit 2 | parse error, exit 6 |
| `config set x 1e3` / `0b11` / `010` / `y` / `2026-10-31` | writes `1000` / `3` / `8` / `"y"` / `2026-10-31T00:00:00Z` | `1000.0` / `"0b11"` / `10` / `y` / `2026-10-31` |
| `config set x '<<'` | writes `!!merge <<` | writes `"<<"` |
| re-encode of the rest of the file | CRLF becomes LF; flow sequences get `, ` spacing (`[x,x]` becomes `[x, x]`); timestamp scalars in flow mappings are quoted (so a later error says `!!str`, not `!!timestamp`); anchor comments move behind the collection (changing reported lines); explicit keys, `\u00e9` escapes, verbatim and `!` tags, `!!int &a 12` order, tagged block sequence indent are normalised | kept as written |
| root that is not a mapping | `root node is a scalar, not a mapping` (or `a sequence`) | `document has no root to descend into` |
| typed decode, anchors | the preceding definition of a redefined anchor; the anchor's line even behind a comment | the last definition; the collection's line |
| typed decode, `!!binary` into `time.Time` | raw decoded bytes in the `parsing time` text | lossy UTF-8 (U+FFFD) for a non-UTF-8 payload |

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
