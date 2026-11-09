# ADR 0037: Proposed ratification of the remaining Go-only residuals at the Rust cutover

Status: **Proposed** 2026-11-08 (maintainer approval pending). Nothing below
takes effect until the maintainer accepts it; an accepted item is binding like
an item of ADR 0034 or ADR 0035. Affects contract rows CLI-002, CLI-003,
CLI-005, CLI-006, CLI-007, PLATFORM-001, PLATFORM-002, IO-002, MCP-003,
BROKER-001, BROKER-002, HTTP-001, APPROVAL-001 and FFI-001. No row changes
status with this ADR, and no code, test or fixture changes.

## Context

The Go implementation is removed ([ADR 0036](0036-go-removal.md), #1575). Go
behaviour survives only as frozen recordings under `testdata/port/**` and as
the tag `legacy/go-oracle`. Windows is out of scope (#1550, #1551; the Windows
Rust code is removed by #1553), so every residual that only names Windows or
"3-OS" is void and is not decided here.

[ADR 0034](0034-proposed-ratification-of-residual-divergences.md) and
[ADR 0035](0035-residual-divergences-before-go-removal.md) decided the
divergences found up to the reconciliation audit at `17a636c6`. A closeout
audit of the open rows of `docs/rust-port/contract-matrix.md` at `20fd7f99`
re-read every residual sentence against the tree and classified it as
`ratify`, `native-evidence`, `go-observation`, `hardware`, `closed`,
`implement` or `void-windows`. This ADR collects the `ratify` class that no
earlier ADR decides, plus the explicitly unbounded `go-observation` classes.

Promotion rule (unchanged, [local-first.md](../rust-port/local-first.md)): a
row becomes `PASS (local)` with a named SHA and both `macos` and `linux`
receipts of `scripts/rust-port/local-gate.sh all`, confirmed by the closing CI
run. Ratifying an item removes it from the list of things that block that
label; it does not replace the receipts.

Recommendation rule (from ADR 0034): a Rust-stricter, safer, spec-conforming
or cosmetic difference, a Go defect or race, and a space that cannot be
enumerated are ratified. A difference that loses data or widens permissions
gets Go parity. No item below is in the second class.

Out of scope here: `implement` items (Rust-only tests or a Makefile gate
entry), `native-evidence` items (receipts), and bounded `go-observation` items.
The last are not ratified; they are listed under "To be recorded from
`legacy/go-oracle`". Hardware items are listed under "Device acceptance
(human)".

Ratifying means the same as in ADR 0032: the Rust behaviour stays the
contract, the check that pins Go's behaviour keeps pinning it as the declared
difference, and reversing it needs a new ADR. "Pin: none" means no test fails
when the behaviour drifts; the item says why.

## Items

### A. CLI-002 (command tree)

**1. The darwin Go-vs-Rust `ui` terminal comparison is permanently unavailable.**
- Difference: the fifteen-case live terminal comparison of the encrypted
  browser drives the real macOS pasteboard. It ran only on a disposable CI
  host and no darwin Go observation was ever recorded; only a Linux
  observation (`scripts/rust-port/fixtures/go-observations/tui-contract.linux.json`)
  exists.
- Why ratified: the Go side is gone with the Go tree, so the gap cannot be
  closed; `scripts/rust-port/go_observations_common.py` already documents it as permanent.
- Rust contract: on macOS the Rust browser is held by `tui-harness-check`, the
  `tui::tests` browser cases and the `ui` signal cases of the process driver;
  the real-pasteboard half is a closing-CI result.
- Pin: `scripts/rust-port/go_observations_common.py:287` (`ACCEPTED_GAPS`),
  `Makefile:1323`.

### B. CLI-003 (flags)

**2. Sub-millisecond `--timeout` values.**
- Difference: for `run --timeout` and `file use --timeout` of roughly a
  microsecond to a millisecond, Go printed `command timed out after 1µs` in one
  run and the expired-context error in another.
- Why ratified: a race inside Go's process start versus the deadline. Rust
  applies Go's rule (a deadline already past before the start refuses the
  start), which is equally timing-dependent there.
- Rust contract: Go's rule as implemented; no promise for that range.
- Pin: none (a race cannot be pinned);
  `docs/rust-port/cli-gap-inventory.md:254-257` records the measurement.

### C. CLI-005 (config and error taxonomy)

**3. Seven commands are excluded from the extra-positional byte comparison.**
- Difference: `broker`, `mcp`, `serve`, `device pair`, `migrate v4` (map
  order), `doctor` and `startup-profile` are not byte-compared for extra
  positionals.
- Why ratified: Go is non-terminating, prints random tokens, host reports or
  timings, or iterates a map; the bytes cannot be compared.
- Rust contract: the generic extra-positional error shape of the other 220
  corpus scenarios applies.
- Pin: `testdata/port/cli/error-taxonomy.json` (`extra_positional_exclusions`
  carries the recorded reason per command).

**4. Test-isolation limits of the error-taxonomy corpus.**
- Difference: absolute-path calls (`/bin/launchctl unload` of
  `intake watch disable` and similar) are not redirected, and the native
  `auth status` Touch ID availability probe is normalised to `__BOOL__`.
- Why ratified: not a Go-vs-Rust difference; the sandbox cannot redirect an
  absolute path, and availability depends on the host. Live availability is
  checked separately.
- Rust contract: as implemented; no scenario creates the launchd plist.
- Pin: `crates/symvault-cli/tests/error_taxonomy.rs:633`,
  `crates/symvault-cli/tests/output_modes.rs:2506`.

**5. `config validate --fix` keeps `clipboard.copyByDefault: false`.**
- Difference: in Go the field is `omitempty`, so the repair drops the key and
  the next load reads the default `true`; an unrelated repair silently turns the
  opt-out into an opt-in. Rust writes `copyByDefault: false`, so the opt-out
  survives. Everything else the repair writes is byte-identical.
- Why ratified: a Go defect with a Rust-safer result, listed as an intentional
  deviation in `cli-gap-inventory.md:367` but in no ADR.
- Rust contract: the key survives the repair.
- Pin: `crates/symvault-cli/tests/config_fix_differential.rs:1004` and `:1066`
  (recorded Go bytes plus a negative control).

### D. CLI-006 (output modes)

**6. `intake watch` output modes are compared for `--once` and the refusal only.**
- Why ratified: the always-on watcher never terminates; it is covered by
  `scripts/rust-port/signal_process_contract.py` and
  `scripts/rust-port/intake_watch_contract.py`, not by the output-modes corpus.
- Rust contract: the watcher text is held by those two contracts.
- Pin: `testdata/port/cli/output-modes.json` (`residuals`, `intake watch`).

**7. `doctor` is pinned only with `--no-network`.**
- Why ratified: network-dependent output cannot be recorded
  deterministically; `doctor` has its own differential.
- Rust contract: network checks follow the implementation; offline output is
  pinned.
- Pin: `crates/symvault-cli/tests/doctor_differential.rs:123`.

**8. Volatile audit and install fields are compared by shape.**
- Difference: `ts`, `kid`, `hmac`, the `argv_hash` digest and the install-time
  `managed_hash` / `managed_installed_at` values are checked for presence and
  shape only.
- Why ratified: the Go values are timestamps, MACs or random.
- Rust contract: presence and shape as asserted.
- Pin: `crates/symvault-cli/tests/output_modes.rs:68`.

**9. Config read errors other than the mapped errnos keep Rust generic text.**
- Difference: `go_errno_text` maps NotFound, PermissionDenied, IsADirectory,
  ENOTDIR, ELOOP and ENAMETOOLONG; any other errno (EIO, EMFILE and so on)
  prints Rust's text instead of Go's.
- Why ratified: those errnos cannot be provoked hermetically.
- Rust contract: the mapped set above; others print the generic text with the
  same exit class.
- Pin: `crates/symvault-cli/src/config.rs:50`.

### E. CLI-007 (signals), BROKER-001 and BROKER-002 (broker and API)

**10. Per-instance broker CA directory instead of `<vault>/broker-ca.pem`.**
- Difference: Go leaves a shared vault-level CA file, so a second concurrent
  broker replaces the first one's trust root. Rust creates a private
  `.broker-ca-*` directory per broker, removed on stop and on catchable
  signals; SIGKILL leftovers are unobservable (ADR 0035 #3).
- Why ratified: deliberate and safer; decided in ADR 0015 (maintainer-delegated),
  measured with two simultaneously live brokers, but absent from every
  ratification list.
- Rust contract: the advertised CA path of the owning instance.
- Pin: `docs/adr/0015-egress-broker-runtime-boundaries.md:119-135`,
  `crates/symvault-cli/src/broker_commands.rs:69`,
  `scripts/rust-port/signal_process_contract.py:15`.

**11. The broker ACL rejects dot segments before any credential access.**
- Difference: Go delivered the credential for `/v1/../denied` and
  `/v1/%2e%2e/denied` under the allow pattern `/v1/*`; Rust answers 403 before
  reading the entry. Malformed percent escapes and non-UTF-8 decoded paths are
  also rejected.
- Why ratified: Rust-stricter on a security boundary; no allowed request is
  lost.
- Rust contract: literal or encoded dot segments, malformed escapes and
  non-UTF-8 paths are denied before normalization.
- Pin: `crates/symvault-mcp/src/store_adapter.rs:4330`,
  `crates/symvault-mcp/tests/egress_broker.rs:183`,
  `scripts/rust-port/egress_contract.py:277-285` (`dot-segment-policy`).

**12. Opaque transport diagnostics of `execute_api_request`.**
- Difference: seven individually asserted cases of the encrypted API corpus
  where Rust's opaque transport diagnostic differs from Go's text.
- Why ratified: decided in ADR 0018 (a response must not carry a
  credential-bearing URL or library diagnostic); not in an ADR 0032/0034/0035
  list.
- Rust contract: the opaque text asserted per case.
- Pin: `docs/adr/0018-api-dns-pinning-and-request-cancellation.md:52-53` and
  `:83`, `scripts/rust-port/api_transport_contract.py`.

**13. SIGQUIT clears an armed clipboard before `ui` exits 2 and before stdio `mcp` exits 0.**
- Difference: Go leaves the secret on the clipboard on SIGQUIT. Rust also
  clears a `ui` copy kept until quit before dying of SIGHUP.
- Why ratified: Rust-safer, loses nothing; only the matrix and the driver
  docstring list it today. (Go's goroutine dump itself is ADR 0034 item 11.)
- Rust contract: clear, then the Go exit status or signal death as recorded.
- Pin: `crates/symvault-cli/src/mcp_shutdown.rs:374`
  (`sigquit_shutdown_clears_an_armed_clipboard`),
  `crates/symvault-cli/src/tui.rs:1237`.

### F. PLATFORM-001 (clipboard and desktop adapters)

**14. Autotype environment whitelist omits `WAYLAND_DISPLAY` and `XDG_RUNTIME_DIR`.**
- Difference: none against Go. Rust's whitelist deliberately equals Go's, so
  `wtype` / `ydotool` under Wayland likely cannot work live in either.
- Why ratified: parity kept on purpose; widening it changes the asserted
  whitelist and needs a Wayland session to prove. Tracked as issue #1479
  (open, deferred).
- Rust contract: Go's whitelist as recorded.
- Pin: `crates/symvault-platform/src/desktop_commands.rs:34`,
  `testdata/port/platform/desktop_linux.json` (`autotype_env_whitelist`).

**15. Non-UTF-8 environment names and values are dropped for desktop tools.**
- Difference: Go passes raw bytes; Rust drops such entries.
- Why ratified: stricter and harmless; no spawned tool needs them.
- Rust contract: only valid UTF-8 entries are passed.
- Pin: none; comment at `crates/symvault-platform/src/desktop_commands.rs:372`.

**16. No `Drop` guard that clears the clipboard after a panic, and copied values are not zeroized.**
- Why ratified: Go has the same two properties; parity, declared as a
  non-claim.
- Rust contract: unchanged; a panic after the copy leaves the clipboard to the
  auto-clear timer.
- Pin: none.

**17. The `initialize` response of the MCP clipboard replay is not compared.**
- Why ratified: the server version string differs by construction.
- Rust contract: version negotiation is held by the MCP-001 corpus.
- Pin: `crates/symvault-mcp/tests/tools_copy_to_clipboard_linux_contract.rs`.

**18. Fixtures name `go1.26.6` where the capture ran on Go 1.26.10.**
- Why ratified: provenance note only; the generators are deleted and the
  fixtures are frozen by `FROZEN.sha256` (ADR 0036), so editing the field would
  break the hash.
- Rust contract: the frozen files as they are.
- Pin: `testdata/port/mcp/copy-clipboard-linux.json`,
  `testdata/port/platform/get_clipboard_linux.json`.

**19. The `get` stdin-write failure is pinned only above the pipe buffer.**
- Why ratified: below the pipe buffer Go's EPIPE behaviour is a timing race.
- Rust contract: the implementation; deterministic above the buffer.
- Pin: `crates/symvault-platform/src/desktop_commands.rs:222`.

**20. `pbcopy` / `pbpaste` are found in `/usr/bin` only.**
- Difference: Go resolves them through `PATH`.
- Why ratified: declared safety deviation (no PATH hijack of the clipboard
  tools).
- Rust contract: fixed `/usr/bin` lookup.
- Pin: `crates/symvault-platform/src/desktop_commands.rs:307`.

**21. Pasteboard tools run under a 30 s deadline with a minimal environment.**
- Difference: Go has no deadline and passes the whole environment; Rust
  restores a `PASTEBOARD_TIMEOUT` of 30 s and passes `PATH`, `HOME`, `LANG` and
  `LC_*` only.
- Why ratified: Go would hang on a stuck pasteboard and over-share the
  environment; Rust-safer.
- Rust contract: as implemented.
- Pin: `crates/symvault-platform/src/desktop_commands.rs:105` and `:826`,
  `crates/symvault-platform/tests/pasteboard_deadline_contract.rs`.

**22. ` (core dumped)` text.**
- Why ratified: implemented from Go's source; no recorded Go run produced a
  core dump and the outcome depends on `ulimit`, so it cannot be reproduced
  hermetically.
- Rust contract: Go's text per its source.
- Pin: `crates/symvault-platform/src/go_exec.rs:128` (unit level).

### G. HTTP-001, IO-002, MCP-003, APPROVAL-001, FFI-001

**23. HTTP rate limiter sweeps lazily (HTTP-001).**
- Why ratified: Go sweeps on a ticker; the difference is unobservable. ADR 0035
  #6 names the other four limiter differences but not this one.
- Rust contract: lazy sweep, eviction as replayed.
- Pin: `crates/symvault-mcp/src/ratelimit.rs:189`,
  `crates/symvault-mcp/tests/http_ratelimit.rs:265`.

**24. A global tar header mixing a valid `path` with an invalid record (IO-002).**
- Why ratified: Go's result depends on map iteration order, so no single
  expected output exists.
- Rust contract: the deterministic result of `crates/symvault-sync/src/gotar.rs`.
- Pin: none for the mix (the corpus is `testdata/port/sync/restore-errors.json`;
  `crates/symvault-sync/src/gotar.rs` holds the logic).

**25. JSON collision values in export (IO-002).**
- Why ratified: Go's map iteration produces two outputs; the replay accepts
  both.
- Rust contract: either recorded output.
- Pin: `testdata/port/sync/export.json`,
  `crates/symvault-sync/tests/export_contract.rs`.

**26. Public DNS is exercised only against a local DNS server (MCP-003, BROKER-002).**
- Why ratified: a live public-DNS run is non-hermetic and cannot be recorded
  from Go. The hermetic local-DNS tests are the closing evidence. Redirects
  are already decided (ADR 0034 item 13).
- Rust contract: pinned resolution through the Hickory resolver with the
  checks of ADR 0018 and ADR 0028.
- Pin: `crates/symvault-mcp/src/api_transport_tests.rs:106` and `:423`.

**27. Device sessions have no periodic cleanup ticker (APPROVAL-001).**
- Difference: Go runs `DeviceSessionStore.StartCleanup` every 15 minutes. Rust
  has `cleanup_expired`, called at enroll time only.
- Why ratified: expiry is enforced at validation in both, so the ticker only
  changes file contents.
- Rust contract: expiry enforced at validation; cleanup at enroll.
- Pin: `crates/symvault-sync/src/device_sessions.rs:307`,
  `crates/symvault-mcp/src/enroll.rs:114`.

**28. mTLS configuration failure is detected before the listener binds (APPROVAL-001).**
- Difference: Go binds and migrates the legacy token registry before it rejects
  a broken client CA/key pair; Rust rejects first, so nothing is bound or
  migrated. Only the `Error:` lines are held equal.
- Why ratified: Rust-stricter with fewer side effects.
- Rust contract: configuration errors are reported before bind and token
  migration.
- Pin: `crates/symvault-cli/src/mcp_commands.rs:247`, `:272`, `:333`,
  `testdata/port/approval/mtls_settings.json`.

**29. Non-mTLS certificate and key failures print Rust's text (APPROVAL-001).**
- Why ratified: Go prints `crypto/tls` library text, which cannot be
  reproduced from Rust; both fail startup.
- Rust contract: Rust's diagnostic, same failure class.
- Pin: none (library text); `crates/symvault-cli/src/mcp_commands.rs:830`.

**30. Stale-timestamp and non-loopback-peer rejection are tested at unit level (APPROVAL-001).**
- Why ratified: a real LAN peer cannot be produced portably in CI; the enroll
  proof window is recorded over HTTP.
- Rust contract: as asserted by the unit tests.
- Pin: `crates/symvault-mcp/src/approval.rs:601`,
  `crates/symvault-mcp/src/enroll.rs:499`,
  `testdata/port/approval/device-enroll.json`.

**31. The end of the 30 s failure cooldown is pinned with an injected clock, not over HTTP (APPROVAL-001).**
- Why ratified: a 30 s wall-clock HTTP test adds no behaviour the injected
  clock does not cover.
- Rust contract: as asserted in the pairing corpus.
- Pin: `crates/symvault-sync/src/pairing.rs:849` and `:868`.

**32. The Swift package test prints a visible SKIP on Linux (FFI-001).**
- Why ratified: there is no Swift toolchain on the Linux lane by design; the
  macOS lane runs it.
- Rust contract: Linux `make ffi-differential` exits 0 with the SKIP;
  macOS runs the Swift part.
- Pin: `Makefile:708`.

## Unenumerable residual classes

The following `go-observation` residuals have no enumerable end: no list of
the missing Go behaviours exists, and recording them one by one would never
finish. For each class the Rust behaviour is declared the contract. A Go-vs-Rust
difference found later inside a class is handled as an ordinary bug report
with a new recording from `legacy/go-oracle`; it does not reopen a promoted row.

- **U1. Whole-tree CLI behaviour behind the 134 reachable paths** (CLI-002,
  CLI-003 inherited-flag resolution, conflicts and diagnostics). Reachability
  is pinned; behaviour is pinned only where CLI-003 to CLI-007 and the feature
  rows record it.
- **U2. The broad exit and error taxonomy outside the corpus families**
  (CLI-005): other command-body errors retain per-command wording.
  `KNOWN_BODY_DIVERGENCES` is empty
  (`crates/symvault-cli/tests/error_taxonomy.rs:272`), but only for the nine
  recorded families. `finish_vault_result` and `finish_session_result` apply
  one generic doubled-`Error` shape to every command
  (`crates/symvault-cli/src/main.rs:4397`, `:5879`).
- **U3. `run` and `file use` argument and separator permutations beyond the
  164 recorded scenarios** (CLI-005).
- **U4. `yaml.v3` decode-error wording beyond the `config set` typed-decode
  shapes and the 276 load-side cases** (CLI-005).
- **U5. Hostile OAuth inputs beyond the actual 46-case corpus and the ADR 0017
  wire negatives** (HTTP-003).
- **U6. Parser, overhead and trailer boundaries of the HTTP server beyond the
  recorded framing, chunk and limit corpora** (HTTP-004).
- **U7. Remaining restore archive path, mode and restore cases beyond
  `testdata/port/sync/restore-errors.json` (290 cases), `testdata/port/sync/restore-gzip-multistream.json` (61) and
  the CLI corpus (173)** (IO-002).

## Already ratified elsewhere (matrix wording only)

These `ratify` residuals are decided by an earlier ADR or by the ADR that
introduced the behaviour. Each needs only a matrix update that cites the ADR.

| Row | Residual | Decided by |
|---|---|---|
| CLI-005 | 34 recorded YAML open divergences (24 wording, 10 behaviour); `33 recorded` and `nesting_depth_10001` text is stale | ADR 0032, 0034 items 1, 2, 6, 9, ADR 0035 #11 |
| CLI-005 | `config set` write side (`1e3`, `y`, `2026-10-31`, `<<`) | ADR 0034 item 3 |
| CLI-005 | CRLF, explicit keys, tags, `!!int &a 12`, comment after anchor, folded blank line, `\u00e9`, flow spacing, timestamps | ADR 0032 item 8, ADR 0034 item 5 |
| CLI-005 | non-mapping root wording; `profiles: {x: null}` | ADR 0034 items 2 and 7 |
| CLI-005, PLATFORM-001 | loader warning counts | ADR 0035 #9 |
| CLI-006 | `remote init` Go nil panic | ADR 0034 item 8 |
| CLI-007 | signals during sync, intake processing, `$EDITOR` hand-off, SIGKILL leftovers | ADR 0035 #3 |
| CLI-007 | SIGQUIT goroutine dump | ADR 0034 item 11 |
| SESSION-003 | passphrase starting with a legacy keyring prefix is refused | ADR 0034 item 26 (an optional pin test is still missing) |
| PLATFORM-001 | scheduler-coincident tick; colour on `cliout` lines | ADR 0034 items 25 and 21 |
| PLATFORM-002 | anomaly detector differences; no desktop notification or GUI backend | ADR 0034 items 29 and 28 |
| IO-001 | non-UTF-8 zip member names, `zipinsecurepath`; argv-borne invalid bytes; 100 MiB cap; `SetLen` quirk; raw-named entry files | ADR 0034 item 27, ADR 0032 items 5 and 6, ADR 0030 items 2 and 4 |
| IO-002 | restore divergences (1), (2), (3), (5), (6); flate offset text; `tarinsecurepath` | ADR 0030 items 1 to 3, ADR 0035 #4 |
| MCP-002 | 364 declared authz differences: allowlist on calls (303 pinned, ADR 0016 text still says 297), delete alias tier (21), `symaira_whoami` allowlist (2), nil share store (38, `upstream-go-bugs.md` 13a) | ADR 0016, `upstream-go-bugs.md` |
| MCP-003 | GUI; redirects | ADR 0034 items 28 and 13 |
| MCP-004 | invalid UTF-8 request id; duplicate keys in `arguments` | ADR 0034 items 14 and 15 |
| HTTP-001 | interim `100 Continue`; body-before-limiter, scope id, zoned proxies, `serve_loopback*` | ADR 0034 item 17, ADR 0035 #6 |
| HTTP-002 | registry edits apply on the next request | ADR 0032 item 2 |
| HTTP-003 | consent, PKCE, DCR, HEAD decisions | ADR 0019, ADR 0021 |
| HTTP-004 | ALPN HTTP/1.1 only | ADR 0034 item 20 |
| APPROVAL-001 | enroll header, body and surrogate refusals | ADR 0035 #7 |
| FFI-001 | X25519 grease stanza, `prepare_entry` path, D-SYMLINK, D-BACKUP; Go removal consequences | ADR 0031, ADR 0036 |
| DIST-005 | rollback to Go and the Go fallback no longer exist | ADR 0036, RUST-014 decision |

## Anchor redefinition: wording conflict between ADR 0034 item 5 and ADR 0035 #8

ADR 0035 #8 says Go takes the first definition of a redefined YAML anchor.
ADR 0034 item 5 says Go resolves the alias to the definition in force at the
alias. The recorded evidence cannot tell the two apart: the only Go-recorded
case (`config-set-residue-anchor-redefined`,
`testdata/port/cli/output-modes.json`) has the alias before the second
definition, where "first" and "in force at the alias" coincide.

Resolution of the wording, applying to both ADRs:

- **Go:** an alias resolves to the definition in force at the alias. Recorded
  2026-11-09 from `legacy/go-oracle` (R20, `alias_after_a_redefined_anchor_matches_go`,
  `testdata/port/cli-transcripts/cli_error_residuals.json`): with `a: &x abc`, `b: &x 5m`,
  `sessionTimeout: *x` Go loads the file (`5m`, the second definition), with
  `a: &x 5m`, `b: &x abc` it rejects it (`abc`), so "Go takes the first" is wrong
  as a general rule. With the alias after the last definition Go and Rust agree
  byte for byte (`config validate`, `--json`, `config get`, `config list`; 12 of 40
  recorded calls); they differ only for an alias that stands before a redefinition
  whose value differs in validity (`config validate` exit 0 in Go, 6 in Rust, or
  the reverse), which is the ADR 0034 item 5 divergence.
- **Rust:** an alias resolves to the **last** definition of the anchor in the
  document, wherever the alias stands. This is the same in both ADRs and is the
  contract.
- ADR 0035 #8's "Go takes the first" is read as shorthand for the recorded case
  and is not a statement about Go's general rule.

## To be recorded from `legacy/go-oracle`

Bounded `go-observation` residuals. They are **not** ratified. Each needs a
Go recording from a worktree of the tag `legacy/go-oracle` and a Rust replay;
until then the row stays below `PASS (local)` for that residual unless the
maintainer accepts it as a gap in a later ADR.

| # | Row | Observation | Why bounded |
|---|---|---|---|
| R1 | CLI-005 | **Closed 2026-11-09.** Suggestion order for inputs with two or more suggestions. Recorded from `legacy/go-oracle` (`ce2390d7`): 1967 inputs (every 1-edit typo of every command name that suggests two or more commands, all one- and two-letter words, 44 two-edit witnesses covering every pair of commands a word can reach) in `suggestion_order_matches_go_for_every_colliding_input`, `testdata/port/cli-transcripts/cli_error_residuals.json`. The 1967 answers fit one total order, which is cobra's registration order (`version`, the `admin`, `auth`, `crud`, `file`, `intakecmd`, `mcp` groups, the commands of `cmd/root.go`, then `completion`); 273 ordered pairs are observed. The old Rust table was a partial order measured from an older oracle and differed from Go in 4 of the 1601 first inputs (`ait`, `auit`, `int`, `seth`). **Rust fix:** `SUGGESTION_ORDER` in `cobra_usage.rs` is now the registration order. Nested groups and `help` suggest nothing in Go (10 recorded shapes) | finite command set |
| R2 | CLI-005 | **Closed 2026-11-09.** `get -` and `get - x` against a vault the oracle initialized: `bare_dash_get_matches_go_in_the_go_initialized_vault`, `testdata/port/cli-transcripts/cli_error_residuals.json` (22 calls in three frozen Go-made vaults: several matches, one match, none; `get -`, `get - x`, `get x -`, `get -- -`, `--json`/`--output yaml` forms, `- get -`). Rust matched Go in all 22; no Rust change | two scenarios |
| R3 | CLI-005 | **Closed 2026-11-09.** The not-initialized shape for every runnable path of `command-tree.json` (90 of 116 paths run, 26 excluded with a reason in `EXCLUDED`) plus 45 approval/file/device/auth variants in an empty sandbox: `not_initialized_shapes_match_go_for_every_runnable_command`, `testdata/port/cli-transcripts/cli_error_residuals.json` (135 calls, 61 of them `vault not initialized`). Rust differed in three places, all fixed: `approval decide` without exactly one of `--approve`/`--deny` and `file get` without (or with an empty) `--out` reached the vault check first (Go: exit 1 / exit 9 before it), and ten paths with a missing `config.yaml` or policy file worded the cause as Rust I/O text (`agent doctor|profile export|profile show|uninstall|upgrade`, `agent profile edit` also asked for the config before the editor, `profile use`, `policy apply|validate`). **New residual R21** (below): four paths in a sandbox without the vault directory | finite command list |
| R4 | CLI-006 | `update apply/check/info` live-release and network branches (hermetic fake release server) | **CLOSED** (see "Closed R items"). three commands |
| R5 | CLI-006 | the `mcp agent …` spelling, where Go resolves `mcp agent list` to `mcp` with positionals | **CLOSED**. one family; check the 116 gate rows first |
| R6 | CLI-006 | forced-colour output of `doctor`, `status` and the TUI (else ratify as cosmetic) | **CLOSED** (colour ratification candidate). finite commands |
| R7 | PLATFORM-001 | Linux clipboard `signal: <name>` text with fake tools that die by signal | one path Status: **Closed.** `clipboard_tool_ended_by_signal_matches_go` (`crates/symvault-platform/tests/clipboard_spawn_errors_contract.rs`) replays SIGKILL/SIGTERM/SIGSEGV from `testdata/port/platform/clipboard_spawn_errors.json` (darwin and the Linux gate image); Rust already matched. |
| R8 | PLATFORM-001 | spawn-error text for non-ENOENT failures (EACCES, ENOEXEC) | two errnos Status: **Closed.** `clipboard_tool_spawn_failure_matches_go` (same file and recording): EACCES and ENOEXEC. Rust differed (io::Error text; non-program file ran through `/bin/sh`) and was fixed in `SystemHost` to report Go's `fork/exec <path>: <errno>`. |
| R9 | PLATFORM-001 | scripted y/n answers to `resolveConfig` prompts of the remaining vault-opening commands | finite command list Status: **Closed.** `native_cli_matches_go_scripted_config_prompt_answers` (`crates/symvault-cli/tests/config_resolve_prompts.rs`, recording `testdata/port/cli/config-prompts.json`): 23 vault-opening commands with y/n/EOF scripts. Fixed in Rust: only the first piped answer is consumed (Go re-creates its bufio reader per prompt), `recipients remove`/`edit` texts and exit class, `git log` author and hash separators. |
| R10 | IO-001 | a pass store path with invalid bytes (Linux only) | one case Status: **Closed (Linux).** `pass_importer_matches_go_for_invalid_utf8_names` (`crates/symvault-sync/tests/pass_gpg_invalid_names_contract.rs`, recording `testdata/port/sync/pass-gpg-invalid-names.json`, real gpg in the gate image). Path bytes, JSON, data and warnings match; the error text carries U+FFFD where Go prints the raw byte, asserted as a bounded difference. |
| R11 | IO-002 | gzip first-member `FNAME`/`FEXTRA`/`FCOMMENT`/`FHCRC` headers | four header flags Status: **Closed.** `gzip_header_flags_restore_matches_go_corpus` (`crates/symvault-cli/tests/restore_gzip_header_caps_contract.rs`, recording `testdata/port/sync/restore-gzip-header-flags.json`, 42 cases). Rust matched every case except Go's `flate: corrupt input before offset N` inflater text, which is compared by stage as in `restore-errors.json` (a bounded, already-known difference). |
| R12 | IO-002 | the 1 MiB cap for the other tar special headers (`g`, `K`) | two header types Status: **Closed.** `tar_special_header_caps_restore_matches_go_corpus` (same test file, recording `testdata/port/sync/restore-tar-special-caps.json`, 14 cases: just under, at, over the 1 MiB cap for `g` and `K`); Rust matched. |
| R13 | MCP-003 | `autotype` and `run_command` handler texts (hand-written expectations today) | two tools Status: **Closed.** `go_autotype_tool_results_replay` and `go_run_command_tool_results_replay` (`crates/symvault-mcp/tests/autotype_run_command_contract.rs`, recording `testdata/port/mcp/autotype-run-command.json`, 39 cases); the hand-written expectations in `tools_authz_order.rs` and `store_adapter.rs` now read the recording. Fixed in Rust: a timeout renders as a Go `time.Duration` (`1m0s`, not `60s`) and a missing `env`/`files` ref reads `secret ref not found: <path>`. Not recordable: the `autotype not available on this platform` branch (`tools_autotype.go:56`) needs a nil backend, which Go's darwin/linux factories never return. |
| R14 | CLI-003 | printed `broker --passthrough` list and `intake watch` interval text for unusual literals, from signal-ended runs | **CLOSED**. two commands |
| R15 | CLI-003 | effective `unlock --ttl` against a persistent session cache | **CLOSED**. one flag |
| R16 | HTTP-003 | remaining OAuth expiry boundaries (code, access, refresh, DCR client) | four boundaries |  **closed** (see "Recorded", R16) |
| R17 | HTTP-004 | combinations of configured header, body, idle and write budgets | finite budgets |  **closed**, one Rust fix (see "Recorded", R17) |
| R18 | HTTP-004 | TLS server identity rotation, client revocation and expiration | three cases |  **closed** (see "Recorded", R18) |
| R19 | BROKER-002 | prompt/biometry diagnostics and tool-name context of `execute_api_request`; whether the template-open check is race-proof in Go | unmeasured, bounded |  **closed**, one Rust hardening (see "Recorded", R19) |
| R20 | CLI-005 | **Closed 2026-11-09.** Alias after a redefined anchor: `alias_after_a_redefined_anchor_matches_go`, `testdata/port/cli-transcripts/cli_error_residuals.json` (10 configs x 4 commands). Go resolves to the definition in force at the alias; Rust (last definition) agrees whenever the alias stands after the last definition, which is the case this item asked for. The earlier-alias divergence stays ADR 0034 item 5; see the section above | one case |
| R21 | CLI-005 | new, from the R3 sweep: in a sandbox without the vault directory `agent token new`, `agent token rotate`, `agent token revoke` and `share revoke` fail in Rust with `failed to read <dir>: No such file or directory (os error 2)`; Go reads the registry as empty (`token "x" not found or already revoked`, `share grant x not found`) or fails at the write of `mcp-tokens.json.tmp-<random>`. Pinned by `OPEN` in `cli_error_residuals.rs`; the test fails when one starts to match. Not fixed here: the store opens its root capability before the registry | four commands |

### Closed R items (local/r-cli006, oracle `ce2390d7`)

Each item below is recorded from the archived Go oracle and replayed against
the native binary; every recording is in the `FROZEN.sha256` set and passes
`recordings_have_no_operator_paths`. Rows stay below `PASS (local)` only for
the declared differences named here.

| # | Test (`crates/symvault-cli/tests/`) | Recording | Result |
|---|---|---|---|
| R4 | `cli_update_live_release.rs::update_live_release_matches_go` | `testdata/port/cli-observations/cli_update_live_release.json` | 44 cases; text and JSON modes; 2 Rust fixes; 2 declared differences (below) |
| R5 | `cli_mcp_agent_spelling.rs::mcp_agent_spelling_matches_go_in_an_empty_sandbox`, `..._in_an_initialized_vault` | `testdata/port/cli-transcripts/cli_mcp_agent_spelling.json` | 24 calls; 1 Rust fix (cobra `Find` for `mcp` subcommand words) |
| R6 | `cli_forced_colour.rs::doctor_and_status_forced_colour_match_go_modulo_the_declared_difference`, `tui_forced_colour_is_recorded_as_go_evidence` | `testdata/port/cli-observations/cli_forced_colour.json` | 21 doctor/`auth status` cases; 1 declared difference (colour) |
| R14 | `cli_signal_literals.rs::broker_passthrough_literals_match_go`, `intake_watch_interval_literals_match_go` | `testdata/port/cli-observations/cli_signal_literals.json` | 54 signal-ended runs, all equal; no Rust change |
| R15 | `cli_unlock_ttl.rs::unlock_ttl_matches_go_against_the_keychain` | `testdata/port/cli-observations/cli_unlock_ttl.json` | 33 cases; 4 Rust fixes |

Differences left open, for the maintainer's decision:

- **R4, transport wording (recommend R, cosmetic).** A failed fetch prints the
  HTTP stack's own text after the product prefix (`Get "<url>": dial tcp:
  lookup ...: no such host` in Go, `error sending request for url (<url>)` in
  Rust). The test reduces both to `<TRANSPORT>`; prefix, step name, exit code
  and streams are compared exactly.
- **R4, first asset URL host check (recommend R, security-motivated).** Go
  checks the host and scheme of *redirects* of a release asset only; a cached
  release record that points the first request at `http://127.0.0.1:...` or
  `https://example.invalid/...` is fetched. Rust refuses any asset URL that is
  not HTTPS on a GitHub host before any request:
  `Error: apply update: apply update: updateapply: release asset URL must use
  HTTPS on a GitHub host`. Seven cases (`DECLARED_HOST_CHECK`) pin Go's text as
  different and Rust's text exactly; the test fails if Rust starts matching Go.
- **R4, not reachable hermetically.** The release endpoint is a hard-coded
  `https://api.github.com` URL and Go's client ignores `HTTPS_PROXY`; the
  HTTP-status and decode branches of its answer sit behind TLS and stay with
  `update_commands.rs::http_tests` (Rust, loopback) and Go's own unit tests.
  The test therefore runs every case under a `sandbox-exec` profile that
  denies non-loopback network access and is macOS-only; it builds a
  `SYMVAULT_VERSION=1.0.0` binary into `CARGO_TARGET_TMPDIR` (about 30 s on a
  warm cache; `SYMVAULT_STABLE_BINARY` names a prebuilt one).
- **R6, colour (recommend R, cosmetic).** Go colours `doctor` lines when stderr
  is a terminal and stdout's lipgloss profile is not Ascii (`CLICOLOR_FORCE`
  not `0`, or `TERM`/`COLORTERM`; `CI`, `NO_COLOR`, `CLICOLOR=0`, `TERM=dumb`
  switch it off); `--color` is parsed but never reaches `cliout`. The native
  `doctor` never emits ANSI: 11 forced-colour cases are pinned as
  `DECLARED_UNCOLOURED` (identical text and exit status, no escape byte), and
  the test fails when the native output starts to colour. The TUI's SGR set is
  Go evidence only: the native TUI needs a terminal that answers
  cursor-position requests and its layout is pinned by `tui-harness-check`, so
  no deterministic Go-versus-Rust colour comparison exists for it.

## Recorded from `legacy/go-oracle`: R16 to R19

Recorded from the tag `legacy/go-oracle` (`ce2390d7`) with Go `go1.26.6`; the
generators are frozen as `scripts/rust-port/*.go.txt` (they were run as `go test`
files inside `internal/mcp/serverbootstrap` and `internal/mcp/server` of the
archived tree; each recording is byte-identical across two captures). Rust
replays each recording; Go is not needed again. Recordings carry no operator
paths.

**R16 (HTTP-003), closed.** `testdata/port/mcp/http-oauth-expiry.json`,
generator `http_oauth_expiry_record.go.txt`, replays
`oauth::expiry_replay::*` (`authorization_code_expiry_matches_the_go_recording`,
`refresh_token_expiry_matches_the_go_recording`,
`dcr_client_expiry_matches_the_go_recording`,
`dcr_registration_stores_no_expiry_like_go`, `recording_covers_all_four_boundaries`)
and `http::tests::access_token_expiry_matches_the_go_recording`. Go has no clock
injection (`time.Now().After(expiry)`), so the recording holds a "before" and an
"after" observation per boundary, taken with a 400 ms TTL read immediately and
after 900 ms (access token, DCR client) or with one-hour offsets, plus the 300 s
code lifetime from the real issuer. Rust replays the same positions on its
injected clock (and on the real clock for the bearer leg). Everything matches
(status, content type, body, `WWW-Authenticate`, no token minted on an expired
code, replay of an expired code, rotated pairs keep both deadlines, a refresh
without a TTL never expires, the real registration stores no expiry and a bare
`ttl_seconds` never expires a client). Two Rust-only stricter behaviours are
pinned next to the replay, both security-motivated:

- Go refuses a refresh once the *access* token has expired
  (`getByRefreshTokenHash` demands `!IsExpired()`); Rust renews with the
  configured finite TTL and keeps the refresh deadline. This is
  [ADR 0019](0019-oauth-consent-binding-and-token-lifetimes.md), recorded again
  as `refresh-valid-but-access-expired`
  (`refresh_after_access_expiry_is_the_adr_0019_divergence`).
- The exact-equality instant is unreachable on Go's wall clock and is not
  recorded. At exactly the refresh deadline Go (`After` is strict) accepts and
  then computes `refreshTTL = Until(deadline) = 0`, which mints a replacement
  pair whose refresh token never expires. Rust refuses at the deadline
  (`refresh_at_exactly_the_deadline_is_refused`).

**R17 (HTTP-004), closed with one Rust fix.**
`testdata/port/mcp/http-budget-combinations.json`, generator
`http_budget_record.go.txt`, replay
`crates/symvault-mcp/tests/http_budget_combinations.rs`. Seven combinations of
`read_header_timeout` / `read_timeout` / `write_timeout` (all six strict
orderings of 1 s, 2 s, 3 s and one tie) through the production
`RunHTTPServerOnListener`, each with eight probes (normal request; persistent
connection with a 2.5 s idle gap; progressing header; progressing body;
header then body; header ending after the read budget with the body in the same
segment and 100 ms later; a body that completes after the write budget). The
idle budget is the constant 120 s (`http.go` `IdleTimeout`) and not
configurable; the idle probe shows that no configured budget bounds an idle
persistent connection. Findings:

- **Fixed in Rust.** The header deadline is `read_header_timeout` alone, even
  when it exceeds `read_timeout` (net/http `readRequest`: the whole-request
  deadline only replaces it once the headers are complete). Rust used the
  earlier of the two (`initial_read.min(request_read)`, from the ADR 0024
  wording), so with `read_header_timeout > read_timeout` it closed a slow
  header at `read_timeout` and refused a request Go serves. `read_wire_request`
  now uses `initial_read` alone. Before the fix the replay failed on
  `header-slow-forever` and both `header-ends-after-read-budget-*` probes of
  the three profiles with `read_header_timeout > read_timeout`; it passes after it.
- Everything else matches in terminal kind and in the 500 ms bucket of the
  close time: header-only expiry, body expiry measured from the start of the
  request (not from the end of the headers), write budget starting when the
  headers are complete (a body finishing after `write_timeout` gets no
  response), idle not bounded by any budget.
- 13 probes end, on the Go side, in the handler's `400 invalid_client_metadata`
  envelope after a body-read timeout where Rust closes without a response. This
  is the ADR 0024 decision ("Go's optional body-timeout error ... Rust
  consistently stops with empty EOF/reset"), not new; the replay pins the count
  (13) so no other Go-only response can hide behind it.

**R18 (HTTP-004), closed.** `testdata/port/mcp/http-tls-lifecycle.json`,
generator `http_tls_lifecycle_record.go.txt`, replay
`crates/symvault-mcp/tests/http_tls_lifecycle.rs`. 26 cases through the
production server with real certificate files, TLS and mTLS: the identity and
the client CA are loaded once at start. Files replaced while running change
nothing for new handshakes or established connections; a restart picks them
up; a mismatched key pair fails the restart closed (both implementations; only
the error wording differs). There is no CRL/OCSP: "revocation" is expressible
only as replacing the client CA file and restarting, and an established
connection survives it. An expired or not-yet-valid client certificate is
rejected on new handshakes (TLS 1.3: seen on the client's first read; TLS 1.2:
in the handshake), an established connection whose certificate expires
afterwards keeps working. All 26 cases match except one alert byte (proposed
item 33 below).

**R19 (BROKER-002), closed with one Rust hardening.**
`testdata/port/mcp/execute-api-diagnostics.json`, generator
`execute_api_diagnostics_record.go.txt`, replay
`store_adapter::tests::{execute_api_request_approval_diagnostics_match_the_go_recording,
unknown_approval_mode_fails_closed_unlike_go,
biometry_diagnostics_carry_the_tool_name_like_go,
template_open_is_pinned_to_the_checked_file_unlike_go,
template_symlinks_are_refused_where_go_follows_them}`. Go side driven through
`Server.executeTool("execute_api_request", ...)` with the terminal seam
(`openTTYDevice`), a mock biometric authenticator and `SYMVAULT_SECUREUI=none`.

- Prompt diagnostics match byte for byte, tool name included: `deny`, no TTY,
  user denies, TTY vanishing before the prompt, raw-mode failure, timeout
  (`approval timed out after 1s`), read failure, user approves, `auto`.
- Biometry texts match byte for byte: `policy requires biometric verification
  for tool "execute_api_request", but biometric authentication is not available
  on this platform. Agent "r19-agent" cannot execute this tool` and
  `biometric verification failed for tool "execute_api_request": biometric
  verification for execute_api_request failed: touch id authentication failed`.
- Recorded Go quirks Rust deliberately does not copy, both stricter: Go's
  `validateToolAccess` lets the tool run when the biometric challenge is
  unavailable or fails and for `prompt`/`deny` policy rules on the caller's
  `path` argument (one upstream request in each recorded case); Rust denies
  with the challenge or policy text. That divergence predates this item and is
  documented in `policy_biometry_challenge` and `tests/authguard_require_biometry.rs`.
  The second quirk is new: an unrecognised approval mode proceeds in Go
  (`default: return nil`) and is refused in Rust (proposed item 34).
- **Template-open race: not race-proof in Go.** `apitemplates.Load` does
  `os.Stat(path)` and then `os.ReadFile(path)`: two path lookups, symlinks
  followed. A concurrent remove/recreate loop reaches the window within a
  second (`read template file ...: no such file` instead of the builtin
  fallback), and a symlink at the template path or at `templates/` is followed
  to a file outside the vault (both deterministic, recorded). Rust refused the
  symlinks already (item 35) but still checked by path and opened by path;
  it now opens the checked path and refuses the file when the opened handle is
  not the inode that passed the `lstat` (`template changed while loading`,
  unix; a deterministic hook swaps the file between check and open in
  `template_open_is_pinned_to_the_checked_file_unlike_go`, with a negative
  control that fails without the check).

### Proposed items from R16 to R19

Same rules as items 1 to 32: not binding until the maintainer accepts them.

- **33 rustls TLS 1.2 alert for a missing client certificate** (HTTP-004). For
  a client that sends no certificate to an mTLS listener over TLS 1.2, Go's
  `crypto/tls` sends `handshake_failure` and rustls sends `certificate_required`.
  Both refuse the handshake; the alert byte is chosen inside the TLS library.
  Pin: `OPAQUE_ALERT_DIFFERENCES` in `tests/http_tls_lifecycle.rs`. Recommendation R.
- **34 unknown approval mode fails closed** (BROKER-002). Go proceeds, Rust
  refuses with `execute_api_request denied: unknown approval mode "<mode>"`.
  Config loading owns mode validation, so the CLI never produces the input.
  Pin: `unknown_approval_mode_fails_closed_unlike_go`. Recommendation R.
- **35 template symlinks refused** (BROKER-002). Go follows a symlink at the
  template path and a symlinked `templates/` directory; Rust refuses
  (`template must be a regular file`, `template directory escapes the vault
  root`) so a vault-local link cannot substitute the endpoint allowlist or the
  credential reference. Pin: `template_symlinks_are_refused_where_go_follows_them`.
  Recommendation R.
- **36 refresh at the exact deadline** (HTTP-003). See R16: Go would accept and
  mint a non-expiring refresh token; Rust refuses. Pin:
  `refresh_at_exactly_the_deadline_is_refused`. Recommendation R.

## Implement items (not ratified)

Rust-only work that closes a residual without any Go data. It is listed so the
residual is not mistaken for a ratification candidate. No item here is done by
this docs-only change.

- Add `data-safety-differential` (`Makefile:656`) to `LOCAL_AREA_DIFFERENTIAL_TARGETS`
  and fix its help text (`Makefile:1406`), so DIST-005 can get a local-gate receipt.
- Add `toolhash-process-contract` (`Makefile:982`) to `LOCAL_AREA_PROCESS_TARGETS`
  (HTTP-002).
- Add tests for exit code 7 (`doctor --strict` with warnings) and exit code 10
  (update available) (`crates/symvault-cli/src/main.rs:3106`,
  `crates/symvault-cli/src/update_commands.rs:1038`) and run the accepting
  probes of the error-taxonomy corpus through the built binary (CLI-005).
- Reproduce `decide_expired` with `ApprovalQueue::enqueue_with_ttl`
  (`crates/symvault-cli/tests/approval_e2e.rs:45`) and add a HEAD-to-unrouted-path
  test (`crates/symvault-mcp/src/http.rs:1585`) (APPROVAL-001).
- Add a concurrent-writer test for `mcp-shares.json`
  (`crates/symvault-store/src/sharing.rs:197`) (MCP-003).
- Add cargo-fuzz targets for the CSV, Bitwarden, 1PUX, CXF and pass importers
  (ADR 0036 follow-up; `fuzz/fuzz_targets/age_envelope.rs` is the only target).

## Device acceptance (human)

Hardware residuals need a person at a device. They are not ratified and not
automated; a maintainer records them as a manual acceptance note.

- **SESSION-003:** Touch ID prompt (accept, cancel, failure) through the JXA
  `LAContext` evaluation; the real default-keychain path
  (`SecurityBiometricItems::system()`), cross-binary access-control prompts,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and the login/data-protection
  keychain with ACL trusted-application lists; reading a Rust-written item with
  Go's cgo store (needs a Touch ID Mac and a build from `legacy/go-oracle`).
- **PLATFORM-001, PLATFORM-002, MCP-003:** a logged-in desktop session
  (macOS accessibility prompt, X11, Wayland) typing and copying for real; macOS
  `keystroke` through JXA versus Go's AppleScript; GUI secure input and
  notification delivery.
- **HTTP-003:** one consent flow in a real browser.
- **FFI-001, FFI-002:** a physical iPhone for the `ios-arm64` slice; whether iOS
  honours `isExcludedFromBackup` on the backup directory; launching the app and
  running `ApprovalSessionStoreTests` on a signed host.

## Decision table

| Item | Rows | Recommendation | Maintainer decision |
|---|---|---|---|
| 1 darwin `ui` Go comparison unavailable | CLI-002 | R | pending |
| 2 sub-millisecond `--timeout` | CLI-003 | R | pending |
| 3 seven extra-positional exclusions | CLI-005 | R | pending |
| 4 test-isolation limits | CLI-005 | R | pending |
| 5 `copyByDefault: false` | CLI-005 | R | pending |
| 6 `intake watch` output modes | CLI-006 | R | pending |
| 7 `doctor --no-network` | CLI-006 | R | pending |
| 8 volatile fields by shape | CLI-006 | R | pending |
| 9 unmapped config read errnos | CLI-006 | R | pending |
| 10 per-instance broker CA | CLI-007, BROKER-001 | R | pending |
| 11 broker dot segments | BROKER-001 | R | pending |
| 12 opaque transport diagnostics | BROKER-002 | R | pending |
| 13 SIGQUIT clears clipboard | CLI-007 | R | pending |
| 14 Wayland autotype whitelist | PLATFORM-001 | R | pending |
| 15 non-UTF-8 env dropped | PLATFORM-001 | R | pending |
| 16 no Drop guard, no zeroize | PLATFORM-001 | R | pending |
| 17 `initialize` not compared | PLATFORM-001 | R | pending |
| 18 `go_version` provenance | PLATFORM-001 | R | pending |
| 19 stdin-write EPIPE | PLATFORM-001 | R | pending |
| 20 `/usr/bin` clipboard tools | PLATFORM-001 | R | pending |
| 21 pasteboard deadline and env | PLATFORM-001 | R | pending |
| 22 core dumped text | PLATFORM-001 | R | pending |
| 23 lazy limiter sweep | HTTP-001 | R | pending |
| 24 global tar header map order | IO-002 | R | pending |
| 25 JSON collision values | IO-002 | R | pending |
| 26 public DNS not exercised | MCP-003, BROKER-002 | R | pending |
| 27 no device-session ticker | APPROVAL-001 | R | pending |
| 28 mTLS check before bind | APPROVAL-001 | R | pending |
| 29 non-mTLS TLS text | APPROVAL-001 | R | pending |
| 30 unit-level peer/timestamp checks | APPROVAL-001 | R | pending |
| 31 cooldown end with injected clock | APPROVAL-001 | R | pending |
| 32 Swift SKIP on Linux | FFI-001 | R | pending |
| 33 rustls TLS 1.2 missing-client-certificate alert | HTTP-004 | R | pending |
| 34 unknown approval mode fails closed | BROKER-002 | R | pending |
| 35 template symlinks refused | BROKER-002 | R | pending |
| 36 refresh refused at the exact deadline | HTTP-003 | R | pending |
| U1 to U7 unenumerable classes | see section | R | pending |
| Anchor wording | CLI-005 | wording | pending |

## Consequences

- If accepted, rows may cite this ADR for the listed residuals; they no longer
  block a `PASS (local)` label. The remaining blockers are receipts
  (`native-evidence`), the entries under "To be recorded", the `implement`
  items and the device acceptance notes.
- The matrix gets a pointer to this ADR in each affected row (done in the same
  commit as a closeout note; no status changes).
- Items marked "Pin: none" stay unpinned on purpose; adding a pin would need a
  new test and is not required for ratification.
- Reversing an accepted item needs a new ADR.
