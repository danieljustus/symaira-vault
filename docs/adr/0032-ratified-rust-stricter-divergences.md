# ADR 0032: Ratified Rust-stricter divergences from the Go oracle

Status: accepted by the maintainer, 2026-11-02 (decision D7).
Affects contract rows HTTP-001, HTTP-002, MCP-004, IO-001, CLI-005 and CLI-006,
and the approval-mode handling recorded here as MCP-PP. Before this ADR these
were recorded as declared or open differences awaiting a decision. No row is
promoted to `PASS` by this ADR: promotion still needs gate receipts.

## Context

The Go oracle accepts, tolerates or re-encodes some inputs that the Rust port
rejects, refuses to answer, or writes differently. Each item below was measured
against the pinned oracle and is pinned by a fixture, a declared-difference
table or a negative-control test, so it cannot drift silently. The port
otherwise targets byte parity; these items are the cases where matching Go
would mean reintroducing request-smuggling shapes, unbounded buffers, an
approval bypass, or reproducing an unreachable Go memory quirk.

This ADR follows [ADR 0030](0030-approved-restore-and-import-divergences.md),
which ratified the restore and import divergences. Maintainer decision of
2026-11-02, quoted: "D7 ratify as approved divergences: HTTP-001/002 declared
Rust-stricter classes, MCP-004 8 MiB frame/buffer limit and duplicate-envelope-key
rejection, IO-001 non-UTF-8 argv values rejected by clap and the unreachable Go
SetLen stale-element quirk, CLI-005 recorded YAML open divergences (yaml.v3
two-token look-ahead class) and the exotic `config set` re-encode items listed
in the CLI-005/CLI-006 rows (CRLF, explicit keys, verbatim/non-specific tags,
`!!int &a 12` order, comment-after-anchor line shift, folded trailing blank
line, tagged block sequence indent). Also MCP-PP: unknown approval mode fails
closed in Rust."

## Decision

Every item in the table is an approved divergence. The Rust behaviour stays;
the corresponding check keeps pinning the Go behaviour as the documented
difference, and a declaration that stops differing still fails its check.

### Per-item table

| # | Row | Go behaviour | Rust behaviour | Why safe | Evidence |
|---|---|---|---|---|---|
| 1 | HTTP-001 (71 declared cases in 10 classes, listed below) | Parses and answers requests that are ambiguous, malformed or beyond its supported framing: answers 200/404/501/505 or the first JSON value | Answers a stricter 400, closes without a response, or waits for the declared length | Ambiguous request forms (duplicate `Host`/`Content-Type`/`Origin`, obs-fold, absolute-form target, two JSON values, Transfer-Encoding) are the usual request-smuggling shapes; rejecting them cannot change what a well-formed client gets | `scripts/rust-port/http_replay_contract.py` (`DECLARED`), `scripts/rust-port/test_http_replay_contract.py`, `docs/adr/0017-http-wire-contract-and-token-sessions.md` |
| 2 | HTTP-002 | A registry file edit (add, revoke, expire) takes effect on Go's 2 s poll | Rust re-reads per request and polls in the background, so edits apply earlier; a failed reload keeps the last good registry as Go does | Only the timing differs; for revocation earlier is stricter, and a revocation survives a later corrupt or deleted file (negative control with the poller disabled fails) | `scripts/rust-port/http_token_contract.py`, `scripts/rust-port/test_http_replay_contract.py` |
| 3 | MCP-004 (frame limit) | Accepts a stdio frame of any size (a 5 MB frame is answered) | Limits a frame to 8 MiB before LF, drains oversized input without growing the buffer, answers `-32600` without trusting a truncated id, then recovers for the next request | A bounded buffer per client; the measured 5 MB compatibility input still passes | `docs/adr/0016-mcp-discovery-and-call-authorization.md`, `crates/symvault-mcp/src/lib.rs`, `crates/symvault-mcp/tests/stdio_hygiene_contract.rs`, `testdata/port/mcp/stdio-hygiene.json` |
| 4 | MCP-004 (duplicate envelope keys) | `encoding/json` resolves a duplicated envelope field silently, last occurrence wins; this includes case variants (`method` then `METHOD`), an `id:null` that replaces an earlier id and a trailing `method:null`/`jsonrpc:null` no-op | The stdio loop answers `-32700` and does not dispatch the frame, for exact and case-variant repeats alike (`duplicate_envelope_probes` records the eight Go answers). The HTTP adapter keeps Go's last-wins | Last-wins is the duplicate-key smuggling shape: an auditing or policy intermediary may read the first occurrence while the server acts on the last | `testdata/port/mcp/stdio-hygiene.json` (`duplicate_object_keys_last_wins`, `duplicate_envelope_probes`), `crates/symvault-mcp/tests/stdio_hygiene_contract.rs`, `crates/symvault-mcp/src/envelope.rs` |
| 5 | IO-001 (argv) | Accepts non-UTF-8 argv values (`--prefix`, `--mapping`, the source path in error text) | clap rejects a non-UTF-8 argv value before the command runs | Fails before any vault write; consistent with the text-path store of ADR 0030 item 4, which only persists UTF-8 entry paths | `crates/symvault-cli/tests/import_command_contract.rs`, `crates/symvault-cli/tests/fixtures/import-command/cases.json`, `docs/adr/0030-approved-restore-and-import-divergences.md` |
| 6 | IO-001 (`SetLen`) | With three or more duplicate keys for one slice field, `SetLen` re-exposes stale backing-array elements of an earlier longer array | The Rust decoder does not reproduce it | Unreachable from real Bitwarden exports; reproducing it would import data the file does not contain | `crates/symvault-sync/src/importer/gojson.rs` |
| 7 | CLI-005 (YAML syntax errors) | yaml.v3 keeps a two-token scanner look-ahead behind the parser, so for a same-line trailing token (for example `a: "x" b: 1`) it reports a scanner failure | libyaml reports the parser failure. 13 `wording` entries: both sides reject, only the message or stage differs. 2 `behavior` entries (below) differ in acceptance | Config is rejected or accepted on a malformed-YAML edge only; each entry pins Go's bytes per command and `recorded_open_divergences_are_still_open` fails if one starts matching or changes | `testdata/port/cli/config-yaml-syntax.json` (`open_divergences`), `crates/symvault-cli/tests/config_yaml_syntax.rs` (`recorded_open_divergences_are_still_open`) |
| 8 | CLI-005 / CLI-006 (`config set` re-encode) | Re-encodes the whole file through yaml.v3. The row records: CRLF is written as LF; a comment after an anchor moves behind the collection (shifting the reported line); `!!int &a 12` is written `&a !!int 12`. Also differing in the probe: `? x` explicit keys, a verbatim `!<tag:yaml.org,2002:int>`, a non-specific `! 5`, a folded scalar's trailing blank line, the indent of a tagged block sequence | Rust's edit through `yaml-edit` does not apply yaml.v3's normalisation for these shapes (exact Rust bytes are not pinned by a Go-recorded case yet) | Probed against the Go binary on 2026-11-01: the differences are in re-encoded layout and ordering of untouched text, not in the key and value being set; the written file stays parseable by both | rows CLI-005 ("Open class — `config set` write side") and CLI-006 in `docs/rust-port/contract-matrix.md`, `crates/symvault-cli/src/config.rs`, `crates/symvault-core/src/config_typed.rs` |
| 9 | MCP-PP (approval mode) | An unknown approval mode is allowed: `requiresApproval` returns false and the approval helper's `default` returns nil | An unknown mode is denied: `set_entry_field`, `delete_entry`, `execute_with_secret`, `execute_api_request` and `prepare_payment` fail with `<tool> denied: unknown approval mode "<mode>"` | Fails closed. Go's profile loader rejects an unknown mode before the runtime exists, so the case is unreachable through the Go CLI and only reachable through a hand-built Rust runtime config | `crates/symvault-mcp/src/call.rs` (`write_approval_decision`), `crates/symvault-mcp/src/store_adapter.rs` (`execute_with_secret_unknown_mode_fails_closed_and_zero_timeout_defaults`), `crates/symvault-mcp/tests/write_tty_approval_contract.rs`, `internal/mcp/server/approval_helper.go`, `internal/mcp/server/server_authorize.go` |

### Item 1: the declared HTTP-001 classes

The declaration table in `scripts/rust-port/http_replay_contract.py` holds 71
cases in 10 classes. Each carries an independently asserted Go status and Rust
status; `None` means no response bytes.

| Class label | Cases | Go | Rust |
|---|---|---|---|
| `stable-parser-error-page` | 36 | 400 | 400 (fixed page instead of the net/http page) |
| `rust-rejects-ambiguous-request-form` | 15 | 200 | 400 |
| `go-501-unsupported-transfer-encoding-vs-rust-400` | 9 | 501 | 400 |
| `complete-json-body-required` | 4 | 200 | 400 |
| `valid-utf8-required` | 2 | 200 | 400 |
| `go-505-unsupported-version-vs-rust-400` | 1 | 505 | 400 |
| `go-options-asterisk-vs-rust-400` | 1 | 200 | 400 |
| `go-mux-404-vs-rust-400` | 1 | 404 | 400 |
| `go-400-page-vs-rust-silent-close` | 1 | 400 | none (silent close) |
| `go-answers-first-json-value-vs-rust-awaits-declared-length` | 1 | 200 | none (awaits the declared length) |

The two `Expect: 100-continue` cases (`INTERIM_ONLY`) are not part of the 71:
their final response is byte-identical and only Go's interim `100 Continue`
line is absent in Rust. They stay a declared interim-line difference under
HTTP-001 and are not widened by this ADR.

### Item 7: scope of the CLI-005 YAML ratification

The CLI-005 row records 33 open YAML divergences (24 `wording`, 9 `behavior`).
This ADR ratifies the yaml.v3 two-token look-ahead class, which is 15 of those
33: the 12 `trailing_token_after_*` entries (names as in the fixture) plus
`directive_without_document_start` (13 `wording`) and two `behavior` entries:
`scanner_failure_after_document_end` (Go fails with exit 6 on the second
document's scanner error, Rust accepts the config: the looser side) and
`third_document_scanner_look_ahead` (Go accepts, Rust rejects the stream as
multi-document: the stricter side). The remaining 18 entries
(`second_document_unknown_anchor`, `get_set_second_document_syntax_error`,
`utf16_bom_only`, `bom_after_first_line`, the root-shape and empty-file
wording entries, and the not-yet-ported `paymentPolicies` and `audit.maxSizeMb`
validation entries) stay open and need their own decision.

## Not covered

- The `config set` value re-coercions listed in the CLI-005 row (`1e3`, `0b11`,
  `010`, bare `y`, `2026-10-31`, `<<`), the `\u00e9` escape, the non-mapping
  root error text and the `profiles: x: null` Go panic. They change the value
  written or the exit class, not only layout, and remain open.
- The invalid-UTF-8 request id in MCP-004 (`invalid_utf8_id_echoed_verbatim`)
  is recorded in the same fixture but was not named in the decision.
- No Windows or Intel Mac variant: Windows left the supported scope with
  #1550/#1551.

## Consequences

- The six rows keep their `in_progress` / `TODO` status; their residual text
  gains a note that the listed differences are ratified here.
- The differential checks keep pinning Go's behaviour, so any further drift,
  in either direction, still fails.
- Reversing one of these items needs a new maintainer decision and an ADR that
  supersedes the item.
