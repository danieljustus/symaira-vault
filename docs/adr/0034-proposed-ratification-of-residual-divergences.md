# ADR 0034: Proposed ratification list of residual Rust-vs-Go divergences

Status: **Accepted** 2026-11-03 by the maintainer (Daniel Justus); decisions are in
the last column of the decision table. Affects
contract rows CLI-005, CLI-006, CLI-007, MCP-003, MCP-004, HTTP-001, HTTP-002,
HTTP-004, PLATFORM-001, PLATFORM-002, SESSION-003 and IO-001. No row changes
status, no code changes, and no fixture changes with this ADR.

## Context

[ADR 0030](0030-approved-restore-and-import-divergences.md) and
[ADR 0032](0032-ratified-rust-stricter-divergences.md) ratified the restore,
import, HTTP-framing, stdio-frame and YAML-lookahead divergences that had been
measured at the time. This list collects what is still recorded in
`docs/rust-port/contract-matrix.md`, `docs/rust-port/cli-gap-inventory.md`,
ADRs 0013 to 0018 and the fixtures as an open or declared difference, so the
maintainer can accept or reject each item on its own. Baseline: `ae6f8340`.
Every Go and Rust claim below was read from the cited file; where a claim comes
from the matrix or inventory text only (no test executes it) the item says so.
No cargo, make, Go or Docker command was run for this document.

Recommendation rule, from the maintainer's earlier policy: a Rust-stricter,
safer or cosmetic difference is **ratify**. A difference that loses user data,
widens permissions or breaks a documented workflow is **implement parity**.
Where the rule does not decide, the item says **maintainer decision**.

Ratifying means the same as in ADR 0032: the Rust behaviour stays, the check
that pins Go's behaviour keeps pinning it as the documented difference, and
reversing it needs a new ADR. An item marked *unpinned* has no fixture or test
that fails when the difference drifts; ratifying it should come with the test
named in its "pin" line.

## Items

### A. Config and CLI (CLI-005, CLI-006)

**1. YAML: acceptance differences outside the two-token class (4 entries).**
- Rows: CLI-005. Fixture entries `second_document_unknown_anchor`,
  `get_set_second_document_syntax_error`, `utf16_bom_only`,
  `bom_after_first_line` (kind `behavior`).
- Go: accepts all four. An alias in a second document to an undefined anchor is
  ignored because Go never decodes the second document; `config get`/`set` read
  only the first document (`set` succeeds and rewrites the file); yaml.v3
  decodes UTF-16 (a lone BOM is an empty stream); it skips a UTF-8 BOM that
  starts a later line.
- Rust: rejects each. `validate`/`doctor` treat the stream as multi-document or
  invalid UTF-8; `config get`/`set` parse the whole stream with `yaml_edit`,
  fail on the later syntax error and leave the file unchanged; a later-line BOM
  is a column and breaks the key.
- Why acceptable: every input is a malformed or exotic file; Rust fails closed
  with an error and never rewrites a file it could not read completely. A real
  UTF-16 config is rejected explicitly rather than misread.
- Pin: `testdata/port/cli/config-yaml-syntax.json` `open_divergences` entries
  15 to 18 (0-based list index), replayed by `crates/symvault-cli/tests/config_yaml_syntax.rs:689`
  (`recorded_open_divergences_are_still_open`, which requires a `behavior`
  entry to differ in exit status or file effect and fails if it starts
  matching).
- Recommendation: **ratify**.

**2. YAML: root-shape and empty-file wording (10 entries).**
- Rows: CLI-005 (and the `root that is not a mapping` row,
  `cli-gap-inventory.md:207`). Entries `scalar_root`, `sequence_root`,
  `null_root`, `comment_only`, `document_start_only`, `empty_file`,
  `ascii_spaces_only`, `no_break_space_only`, `byte_order_mark_only`,
  `zero_width_space_root` (kind `wording`).
- Go: node-layer texts such as `parent is a scalar node, not a mapping`,
  `root node is a scalar, not a mapping`, `root node is a unknown(0), not a
  mapping`, `cannot unmarshal !!str ... into config.Config`.
- Rust: same exit status (6) and unchanged file, different text
  (`document has no root to descend into`, `cannot load config: missing YAML
  document`, `invalid type: string`).
- Why acceptable: error wording only; effect on the file and exit class are
  asserted equal by the same check.
- Pin: same fixture, entries 19 to 28 (0-based), same test
  (`config_yaml_syntax.rs:689` asserts that a `wording` entry never differs in
  exit status or file effect).
- Recommendation: **ratify**.

Note on counts: the fixture now holds 29 open entries
(`config_yaml_syntax.rs:124`, `OPEN_DIVERGENCES = 29`). ADR 0032 counted 33; the
`paymentPolicies` and `audit.maxSizeMb` entries were closed by CONFIG-RESID
(`cli-gap-inventory.md:338-348`). 15 are ratified by ADR 0032, 14 are items 1
and 2 here. The matrix text "33 recorded open divergences" is stale.

**3. `config set` value re-coercions that keep the user's text.**
- Rows: CLI-005, CLI-006. Inputs `1e3`, bare `y`, `2026-10-31`, `<<`
  (`cli-gap-inventory.md:204-205`).
- Go: writes `1000`, `"y"`, `2026-10-31T00:00:00Z`, `!!merge <<`.
- Rust: writes `1000.0`, `y`, `2026-10-31`, `"<<"` (inventory text; probed
  against the Go binary 2026-11-01).
- Why acceptable: `1e3` and `1000.0` are the same number (the typed decode
  truncates floats into int fields, CONFIG-SECTIONS-001); `y` versus `"y"` is
  quoting only; Rust keeps the date text the operator typed where Go writes a
  different text; Rust quotes `<<` instead of writing a merge tag from a value
  the operator meant as text.
- Pin: **unpinned**. The probe is in the inventory only; `output-modes.json`
  has 132 `config set` cases, none with these values. Would be pinned by Go
  recorded `config set` cases for the four values in `output-modes.json`
  (`outputmodegen`) replayed by `crates/symvault-cli/tests/output_modes.rs`
  with the Rust bytes declared.
- Recommendation: **ratify**.

**4. `config set` value re-coercions that change the number or type: `010`, `0b11`.**
- Rows: CLI-005, CLI-006 (`cli-gap-inventory.md:204`).
- Go: `010` is written `8`, `0b11` is written `3` (yaml.v3 YAML-1.1 integer
  resolution).
- Rust: writes `10` and the quoted string `"0b11"`.
- Why this is a gap: the stored value differs from what Go (and Rust's own
  loader, which reads `017` as octal per CONFIG-SECTIONS-001) takes the same
  text to mean. For an integer-typed key the quoted string is a typed-decode
  error on the post-write reload (inferred from `config_typed::unmarshal_errors`
  in `config.rs:set`, not probed). No data is lost, but the written value is
  wrong against the oracle rather than merely laid out differently.
- Pin: **unpinned** (as item 3).
- Recommendation: **implement parity** (judgement call: a maintainer who
  considers hand-typed octal/binary literals out of scope can ratify instead).

**5. `config set` re-encode and typed-decode residue not named in ADR 0032.**
- Rows: CLI-005, CLI-006. Per `cli-gap-inventory.md:206,208,209` and the matrix:
  a `\u00e9` escape in a double-quoted scalar (Go writes the character),
  flow-sequence spacing (`[x,x]` becomes `[x, x]` in Go), timestamp scalars in
  flow mappings (Go quotes them, so a later error says `!!str`), the anchor
  line reported for a redefined anchor or an anchor behind a comment, and
  `!!binary` into `time.Time` (Go prints the decoded bytes, Rust lossy UTF-8).
- Rust: keeps the text as written, reports the last definition's line.
- Why acceptable: layout, and error attribution text. The key and value being
  set are not affected.
- Pin: **unpinned**. The matrix says "exact Rust bytes are not pinned by a
  Go-recorded case yet" (ADR 0032 item 8). Would be pinned by Go-recorded cases
  in `output-modes.json` for each shape.
- Uncertain: the inventory rows are terse; whether the anchor attribution
  changes a value Rust loads (rather than only a line number in an error) was
  not probed.
- Recommendation: **ratify**.

**6. YAML nesting depth: Rust 256, Go 10000.**
- Rows: CLI-005 (`cli-gap-inventory.md:202`).
- Go: yaml.v3 accepts up to 10000 levels.
- Rust: refuses beyond 256 (`yaml_edit` 0.3.3 `MAX_FLOW_DEPTH = 256`,
  `parser/mod.rs:38` in the crate; used by `config set`). Per the inventory,
  100k `[` take about 100 s to refuse.
- Why acceptable: a bounded parser stack is stricter, in the same class as the
  8 MiB frame limit of ADR 0032 item 3; no real config nests past a few levels.
  The 100 s refusal time is a separate performance defect, not part of this
  ratification, and should get its own issue.
- Pin: **unpinned**; the corpus has `deep_flow_sequence` (50 levels) only.
  Would be pinned by two Go-recorded cases at 257 and 10000 levels in
  `config-yaml-syntax.json`.
- Uncertain: whether the read path (`serde_yaml_ng`, `config.rs:902`) has its
  own recursion limit different from 256 was not checked.
- Recommendation: **ratify** (limit); open a separate issue for the latency.

**7. `profiles: {x: null}`.**
- Rows: CLI-005. Also recorded as Go bug 7 in `upstream-go-bugs.md`.
- Go: nil pointer panic in `mergeTopLevel` (`config_merge.go:106`), exit 2 with a
  goroutine trace.
- Rust: `ConfigError::Parse("profiles.x: profile must not be null")`, exit 6
  (`crates/symvault-core/src/config.rs:1020`).
- Why safe: a crash is not behaviour to reproduce and the trace carries build
  paths.
- Pin: `crates/symvault-core/tests/config_profiles_contract.rs:98` and `:133`
  (Go-recorded `null_profile` case whose recorded error contains
  `nil pointer dereference`; Rust must return a `Parse`/`Yaml` error).
- Recommendation: **ratify**.

**8. `remote init` without sync config.**
- Rows: CLI-006 residual.
- Go: nil pointer dereference in `enableAutoPush` (`cmd/remote.go:136,267`), goroutine
  trace on stderr.
- Rust: `enable_auto_push` loads the config or the default and saves it; a
  failure prints `Warning: remote added but could not enable auto_push in
  config: ...` and the command succeeds (`remote_commands.rs:60`, `:197`).
- Why safe: a Go crash with host paths in the trace is not a stable contract.
- Pin: **unpinned** for this branch. `output-modes.json` residual `remote init`
  records only the usage refusal; `remote_differential.rs:262-340` covers
  other branches. Would be pinned by a Rust-only test of `remote init` in a
  HOME without sync config asserting exit 0 and the resulting `config.yaml`.
- Uncertain: I read the Rust code but did not establish which branch of Go's
  panic corresponds to which Rust path.
- Recommendation: **ratify**.

**9. `__complete` and `completion <shell>` print the loader warning fewer times.**
- Rows: CLI-005 (`cli-gap-inventory.md:549-551`).
- Go: loads the global config at startup for every `__complete` and `completion`,
  so a deprecation warning is printed twice / once.
- Rust: the completion path loads only what the completer needs: once / not at
  all (`__complete get ''`, `completion bash`).
- Why acceptable: stderr deprecation text during shell completion; no value,
  exit status or stdout differs. Ordinary commands match.
- Pin: **unpinned**. Would be pinned by an `error_taxonomy`-style Go-recorded
  case for `__complete get ''` with an `envWhitelist` config.
- Recommendation: **ratify**.

**10. `agent profile show` fails on a duplicate agent key reached through an alias.**
- Rows: CLI-005 (`cli-gap-inventory.md:374`).
- Go: loads it, exit 0.
- Rust: `show` loads the config correctly and then re-reads the raw YAML for the
  field set (`agent_profile_commands.rs:303`, `source_fields`, `serde_yaml_ng`
  rejects the duplicate); same for `export`/`edit`. Exit 1,
  `agents: duplicate entry with key "x"`. `config validate` and `agent list`
  agree with Go.
- Why acceptable: refuses to display an ambiguous profile; stricter only for
  hand-written alias tricks. Inconsistent with `agent list`, which is why it
  is listed.
- Pin: **unpinned**. Would be pinned by a Go-recorded `agent profile show` case
  with `&a x: {...}` then `*a : {...}`.
- Recommendation: **ratify**.

### B. Signals (CLI-007)

**11. SIGQUIT goroutine dump.**
- Go: the runtime prints a goroutine dump to stderr and exits 2.
- Rust: exits 2 with no dump (`mcp_shutdown.rs` prints Go's one SIGQUIT warning
  for `mcp`; `broker`, `intake watch`, `run` match the exit status).
- Why safe: a runtime artefact that is unbounded and carries host paths; the
  exit status and on-disk state are what is compared.
- Pin: `scripts/rust-port/signal_process_contract.py:251-253` (stderr is
  recorded as `<not compared: Go SIGQUIT goroutine dump>`; exit 2 is asserted
  at `:54-60`, `:72-75`).
- Recommendation: **ratify**.

**12. `run --timeout`: terminal Ctrl-C does not reach the child.**
- Rows: CLI-007 (matrix text, `implementation-plan.md:50`).
- Go: the child shares the caller's process group, so a terminal Ctrl-C reaches
  it.
- Rust: a bounded run puts the child in its own process group so the timeout
  can kill the tree (#1199, `run_commands.rs:363`). Ctrl-C kills the Rust
  parent (default disposition for plain `run`, per the matrix) but not the
  child; no parent remains to enforce `--timeout`, so a child carrying injected
  secrets keeps running unbounded. The same group is used for the MCP
  `execute_with_secret` child (`run_commands.rs` comment, #1242).
- Why this is a gap: Ctrl-C is the documented way to stop `run`; the child
  outlives it with the secret environment.
- Pin: `signal_process_contract.py:303` (`KNOWN_DIVERGENCES =
  {"run-timeout-group-sigint": ...}`; the check fails if Rust starts
  matching, `:384`, `:414`) and `run_commands.rs:1497`
  (`bounded_run_isolates_the_child_so_a_timeout_can_kill_the_tree`, which would
  have to change with the fix); the unbounded counterpart is
  `run_commands.rs:1489`.
- Recommendation: **implement parity** (keep the group, install a handler that
  forwards SIGINT/SIGTERM/SIGHUP to the child's group before exiting).

### C. MCP (MCP-003, MCP-004)

**13. `execute_api_request` does not follow redirects.**
- Rows: MCP-003 ([ADR 0018](0018-api-dns-pinning-and-request-cancellation.md)
  "Keep Rust's previously documented narrower redirect/cleartext boundaries";
  [ADR 0015](0015-egress-broker-runtime-boundaries.md)).
- Go: `internal/ssrf/ssrf.go:123` validates each redirect target and follows it,
  delivering the credential to the new URL.
- Rust: `redirect(Policy::none())` (`broker.rs:337`, `:460`); the 302 is returned
  to the caller without a credential reaching the target.
- Why safe: a credential-bearing request cannot be redirected to another
  authority; ADR 0015 measured Go delivering the bearer to a second port of the
  same host. The cost is that an API that answers with a redirect needs a
  second call by the agent.
- Pin: the egress broker is pinned by `scripts/rust-port/egress_contract.py:602-604`
  (`redirect-authority-binding`: Go 200 with the credential received, Rust 302
  without). The `execute_api_request` path itself is **unpinned**: no test in
  `crates/symvault-mcp` mentions a redirect. Would be pinned by a case in
  `api_transport_tests.rs` with a 302 peer asserting Rust returns the 302 and
  the second peer receives zero requests.
- Recommendation: **ratify**.

**14. Invalid UTF-8 in a request id.**
- Rows: MCP-004; named as not covered in ADR 0032 "Not covered".
- Go: accepts and echoes the bytes on stdout.
- Rust: answers `-32700` and emits no invalid byte (`RawValue` is `str`-backed).
- Why safe: attacker-chosen invalid bytes would otherwise reach the stream the
  client parses as framing.
- Pin: `testdata/port/mcp/stdio-hygiene.json:346`
  (`invalid_utf8_id_echoed_verbatim`), asserted by
  `crates/symvault-mcp/tests/stdio_hygiene_contract.rs:271`
  (`invalid_utf8_is_rejected_fail_closed`, which also requires the divergence
  to stay recorded).
- Recommendation: **ratify**.

**15. Duplicate key inside `params` (and the raw-id case).**
- Rows: MCP-004 (fixture `divergences[0].oracle_behavior` SCOPE note; cases
  `duplicate_key_inside_params` and `duplicate_params_*` in
  `stdio-hygiene.json`).
- Go: a *plain* duplicate member inside `params` is last-wins (`initialize`
  negotiates the second `protocolVersion`); a wrong-typed duplicate fails the
  whole decode wherever it sits (`{"protocolVersion":123,"protocolVersion":"2025-03-26"}`
  is `-32602`, because `encoding/json` records the first `UnmarshalTypeError`
  and still returns it), `null` is a no-op that keeps an earlier value, and
  case variants of one name all land in the same field in document order.
- Rust: identical. Plain duplicates inside `params` are last-wins as in Go,
  **not** `-32602` (an earlier version of this item claimed otherwise; that was
  read from a fixture note and is wrong). The `initialize` decoder walks the
  members in order like `encoding/json`, so wrong-typed earlier duplicates (in
  `protocolVersion`, `clientInfo` and inside `clientInfo`) fail like Go;
  `prompts/get` and `tools/call` params already behaved this way. A duplicate
  inside a raw `id` or an unknown top-level key is last-wins exactly as Go. So
  `params` is parity and not a divergence; only duplicated *envelope* members
  are rejected (ADR 0032, `-32700`).
- Pin: `stdio-hygiene.json` cases `duplicate_key_inside_params`,
  `duplicate_params_wrong_typed_first`, `duplicate_params_wrong_typed_last`,
  `duplicate_params_null_after_string_keeps_string`,
  `duplicate_params_case_variants_*`, `duplicate_params_clientinfo_*`,
  `clientinfo_inner_*` and `prompts_get_duplicate_*` (recorded from the real Go
  transport, `mcpstdiogen --check`), asserted for both sides by
  `stdio_hygiene_contract.rs`
  (`duplicate_key_inside_params_is_last_wins_like_go_not_invalid_params`,
  `duplicate_and_wrong_typed_params_members_follow_encoding_json`) and
  `call::params_duplicate_tests` for `tools/call`.
- Not covered: duplicates nested inside `tools/call` `arguments` are raw bytes
  to the tool layer and belong to the MCP-002/003 fixtures.
- Recommendation: **no ratification needed**; this is parity. The only
  divergence on duplicate keys is the envelope one (ADR 0032 item 4).

**16. SIGINT/SIGTERM on HTTP: Go drains for up to 5 s, Rust aborts at once.**
- Rows: MCP-003, HTTP-001 (shutdown); [ADR 0009](0009-http-shutdown-ownership.md)
  (accepted direction: bounded drain, "Rust callback lifecycle parity remains
  separately pending").
- Go: `drainHTTP` (`internal/mcp/serverbootstrap/http_lifecycle.go:64`) calls
  `Shutdown` with the configured timeout (default 5 s), closes the admission
  gate and waits for dispatched callbacks.
- Rust: exits at once and aborts in-flight requests (`mcp_shutdown.rs:11-13`);
  `HttpShutdown` is "not a graceful-drain API" (`http_shutdown.rs`).
- Why this is a gap: in-flight requests are aborted instead of drained, and ADR
  0009 already decided on a bounded drain.
- Pin: `mcp_shutdown.rs:11-13` records it as a known residual; no test pins
  the abort. Would be pinned by a process test sending SIGTERM during a slow
  in-flight HTTP request and asserting the response completes within 5 s.
- Recommendation: **implement parity** (planned).

### D. HTTP (HTTP-001, HTTP-002, HTTP-004)

**17. `Expect: 100-continue` interim line.**
- Rows: HTTP-001; ADR 0032 states these two cases are "not widened".
- Go: writes `HTTP/1.1 100 Continue` when its handler first reads the body, after
  the Origin, bearer, agent, Content-Type and Accept checks.
- Rust: reads the whole body first and never writes the interim line; the final
  response is byte-identical.
- Why acceptable: only the interim line is absent; a client that waits for it
  falls back to sending the body after its own timeout (client behaviour, not
  measured here). Reproducing the emission point means deferring body reads
  behind authentication.
- Pin: `scripts/rust-port/http_replay_contract.py:71-73` (`INTERIM_ONLY`, cases
  `expect-100` and `expect-100-chunked`) and `:439-445` (asserts Go emits
  exactly one `100` and Rust none, and the final response is identical).
- Recommendation: **ratify**.

**18. Request-line and header size limits.**
- Rows: HTTP-001/HTTP-004.
- Go: `MaxHeaderBytes = 1 << 20` (`serverbootstrap/http.go:400`); a 17 KiB header
  or oversized request line reaches the handler (200).
- Rust: request line 8 KiB, headers 16 KiB (`crates/symvault-mcp/src/http.rs:442`,
  `:447`); a 17 KiB header answers 413 `request too large`.
- Why acceptable: bounded per-connection buffers, same class as ADR 0032 items
  1 and 3; real clients send far less.
- Pin: `http.rs:5394` (`source_bound_request_line_limit_is_stricter_than_go_server_limit`,
  asserts Go `oversized_request_line_reaches_handler` is 200) and `http.rs:5619`
  (`raw_loopback_caps_headers_at_the_documented_rust_limit`, asserts Go
  `oversized_header_reaches_mcp_handler` is 200 and Rust 413), both from
  `testdata/port/mcp/http-initialize.json`.
- Recommendation: **ratify**.

**19. Repeated `allowed_tools` containing `null` rejects the registry document.**
- Rows: HTTP-002 (`cli-gap-inventory.md` "Token registry decoder"; module
  comment `go_registry.rs:1-12`).
- Go: `json.Unmarshal` overlays the second array onto the first slice and
  adopts the document.
- Rust: `decode_go_registry` returns an error
  (`crates/symvault-store/src/go_registry.rs:437`); on a live reload the last
  good registry stays in force.
- Why this is a gap, not only stricter: the matrix and the module comment say
  it themselves: a Rust-stricter rejection on reload "is never merely
  harmless". A new document that Go adopts but Rust refuses can carry a
  revocation or an expiry that Rust then does not apply, so a revoked token
  stays valid. Real registry files are written by the CLI and never contain
  duplicate keys, so it needs a hand edit.
- Pin: `crates/symvault-mcp/src/http.rs:3537`
  (`duplicate_member_with_a_type_error_fails_the_document_like_go`, assertions
  at `:3617-3624`: `["a"],[null]` returns `None`). No Go-recorded case holds
  the Go outcome; `http_token_contract.py:276` covers only the type-error
  duplicate.
- Recommendation: **implement parity** (model the slice overlay; small).

**20. ALPN: Go offers `h2` on plain TLS, Rust negotiates HTTP/1.1 only.**
- Rows: HTTP-004 ("ALPN ... open", [ADR 0025](0025-live-tls-and-client-identity-proof.md)
  and [ADR 0027](0027-absolute-http-write-deadlines.md): "ALPN ... stay open").
- Go: TLS without mTLS serves through `ServeTLS` (`serverbootstrap/http.go:475`),
  which enables HTTP/2 and advertises `h2`; with mTLS it uses
  `tls.NewListener` with no `NextProtos` (`:465`), HTTP/1.1 only.
- Rust: the rustls `ServerConfig` sets no ALPN protocols (`http.rs:377-400`;
  `alpn_protocols` appears only for the outbound broker client,
  `broker_egress.rs:263`), so every connection is HTTP/1.1.
- Why acceptable: a smaller protocol surface; a client offering `h2` and
  `http/1.1` falls back, and MCP over HTTP is plain JSON-RPC requests. A client
  that only accepts `h2` would fail.
- Pin: **unpinned** (ADR 0025 says the live TLS probe "does not cover
  ALPN/HTTP2"). Would be pinned by adding an ALPN-offer step
  (`h2, http/1.1`) to the ADR 0025 live corpus recording Go's negotiated
  protocol per mode and asserting Rust's.
- Recommendation: **ratify**.

### E. Platform, session and import (PLATFORM-001, SESSION-003, IO-001)

**21. Colour on `cliout` lines.**
- Rows: PLATFORM-001 residual (3).
- Go: colours the two `cliout` lines of `get` clipboard mode (hint, warning)
  with lipgloss on a colour stderr.
- Rust: plain text.
- Why acceptable: cosmetic.
- Pin: **unpinned**; `get_clipboard.json` is recorded without colour. Would be
  pinned by a forced-colour Go scenario in `get_clipboard.json` with the Rust
  plain text declared.
- Recommendation: **ratify**.

**22. Non-string field values copied by `get`.**
- Rows: PLATFORM-001 residual (4), (10).
- Go: `fmt.Sprintf("%v", value)` (`cmd/crud/get.go:167`); a JSON null is `<nil>`,
  objects print as `map[...]`.
- Rust: JSON text; null copies as empty text.
- Why acceptable: JSON text is stable and null does not put the literal
  `<nil>` on the clipboard. Differs only for fields that are not strings.
- Pin: Rust side only, `crates/symvault-cli/src/main.rs:6549`
  (`non_string_values_are_copied_as_json_text`, `5432`). No Go-recorded case.
  Would be pinned by a `get_clipboard.json` scenario with a number, a bool and
  a null field.
- Recommendation: **ratify**.

**23. Error text of a failing native copy on macOS.**
- Rows: PLATFORM-001 residual (11).
- Go: atotto's text after `copy to clipboard: `.
- Rust: `pbcopy`'s own message on macOS (Linux text is matched and verified).
- Why acceptable: wording of a failure path; exit status and doubled stderr line
  match.
- Pin: **unpinned**. Would be pinned by a fake `pbcopy` stand-in exiting 1 in
  a Go-recorded macOS scenario.
- Recommendation: **ratify**.

**24. Signal-death text of a clipboard/autotype tool.**
- Rows: PLATFORM-001 residual ("subprocess signal-death text").
- Go: `os/exec`'s per-signal text (`signal: killed`, ...).
- Rust: `signal: terminated` for every signal.
- Why acceptable: wording of a tool failure.
- Pin: **unpinned**. Would be pinned by a fake tool that kills itself with
  SIGKILL in `desktop_linux.json`.
- Recommendation: **ratify**.

**25. Scheduler-coincident auto-clear tick.**
- Rows: PLATFORM-001 residual (2).
- Go: when the last countdown tick and the timer coincide the output depends on
  the scheduler.
- Rust: prints `0s` first, deterministically.
- Why acceptable: Go's own output is non-deterministic here.
- Pin: `crates/symvault-platform/tests/get_clipboard_contract.rs:336`
  (`real_clock_counts_down_and_clears`) and
  `crates/symvault-cli/tests/clipboard_linux_entrypoints.rs:23,782` (strips the
  extra `\r[clearing clipboard in 0s] ` tick before comparing with Go).
- Recommendation: **ratify**.

**26. Touch ID items written by earlier Rust builds are refused.**
- Rows: SESSION-003 (matrix: "Approved Rust-only migration behavior", but no
  ADR records the approval).
- Go: has no such format; it would use the stored bytes as the passphrase.
- Rust: an item whose value starts with `go-keyring-base64:` or
  `go-keyring-encoded:` is refused after the biometric prompt with
  `LEGACY_TOUCH_ID_ITEM_ERROR` (`session_commands.rs:25,181`); the item is not
  decoded or rewritten, the passphrase prompt follows, and `auth set touchid`
  replaces it. A real passphrase beginning with those prefixes is
  indistinguishable and also refused.
- Why safe: explicit error, nothing echoed, no secret silently re-stored,
  passphrase unlock remains.
- Pin: `crates/symvault-cli/src/session_commands.rs:381`
  (`touch_id_legacy_rust_wrapped_item_is_reported_not_returned_or_rewritten`)
  and `crates/symvault-core/src/keychain_status.rs:372`
  (`legacy_wrapper_prefixes_are_recognised_exactly`). Not covered: the
  prefix-start passphrase residual has no test.
- Recommendation: **ratify**.

**27. IO-001: non-UTF-8 zip member name and `GODEBUG=zipinsecurepath`.**
- Rows: IO-001 residuals. Precedent: ADR 0030 item 3 for restore.
- Go: prints the raw bytes of a non-UTF-8 member name in `open`/`read <name>:`;
  honours `GODEBUG=zipinsecurepath`.
- Rust: prints U+FFFD; the setting is not modelled.
- Why acceptable: error text only; the importers read the same members. The
  GODEBUG toggle only weakens a path check Rust does not weaken.
- Pin: **unpinned** (matrix: "the corpus has no such selected name"). Would be
  pinned by a `zip-errors.json` case with a non-UTF-8 member name selected by
  the importer.
- Recommendation: **ratify**.

**28. No GUI secure-input or approval backend (PLATFORM-002).**
- Go: `secureui` detects `osascript` on macOS and `zenity`/`kdialog` on Linux
  (`internal/secureui/backend_darwin.go`, `backend_unix.go`) and uses a dialog
  when there is no TTY.
- Rust: `SecureUi` and `Notifier` are implemented for `MacOsPlatform`
  (`crates/symvault-platform/src/macos.rs:320,331`) but no CLI or MCP code uses
  them; `secure_input_capable` is true only for stdio with a TTY
  (`mcp_commands.rs:966`), and approval without a terminal fails closed with
  `<op> requires approval but no TTY or GUI dialog available`
  (`crates/symvault-mcp/src/call.rs:471`, `store_adapter.rs:884`). The Linux
  tools are not probed outside metadata (`mcp_commands.rs:96`).
- Option A, ratify (fail closed): headless HTTP and non-TTY stdio sessions
  cannot reach `secure_input`, `request_credential` or an `approvalMode:
  prompt` write; the safe direction, but a documented desktop workflow (HTTP
  server started by launchd, approved by dialog) does not work.
- Option B, implement parity: wire the existing macOS adapters and add
  `zenity`/`kdialog` adapters behind the same trait; needs desktop smoke tests
  the project does not have (PLATFORM-002: "GUI permission smoke pending").
- Pin: `mcp_commands.rs:966` doc comment only; **unpinned** as a behaviour.
  Would be pinned by an HTTP-transport process test asserting the `no TTY or
  GUI dialog available` denial.
- Recommendation: **maintainer decision**.

**29. No anomaly detection or desktop notifications in Rust MCP (PLATFORM-002).**
- Go: `anomaly.AnomalyDetector` (rate, off-hours, canary access) runs after each
  tool call (`internal/mcp/server/server_dispatch.go:250-300`): logs a warning,
  writes an `anomaly_<type>` audit row, shows a desktop notification for high
  severity and invalidates the approval cache so the next call is re-approved.
- Rust: no detector exists. `grep` for anomaly/off-hours/rate-anomaly finds no
  match under `crates/`; the `canary` flag is stored on entries
  (`symvault-store/src/lib.rs:210`) but `crates/symvault-mcp` has no consumer
  that raises an alert for it; the approval cache
  (`store_adapter.rs:495`) is never invalidated by an anomaly; `Notifier` is
  unused (item 28). ADR 0013 defers it to #1248/#1241/#1245.
- Option A, ratify (absent): no async work on the call path and no
  clock-dependent output; loses canary/honeytoken alerts, off-hours logging
  and forced re-approval, which are Go security features rather than cosmetics.
- Option B, implement parity: port `internal/anomaly` (deterministic with an
  injected clock) and the audit rows and approval-cache invalidation first;
  notifications follow item 28.
- Pin: **unpinned**. The ordered Go reference `mcp-anomaly-ordered-v1`
  (ADR 0016, `24acdb08`) exists to record Go's behaviour; a Rust process test
  against it would pin the audit rows and the cache invalidation.
- Recommendation: **maintainer decision**. Weighing "loses a security
  feature": the audit-row and approval-cache invalidation part leans to
  parity; the desktop notification part leans to item 28.

## Already decided elsewhere (listed by reference, not repeated)

- ADR 0030 items 1 to 4: atomic restore, `MAX_ARCHIVE_ENTRIES` and the 100 MiB
  import cap, restore error class (flate offset, U+FFFD in names), non-UTF-8
  import entry paths.
- ADR 0032 items 1 to 9: the 71 HTTP-001 declared cases in 10 classes, HTTP-002
  registry-edit timing, MCP-004 8 MiB frame limit and duplicate envelope keys,
  IO-001 non-UTF-8 argv and the `SetLen` quirk, the 15 CLI-005 two-token YAML
  entries (12 `trailing_token_after_*`, `directive_without_document_start`,
  `scanner_failure_after_document_end`, `third_document_scanner_look_ahead`),
  the seven `config set` re-encode shapes (CRLF, explicit keys, verbatim and
  non-specific tags, `!!int &a 12`, comment after anchor, folded trailing blank
  line, tagged block sequence indent) and MCP-PP unknown approval mode.
- `upstream-go-bugs.md` entries 1 to 11: `SaveTo` dropping `paymentPolicies`,
  `security`, `envAllowlist`, `vault.*`, `mcp.oauth`, `mcp.perplexity` and
  others; `omitempty` on meaningful zeros; `mergeAgentProfiles` ignoring hooks;
  `profiles: {p: null}` panic (bug 7; the ratification of the exit class is
  item 7 here); yaml.v3 literal blocks with leading break/space/tab; tier
  widening on rewrite (bug 11). They are Go defects with recorded Rust-safer
  or copied behaviour, not Rust-vs-Go ratification items.
- Dropped as already fixed: the `paymentPolicies` and `audit.maxSizeMb`
  validation entries of ADR 0032's "18 remaining" YAML entries (CONFIG-RESID,
  `cli-gap-inventory.md:338-348`).

## Decision table

Recommendation key: R = ratify, P = implement parity, M = maintainer decision.

| Item | Rows | Recommendation | Maintainer decision |
|---|---|---|---|
| 1 YAML behaviour entries (4) | CLI-005 | R | R: ratified |
| 2 YAML root-shape/empty wording (10) | CLI-005 | R | R: ratified |
| 3 `config set` `1e3`, `y`, `2026-10-31`, `<<` | CLI-005/006 | R | R: ratified |
| 4 `config set` `010`, `0b11` | CLI-005/006 | P | P: implement parity |
| 5 `config set` re-encode and typed-decode residue | CLI-005/006 | R | R: ratified |
| 6 YAML nesting depth 256 vs 10000 | CLI-005 | R | R: ratified |
| 7 `profiles: {x: null}` | CLI-005 | R | R: ratified |
| 8 `remote init` Go nil panic | CLI-006 | R | R: ratified |
| 9 completion loader warnings | CLI-005 | R | R: ratified |
| 10 `agent profile show` duplicate key via alias | CLI-005 | R | R: ratified |
| 11 SIGQUIT goroutine dump | CLI-007 | R | R: ratified |
| 12 `run --timeout` Ctrl-C to child | CLI-007 | P | P: implemented (a6c09463) |
| 13 `execute_api_request` redirects | MCP-003 | R | R: ratified |
| 14 invalid UTF-8 request id | MCP-004 | R | R: ratified |
| 15 duplicate key inside `params` | MCP-004 | R | R: ratified (corrected: plain duplicates are last-wins in Go and Rust; wrong-typed earlier duplicates fail like Go; parity, not a divergence) |
| 16 HTTP SIGINT/SIGTERM drain | MCP-003, HTTP-001 | P | P: implemented (b0ea8ea0) |
| 17 `Expect: 100-continue` interim line | HTTP-001 | R | R: ratified |
| 18 request-line / header size limits | HTTP-001, HTTP-004 | R | R: ratified |
| 19 repeated `allowed_tools` with `null` | HTTP-002 | P | P: implement parity |
| 20 ALPN HTTP/1.1 only | HTTP-004 | R | R: ratified |
| 21 colour on `cliout` lines | PLATFORM-001 | R | R: ratified |
| 22 non-string field copy (`%v`) | PLATFORM-001 | R | R: ratified |
| 23 macOS copy error text | PLATFORM-001 | R | R: ratified |
| 24 signal-death text | PLATFORM-001 | R | R: ratified |
| 25 scheduler-coincident tick | PLATFORM-001 | R | R: ratified |
| 26 Touch ID legacy prefix refusal | SESSION-003 | R | R: ratified |
| 27 non-UTF-8 zip member name, `zipinsecurepath` | IO-001 | R | R: ratified |
| 28 no GUI secure input/approval backend | PLATFORM-002 | M | Ratify, fail closed (no GUI backend; documented in PLATFORM-002) |
| 29 no anomaly detection/notifications | PLATFORM-002 | M | Partial parity: port detector, `anomaly_<type>` audit rows and approval-cache invalidation; desktop notification ratified as absent (item 28) |

## Consequences

- Nothing changes until the table is filled. Items accepted as R get their
  residual text in the matrix updated, as ADR 0032 did, and the unpinned ones
  get the test named in their pin line before the row is promoted.
- Items accepted as P become implementation issues (items 4, 12, 16, 19); the
  existing pins for 12 and 16 keep failing "if Rust starts matching", so the
  fix must update them in the same change.
- An M item accepted as "ratify, fail closed" must say so in the
  PLATFORM-002 row, because it is a feature absence, not a layout difference.
