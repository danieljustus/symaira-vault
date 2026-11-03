# ADR 0035: Residual Rust-vs-Go divergences before the Go removal

Status: **Accepted (provisional)** 2026-11-03. The maintainer was asked once
(clarify, 2026-11-03 22:44) and did not answer before the timeout; the
recommended option was applied as the default and stays revisable by a later
ADR. Affects contract rows CLI-003, CLI-005, CLI-006, CLI-007, SESSION-001,
IO-002, HTTP-001 and APPROVAL-001.

## Context

[ADR 0032](0032-ratified-rust-stricter-divergences.md) and
[ADR 0034](0034-proposed-ratification-of-residual-divergences.md) ratified the
divergences measured up to `ae6f8340`. The reconciliation audit at `17a636c6`
and the pin work after it found ten further items that no ADR covered. The Go
backend is removed at the Rust-only cutover (work item RUST-015), so every item
must be decided before the live Go oracle disappears.

Rule (unchanged from ADR 0034): a Rust-stricter, safer, spec-conforming or
cosmetic difference is ratified; a difference that loses data, widens
permissions or breaks a documented workflow gets Go parity.

## Decisions

| # | Row | Difference (Rust vs Go) | Decision | Pin |
|---|---|---|---|---|
| 1 | CLI-003 | `file add --max-size`: a source that grows past the limit between stat and read is refused (bounded read); Go stores it | ratify (stricter) | `cli-gap-inventory.md` max-size note; typed-flag corpus |
| 2 | CLI-006 | the output-modes corpus is recorded on Darwin only; Linux prints a visible `SKIP` | ratify; the corpus is frozen at the Go removal | `check_output_modes_cli.sh` `recorded_goos` |
| 3 | CLI-007 | signals during sync/git push, during in-flight intake processing, during the `$EDITOR` hand-off and SIGKILL leftovers have no Go-vs-Rust observation | ratify as unobservable; no Go recording exists or can exist after removal | matrix CLI-007 residual text |
| 4 | IO-002 | `GODEBUG=tarinsecurepath=0` is not modelled: Rust always rejects insecure archive paths | ratify (stricter); mirrors ADR 0034 item 27 for zip | restore-errors corpus |
| 5 | SESSION-001 | session/cache JSON field names are matched case-sensitively; Go's `encoding/json` matches case-insensitively | ratify; Go and Rust both write the canonical case | session cache fixtures |
| 6 | HTTP-001 | the request body is read before the rate limiter (Go answers 429 first); link-local IPv6 peers keyed by numeric scope id; zoned `trusted_proxy_ips` never match; `serve_loopback*` library entry points unlimited | ratify; body reads stay bounded, CLI paths apply `mcp.rate_limit` | `mcp-http-ratelimit-differential` |
| 7 | APPROVAL-001 | enroll: repeated `X-Enroll` headers, bodies over 1 MiB, non-UTF-8 bodies and lone surrogate escapes are refused | ratify (stricter) | device-enroll corpus |
| 8 | CLI-005 | a redefined YAML anchor resolves to the last definition (YAML 1.2 spec); Go takes the first | ratify (spec) | `config-yaml-syntax.json` `anchor-redefined` |
| 9 | CLI-005 | Rust prints fewer duplicate `envWhitelist` loader warnings than Go | ratify (cosmetic); Go counts kept as recorded bounds | `config_yaml_syntax.rs` warning-count pin |
| 10 | CLI-005 | `config validate` accepted 10001 nesting levels where Go rejects | **Go parity** (implemented on `local/nest`) | Go-recorded depth cases in `config-yaml-syntax.json` |

ADR 0034 items 21 to 23 are now pinned (`local/plat-pins`); their text in ADR
0034 describes the state before the pins and is superseded by those tests.

## Consequences

- Rows may reference this ADR for the listed residuals; they no longer block a
  `PASS (local)` label.
- After the Go removal the pins above compare Rust against frozen Go
  recordings; re-recording needs the archived oracle (`legacy/go-oracle`).
- Reversing an item needs a new ADR.
