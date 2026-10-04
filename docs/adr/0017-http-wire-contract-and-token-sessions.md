# ADR 0017: HTTP wire responses and token session isolation

## Status

Accepted maintainer-delegated direction, 2026-10-04. The user requested
autonomous long-term decisions and their rationale in docs. #1249 and
HTTP-001..004 remain in progress; this slice does not establish full acceptance.

## Decisions and rationale

Route unknown paths to Go's unauthenticated 404 before selecting an agent or
token session. Match known-route method failures, complete Allow headers,
missing-agent diagnostics and OAuth validation descriptions. Preserve Origin
error field order on the wire. Equivalent JSON objects do not establish the
body-byte parity required by the HTTP contract.

Require stdin confirmation before creating an HTTP listener whenever
MCP.allow_insecure_bind is enabled, including mixed configurations with explicit
TLS flags, as actual Go does. EOF, refusal, blank/other input and an unterminated
affirmative fail closed. Bound confirmation at 256 bytes. Stdio never reads
this confirmation, preserving protocol input ownership.

Validate the entire JSON body before MCP dispatch. Invalid JSON returns HTTP
400 with Go's HTTP parse-error envelope rather than a 200 with stdio parser
details. Retain the one-MiB request bound: read a bounded prefix and one
lookahead byte, distinguish already-invalid JSON from exceeded input, and
emit the measured 413 response. The lookahead prevents losing the one-byte-over
response to an unread TCP byte. This is not an RSS or arbitrary oversized-peer
drain guarantee. Match Go's five-second initial wait; retain the ten-second
body wait and separate keep-alive idle bound. Complete deadlines across a
continuously progressing slow peer remain separate acceptance work.

Combine repeated Accept fields, a standard comma-separated HTTP list. Keep
duplicate authentication, Host and Content-Length rejection. Use chunked
HTTP/1.1 framing above 2048 response bytes, matching actual Go; small responses
and HTTP/1.0 retain length framing. Compare complete wire and entity bodies.

Project native get_entry_metadata creation/update times to RFC3339 whole
seconds, as measured from the encrypted Go fixture. Reuse the fetch projection.
Value responses retain their precision. Do not mask timestamps in the driver.

## Explicit narrower boundaries

| Boundary | Actual Go response | Rust decision and rationale |
| --- | --- | --- |
| New token for an initialized agent | A health call succeeds using another token's initialized agent handler. | Require independent initialization per token/agent session. Share runtime authorization/quota state, not another token's protocol state. |
| Two JSON objects in one HTTP body | Decode the first object and return a successful ping. | Require one complete JSON body and return 400 before dispatch. Trailing input must not carry an ignored operation. |
| Invalid UTF-8 in an ignored JSON field | Decode with replacement and return a successful ping. | Reject with 400, preserving the existing explicit text boundary. |

Individually assert both full responses and header multisets for these three
differences; no general error exception is allowed.

## Actual process evidence

The driver rebuilds immutable Go d1cd0f97ac550bc3020bc86b0514989f8d28d95c.
Its helper calls real Go config/vault/token APIs: an encrypted disposable vault
with Argon2id 19456 KiB/2/1, two agents and valid, scoped, expired and revoked
tokens. Both actual CLIs start from byte-identical copies of every seeded file
and bind the same loopback port sequentially. Use public fixture credentials,
isolated HOME/XDG roots and a memory keyring; no operator credentials are used.

Compare status lines, full header multisets and wire/entity bodies, removing
only Date. Retain actual responses and partial exchanges, including failures.
Startup rejection compares all stdout/stderr bytes and exits while checking
that no listener opens. Real idle/incomplete-body EOF controls must satisfy
bounded timing and a subsequent successful ping. No response is reconstructed
for an EOF. Fixture-server forced disposal is not graceful shutdown evidence;
the owned shutdown gate remains ADR 0009.

A permitted metadata call proves encrypted-entry access under its scoped token.
Both servers generate fresh paired 16-hex usage_hint markers. Verify their
label, pairing, independent IDs and every other body byte, plus full headers.
Preserve both raw bodies. This is a separate semantic control, not Date-only
byte parity. Never make production entropy predictable to manufacture parity.

The initial 28-case harness omitted a valid Accept header from positive MCP
requests; those error-only observations do not prove handler coverage. The
corrected corpus requires actual initialization, ping, health and metadata
success, unauthorized scoped-call denial, exact/over-limit controls and
post-timeout recovery. Secret/token canaries may not occur in process output.

Hash candidate sources, fixtures, embedded assets, executables, driver and
helper, all production Go sources and its 17 embedded MCP assets. Require the
same clean commit and source inventory throughout a native run. Execute the
same corpus on Linux, macOS and Windows; skipped/zero cases cannot promote rows.

## Remaining acceptance

Full OAuth consent/PKCE/DCR/token/refresh flows, replay/rotation, HEAD and other
framing cases, the complete hostile-origin/host/slow-peer matrix, TLS/mTLS and
native gates remain required. OAuth entropy/time need controlled-provider or
explicit semantic evidence; they cannot be silently normalized under the
Date-only rule. HTTP-001..004 and #1249 stay open until full acceptance.
