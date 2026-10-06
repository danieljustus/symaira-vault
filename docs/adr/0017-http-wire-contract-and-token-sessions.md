# ADR 0017: HTTP wire responses and token session isolation

## Status

Accepted maintainer-delegated direction, 2026-10-04. The user requested
autonomous long-term decisions and their rationale in docs. #1249 and
HTTP-001..004 remain in progress; this slice does not establish full acceptance.

## Decisions and rationale

At dispatch, route unknown paths to Go's unauthenticated 404 before selecting
an agent or token session. Match known-route method failures, complete Allow headers,
missing-agent diagnostics and OAuth validation descriptions. Preserve Origin
error field order on the wire. Equivalent JSON objects do not establish the
body-byte parity required by the HTTP contract.

For protected-resource discovery, authorization-server discovery and authorize,
route HEAD through the existing GET validation and suppress the entity on the
wire while retaining its representation length. The native corpus checks both
discovery responses, missing authorization parameters and hostile-Origin denial.
This bounded correction does not establish full HEAD consent/redirect/framing
acceptance for the remaining routes.

Require stdin confirmation before creating an HTTP listener whenever
MCP.allow_insecure_bind is enabled, including mixed configurations with explicit
TLS flags, as actual Go does. EOF, refusal, blank/other input and an unterminated
affirmative fail closed. Bound confirmation at 256 bytes. Stdio never reads
this confirmation, preserving protocol input ownership.

Validate each in-budget JSON body before MCP dispatch. Invalid JSON returns HTTP
400 with Go's HTTP parse-error envelope rather than a 200 with stdio parser
details. Retain the one-MiB request bound: use the existing streaming JSON
parser through a bounded reader, rejecting definitive syntax errors before
waiting for unsent oversized input. A still-valid/incomplete bounded prefix
requires one lookahead byte before the measured 413 response. The lookahead
prevents losing the one-byte-over
response to an unread TCP byte. This is not an RSS or arbitrary oversized-peer
drain guarantee. Match Go's five-second initial wait; retain the ten-second
body wait and separate keep-alive idle bound. Complete deadlines across a
continuously progressing slow peer remain separate acceptance work.

The public in-memory HTTP adapter enforces the same parsing budget after its
existing route/method/content checks. For a known oversized string, classify only
the first one-MiB byte slice: return 400 for a definitive invalid prefix and 413
otherwise, without deserializing the remainder or copying an oversized RawValue.
Slice bytes rather than UTF-8 text so a split character stays a bounded EOF.
Syntax beyond that budget is not examined; this is resource-bound enforcement,
not a new complete-HTTP parity claim.

For `/mcp`, carry a classified oversized body failure with its request metadata
through the existing route, admission/rate, Origin, bearer, agent, method,
Content-Type and Accept checks. Only then write the parse/size error, before
constructing an agent handler or token session. Share the method/content checks
with the in-memory HTTP adapter, rather than maintaining a second policy.
Close the connection on these errors because the body can remain unread;
never parse the remainder as another keep-alive request. Restrict streaming body
classification to `/mcp`, including query variants. Other routes retain the
accepted-main behavior: reject a declared oversized body immediately with the
HTTP 400 invalid-JSON envelope, without waiting for body bytes. This baseline
is accepted main `746c7c66f84cf322b85e3ebeba5b9ea1036ab3b7`, not the immediately
preceding PR candidate, which already contained the broader parser change.

The crate-local [preservation fixture](../../crates/symvault-mcp/testdata/nonmcp-oversized-main.json)
derives unchanged complete wire responses from an actual clean Darwin/arm64
accepted-main CLI capture for `/oauth/register` and an unknown path. Its source,
binary, original-capture and response digests remain explicit. The native TCP
regression consumes those bytes, checks the fixed response digest and both
routes, and sends headers plus captured prefix from one contiguous buffer, as
the process capture did. Formatting directly into the socket performs multiple
writes and can deliver the prefix after the immediate header-time rejection,
racing unread late input with close. The regression requires complete response
plus EOF within three seconds while the
remaining declared body is unsent. This is a preserved Rust-baseline boundary,
not Go parity: actual Go returns 400 on the tested OAuth route and 404 on the
unknown route. The ordinary 65-case Go/Rust corpus and its four declared
differences are unchanged; full hostile-route acceptance remains open. With a
fully delivered oversized body, unread input can still cause transport reset;
neither the fixture nor this repair establishes a drain guarantee or acceptance
of arbitrary request fragmentation. Resets are still failing observations.

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

Write native receipts under ignored `target/`, then measure and persist the
candidate's final Git status after receipt creation. Unignored output must
invalidate a previously passing receipt and fail the driver. The workflow
also checks Git status independently; the isolated Git unit control exercises
both ignored and unignored output without claiming native HTTP observations.

## Remaining acceptance

Full OAuth consent/PKCE/DCR/token/refresh flows, replay/rotation, HEAD and other
framing cases, the complete hostile-origin/host/slow-peer matrix, TLS/mTLS and
native gates remain required. OAuth entropy/time need controlled-provider or
explicit semantic evidence; they cannot be silently normalized under the
Date-only rule. HTTP-001..004 and #1249 stay open until full acceptance.

The first Windows run at ddf346e passes all 227 owning runtime tests and the
assembled API control, then times out in the actual Go HTTP process after 43
requests. Its retained stderr contains the per-request missing-Origin warnings;
the recorder left stderr unread until disposal. Windows' smaller pipe capacity
can block the logger before the OAuth missing-parameter handler responds.
Drain both process pipes concurrently throughout the corpus, cap each retained
stream at 1 MiB, join both readers after owned process disposal and fail if
capture is incomplete. Keep every actual warning byte and the existing canary
checks. Do not remove requests or suppress the measured Go logger to pass CI.

Also retain partial HTTP bytes in a finally block when recv times out, rather
than retaining only exchanges that return normally. Neither change reconstructs
responses, changes runtime behavior, promotes forced disposal to shutdown proof
or relaxes status/header/body comparisons. Fresh Windows and other native
current-head evidence remains required.

## Default read/write deadline boundary

The retained Windows Go observation from run 37214402152, job 111471877187,
disproves the recorder's assumption that an incomplete body always closes
without a response. At 9.990889700000025 seconds the immutable Go CLI returned
the complete HTTP 400 invalid-JSON envelope and then EOF. Its original receipt
is failed, not complete acceptance, and retains SHA-256
`a5039d6e57180434587259ee5ae1c7d7c9ee0a093ded60b6938622016569a555`.
The committed fixture extracts only that unchanged observation and safe
source/binary identities; it does not synthesize the missing Rust observations
or promote the historical failed report.

Go's default read and write deadlines are both ten seconds. The read deadline
starts before acquiring the headers, while net/http sets the write deadline
after the headers. Consequently the parse-error write and write expiry can
overlap. A preregistered, three-exchange native Darwin diagnostic of the same
Go1.26.6 oracle observed default silence, a complete 400 when the diagnostic
write deadline was fifteen seconds, and silence with a five-second diagnostic
write deadline. Those overrides diagnose the boundary; they are not replacement
acceptance or changes to production/default tests. They do not establish the
physical scheduler cause of the original Windows timing.

The incomplete-body control therefore retains either actual Go EOF with no
bytes or its exact complete invalid-JSON 400 response. In the latter case it
validates the status, entity/wire body, complete non-Date header multiset,
framing and single HTTP Date. It never discards or reconstructs those bytes.
Rust remains required to close silently; both implementations' idle-before-
request controls also remain silent. This narrow measured reference boundary
does not permit any other status, body, header, credential or success response.

Keep the original four-to-eight-second initial wait and nine-to-fifteen-second
body bound unchanged. Require actual peer EOF, explicit boolean passing
assertions, the exact two-case inventory and identical request hashes. A reset,
local socket timeout, partial 400, unexpected output or a subsequent unusable
listener still fails. Preserve partial bytes and elapsed time on failure.
The actual post-timeout ping, all 51 ordinary transcripts, five startup denials
and four explicitly declared semantic differences are preserved. Four HEAD
controls and two early-invalid oversized prefixes extend the initial total to
57. Eight additional combined-invalid MCP controls bring the total to 65 on
every native target: missing/invalid bearer, foreign Origin with/without bearer,
missing/mismatched agent, wrong Content-Type and denied Accept. Every invalid
prefix declares a body above one MiB, sends only the prefix and holds the
connection open; its complete Go-matching 400, 401, 403, 415 or 406 must arrive
within three seconds without the remaining input. Mutation
tests reject changed real response bytes, missing/
false/type-substituted success, wrong cases/hashes and out-of-bound times.
