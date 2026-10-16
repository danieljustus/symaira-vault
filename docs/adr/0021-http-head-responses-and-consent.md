# ADR 0021: HTTP HEAD framing and read-only OAuth inspection

Status: accepted design; native acceptance pending, 2026-10-04.

## Decision and rationale

Recognize HEAD for the protected-resource and authorization-server discovery
routes and the OAuth authorization GET route. Preserve authentication, Origin,
route validation and method errors on every other route. Write the same status
and applicable response headers while suppressing entity bytes for every
recognized HEAD request, including parser, authentication and application errors.
The transport owns this rule so individual handlers cannot accidentally send
a body and corrupt the next response on a persistent connection. Reset the
per-request flag before reading each request; a subsequent GET must retain its
full representation.

Validate a HEAD authorization request's registered client, redirect URI, S256
challenge and scopes, then return without requesting human consent, checking
a passphrase, allocating a browser flow ticket or issuing an authorization
code. HEAD is an inspection request. Allowing probes to start authorization
would exhaust the bounded ticket store and introduce consent side effects.
An owning regression exercises the HTTP method dispatcher, makes both consent
and passphrase callbacks panic if invoked, and checks that ticket/code maps
remain empty. Preserve the original HEAD flag before GET route normalization.

For these body-free authorization HTML responses, omit Content-Length and
Transfer-Encoding, as the actual Go server does. No representation was
generated, so a fabricated zero length would describe the eventual GET page
incorrectly. Preserve Rust's explicit no-store consent-page policy from
ADR 0019. For measured discovery and error responses, retain their GET entity
length while transmitting no entity bytes. Do not normalize missing or extra
headers in the contract driver.

## Evidence and boundaries

`http_head_contract.py` builds the immutable production Go CLI at
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c` and drives both real CLI entry points
over native loopback TCP from byte-identical encrypted fixtures. It reuses the
actual Go OAuth fixture with an explicit rate limit of 1000, isolating HEAD
semantics from rate exhaustion. The 13 paired cases include discovery/query,
unknown route, foreign Origin, authenticated/unauthenticated/invalid bearer,
missing agent, registration/token method errors and invalid authorization.
Compare full status lines, header multisets and body bytes with only Date
excluded; every HEAD entity must be empty. Retain requests, raw responses,
source/executable inventories and complete bounded process output.

A real single-connection HEAD followed by GET checks the protocol boundary
and the complete subsequent metadata entity. Before the correction, the Rust
response body contaminated the following status line and this control failed.
The corrected development run passes all 13 pairs and the pipeline without
unexpected differences.

A development mutation disables the parsed HEAD-response flag in the owning
transport and rebuilds the actual CLI. The same corpus rejects transmitted
HEAD entity bytes and the contaminated pipeline status line. Restore the
original source bytes and rebuild before publication. This demonstrates that
the new control detects the production defect; a successful GET alone would
not establish that boundary.

Each implementation independently issues and persists a fresh DCR client,
then receives 512 valid authorization HEADs. Individually assert every full
header multiset and empty entity. Rust's only explicit header difference here
is no-store from ADR 0019. The persisted token registry stays byte-identical.
A subsequent actual browser GET must render the complete expected consent
form, proving that HEAD traffic has not exhausted Rust's 256-ticket capacity.
Validate real client entropy/time separately and scan unrelated responses and
process output for fixture secrets/tokens; never make issuers deterministic.

The required Linux/macOS/Windows workflow runs the same HEAD corpus, owning
tests, and the current 65-case HTTP and 46-case OAuth corpora. The HTTP corpus
retains the original 51 cases plus accepted-main admission regressions. Store all CI
receipts under ignored `target/` so retained observations cannot dirty the
source checkout between corpora. Forced fixture disposal is not graceful
shutdown proof. This slice does not complete TLS/mTLS, the entire hostile
Host/Origin/framing/slow-peer matrix, SSE/replay or device consent. HTTP-001..004
and #1249 remain open until their complete native acceptance passes.
