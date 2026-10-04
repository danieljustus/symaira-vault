# ADR 0023: Bounded, complete chunked request framing

Status: accepted design; native acceptance pending, 2026-10-04.

## Decisions and rationale

Support HTTP/1.1 chunked request bodies. The actual Go CLI accepts ordinary,
bytewise and extended chunked pings; Rust previously rejected all transfer
encoding before dispatch. Decode into the existing one-MiB entity bound plus
one lookahead byte. Limit chunk-size lines to 4096 bytes, cumulative trailer
headers to 16 KiB, and excessive non-data overhead to 16 KiB using Go's measured
allowance of 16 bytes per chunk plus twice its data length. Discard extensions
and validated ordinary trailers; neither changes application data or metadata.

Require a valid hexadecimal size, every chunk's CRLF, the terminal zero chunk
and the trailer terminator before any endpoint sees the request. Reject a
simultaneous Content-Length and Transfer-Encoding rather than choosing a
potentially different length from an intermediary. Reject chunked framing on
HTTP/1.0. Keep the recognized HTTP version for early parser errors as well as
normal responses and reset it between requests.

Trailer fields must never replace framing, route, Origin, authentication,
agent or enrollment metadata. Reject security-sensitive and hop-by-hop trailer
names explicitly; validate and discard ordinary trailers. A later code path
must not accidentally promote ignored attacker-controlled metadata to headers.

Keep opaque transport framing failures as a closing 400 plain-text response,
before MCP JSON dispatch. The actual Go handler returns its JSON parse-error
envelope for invalid chunk sizes, and can return a successful ping before
discovering malformed final framing or sensitive trailers. Retain Rust's full
framing validation and document each measured response rather than accepting
any 400 or rewriting errors to look equal.

At one byte above the entity limit, leaving the short chunk terminator/final
chunk unread in the TCP receive queue can reset the connection and truncate
the 413 response. A failed development run retains that partial response and
reset. Perform one bounded BufReader prefetch with a short socket read timeout
before returning the limit error. This consumes the already sent short suffix
in the measured just-over-limit request; it never drains an arbitrary oversized
entity. The prefetch retains at most the existing reader buffer capacity.
Its socket timeout is not a complete elapsed-time or TLS-progress guarantee.
Whole-request deadlines for progressing headers, bodies and TLS records remain
separate required work. Preserve the existing JSON-prefix versus exceeded-body
classification and exact measured 413 envelope.

## Actual evidence and boundaries

`http_framing_contract.py` rebuilds immutable production Go
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c` and drives both actual CLIs from identical
encrypted fixtures on the same sequentially bound native loopback port. The
33 paired cases cover initialization and recovery, HTTP/1.0 length-framed calls,
normal/bytewise/uppercase/extended chunks, declared/ordinary trailers, seven
sensitive trailers, bad/signed/negative/overflow sizes, incomplete final framing,
length ambiguity, HTTP/1.0 chunks, and exact/one-byte-over entity limits.

A real chunked ping with an ordinary trailer followed by discovery GET on one
persistent connection checks complete consumption and the next response boundary.
Retain both actual responses and compare status, full header multisets and entity
bytes with only Date excluded. Scan unrelated responses and complete owned
process output for fixture secret/token canaries. Source, fixture, embedded
asset and executable inventories bind clean publication observations.

The development run passes all 33 cases and the persistent pipeline. Eighteen
paired responses have five individually asserted decisions: validation before
dispatch, complete chunk framing, one request length, security metadata in
headers, and HTTP/1.1 required for chunks. Assert every expected status, header
and entity independently, including cases where a mutation could make both
implementations appear equal. Keep both full responses in the receipt.

A development mutation removes the sensitive-trailer name rejection and
rebuilds the actual CLI. Both processes complete all 33 observations and their
pipelines, but Rust now accepts the Host trailer with a successful ping. The
independent expected-status assertion rejects it. Restore the original source
bytes and rebuild before publication. Existing owning tests and strict Clippy
must also pass after the restored implementation.

The required native Linux/macOS-arm64/Windows workflow runs the same corpus
and owning tests. Existing HTTP/OAuth/HEAD/Origin gates remain required. Forced
fixture disposal is not graceful shutdown proof. This slice does not complete
all parser/overhead/trailer/slow-peer boundaries, TLS/mTLS, SSE/replay, token
storage/expiration or device consent. HTTP-001..004 and #1249 remain in progress
until complete native acceptance.
