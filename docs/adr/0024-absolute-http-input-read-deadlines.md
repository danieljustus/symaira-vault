# ADR 0024: Absolute HTTP header and entity read deadlines

Status: accepted design; native acceptance pending, 2026-10-04.

## Decisions and rationale

Use monotonic absolute deadlines for HTTP input reads, not a fresh full timeout
for each socket operation. Actual CLI controls show that Go closes progressing
headers at about five seconds and progressing entity input at about ten seconds.
Before the correction Rust remains open at the recorder's 7.5/12.5-second limits
despite both peers supplying bytes every 200 ms. Retain those failed observations.
An inactivity timeout alone does not bound admission under a progressing peer.

Enforce the remaining deadline at the underlying TCP reader, including when
rustls reads another fragment inside one outer TLS operation. Preserve existing
write and shutdown delegation. Zero-length reads still obey the Read contract.
Header admission has the five-second default; the ten-second entity-read deadline
starts with the admitted request, rather than starting again after headers.
Keep the earlier of header and overall input-read bounds during header parsing.
The deadline applies to both fixed-length and chunked bodies and their trailers.
Do not reset it when a peer makes progress.

Keep idle admission separate from a new request's header/entity deadline. The
existing 120-second keep-alive idle allowance must not become a five-second
request limit. After the next request arrives, start its read budget; clear the
read deadline once complete input is validated. Retain the source-bound short
idle regression and a real six-second pause followed by another successful GET.

Apply a separate short absolute deadline to ADR 0023's single oversized-chunk
prefetch, bounded by the remaining request deadline. A TLS record progressing
within a per-operation timeout cannot turn that prefetch into an arbitrary
drain. The older one-byte-over development failure and measured bounded-buffer
limit remain recorded in ADR 0023.

When input reading expires, close that connection without attempting a late
application response. The actual Go body-timeout control sometimes transmits
its complete 400 JSON parse-error envelope before its separate write deadline,
and sometimes reaches EOF without response bytes. Keep and individually assert
both observed Go outcomes. Rust consistently stops with empty EOF/reset. A
recorder must never replace an actual JSON response, partial output or forced
client disposal with a claimed empty EOF. This specific expiration boundary
is not a general exception for response statuses, headers or bodies.

## Actual evidence and boundaries

`http_slow_peer_contract.py` rebuilds immutable production Go
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c` and drives both actual CLIs from identical
encrypted fixtures on the same sequentially bound native loopback port.
Initialization and ping before/after the controls must succeed. Two real peers
continuously extend unfinished headers or entity input. Independently require
at least four sent progress bytes, actual peer termination in bounded time,
joined sender threads and no forced client close. Keep all received bytes,
terminal kind, elapsed times and sent-prefix provenance.

For headers, require 3.5..7.5 seconds; for entity input, 8..12.5 seconds. These
fixed ranges allow native scheduling variation around Go's measured five/ten
seconds while requiring the server itself to terminate each peer. Go's optional
body-timeout error must match its entire 400 status, header multiset and JSON
entity with only Date excluded. A partial or other error does not qualify.

A third connection waits six seconds between two discovery requests and must
return both complete expected responses. Run these controls concurrently within
the owned connection budget and finish with a real ping. Preserve complete
bounded process output and scan responses/output for fixture secret/token
canaries. Inventory source, helper, embedded assets and executables throughout
a clean run; forced fixture-server disposal is not graceful shutdown evidence.

The corrected development run closes both Rust peers at about five/ten seconds,
retains idle reuse and completes all real handler controls. A development
mutation removes the absolute socket check: both implementations complete
their observations, but Rust now requires forced client disposal in both
progressing cases. The independent termination assertion rejects the mutant.
Restore original source bytes and rebuild before clean publication.

Existing owning MCP tests and strict Clippy pass. The required native
Linux/macOS-arm64/Windows workflow runs the same live control; other HTTP,
OAuth, HEAD, Origin and framing gates remain required. These live controls are
cleartext. Existing TLS regressions exercise the wrapper, but full live
TLS/mTLS/progress acceptance, configurable timeout overrides, outbound-write
deadlines, all parser/overhead boundaries, SSE/replay and device consent remain
separate work. HTTP-001..004 and #1249 stay in progress until complete acceptance.
