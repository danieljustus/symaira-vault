# ADR 0022: Complete loopback Host and Origin authority validation

Status: accepted design; native acceptance pending, 2026-10-04.

## Decisions and rationale

Validate the entire authority of cleartext MCP/OAuth Host and Origin fields.
The previous helper extracted the text between IPv6 brackets and discarded
the rest. Actual native process controls show that Rust accepted
`http://[::1]public`, `http://[::1]:public` and a bracketed IPv4 Origin while Go
rejected them. An authenticated Rust ping reached the handler under those
invalid origins. Reject suffix garbage and bracketed non-IPv6 addresses before
authorization. Reuse the existing TLS authority validator with a scheme-specific
default port rather than keeping an incomplete second parser.

Explicit ports must be nonempty decimal digits in 1..65535. Reject signed,
negative, empty, zero, overflow and service-name ports. A numeric parser alone
accepts a leading plus sign, so syntax and range both need validation. No
explicit port uses 80 for HTTP or 443 for HTTPS. For cleartext local routes,
retain the existing allowance for different loopback hosts and ports. TLS
continues to require HTTPS and matching Host/Origin authority; complete live
TLS/mTLS differential acceptance remains separate work.

Accept HTTP/HTTPS scheme names without regard to ASCII case and treat an
IPv4-mapped loopback address as loopback. The old cleartext implementation
rejected both although actual Go accepts them. Only mapped IPv4 loopback
addresses qualify; mapping does not make private or arbitrary remote addresses
local. Preserve the cleartext requirement that the request Host itself must
be loopback, including when Origin is absent. A matching remote Host/Origin
pair must not confer the listener's local trust.

An Origin must be a serialized HTTP/HTTPS origin. Retain rejection of userinfo,
path, query, fragment and FTP URLs even though the actual Go validator accepts
them when the extracted hostname is loopback. Go also accepts empty/zero/
overflow ports and permits arbitrary Host values when Origin is missing.
Keep Rust's stricter complete authority and local Host rules. These specific
decisions prevent malformed URL text or a spoofed Host from being interpreted
as a trusted local origin; they are not general exceptions for HTTP errors.

## Actual evidence

`http_origin_contract.py` rebuilds immutable production Go
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c` and drives both real CLIs over native
TCP from identical encrypted Go fixtures and the same sequentially bound port.
The explicit fixture rate limit of 1000 isolates origin checks from exhaustion.
The final corpus has 202 cases per implementation: real initialization,
47 Origin values across authenticated ping, missing bearer and OAuth validation;
23 Host values across authenticated/missing-bearer requests; two matching
remote Host/Origin pairs across both auth states; public discovery/404 controls;
and a final successful authenticated recovery ping.

Require exactly one Host field when testing an override. The first development
recorder appended an override to its helper's default Host, testing duplicate
Host rejection instead. Those Host observations are invalid for authority
coverage. Correct the recorder and rerun before assessing Host outcomes. The
paired Origin observations still identified the pre-fix IPv6 defect; the
corrected baseline retains 178 complete cases per implementation before the
additional signed-port and matching-remote-origin cases were added.

The development run passes all 202 final cases. Assert each protected-route
status, every body byte and the complete header multiset independently, then
compare remaining paired wire responses with only Date excluded. Exactly 69
responses receive one of three explicit decisions: serialized HTTP origin,
valid loopback authority, or local Host required. Both full responses remain
in the receipt and must satisfy their precise expected status, headers and
entity; do not normalize them to equal errors. Public-route controls keep
discovery public and missing routes at 404 for the measured Origin values.

A development mutation discards the IPv6 suffix again and rebuilds the actual
CLI. Both processes complete all 202 observations, but the authenticated Rust
ping under `http://[::1]public` succeeds while Go returns 403. The independent
expected-status assertion rejects the mutant. Restore the original source
bytes and rebuild before publication. A strict corpus must detect this defect
rather than classify its successful Rust response as a permissible difference.

Existing owning MCP regressions cover malformed authority/port rejection and
valid uppercase/mapped-loopback input without adding ignored tests. Source,
fixture, embedded-asset and executable inventories bind actual observations
to a clean commit. Preserve raw requests/responses and complete bounded process
output, and scan both for fixture secret/token canaries. Forced fixture disposal
does not establish graceful shutdown.

The required Linux/macOS-arm64/Windows workflow executes all 202 cases and
owning tests. Existing HTTP, OAuth and HEAD native workflows remain required.
The full parser/chunking/slow-peer, TLS/mTLS, token storage/expiration, SSE/replay
and device-consent boundaries remain separate. HTTP-001..004 and #1249 stay
in progress until complete native acceptance, rather than promoting this
cleartext Host/Origin slice to full HTTP acceptance.
