# ADR 0025: Live TLS transport, separate client trust and encrypted read progress

Status: accepted design; native acceptance pending, 2026-10-04.

## Decisions and rationale

Keep server identity verification and client authorization separate. Use the
configured server identity and require the configured client CA when mTLS is
selected. A successful TLS handshake never replaces bearer and agent checks.
Verify this through actual Go/Rust CLI listeners with TLS 1.2 and TLS 1.3,
including valid clients, missing clients and clients from an unrelated CA.
Client probes require certificate and hostname verification; no production
trust store, environment CA override or insecure client option is added.

Retain HTTPS URLs in discovery from a TLS listener. Actual immutable Go returns
HTTP resource, issuer and OAuth endpoint URLs over TLS; following those URLs
would choose the wrong transport. This continues ADR 0013. Independently assert
both entire discovery representations and their complete header multisets,
including the different GET representation lengths on HEAD. Record the original
responses with the explicit decision `https-discovery-on-tls`; never rewrite Go
URLs in a receipt or classify them as byte equality.

Retain the existing requirement that a TLS Origin uses HTTPS and matches the
complete request Host authority, including the port. Actual Go accepts an HTTP
Origin and another port with the same loopback host. Cross-origin requests must
not gain access solely because a hostname matches. Continue ADR 0022's decision
and independently require Go's complete authenticated ping response and Rust's
complete 403 response for these two concrete controls. Other responses retain
strict status, full header and entity comparison with only Date excluded.

Keep absolute input deadlines below rustls, as decided in ADR 0024. After a
verified handshake, send one real encrypted application record a byte every
200 ms without completing it. For the header control, that record contains an
unfinished header. For the entity control, send complete encrypted headers
first and progress inside a separate body record. Require at least four sent
record bytes, an incomplete record, and actual socket EOF/reset within fixed
3.5..7.5-second header or 8..12.5-second body bounds. A TLS alert, a client-side
exception or forced fixture disposal alone is not socket termination evidence.
Retain encrypted traffic, all decoded application bytes, TLS diagnostics,
certificate identities, times and sender-thread completion.

Go can send its complete 400 JSON parse-error response after an expired body,
or stop with no application bytes; some actual Go TLS 1.2 observations also
produce an OpenSSL record-layer error before EOF. Preserve that diagnostic and
continue observing the underlying socket. Any transmitted application response
must independently match the entire specific Go JSON error, including status
and headers. Rust terminates expired input without application bytes. Partial
or different output does not qualify. This is the same narrow expiration
boundary as ADR 0024, not a general HTTP error exception.

## Actual evidence and boundaries

`http_tls_contract.py` rebuilds production Go at immutable
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c`. Its seed uses the actual Go vault,
config and token APIs with the recorded single transformation disabling
cleartext opt-in. Create byte-identical encrypted fixture clones in disposable
HOME/XDG roots and bind Go/Rust sequentially to the same native loopback port.
A separately hashed Go helper generates fresh P-256 server/client/unrelated
CAs with explicit basic constraints, key usages and SKI/AKI for strict native
Python 3.13 verification. Keys and certificates remain in the owned temporary
directory (0700 directory, 0600 files on Unix), and are never installed.

Four profiles execute 48 real HTTP responses, twelve identity denials and eight
progressing encrypted records per implementation. Each profile finishes with
an actual authenticated ping. Capture and join both process output readers,
retain full bounded observations and scan application output for secret/token
canaries. Inventory candidate sources, immutable Go sources and its seventeen
embedded API assets, executable hashes and generated identities. Forced fixture
server cleanup remains explicitly separate from graceful shutdown evidence.

The initial recorder assumed Go applied Rust's secure-Origin rule and failed
on an actual Go HTTP-Origin 200. Retain that failure, then derive separate
expected responses from actual Go observations and its middleware source.
A later run retained all four profiles but rejected a complete Go body-timeout
400; classify only that exact measured envelope as described above. These were
recorder corrections, not runtime fixes or permission to omit response bytes.
The corrected development proof passes with twenty full-response controls:
three discovery and two secure-Origin decisions in each of the four profiles.

A development mutation changes the actual client verifier to permit an
anonymous client. The rebuilt Rust CLI now returns an actual HTTP 200 to the
missing-client control; the independent denial assertion rejects the mutant.
Restore the exact original source bytes and rebuild the CLI before publication.

The native workflow requires the same nonzero live corpus on Linux, macOS
arm64 and Windows, alongside owning MCP tests and CLI assembly. Native gates
are pending. This HTTP/1.x probe does not cover ALPN/HTTP2, server identity
rotation, client revocation/expiration, device consent, configured timeout
routing, outbound write deadlines or all parser/overhead boundaries. These
remain explicit work; HTTP-001..004 and #1249 stay in progress until complete
acceptance. The runtime is unchanged by this proof slice.
