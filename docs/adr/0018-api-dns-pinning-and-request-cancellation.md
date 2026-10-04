# ADR 0018: API DNS pinning and request cancellation

Status: implementation and native evidence in progress; BROKER-002 and #1237
remain open. These decisions are made under the user's delegated authority.

## Problem and decision

The installed egress broker and the older MCP API helper use different network
paths. The helper still rejects every public DNS HTTPS target and uses blocking
HTTP work, which cannot cooperate with HTTP server cancellation. Complete this
helper's path without treating the egress corpus as proof of its behavior.

Use pinned Hickory Resolver 0.26.3 with only system-config and Tokio features.
Read the host OS DNS configuration; do not substitute a public DNS service or
add an environment/CLI override. The dependency supports the native Unix/macOS
and Windows configuration paths. Its DNS sockets/tasks run on the request's
owned current-thread Tokio runtime. Dropping cancelled work and then that
runtime closes the network work; placing a timeout around blocking OS lookup
would leave an uninterruptible lookup running after its caller returns.
Verify the exact dependency graph with the existing dependency policy gate.

Resolve both IPv4 and IPv6 answers. Reject an empty answer set, more than 32
addresses, or any private/local/mapped-private member unless the template
explicitly permits private destinations. Pin the entire accepted set into the
verified HTTPS client, keeping the original host for Host/SNI and certificate
verification. Resolve before approval/credential access and validate again at
the actual request boundary. A DNS change cannot redirect a credential-bearing
connection to a new, unchecked address. Cleartext remains restricted to
explicit loopback targets; redirects are returned without following them.

The retained real Go reference is
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c`, particularly
`internal/ssrf/ssrf.go`: its validation and dial paths resolve and reject private
answers, while redirects are validated and followed. Keep Rust's previously
documented narrower redirect/cleartext boundaries. Add no predictable credentials
or fake expected responses to obtain parity.

## Context and ownership

Give each protocol session an explicit request context with shared cancellation
and an absolute deadline. The shared application runtime receives that context
as an argument; one authenticated session cannot overwrite another's context.
Fresh sessions start with fresh context. The HTTP shutdown owner propagates its
cancellation to dispatched API work as well as registered client sockets.
Existing non-network callbacks remain responsible for their own lifecycle.

The API timeout begins before template validation, DNS, approval and credential
projection. DNS receives at most ten seconds within that same deadline. Check
again after approval before accessing credentials. Poll cancellation/deadline
while sending, awaiting headers and receiving chunks; progress does not reset
the absolute deadline. Retain bounded request/response bodies, header bounds,
opaque transport errors and existing redaction/audit ordering. A response error
must not include a credential-bearing URL or library diagnostic.

Explicit library options may supply a disposable DNS server or trust root for
real native fixtures; production MCP uses neither option. These inputs do not
install system trust and are not exposed through shipped CLI flags or ambient
environment variables.

## Required evidence and limits

Require actual DNS packets, positive verified-TLS controls, mixed-family private
answer rejection, pinned destinations, owned upstream EOF after cancellation,
and a slowly progressing response that still reaches its absolute deadline.
Compare actual immutable Go and Rust behavior in isolated native fixtures;
retain source, executable and raw observation receipts. Keep all existing API,
MCP, CLI and HTTP acceptance gates.

No native acceptance, installed MCP signal routing, generic command/GUI callback
cancellation, DNS performance bound or complete BROKER-002 PASS is claimed by
this design document. Record concrete results and failures as they are measured.

The first actual encrypted Go/Rust positive control reaches the correct DNS/TLS
upstream and redacts the real credential in both body and header, but the full
API result comparison fails: Rust includes `Connection: close`, while Go's
net/http response projection consumes that transport field. Consume exactly a
Connection field containing the close token in the API helper. Do not delete
arbitrary application headers or normalize away the difference in the driver.
The TLS positive regression also checks the field is absent.


The local development corpus now passes all eight actual Go/Rust encrypted API
cases, with seven individually asserted opaque transport diagnostic differences
and zero unexpected differences. The positive result compares the entire parsed
API response object, including every projected header, content type, truncation
flag and masked body. Each case starts from byte-identical copies of an actual
Go-initialized encrypted vault. Real DNS queries/responses, upstream requests,
EOF/progress observations and complete process output are retained. The Go probe
calls the actual pinned handler in its server package and changes only explicit
fixture DNS/trust inputs; its retained test helpers and all compiled Go source
files are inventoried. It is not a Go CLI HTTP/token or GUI acceptance claim.

Six additional regressions execute actual DNS sockets, complete mixed-family
answer validation, bounded address sets, TLS chain/hostname verification,
resolver port reclamation after cancellation, upstream EOF and absolute response
deadlines. A protocol-level encrypted-entry control verifies one credential
read and one request, followed by cancellation through the injected call context.
The complete owning suites pass 235 MCP tests with zero ignored, and 487 CLI
tests with five existing dedicated acceptance helpers ignored. Strict Clippy
and dependency advisories/bans/licenses/sources checks pass. The new resolver
graph adds packages without changing any existing pinned package version.

Required native Linux/macOS/Windows jobs execute all six new regressions and all
eight real Go/Rust API cases on a clean source-bound commit. Exact owning suite
counts are updated in the dependent MCP and HTTP workflows. Development results
do not promote BROKER-002 or close #1237.


A controlled mutation drops only protocol-to-runtime context propagation. The
actual encrypted API request still reaches its upstream, but cancellation no
longer closes it; the upstream reaches its socket deadline and the regression
fails. Restoring the original propagation makes that same test pass. No mutated
source is included in the publication candidate.
