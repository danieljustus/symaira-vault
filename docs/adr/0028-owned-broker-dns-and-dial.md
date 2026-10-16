# ADR 0028: Share owned DNS and connection admission with the API transport

Status: accepted design; native acceptance pending, 2026-10-04.

## Decisions and rationale

Use the existing pinned Hickory/Tokio resolver for API requests, credential
forwarding and CONNECT admission. Blocking OS resolution previously belonged
to a broker worker without a cancellation boundary. Creating a detached helper
thread would preserve that resource after service shutdown. Each resolver runs
on an owned current-thread runtime and shares HttpShutdown's existing request
context. Its complete lookup has a ten-second absolute allowance, checks the
same stop signal every ten milliseconds and drops all resolver tasks/sockets
before returning. No background DNS worker survives the runtime owner.

Resolve both address families before admission, disable caching and reject an
empty set or more than 32 results. Reject any private/local or mapped private
answer unless the explicit library fixture/application option allows it. Reuse
the API's local-hostname boundary for localhost and .localhost/.local names.
Literal addresses take the same validation path. Credential forwarding pins
its complete admitted answer set before credential reads; passthrough dialing
uses the checked CONNECT answer set. Do not resolve again after credential reads.
The optional DNS server is an explicit in-process fixture seam, selected by the
consuming `EgressBroker::with_dns_server` builder. Keep the existing public
`EgressOptions` fields unchanged so downstream struct literals remain source
compatible. The shipped CLI supplies no DNS override flag or ambient resolver
override.

CONNECT validates and resolves its authority before choosing passthrough or
interception. This admission lookup does not open an upstream TCP connection.
Only passthrough uses those checked addresses for the actual tunnel socket;
never dial and discard a reachability-only probe in the interception branch.
Interception admits the inner authority, template, method and endpoint first,
then resolves and pins that request's upstream before reading credentials.
The initial CONNECT answer set is not reused as the inner request's dial set.

Passthrough's checked address attempts also run on an owned async runtime, with
one ten-second allowance across the complete dial sequence and the same stop
signal. Successful Tokio sockets are converted to standard sockets and reset
to blocking mode before the existing platform cancellation adapter configures
them. This preserves the accepted macOS socket-mode decision. DNS and dial
are separate bounded phases; this is not a ten-second whole-handler deadline.
Request computation and unrelated lifecycle work retain their own ownership.

Integrate the existing API cancellation and HTTP options/deadline slices before
using their shared context. Each admitted HTTP worker receives both configured
timeouts and the real request context. Retaining either a fresh fixed timeout
or a fresh unrelated context would silently discard one accepted behavior.
Existing public server entry points keep their signatures and defaults.

## Evidence and acceptance boundaries

A new actual broker regression sends both an absolute proxy request and CONNECT
to a private stalling DNS fixture. A missing credential reference makes any
premature store access fail before the required real DNS packet. Only after
observing that packet, stop the running broker and require actual client
EOF/reset, joined service workers, a reusable observed UDP source port and a
released listener within one second. This checks the complete broker ownership
path rather than only calling a resolver directly.

The development regression passes both request paths. A mutation replaces its
shared cancellation context with an unrelated default context in the real DNS
admission helper. The worker remains until DNS expiry and fails the independent
one-second join assertion. Restore exact original source bytes; the actual
regression passes again. Existing complete-answer, TLS, socket, encrypted API
and HTTP deadline regressions remain required. The initial slice recorded 236
passing local MCP tests with zero ignored and native counts of 234 on Windows
and 236 on Unix. The integrated suite records 240 local Unix tests with zero
ignored; current native gates require 238 on Windows and 240 on Unix, retaining
the two existing Unix-only omissions. Do not relax the exact counts or ignore
the new case.

Preserve actual immutable Go/Rust broker (19 runtime/14 CLI), API (eight cases)
and CONNECT (three cases) corpora, plus every earlier live HTTP/OAuth/HEAD/
Origin/framing/read/TLS/configuration/write corpus on the clean publication
candidate. New broker stop/port evidence is an actual Rust ownership regression;
it does not invent a matching Go DNS cancellation observation. Full native
Linux/macOS-arm64/Windows gates and remaining Go behavior, signal, device and
release acceptance stay required. #1237, #1140 and BROKER-001/002 stay in progress.

## Reproducible local validation

Use a separate build directory per checkout, or invalidate only owned workspace
crate artifacts before switching checkouts in a shared dependency cache. A
reused local cache emitted an earlier branch's MCP types even though the current
source contained the referenced fields. Discard that compilation as evidence,
clear owned workspace artifacts and rebuild; keep dependency downloads and
operator work intact. Frozen actual executables used by concurrent live proofs
have explicit hashes and remain outside mutable build output. Native jobs use
their isolated checkout and recompile the current candidate.
