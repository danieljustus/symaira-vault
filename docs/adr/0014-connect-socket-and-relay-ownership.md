# ADR 0014: CONNECT socket mode and relay ownership

## Status

Accepted maintainer-delegated decision, 2026-10-04. Implements the focused
#1140 library regression; clean native Linux/macOS/Windows acceptance and the
normal merge gates remain required. Full broker CLI/MITM/template/secret
injection remains #1237, and neither BROKER row is promoted here.

## Decision and rationale

Restore the earlier draft's explicitly allowlisted CONNECT passthrough as a
separate reusable module. Immediately set each accepted client to blocking mode
before ordinary header or relay I/O. macOS inherits the nonblocking listener's
mode; io::copy can otherwise see WouldBlock while the client is legitimately
waiting to send TLS/tunnel bytes. A regression forces that inherited mode on
every native OS and delays the first payload, so deleting the reset fails even
on platforms whose accept normally returns a blocking socket.

Use four owned workers and a four-connection admission queue. Excess sockets
are closed without another worker or payload allocation. Each bidirectional
relay owns its outgoing thread until it joins; there are no detached tunnel
threads. Reuse the existing HttpShutdown socket registry internally, widening
only crate-private visibility. Stop closes registered client/upstream sockets
and joins the workers. On Windows, the existing cancellable nonblocking I/O
wrapper handles WouldBlock and checks cancellation because shutdown alone does
not reliably wake a blocking recv. Unix uses blocking I/O after the explicit
reset. Retain TCP half-close behavior until both directions finish.

Resolve the requested destination, reject private/local/mapped-private
addresses unless an explicit application test seam allows them, and dial only
those validated IPs. Passthrough selection uses exact or dot-delimited domain
suffix matching. Native test launchers set allow_private only for disposable
numeric-loopback upstreams; no production CLI policy is weakened. Header size
is capped at 64 KiB, header read time at 30 seconds, and socket idle I/O at
60 seconds. System DNS resolution itself is a bounded-worker blocking operation,
not an established cancellable-DNS or full broker shutdown contract.

The helper deliberately implements passthrough only. A non-passthrough target
cannot gain an invented credential-injection or TLS-interception path. #1237
must connect the actual broker CLI/runtime and establish its separate full
allow/deny/strict/secret/template/TLS contracts before either BROKER row passes.

## Evidence

Four actual socket tests pass locally: forced nonblocking-mode reset with delayed
payload, complete allowlisted delayed tunnel round trip, idle relay cancellation
and owned upstream closure, and zero-connection private/unlisted rejection.
A controlled mutation removing the blocking reset makes its regression fail;
restoring the source makes all four pass. The complete MCP crate passes 218
tests with zero failures or ignored cases, and strict all-target Clippy passes.

The source-bound driver builds the real retained Go broker handler at
d1cd0f97ac550bc3020bc86b0514989f8d28d95c through a small recorded probe. Actual
Go/Rust ordinary, delayed and fragmented binary round trips match exactly,
including CONNECT status bytes and both payload directions. Receipts bind the
complete Go production inventory, probe, driver, candidate sources, real
binaries and native OS. Probe processes are force-stopped after observation;
that is not signal/drain acceptance. Native jobs must execute all named cases
and require a clean candidate; skipped or cross-compiled results do not count.
