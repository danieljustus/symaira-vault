# ADR 0015: Shared egress broker runtime and credential boundary

## Status

Accepted maintainer-delegated implementation direction, 2026-10-04. #1237 is
in progress. No BROKER-001/002 acceptance or new runtime is claimed here.

## Decision and rationale

Build one owned egress runtime for the standalone broker and run --broker.
Keep the existing command runner responsible for the child's environment,
timeout, process tree and output redaction. The broker provides only public
proxy/CA environment assignments to that runner; resolved broker credentials
stay inside the broker and never become child argv or environment values.
Explicit run --env mappings keep their separately authorized behavior.

Reuse the existing source-tested API template loader, auth/substitution logic,
response sanitization and encrypted-store read limits. Broker startup resolves
the embedded catalog plus vault overrides; entry credentials are read at request
time after request/template preflight. Do not create a second auth implementation
or use the HTTP request helper as a pretend forward proxy. The actual CONNECT
passthrough module from #1140 supplies its tested socket mode/ownership behavior;
TLS interception must issue real ephemeral per-host certificates and validate
the upstream independently.

Keep the listener on loopback. Preserve the Go production private-destination
block even when a template permits private targets for another API use case.
Controlled native fixtures may explicitly inject private loopback transport
and a fixture CA without enabling either in the shipped CLI or installed trust.
Validate target authority and transport before reading credentials, pin checked
DNS addresses for the connection, bound request/response/admission resources,
and keep arbitrary network errors from printing credential-bearing URLs.

Keep service-owned workers and relays until they join. Cancellation stops new
admission and closes owned transports; already running application work remains
owned until completion. Per-host certificate material, intercepted request
buffers and decrypted entry projections must not become unbounded caches.

## Required evidence and scope

Before accepting this issue, execute real immutable Go and Rust CLI/runtime
cases in disposable HOME/XDG/vault roots on native Linux, macOS and Windows.
Cover all run/broker flags, proxy-only child environment, ordinary/error/timeout
cleanup, matching/unmatched/strict/passthrough requests, all auth/substitution
surfaces and built-in/override templates, verified TLS and secret canaries in
response bodies/headers/errors/output. Source inventories must include the
embedded template assets as well as code, probes, drivers and real binaries.

If an actual Go observation exposes an unsafe authority, plaintext transport or
redirect behavior, record the exact observation and the chosen Rust policy
before accepting a divergence; do not invent Go-equivalence or suppress the
failed observation. Broader GUI/device, full HTTP/OAuth and distribution/value
gates retain their separate issues. CLI help reachability alone is no runtime
evidence, and a cross-compiled or skipped target is not native acceptance.
