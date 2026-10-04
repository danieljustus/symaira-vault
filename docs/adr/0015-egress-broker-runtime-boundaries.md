# ADR 0015: Shared egress broker runtime and credential boundary

## Status

Accepted maintainer-delegated implementation direction, 2026-10-04. #1237 is
in progress. The implemented runtime has development evidence; BROKER-001/002
acceptance still requires clean-source and native-platform receipts.

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

## Measured authority decisions

The 2026-10-04 Linux development transcript executes actual Go at immutable
d1cd0f97ac550bc3020bc86b0514989f8d28d95c and the Rust runtime against private
TLS peers and a real Go-initialized encrypted vault. It covers all five auth
types, all four substitution surfaces, denied methods/endpoints, unmatched
forwarding/strict mode, passthrough, upstream trust rejection and four authority
cases. Development receipts are not native acceptance for a clean candidate.

Actual Go delivers the fixture bearer credential and returns 200 when the
template's port differs from the request, when a HTTPS template is used through
plain HTTP, and when the inner Host after CONNECT differs from the CONNECT
target. It also follows a redirect to another port of the same host, delivering
the bearer credential there and returning the final 200. Rust returns 403
without credential delivery for the first three and returns the sanitized 302
without following the redirect. Preserve these narrower boundaries: hostname
alone does not identify a credential destination; scheme and effective port
belong to that destination, and a CONNECT peer cannot introduce another one.
In the shipped runtime, credential templates require HTTPS. Plain/private
fixture transport remains an explicit in-process seam. Do not export this seam
as a CLI option or install the fixture CA in system trust.

The same development run initially measured Go ignoring a custom auth_type none
template without substitutions, silently forwarding with caller headers. Rust
rejects that invalid template at startup. A valid none template with declared
substitutions is executed separately and matches actual Go injection/masking.
Failing startup avoids silently changing an operator's credential policy.
Reject duplicate host templates and oversized catalogs for the same reason.

The actual CLI comparison also measures Go accepting a wildcard listener while
Rust rejects it. Keep the shipped broker on loopback: exposing a local
credential-injecting proxy to another host must require a separately designed
and authenticated service boundary. Empty passthrough CSV selectors never match
a destination, including a DNS name with a trailing dot. The passthrough list
continues to use exact names or dot-separated subdomains.

The runtime uses four owned workers and four pending sockets, 64 KiB aggregate
headers, 8 KiB request lines and 16 MiB request/response bodies. ACL glob work
shares an eight-million-operation allowance per request and uses linear memory;
an exhausted allowance denies the request before any credential read. The
encrypted-store admission and batch limits remain in force. These are payload
and operation bounds, not a measured RSS claim. Per-host certificates are minted
without a retained leaf cache; their lifetime is 24 hours and the ephemeral CA
is valid for one year, matching the Go certificate lifetime policy.

Each forwarded request owns a current-thread async transport runtime. Stop
checks interrupt its network future and dropping that runtime drops its network
tasks/sockets before the worker joins. An actual pending upstream test proves
EOF and complete shutdown in under two seconds, rather than merely waiting for
the 60-second network timeout. Blocking system DNS resolution still belongs to
the worker and is not advertised as cancellable. Every checked address is pinned
for the connection; private/local destinations remain blocked in production.
Neither admission stop nor transport cancellation claims to undo a request that
an upstream has already received.

Five integration tests use actual encrypted entries, verified TLS peers,
binary response bytes, repeated Set-Cookie headers, preflight failures, idle
clients and pending upstream cancellation. Strict CLI/MCP Clippy and the full
MCP suite passed during development; final clean-source and native receipts
remain required, including real CLI child error/timeout/launch and console stop.

The complete Linux development driver subsequently passed 16 real Go/Rust
runtime cases and 13 CLI cases. The CLI cases exercise ordinary child exit,
child error, timeout, explicit separately authorized environment mappings,
launch failure, valued/repeated boolean flags, CSV passthrough, public proxy
environment and native console stop. Actual missing-vault observations required
Rust run/broker to return the Go initialization exit code 3; a locked vault uses
4. These decisions are scoped to run/broker and do not rewrite unrelated CLI
error classifications. Both drivers retain actual output and binary/source
hashes. Development success does not substitute for the required clean commit
or native macOS/Windows jobs.

At clean integrated Linux commit 55e781aa8a43303aa8b649f2e630cc49fa2fe911,
all 16 runtime and 13 CLI comparisons passed against immutable Go. The owning
CLI suite passed 487 tests with five existing ignored cases; MCP passed 222
tests without an ignored case, the core policy suite passed 11, and strict
Clippy plus pinned dependency checks passed. Subsequent CA-lifetime changes
require a fresh clean receipt and their additional real concurrency case.

Give each live CLI broker a private temporary directory containing only its
public CA certificate. Keep that directory alive through child process-tree
completion and joined broker workers, then explicitly remove it. Preserve the
primary execution failure if certificate cleanup also fails; otherwise expose
the cleanup failure. The ephemeral private key remains solely in RAM. A shared
vault-level broker-ca.pem permits a second concurrent broker to replace the
first broker's trust root, disrupting a still-running child or standalone
client. The public environment and startup message therefore name the owning
instance's CA path. Callers must use those advertised values instead of
guessing a persistent vault filename. This is a deliberate lifetime/path
decision, measured against two actual simultaneously live Go/Rust CLI brokers;
it does not install trust globally or change decrypted credential handling.

The actual Linux concurrency observation is Go paths_distinct=false,
first_ca_unchanged=false and ca_removed_after_stop=false. Rust measures true
for all three. All other runtime and CLI cases still pass with the lifetime
decision: 16 runtime and now 14 CLI cases in the development transcript. The
child reads and validates its actual public PEM and Unix 0600 file/0700 parent
permissions while alive; after exit, the driver independently verifies that
Rust's instance certificate/directory and listener have gone. The CA directory
is created with narrow permissions rather than tightened after publication.

Authorize the percent-decoded original HTTP path, before URL-library
normalization. Actual Go allows /v1/%61llowed under the decoded /v1/allowed
pattern and denies it under the literal /v1/%61llowed pattern. The first Rust
comparison measured the reverse, including actual bearer delivery in the
denied case. The repaired runtime matches both Go outcomes before entry reads.
An independent regression uses a missing entry and verifies denial before a
500 lookup error or any upstream connection can occur.

Reject literal or encoded dot segments before normalization, rather than let
the URL library turn an initially denied path into an allowed endpoint. Actual
Go delivers the credential for both /v1/../denied and /v1/%2e%2e/denied under
/v1/*; Rust denies both with 403 before credential access. Reject malformed
percent escapes and non-UTF-8 decoded paths instead of authorizing a replacement
character. The bounded original-path parser comes from the already retained
http crate; shared percent decoding is reused without changing the older MCP
helper's error contract. The latest development corpus passes 19 runtime and
14 CLI cases, including both encoded ACL outcomes and measured dot-segment
policy. Native acceptance must repeat the complete corpus at a clean commit.

Disposable native fixture vaults use explicitly configured Argon2id parameters
of 19456 KiB, two iterations and one lane, within Go's configured minimum
policy. Real Go InitWithPassphrase writes the encrypted identity and entries;
both implementations then decrypt those actual artifacts. Keeping functional
fixtures within that supported configuration avoids repeatedly benchmarking
an unoptimized debug KDF during transport tests. Production defaults, the
accepted KDF resource policy and release performance gates remain separate.
The receipt records these fixture parameters and the actual binary hashes.

## Required acceptance

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
