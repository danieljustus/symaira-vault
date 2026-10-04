# ADR 0009: HTTP shutdown owns callbacks until drain or explicit timeout

## Status

Accepted maintainer-delegated decision, 2026-10-03. Implementation and native
acceptance for issue #1220 remain pending.

## Decision and rationale

Stop listener and application admission on cancellation. Give HTTP requests and
handler factories one fresh, bounded shutdown context, independent of the
already-canceled serving context. Keep the existing configurable five-second
default. The serving function waits for the drain result rather than returning
when `Serve` merely releases the listener.

Request contexts cancel at shutdown. Pending device approvals, terminal/GUI
consent and authorization must fail closed, including a late affirmative reply.
An already-dispatched operation may complete its mutation or honor its own
cooperative cancellation. Cancellation does not roll back a completed write,
and transport disconnection does not prove that a mutation did not happen.

At the deadline, force-close active transports and return an explicit timeout.
Go cannot forcibly terminate an arbitrary embedding callback that ignores
cancellation. Keep its audit/token/handler resources owned until its tracked
callback eventually exits, then close them exactly once. Do not report clean
drain while such a callback is alive, or close resources underneath it.
Factories finishing after shutdown must close their result instead of adding
it to a closed cache. Normal drain closes resources before returning.

The timeout error exposes a `Drained` signal, closing after owned callbacks and
cleanup finish, and unwraps the deadline for `errors.Is`. Embedders retain
caller-owned vault/credential resources until that signal. Server ownership
does not authorize clearing an embedding application's shared vault object.

This keeps shutdown bounded without inventing cross-file rollback or claiming
that arbitrary callbacks can be killed. Idle and partial transports must close
within that bound; new requests must not enter application callbacks after the
admission gate closes. A new server can bind the released endpoint.

## Acceptance

Real authenticated requests exercise a blocked factory, successful drain,
deadline/forced-close behavior and late factory cleanup. Real idle and partial
sockets exercise cancellation and restart. Approval tests prove cancellation
cannot grant access or publish a write; existing token, OAuth, mTLS and mutation
tests remain required. Run these contracts natively on Linux, macOS and Windows.
Rust callback lifecycle parity remains separately pending until implemented and
verified against this corrected Go contract.

## Local evidence

The complete owning Go packages pass under the race detector: serverbootstrap,
MCP server, secure UI, approval queue and policy. The real authenticated factory
tests distinguish clean drain from deadline/forced close; idle discovery and
restart, incomplete-body transport, retained cleanup ownership, and canceled
terminal replies pass. Strict owning-package lint reports zero issues. Native
Linux/macOS/Windows acceptance and final combined repository gates are pending.

MCP's historical Windows `TestMain` skips its suite by default. Contract jobs
explicitly enable the existing cross-language opt-in and assert named tests
actually passed. The owning portable packages run completely; the MCP package
runs the named cancellation and authorization/scope contracts on every host,
avoiding unrelated POSIX-shell-only command cases. General CI and the local
complete owning suite retain the broader Linux/macOS coverage.

Device-consent cancellation is checked in the shared policy authorizer, before
authorization and again after queue wait. A reply racing cancellation cannot
grant access. Retire only that authorization call's still-pending request; other
requests in a shared queue remain pending. The real queue/authorizer test covers
ordinary approval and a late affirmative after cancellation. The server's
private forwarding method remains unchanged.

The first executed Windows MCP lifecycle run exposed leaked audit handles in
existing authorization tests. Register audit-log cleanup in the shared fixture
helper, before temporary-directory removal; its existing close method is
idempotent. The Rust twenty-request/idle-socket regression continues to test
real behavior; remove its obsolete assertion about the Go local variable name
now that the owning listener is wrapped for lifecycle admission.

Windows anonymous pipe handles cannot set read deadlines. Retain fail-closed
behavior for an uninterruptible terminal: deny before entering its read, rather
than retain an unjoinable goroutine during shutdown. The native receipt requires
that actual denial on every host. Linux/macOS also require the actual blocked
pipe interruption and canceled late affirmative reply; Windows does not claim
those unsupported pipe observations. All hosts still require portable queue and
GUI/process cancellation tests. Windows HTTP TTY consent remains unavailable
when the underlying terminal cannot support deadlines; other approval adapters
retain their cancellation contracts.

## Combined oracle and verification decision, 2026-10-04

Integrate the accepted KDF implementation and the read-policy candidate before
final shutdown verification. Shutdown, authorization and bounded reads share
production handlers; testing isolated branches would leave their interaction
unverified. Merge the read-policy PR first, then this dependent PR using ordinary
protected merges with the tested head SHA.

Freeze the combined production Go source at
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c`, retained by
`oracle/http-shutdown-source-20261004`. Re-execute all 25 MCP captures and the
27-case authenticated HTTP capture against those actual bytes. Their recorded
observations are unchanged. Expand the source inventories to 177 production
files covering vault, crypto, config, filesystem, template, MCP, policy,
approval and secure UI. The inventory guard also rejects a compiled untracked
helper omitted from these declared package closures. Bind the HTTP generator's
own bytes separately, and require cleanup to complete rather than silently
accepting a still-running oracle server.

Always select the memory keyring and disposable HOME/XDG directories inside
the HTTP generator. HOME isolation alone does not isolate an OS credential
service. Keep the read-resource fixture's previous immutable source pin and
independently execute its current-candidate check; unrelated handler changes do
not justify replacing historical observations with manually edited metadata.

The combined full Rust workspace passes 1,229 tests with six existing ignored
tests. All Go generator tests pass and strict owning-package lint reports zero
issues. The full port contract, current-candidate read proof and owning-package
race tests must also pass. Native Linux/macOS/Windows jobs remain acceptance
requirements; pending jobs are not counted as completed evidence.
