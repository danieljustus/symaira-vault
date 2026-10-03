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
