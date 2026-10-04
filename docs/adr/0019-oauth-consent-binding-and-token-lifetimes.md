# ADR 0019: OAuth consent binding and configured token lifetimes

Status: accepted design; native acceptance pending.

## Decisions

Keep cryptographic randomness for client IDs, authorization codes, browser flow
tickets and access/refresh tokens. A fixture must exercise the actual issuer;
it must not replace entropy or production clocks to obtain equal response bytes.
Keep the strict Date-only HTTP corpus from ADR 0017 and supplement it with
explicit semantic controls for entropy, time, consent UI and security decisions.
Retain complete actual wire responses, requests and headers in both corpora.

Keep the Rust browser confirmation bound to a server-side, expiring, single-use
flow ticket. Client, redirect URI, state and S256 challenge come from that stored
request, rather than mutable hidden form fields. Wrong passphrase must not mint
tokens; a correct passphrase verifies the real encrypted vault identity. Denial
consumes the ticket and redirects with the original state. Add no-store to the
consent page. These decisions preserve the user's original authorization intent
and prevent browser caches from retaining an active consent ticket.

The actual Go browser form carries editable client/redirect/state/PKCE fields.
Our real process control changes all of them before confirmation. Go redirects
to the changed registered client/URI and the original verifier then fails; Rust
redirects to the original URI/state and that verifier succeeds. Replaying the
confirmed Go form creates a fresh code, whereas Rust rejects the consumed ticket.
Go's Deny button navigates in the browser; a server POST with decision=deny and
no passphrase renders a missing-passphrase page. Rust accepts explicit denial
and issues no code or token. Record these specific differences, not a general
exception for OAuth responses or errors.

Honor explicit `mcp.oauth.access_token_ttl` and `refresh_token_ttl` from the owning
CLI configuration. Previously Rust silently ignored both and used 24h/720h.
Parse and preserve explicit OAuth settings through config save/reload. Match
Go's positive-only merge: missing/null, zero and valid negative durations retain
the defaults; invalid duration syntax fails. The effective defaults remain
24h access and 720h refresh. An absent optional config block keeps the established
configuration projection; runtime defaults do not depend on serializing it.
Expose positive TTL inputs at the library boundary without changing existing
serve function signatures. Reject zero or unsupported explicit library TTLs.

A still-valid refresh token can renew an expired access token with the effective
configured positive access TTL. Keep the original refresh deadline and revoke
the old access/refresh pair atomically. Access expiry must not implicitly make
the replacement permanent or extend refresh authorization. This supports the
OAuth refresh lifecycle while maintaining a finite authorization window. The
pinned Go implementation rejects refresh after access expiry; record that
specific difference and verify both actual outcomes. For ordinary rotation,
keep the existing access and refresh deadlines and reject replay.

## Evidence and boundaries

`http_oauth_contract.py` rebuilds immutable Go
`d1cd0f97ac550bc3020bc86b0514989f8d28d95c` and drives real installed CLI entry
points over native loopback TCP. Its Go helper uses real config, vault and token
APIs to create encrypted fixtures with Argon2id 19456 KiB/2/1. Go and Rust start
each phase from byte-identical seeded files in disposable HOME/XDG roots and
use the same port sequentially. The OAuth agent is configured explicitly;
default-agent fallback is not claimed by this fixture. A high explicit fixture
rate limit separates lifecycle proof from rate-limit exhaustion acceptance.

The 35 default-lifetime cases execute independent DCR, browser consent with
wrong/correct passphrases, S256 success/failure, consumed-code replay, issued
token use and agent mismatch, refresh rotation/replay, old-token denial, consent
replay/tamper/denial, and process restart. After restart, clients and issued
tokens remain usable, refresh still rotates and an unpersisted pending code is
rejected. Storage snapshots verify token hashes, scopes, label/agent binding,
revocation and deadlines; raw token values must not be persisted.

Eleven additional cases use actual two-second access and one-minute refresh
configuration. Both processes allow a real handler call before access expiry
and reject access after actual elapsed expiry. Go rejects subsequent refresh;
Rust returns an independently generated pair with a two-second access lifetime
and the unchanged refresh deadline. That pair must initialize and call the real
health handler while the old access stays denied. No simulated time substitutes
for this process control. Existing owning regressions also verify custom TTLs
and config roundtrip/default/error behavior.

All 46 cases per implementation pass in local development. Individually assert
the semantic controls, including complete header multisets; compare remaining
status/header/body/wire bytes with only Date excluded. Assert fresh formats and
independent entropy across implementations, and retain actual times and bytes.
No broad nonce/timestamp replacement or body rewriting is used. Public ephemeral
fixture token responses necessarily contain issued tokens and are retained as
private test receipts. Credentials and old/new fixture tokens must never occur
in process stdout/stderr or unrelated responses; console output reports counts.

Drain both owned process output pipes with the ADR 0017 bounded capture. Force
fixture disposal only after observations and join readers; the three process
lifetimes per implementation do not prove graceful shutdown. Inventory sources,
driver/helper, embedded assets and executable hashes throughout a clean run.

The required Linux/macOS/Windows workflow runs the same real corpus, owning
runtime/config tests and the original 51-case HTTP corpus. Native gates, HEAD,
the full hostile origin/Host/framing/slow-peer matrix, complete token storage
and expiration boundaries, TLS/mTLS acceptance and GUI/TTY/device consent remain
separate required work. HTTP-001..004 and #1249 stay open until full acceptance.
