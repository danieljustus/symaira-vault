# SESSION-002: the Go in-memory keyring is not opaque storage

Status: **decision required.** Nothing here is implemented. The divergence is
pinned by `crates/symvault-core/tests/keyring_keys_contract.rs`, whose
`KNOWN_DIVERGENCES` set is asserted exactly and may neither grow nor shrink
unnoticed, so this question stays visible until it is answered.

Measured at `7743fd21`. Fixture: `testdata/port/session/keyring-keys.json`.

## What the interface says

`internal/session.KeyringBackend` documents itself as opaque storage:

> `Get` returns the value previously stored under key, or `ErrKeyringNotFound`
> if no such entry exists.

The Rust `Keyring` trait is the same shape, and `MemoryKeyring` implements it
literally: a `BTreeMap<String, Vec<u8>>`.

## What the Go in-memory backend actually does

`internal/session/memory_keyring.go` is not a map. It branches on the account:

| account | `Set` | `Get` |
|---|---|---|
| `wrap-key`, `identity` | opaque | opaque |
| `session` | **opaque** | **parses the value as a session document** |
| anything else | requires session JSON, and **encrypts the passphrase** | parses |

The `session` row is the defect, and it is an asymmetry rather than a design:
`Set` accepts any value, and `Get` then parses it, and **deletes the entry when
the parse fails**. A value the backend has just accepted is destroyed on the
first read, and the caller is told the entry was never there.

Measured, both sides, same script:

```
set("symvault:/v|session", "opaque-value")   Go: ok        Rust: ok
get("symvault:/v|session")                   Go: not_found Rust: found
get("symvault:/v|session")                   Go: not_found Rust: found
```

## Why this is not merely cosmetic

Three consequences, in order of how much they matter.

### 1. Idle expiry is reported as the wrong error class

The backend enforces its own TTL check before the `Manager` sees the value, and
reports an idle-expired session as **not found**. On the OS-keyring path the
same session reaches `Manager.Load`, which reports it as **expired**.
SESSION-001's fixture pins `not_found` and `expired` as distinct error classes,
so which class a caller observes depends on which backend happens to be active.

The in-memory backend is the **fallback** — it activates precisely when the OS
keyring starts failing — so this is a live path, not a test-only one.

### 2. The TTL rule is duplicated, and the two copies differ

`Manager` checks idle TTL **and** `MaxLifetime` (`cacheExpired`,
`session.go:145`). The backend checks TTL only. Max lifetime is still enforced,
because the backend refreshes `LastAccess` but never `SavedAt` and `cacheExpired`
measures max lifetime from `SavedAt` — so there is **no security hole here**,
which is worth stating plainly rather than leaving implied. But the rule now
lives in two places with two different definitions, and only one of them is the
documented one.

### 3. There is a dead encryption path below the storage interface

For an account that is not one of the three known ones, `Set` parses the value
and encrypts the passphrase with a wrap key it looks up **in its own store**.
Production never reaches this branch: the three accounts it uses are exactly the
three that take the opaque path. So this is dead code that nonetheless
implements session encryption a second time, below the interface that is
supposed to know nothing about sessions.

## Recommendation

**Make the Go in-memory backend a plain key-value store**, matching its own
documentation, the OS backend, and the Rust side.

The TTL, last-access and encryption logic is not lost, because `Manager`
already implements all three above the interface — that is where the Rust port
put it, and where Go's own `Load` path already does the work. The change is a
deletion, not a reimplementation.

Two things must be verified before it lands, and neither is difficult:

1. **`Manager.Load` must still refresh `LastAccess` on the fallback path.**
   It does (`session.go:396`), but it writes through `Set`, so the round trip
   needs a test rather than a reading.
2. **An idle-expired session on the fallback path must report `expired`, not
   `not_found`.** That is the behaviour change users would see, and it is an
   improvement: the current message says the session was never there.

## Why it is not implemented here

This is security-relevant code in the session store, and the change deletes an
encryption path. It belongs in its own commit with its own evidence, not
bundled into the commit that discovered it. The divergence is pinned in the
meantime, in both directions: the fixture records what Go does *and* what a
plain store does, and the contract test fails if either side moves — including
if Go is aligned, which forces this paper to be revisited rather than letting
the row pass quietly.

## What is already aligned

Two smaller divergences found in the same audit were fixed directly, because
each was a one-line contract question with no ambiguity:

- **A key without the `service|account` separator** was silently stored by the
  Go OS backend under an empty service, where every such key collides. Rust
  refused it. Go now refuses it too, before touching the keychain.
- **Deleting an absent entry** returned `ErrKeyringNotFound` from the Go OS
  backend, against the interface's documented idempotence, the in-memory
  backend, and the Rust native backend. Every caller in `session.go` carried a
  compensating branch. Go now returns success; the compensating branches stay,
  because they still guard other backends.
