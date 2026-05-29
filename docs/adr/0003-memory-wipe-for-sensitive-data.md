# ADR 0003: Memory Wipe for Sensitive Data

## Status

Accepted (reconfirmed 2026-05-28 after code review reassessment)

## Context

Symaira Vault handles highly sensitive data:

- Master passphrases for vault unlocking
- age identity bytes (X25519 private keys)
- Decrypted entry fields (passwords, TOTP secrets)

By default, Go stores strings and byte slices on the heap. When these values
are no longer referenced, the garbage collector reclaims the memory—but does
not overwrite it. This leaves sensitive data in process memory until that
memory page is reused.

Threats:

1. **Heap dump / core dump**: A crash or deliberate dump captures the entire
   process memory, including lingering passphrases.
2. **Swap to disk**: The OS may swap memory pages to disk, writing secrets to
   persistent storage.
3. **Debugger attachment**: A debugger can inspect process memory and extract
   secrets.

We evaluated two approaches:

### Option A: github.com/awnumar/memguard

`memguard` provides `Enclave` and `LockedBuffer` types that use `mlock(2)` to
prevent swapping and overwrite data on free.

Pros:
- Stronger guarantees against swap and GC copies
- Handles `mlock` fallbacks for platforms without it

Cons:
- Additional dependency (~2k LOC)
- Requires significant refactoring (replace `string`/`[]byte` with `memguard`
  types throughout crypto and vault packages)
- `mlock` limits may be hit in constrained environments

### Option B: Best-effort `crypto.Wipe` helper

A simple function that overwrites a byte slice with zeros.

Pros:
- Zero dependencies
- Minimal code changes
- Works on all platforms

Cons:
- Does not prevent GC from copying data during allocation/movement
- Does not prevent swapping
- Best-effort only

## Decision

We implement **Option B** (`crypto.Wipe`) as the minimum viable security
measure, with a documented path to Option A if threat models require it.

Rationale:

1. The primary threat for a CLI password manager is local malware or
   post-compromise forensics. `Wipe` raises the bar by ensuring the most
   obvious copies of secrets are cleared.
2. Go's GC copying is a real but secondary concern. The passphrase exists in
   memory only briefly during unlock; wiping it immediately after use removes
   the largest window of exposure.
3. Adding `memguard` would touch every crypto and vault API, increasing
   complexity and risk of bugs. We defer this until a concrete threat model
   justifies the cost.

## Implementation

### Phase 1 (Original)

- `internal/crypto.Wipe` is added and called with `defer` after passphrase
  use in `cmd/root.go`.
- **Limitation**: Passphrase was converted from `[]byte` (terminal input) to
  `string` immediately at the read boundary. `crypto.Wipe([]byte(passphrase))`
  created and wiped a *copy* — the immutable original `string` remained in the
  heap. This was a documented limitation but not an effective wipe.

### Phase 2 (Completed — OPENPASS-554)

- Passphrase is kept as `[]byte` from input (`term.ReadPassword`) through the
  entire lifecycle: cmd layer → vault layer → crypto layer → age library
  boundary.
- `crypto.Wipe(passphrase)` now zeros the *actual* passphrase bytes, not a
  copy.
- Only at the age library boundary (`age.NewScryptRecipient`,
  `age.NewScryptIdentity`) is `string(passphrase)` used. The age library
  internally converts to `[]byte` anyway, so the `string` copy is transient.
- All call sites audited: `cmd/root.go`, `cmd/auth.go`, `cmd/init.go`,
  `internal/mcp/tools_auth.go`, `internal/session/`, `internal/vault/`,
  `internal/crypto/`.
- Tests updated: `go test ./...` passes. Build clean.

### Phase 3 (Completed — OPENPASS-549)

Extended wipe coverage to decrypted entry data and additional passphrase paths:

- `internal/vault/entry.go:ReadEntry` — `defer vaultcrypto.Wipe(plaintext)` after
  decrypting entry JSON (covers all read paths: get, find, edit, MCP tools).
- `internal/vault/entry.go:GetEntryMetadata` — `defer vaultcrypto.Wipe(plaintext)`
  after decrypting entry for metadata extraction.
- `internal/crypto/keygen.go:LoadIdentity` — `defer Wipe(plaintext)` after
  reading decrypted age identity key material.
- `cmd/init.go` — `defer cryptopkg.Wipe(passphrase)` after reading vault
  initialization passphrase.
- `cmd/set.go` — `defer cryptopkg.Wipe(password)` after reading interactive
  password input.
- `cmd/add.go` — `defer cryptopkg.Wipe(password)` after reading interactive
  password input.
- `internal/session/memory_keyring.go:Get` — capture and `zeroBytes(plain)` the
  decrypted passphrase verification result (was previously discarded without
  wiping).

Total `crypto.Wipe` / `zeroBytes` call sites: 10 (3 original + 7 new).

## Consequences

- `crypto.Wipe` is now effective for the passphrase lifecycle.
- Decrypted entry fields should still be wiped after use (applied where feasible).
- The ADR is reviewed if:
  - A security audit identifies heap exposure as a critical finding
  - We add a daemon mode where secrets persist in memory longer
  - We target platforms with stricter memory-protection requirements

## References

- [memguard](https://github.com/awnumar/memguard)
- Go runtime: strings are immutable; `[]byte` may be copied by GC
- `mlock(2)` man page for swap prevention
