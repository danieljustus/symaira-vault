# ADR 0005: Post-Quantum Transition Plan for Vault Crypto Envelope

**Date:** 2026-06-18
**Status:** Proposed
**Author:** Symaira Vault Team

## Context

Symaira Vault uses [age](https://age-encryption.org/) (v1.3.1) for all
encryption operations. The current cryptographic baseline is:

- **Key exchange**: X25519 (Curve25519 ECDH)
- **Symmetric encryption**: ChaCha20-Poly1305 (AEAD)
- **Key derivation**: scrypt (N=262144, r=8, p=1) with a planned migration to
  argon2id (see SECURITY.md KDF Migration Path)

This combination provides strong classical security. However, a
cryptographically-relevant quantum computer (CRQC) could break X25519 via
Shor's algorithm. NIST has standardized Module-Lattice Key Encapsulation
Mechanism (ML-KEM, FIPS 203) as the primary post-quantum key-establishment
standard, and the BSI (German Federal Office for Information Security) also
recommends ML-KEM-768 as the transition target for government and regulated
procurement.

The EU commercialisation research (see
`docs/research-handoff-eu-commercialization.md`) flagged that German and EU
regulated buyers will ask for a documented post-quantum transition plan before
long-term procurement decisions. No public Symaira Vault documentation currently
mentions PQC, ML-KEM, hybrid recipients, or a migration strategy.

**This document does not implement any crypto migration. It establishes the
strategy and monitoring commitments so that operators, auditors, and
procurement reviewers can assess the project's readiness posture.**

## Current Cryptographic Baseline in Detail

| Layer | Mechanism | Standard / Source |
|-------|-----------|-------------------|
| Public-key encryption | X25519 (Curve25519 ECDH) | RFC 7748 |
| Authenticated symmetric encryption | ChaCha20-Poly1305 | RFC 8439 |
| Passphrase key derivation (identity) | scrypt (N=262144, r=8, p=1) | RFC 7914 |
| Passphrase KDF (planned) | argon2id | RFC 9106 |
| Key encoding | Bech32 (`age1...`, `AGE-SECRET-KEY-1...`) | age specification |

All vault entries are individually encrypted `.age` files. The vault identity is
an `*age.X25519Identity` serialised with Bech32 and stored in an encrypted file
(`identity.age`).

## Upstream Availability: age v1.3.1 Already Supports Post-Quantum Hybrid Keys

The dependency `filippo.io/age` version v1.3.1 already ships post-quantum hybrid
key types:

| Type | Public Key Prefix | Secret Key Prefix | Stanza |
|------|-------------------|-------------------|--------|
| X25519 (current) | `age1...` | `AGE-SECRET-KEY-1...` | `X25519` |
| Hybrid ML-KEM-768 + X25519 | `age1pq...` | `AGE-SECRET-KEY-PQ-1...` | `mlkem768x25519` |

The hybrid type (`age.HybridRecipient` / `age.HybridIdentity`) uses HPKE
(ML-KEM-768 + X25519) via `filippo.io/hpke`. This means age v1.3.1 provides a
concrete, supported upstream option for post-quantum encryption right now.

### Critical Constraint: Recipient Label Isolation

age v1.3.1 enforces a label-based isolation rule: `HybridRecipient` returns a
`"postquantum"` label via `WrapWithLabels`. The age library prevents mixing
recipients with different labels in the same `age.Encrypt()` call. This means:

- A single `.age` file cannot be encrypted to both a `*age.X25519Recipient` and
  an `*age.HybridRecipient` simultaneously.
- Migrating a vault entry from X25519 to hybrid encryption requires
  **re-encrypting** the entry file with the hybrid recipient and removing the
  X25519 recipient.
- This makes a grace-period "dual recipient" mode impossible at the single-file
  level without workarounds (e.g., wrapping one recipient type to drop labels).

### Workaround for Dual-Key Support

If the project needs to keep both keys usable during a transition window (for
example, a user rotates their identity but older backups still use X25519), the
label restriction can be bypassed by wrapping `HybridRecipient` in a custom type
that does not implement `WrapWithLabels`. This is fragile, increases
maintenance surface, and should only be considered for a documented transition
period, not as a permanent design.

## Migration Risks and Constraints for Existing Vaults

### 1. Identity Format Break

The vault identity pipeline currently works with concrete `*age.X25519Identity`
types:

- `GenerateIdentity()` calls `age.GenerateX25519Identity()`
- `SaveIdentity()` expects `*age.X25519Identity`
- `LoadIdentity()` parses with `age.ParseX25519Identity()`
- `GetRecipientFromIdentity()` returns `*age.X25519Recipient`

A hybrid identity would require parallel or alternative functions accepting
`*age.HybridIdentity`. The API surface in `internal/crypto/` uses strong typing
rather than the `age.Identity` interface, so adding hybrid support touches
every caller.

### 2. Recipient Management Format Break

Recipient parsing (`ValidateRecipient`) expects `age1...` prefix and calls
`age.ParseX25519Recipient()`. Hybrid recipients use `age1pq...` prefix and
require `age.ParseHybridRecipient()`. The existing recipient storage, listing,
and multi-user sharing code would need to handle both formats.

### 3. File Format Migration (All Entries)

Every vault entry (each `.age` file in `entries/`) is encrypted to X25519
recipients. Migrating to hybrid encryption requires re-encrypting every entry.
The number of entries could be thousands, and each re-encryption requires the
vault to be unlocked.

### 4. Multi-User Vault Break

The multi-recipient sharing system (`internal/vault/recipients.go`) stores
X25519 recipient strings and encrypts entries to all of them. With the label
isolation constraint, you cannot encrypt a single entry to a mix of X25519 and
hybrid recipients. A vault shared between users would require all participants
to migrate simultaneously, or a coordination mechanism that re-encrypts
per-recipient on read.

### 5. Backup and Recovery Compatibility

Backup archives (`.tar.gz` created by `symvault backup`) contain encrypted
vault files, identity material, and config. A hybrid identity would not match
existing X25519 backups. Restore from a pre-migration backup after migration
would fail unless both key formats are kept.

### 6. Third-Party Tool Interoperability

Symaira Vault's age-encrypted files are standard `.age` files. Any tool that
consumes age-encrypted vault entries (monitoring, export scripts, custom
tooling written by users) would need to support the `mlkem768x25519` stanza
type. At the time of writing, many age-based tools and libraries are still
catching up to the hybrid format.

## What Would Require a File Format or Identity Format Migration

A file format or identity format migration would be triggered by any of the
following:

1. **A user generates a new hybrid identity** (`age1pq...` key). The vault
   identity file format changes because the decrypted identity string now
   starts with `AGE-SECRET-KEY-PQ-1...` instead of `AGE-SECRET-KEY-1...`.

2. **A vault switches its primary encryption recipient from X25519 to hybrid**.
   Every vault entry must be re-encrypted because a single `.age` file cannot
   mix X25519 and hybrid recipients.

3. **A multi-user vault adds a hybrid-recipient user**. Every existing shared
   entry must be re-encrypted, unless all participants switch simultaneously.

4. **The passphrase-based encryption path changes**. Passphrase-encrypted
   entries (used by the identity file encryption) do not have the same label
   constraint because scrypt/argon2id recipients don't implement
   `WrapWithLabels`. However, the identity stored inside is the key format that
   changes.

A migration is NOT required for:
- Users who stay with X25519 indefinitely. The classical security of X25519 +
  ChaCha20-Poly1305 is not weakened by the existence of hybrid keys.
- Tools that only decrypt entries using the vault identity (they verify the
  stanza type at runtime).

## Migration Principles

### Principle 1: User-Initiated, Not Silent Migration

No automatic or silent re-encryption of vault entries. The user must explicitly
opt in via a dedicated command (similar to the KDF migration approach in
SECURITY.md). This avoids surprising failures on backup restore, multi-user
setups, or third-party tooling.

### Principle 2: Backward Compatibility Window

A migration tool must preserve the ability to decrypt the old format entries.
The simplest model: keep the X25519 identity for legacy decryption while the
hybrid identity becomes the primary encryption target. The old X25519 identity
is only discarded after the user confirms all entries and backups have been
migrated.

### Principle 3: Whole-Vault Migration

Because of the label isolation constraint, migration must process all vault
entries as a single operation. A partial migration (some entries hybrid, some
X25519) forces the user to manage two identities simultaneously, which
increases key-management complexity and the risk of data loss.

### Principle 4: Single Recipient Label Per Entry

Every `.age` file in the vault will be encrypted to exactly one recipient type
label (either all X25519 or all hybrid). The migration rewrites each entry file
by decrypting with the old identity and re-encrypting with the new one.

### Principle 5: Multi-User Coordination

For shared vaults, migration requires all participants to generate hybrid keys
before the vault operator initiates the migration. The command must check that
all stored recipients are of the same family (hybrid vs. X25519) before
proceeding.

### Principle 6: Documented Toolchain Compatibility

The migration command must warn about third-party tool compatibility before
proceeding. Users who rely on external age-based workflows should verify their
toolchain supports `mlkem768x25519` stanzas first.

## Migration Command Design (Future)

When implemented, the migration flow should follow the KDF migration precedent:

```
symvault migrate pq
```

Steps:
1. Generate a new `*age.HybridIdentity` (or use one the user provides).
2. Backup the existing vault (automatic or user-confirmed).
3. Decrypt each entry with the current X25519 identity.
4. Re-encrypt each entry with the new hybrid recipient.
5. Replace the stored identity with the hybrid identity.
6. Re-encrypt the identity file with the vault passphrase.
7. Update the recipient list if multi-user.
8. Log all migrated entries and any failures.
9. Keep the old X25519 identity in a backup location (not used for encryption,
   retained for legacy decryption only).

The vault config should track the active key type (e.g.
`crypto.keyType: hybrid-mlkem768x25519` or `crypto.keyType: x25519`) for
doctor checks and future automation.

## Near-Term Monitoring Inputs

### 1. age Upstream Development

- **Tracked**: filippo.io/age v1.3.1 and later releases.
- **Watch**: The `filippo.io/age` `pq.go` file for changes to hybrid recipient
  handling, label rules, or the introduction of standalone ML-KEM (without
  X25519 fallback) as the ecosystem matures.
- **Watch**: Any changes to the label isolation design that would allow
  grace-period dual-key encryption.

### 2. Go Standard Library Crypto

- **Tracked**: `crypto/mlkem` package (proposed for Go standard library).
- **Status**: Not yet in any Go release as of Go 1.26.4.
- **Trigger**: Once `crypto/mlkem` is available in the Go standard library, age
  and other Go crypto libraries may migrate their ML-KEM dependency to the
  stdlib implementation, potentially changing the import path or API.

### 3. BSI (Germany) Guidance

- **Tracked**: BSI TR-02102 (Cryptographic Mechanisms: Recommendations and Key
  Lengths).
- **Current**: BSI recommends ML-KEM-768 (FIPS 203) as the post-quantum KEM for
  government procurement, with a migration horizon of 2026-2030.
- **Trigger**: If BSI accelerates its timeline or mandates hybrid-only encryption
  for certain procurement categories, it directly affects the priority of this
  migration for EU regulated buyers.

### 4. NIST FIPS Standards

- **Tracked**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).
- **Current**: ML-KEM-768 is finalised and used by age v1.3.1.
- **Watch**: Any revision to FIPS 203 parameters that would change the age
  hybrid stanza format.

### 5. Interoperability Expectations

- **Tracked**: Adoption of `mlkem768x25519` stanza in the age ecosystem.
- **Watch**: Whether age CLI (`age -p`) and `age-keygen -pq` are adopted by
  downstream tools, package maintainers, and CI/CD systems that interact with
  vault entries.
- **Trigger**: When the age-encrypted file format with hybrid stanzas is
  supported by major age-consuming tools (e.g., `rage`, `age-plugin-*`,
  language-specific age bindings), the interop risk during migration decreases
  and the migration priority can be raised.

### 6. User Demand Signals

- **Tracked**: GitHub issues, procurement inquiries, security reviews.
- **Trigger**: Multiple inquiries from EU regulated buyers, or a procurement
  requirement listing PQC readiness as a gating criterion.

### 7. Key Size and Performance Impact

Hybrid identities are larger than X25519 identities:

| Measure | X25519 | Hybrid (ML-KEM-768 + X25519) |
|---------|--------|------|
| Public key (recipient) string | ~62 chars (age1...) | ~76 chars (age1pq...) |
| Private key (identity) string | ~70 chars (AGE-SECRET-KEY-1...) | ~90 chars (AGE-SECRET-KEY-PQ-1...) |
| Encryption overhead per entry | ~200 bytes | ~1200 bytes (shared secret + ciphertext) |
| Key generation time | <1ms | ~1-2ms |
| Encryption/decryption cost | ~microseconds | ~100-200 microseconds |

The per-entry size increase (~1KB) is negligible for vault storage. The
performance cost is acceptable for a CLI password manager. No blockers here.

## Timeline and Triggers

| Phase | Trigger | Action |
|-------|---------|--------|
| **Monitor** (now) | None | This ADR; document the plan; no code changes |
| **Evaluate** | age upstream stabilises dual-key support or removes label restriction | Prototype hybrid identity generation in a feature branch |
| **Implement** | >=2 of: (a) BSI guidance deadline approaches, (b) Go stdlib ML-KEM lands, (c) user demand reaches procurement threshold | Ship `symvault migrate pq` as opt-in |
| **Default** | age ecosystem drops X25519-only default | Switch `symvault init` to hybrid by default |
| **Mandate** | Regulatory requirement for PQC-only encryption | Provide migration tooling and deprecation warning for X25519 |

The project commits to publicly documenting progress on this timeline in the
ADR and on related GitHub issues.

## Consequences

- **No immediate code change.** This ADR is documentation only. The vault
  continues to use X25519 + ChaCha20-Poly1305 as the default.
- **Procurement readiness.** EU regulated buyers can reference this document as
  evidence of a planned post-quantum migration path.
- **Upstream dependency.** The migration plan depends on upstream age and Go
  crypto developments. The project will not implement a custom crypto primitive.
- **Pro consumption.** The private `symaira-vault-pro` repository can reference
  this public-core ADR when answering procurement questions about the hosted
  service's PQC readiness. Any Pro-specific PQC requirements that require core
  changes must first be implemented here, released, and then consumed.

## References

- [age v1.3.1 pq.go](https://pkg.go.dev/filippo.io/age@v1.3.1#HybridIdentity) —
  ML-KEM-768 + X25519 hybrid key implementation
- [filippo.io/hpke](https://pkg.go.dev/filippo.io/hpke) — HPKE library used by
  age for hybrid encryption
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM (Module-Lattice
  Key Encapsulation Mechanism)
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization)
- [BSI TR-02102](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102.html) —
  Cryptographic Mechanisms: Recommendations and Key Lengths
- [RFC 9106](https://datatracker.ietf.org/doc/rfc9106/) — Argon2id (planned KDF
  migration target, see SECURITY.md)
- `docs/research-handoff-eu-commercialization.md` — EU compliance research
  findings that triggered this plan
- `docs/adr/0003-memory-wipe-for-sensitive-data.md` — Existing ADR on crypto
  memory safety
- `SECURITY.md` — Current crypto documentation and KDF migration plan
