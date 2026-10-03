# ADR 0007: Versioned Argon2 resource policy and explicit legacy migration

## Status

Accepted product decision, 2026-10-03. Implementation and issue #1002 acceptance
remain pending until the Go/Rust resource, compatibility and migration checks
pass. The maintainer delegated the remaining product choices and their recorded
rationale on this date.

## Context

The retained Argon2id format accepts up to 2 GiB, 16 passes and 16 lanes. These
are format compatibility ceilings, not suitable automatic-service budgets.
An unauthenticated age header chooses its KDF parameters; simultaneous requests
and repeated recipient attempts multiply the cost before authentication.

Changing only Rust would make previously interoperable vaults unreadable in
one implementation. Raising decryption floors would also reject genuine older
small-parameter envelopes. Configuration loading must remain possible before
an old vault can be migrated.

## Decision

Adopt host resource policy `argon2-resources-v1` in both implementations. Keep
the `argon2id` stanza, salt encoding, HKDF label `symvault-argon2id-v1` and vault
format version 2 unchanged: a resource admission policy does not require a new
cryptographic suite or irreversible data-format change.

| Boundary | Policy |
| --- | --- |
| Default new encryption | Existing 64 MiB, 3 passes, 4 lanes |
| Automatic encryption/decryption | At most 128 MiB, 4 passes, 4 lanes per derivation |
| Per-process automatic admission | At most 256 MiB of reserved Argon2 working memory and 4 active derivations |
| Pending admission | At most 32 waiters, each waiting at most 10 seconds; exhaustion returns a resource-busy error |
| Untrusted recipient attempts | At most 4 Argon2 stanzas; preflight the entire set before KDF work, with total work no greater than 128 MiB × 4 passes |
| Historical format/config validation | Retain 2 GiB, 16 passes, 16 lanes for classification and migration |
| Explicit historical read | Only `migrate kdf --allow-legacy-kdf`; one exclusive derivation in the process, historical ceilings still enforced |

The memory reservation includes Argon2's effective minimum of 8 KiB per lane.
It is a KDF working-memory bound, not a promise that total process RSS is 256
MiB: the runtime, ciphertext, plaintext and other services use additional
memory. Independent CLI processes have independent budgets. The local user
already controls how many processes they launch.

The bounded queue tolerates a short burst of ordinary local unlocks without
allocating all KDF work simultaneously. Its count and deadline prevent an
unbounded backlog. An explicit legacy operation excludes ordinary derivations
and is never selected by envelope contents, configuration, environment, MCP,
HTTP, daemon or automatic zero-key healing.

Validate a bounded, unambiguous parameter triplet, the exact salt and wrapped
file-key shape before entering the KDF. Preserve legitimate field ordering and
older low-budget reads; use the existing stronger floors for new configuration.
Distinguish malformed input, historical format bounds, current resource-policy
rejection, resource-busy and authentication failure. Preserve resource errors
through the age adapter; they must not trigger zero-key recovery retries.

## Compatibility, migration and rollback

Ordinary historical envelopes within the automatic policy remain readable with
the same passphrase and key derivation. Envelopes above it receive an actionable
policy error instead of silently consuming the historical maximum. The explicit
local migration reads them with historical compatibility and rewrites the same
identity using the unchanged default parameters and format. It must verify
the original passphrase and replacement identity, prepare configuration before
mutation, retain an encrypted backup, and restore the original identity if a
later write fails. Declining migration or a wrong passphrase leaves files intact.

Do not advertise an Argon2 envelope as already current merely because its
stanza family is Argon2id. Inspect its parameters without deriving a key and
report when this migration is needed. Retain the original encrypted identity
and configuration for rollback; reverting the executable alone is not a data
migration. Never weaken the new default to work around a policy rejection.

## Alternatives and rationale

- Keeping automatic 2 GiB acceptance and merely serializing requests still
  permits one unauthenticated request to exhaust a typical client or service.
- Lowering a format parser ceiling globally strands existing vaults before
  their owner can recover them. Separate format validation and execution
  admission preserve an explicit, bounded compatibility route.
- A new age stanza or HKDF label changes the cryptographic format without
  being needed to enforce resource admission. Retaining the existing wire
  contract preserves Go/Rust and released-reader interoperability.
- An unbounded wait queue hides overload as growing latency and retained
  requests. Bounded admission provides a predictable failure classification.

## Verification required before closure

Verify exact and over-policy values without allocating a historical 2 GiB KDF;
reject malformed/duplicate/oversized parameters, malformed wrapping bodies and
excessive cumulative stanza work before derivation. Exercise actual concurrent
small derivations with admission observations, ordinary retained Go/Rust
envelopes, explicit historical migration, wrong passphrase, declined migration,
backup retention and write-failure rollback. Run owning package checks and
native CI. This ADR alone does not satisfy these acceptance requirements.

## Recorded implementation choices

A genuine released-Go `m=4,p=1` vector exposed a compatibility gap in the
RustCrypto standard parameter constructor. Go authenticates the requested
memory in H0 before applying its internal eight-block minimum; rounding the
requested parameter in Rust changes the key. Retain RustCrypto 0.5.3 with one
narrow parameter constructor, its original licenses and checksummed provenance
in `third_party/argon2`. Keep the upstream algorithm and standard constructor
unchanged. This preserves existing vaults without maintaining a second KDF.
The fixture exercises real authenticated encryption rather than a fabricated
header. Dependency updates must pass the upstream known-answer tests and this
Go vector before the retained patch can be replaced.

The explicit migration also accepts a Scrypt identity whose configured future
Argon2 write parameters exceed the automatic policy. This avoids stranding a
valid older vault behind an unusable write configuration. It uses the normal
Scrypt reader, resets future Argon2 writes to existing defaults, and follows the
same confirmation, backup and identity-verification transaction. Automatic
migration must reject such write parameters before creating a backup.

Load and validate migration configuration from the exact retained snapshot,
then validate the rendered replacement. Reopening the path for validation can
validate different bytes from the document that is later rewritten. Preserve
unknown fields; YAML formatting and comments may normalize. Retain both .bak
files without overwriting different previous backups, and restore both current
files after a late config write failure. Atomic replacement applies to each
file separately; a power loss between replacements is recovered using backups,
not described as a cross-file atomic transaction.

Normal config loading accepts `vault: null` as defaults. The new transaction
must treat it like an absent section, create the default vault mapping, and
retain unrelated fields. Independent candidate review reproduced this case;
both implementations carry a regression for it.

The existing pinned-Go migration gate retains its original Scrypt scenarios.
The new policy is an intentional correction absent from that released oracle;
a separate current-Go/Rust CLI gate exercises it using genuine historical
ciphertexts. Both gates are required, rather than asking the old executable to
accept a flag or resource policy that it never implemented.

The immutable implementation source `21f849ee971ba60ca3a85eaf4e61e6e520b41034`
is retained for command-tree and config/Auth-status fixture provenance. Actual
Go regeneration preserves every config, platform and Auth-status observation
and each source inventory; the only command-tree behavior change is the new
`migrate kdf` flag and its operational help. These are generated observations,
not manually rewritten source digests. The historical KDF oracle remains the
released `caadd5e` source and still authenticates its original envelopes.

The CXF generator records the importer's complete Go dependency closure, which
also includes config, crypto and vault. Recapture its twenty synthetic cases
against the same immutable source after the KDF changes. Every observation is
unchanged; its source inventory gains the two new resource-policy/migration
files, so retaining the old closure or merely replacing a digest would be
incorrect. The actual detached Go run and Rust replay both pass.

Native acceptance requires each named Go migration test to run. The vault
package's historical Windows `TestMain` otherwise exits without running any
tests; enable its existing cross-language opt-in on the disposable CI runner.
Keep the named pass/skip assertions, so a package exit code alone cannot prove
Windows coverage. The platform replay pins the actually regenerated immutable
source above. All three native policy jobs passed on head `7384ae75`. Subsequent source-binding
repairs and integration with main require fresh green jobs for the final head.

The ordinary Go CI also executes generator unit tests. The manifest-key source
inventory correctly rejected the newly added crypto files; its oracle advances
to retained source `41d5aaeb5eaa7685c69752f02a1f8f19450c7245`. Actual regeneration
preserves all 16 observations, and the Rust replay passes. Keep inventory and
source-content checks strict rather than exempting changed crypto dependencies.

The session generator's synthetic subprocess isolation test now invokes its
case runner directly. A harness probe does not represent a production CLI
oracle and must not require current production sources to match a historical
pin. The production generator still verifies its immutable source pin, and its
committed generator-digest test remains in place.
