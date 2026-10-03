# Retained Argon2 0.5.3 compatibility patch

This is the public RustCrypto `argon2` 0.5.3 crate, retained under its original
MIT/Apache licenses. `UPSTREAM.json` records its registry archive checksum,
upstream revision and hashes of every retained original file. The archive hash
matches the previous root Cargo.lock. Source and known-answer tests are retained.

The sole upstream source change adds `Params::new_go_legacy_memory`. Released
Go accepts encoded memory from `4 * lanes` while its Argon2 implementation fills
at least `8 * lanes` blocks. The requested memory is included in H0 **before**
that minimum is applied. Upstream `Params::new` rejects this historical range;
raising the encoded memory produces a different key and rejects genuine vaults.

The added constructor permits only `4 * lanes <= memory < 8 * lanes` with
1–16 lanes. It delegates time/output validation to the unchanged constructor,
then preserves the original memory field. Upstream hashing, compression, block
filling and the standard constructor remain unchanged. Host policy reserves
the effective memory before derivation. Production write defaults stay at
64 MiB, three passes and four lanes.

The immutable released Go source generates and authenticates the retained
`minimum_read` identity with memory=4 and lanes=1. Both implementations must
read it with the original passphrase. Upstream known-answer tests and a source
hash guard cover the standard algorithm and limit the retained patch surface.

On a dependency update, compare all upstream changes, regenerate provenance
from the public archive, rerun upstream known answers and genuine Go historical
vectors, and update both the root and fuzz locks. Remove the patch when upstream
provides an equivalent explicit compatibility constructor. Never replace this
with parameter rounding or a separate cryptographic implementation.
