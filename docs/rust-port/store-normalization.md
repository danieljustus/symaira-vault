# Store observation comparison contract

Version: `store-observation-v1` (issue #1015).

`store.json` remains a raw capture from the actual detached Go `caadd5e`
(v0.22.1) implementation. Its encrypted bytes are authenticated, materialized
and read by Rust interoperability tests. Raw ciphertext bytes are test inputs,
not a requirement that two randomized encryptions produce identical output.
The fixed identity is public, synthetic fixture material. Production encryption,
clocks and vault code are unchanged.

`storegen --check` rejects unknown JSON fields, validates complete source/generator
provenance, executes both
fresh and legacy layouts again and compares the following projection. This is
also required before a provenance-only refresh writes a file. Generation still
records genuine raw observations; it does not rewrite encrypted payloads or
pretend the projection is a Go capture.

| Observation | Comparison rule |
| --- | --- |
| Every captured file | Decode base64 and verify its raw size/SHA256 before normalization. |
| Every `.age` file | Authenticate and fully decrypt with the synthetic identity; failure is fatal. Compare normalized plaintext instead of randomized ciphertext, deriving projected size/SHA256 from that plaintext. |
| Entry `meta.created`/`meta.updated` | Require valid nonzero RFC3339 timestamps and equality for these newly written entries. Replace these two parsed fields only with a fixed comparison sentinel. Preserve all other JSON bytes, including user values that resemble timestamps, field order, number representation and escaping. |
| Entry observations | Require exact JSON and decoded observation consistency, and identical before/after migration observations. Apply the same two-clock rule. |
| Manifest | Preserve version, generation and entry inventory. Verify every authenticated entry digest/size against its actual captured ciphertext before projecting it to the corresponding normalized entry digest/size. Require valid creation/update ordering; normalize those clocks and each entry's parsed `mtime`. |
| Config | Require `vaultDir` to name the generated `symvault-store-oracle-*` temporary root. Replace only this YAML scalar with a sentinel; preserve every other YAML node/value. YAML presentation is not a contract here. |
| Platform file modes | Preserve Unix modes exactly. A capture explicitly labelled `windows` must report Go's generic writable-file `0666`/directory `0777` stat bits; map those to the corpus's `0600`/`0700` comparison modes. This does not assert Windows ACL parity. Unknown modes/platforms fail. |
| Migration | Preserve raw byte-identical before/after file evidence, paths, directories, marker and `data_preserved`; reject inconsistent duplicate after snapshots. |
| All other fields | Preserve source pin and digests, generator file list/digest, layout and case inventories, paths, identity plaintext, recipients, presence, type vectors and malformed bytes. Only the explicit capture-platform label becomes a comparison sentinel. |

Two independent real generations must differ as raw captures and agree under
this projection. Negative controls cover semantic entry/type/path/mode/presence
changes, malformed input, recomputed-public-hash ciphertext corruption and valid
ciphertext swaps that violate authenticated manifest binding. A clock-looking
user value and JSON formatting outside selected metadata remain unchanged.
A projection mismatch is reported as semantic drift, and a failed live oracle
as unavailable; neither advises blindly resetting the fixture.

This contract adds no migration-row promotion, release approval, new resource
ceiling or claim about native device/UI behavior.
