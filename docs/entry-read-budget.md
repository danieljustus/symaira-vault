# Entry Read Budget V1

Go entry readers and Rust `Store` entry readers enforce the same versioned
resource envelope before allocating entry contents:

| Layer | Limit | Enforcement |
| --- | ---: | --- |
| Age ciphertext | 24 MiB | Opened regular file is size-checked, then read through a 24 MiB + 1 byte cap. |
| Decrypted plaintext | 16 MiB | Age output is read through a 16 MiB + 1 byte cap; excess output is wiped and rejected. |
| Entry data shape | 1,024 top-level fields; 1,024 total nested fields; depth 32; 1,024 array elements; 1 MiB per string/key | Validated before typed entry deserialization and on both writers. |
| Vault entry traversal | 100,000 visited filesystem entries; logical path depth 64 | Go and Rust writers and enumeration use the same ceiling. |

The plaintext allowance is deliberately generous for a single JSON vault
entry. The larger ciphertext allowance leaves room for Age's armored encoding,
header, and per-chunk authentication framing around a full 16 MiB plaintext.
Both limits are rejection limits: readers never truncate an entry. The
one-byte probe makes the exact limit valid and the first byte over invalid.

This policy is entry-specific. Rust's existing 16 MiB `MAX_FILE_BYTES` remains
the bound for config and other generic vault files. The data-shape ceilings
match Go and Rust readers and writers; they prevent a small ciphertext from
expanding into an excessively deep or broad in-memory value. Vault-rooted reads
use a root capability, so an entry path cannot escape through a parent symlink.
Entries that exceed any listed limit are rejected, never truncated or
published by either writer. Changing a limit requires a new versioned contract
and matching Go/Rust boundary tests.
