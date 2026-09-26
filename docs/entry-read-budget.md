# Entry Read Budget V1

Go `vault.ReadEntry`/`readEntryInner` and Rust `Store::get` enforce the same
versioned resource envelope before allocating entry contents:

| Layer | Limit | Enforcement |
| --- | ---: | --- |
| Age ciphertext | 24 MiB | Opened regular file is size-checked, then read through a 24 MiB + 1 byte cap. |
| Decrypted plaintext | 16 MiB | Age output is read through a 16 MiB + 1 byte cap; excess output is wiped and rejected. |

The plaintext allowance is deliberately generous for a single JSON vault
entry. The larger ciphertext allowance leaves room for Age's armored encoding,
header, and per-chunk authentication framing around a full 16 MiB plaintext.
Both limits are rejection limits: readers never truncate an entry. The
one-byte probe makes the exact limit valid and the first byte over invalid.

This policy is entry-specific. Rust's existing 16 MiB `MAX_FILE_BYTES` remains
the bound for config and other generic vault files. The V1 read budget does not
change entry serialization, JSON depth/value limits, or write APIs; entries
already larger than this read envelope are rejected instead of being loaded.
Changing either limit requires a new versioned contract and matching Go/Rust
boundary tests.
