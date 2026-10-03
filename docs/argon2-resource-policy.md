# Argon2 resource policy and historical vault migration

The host policy is `argon2-resources-v1`; the age stanza and vault format remain
unchanged. New identities retain 64 MiB, three passes and four lanes. Automatic
operations accept at most 128 MiB, four passes and four lanes. Each process
reserves at most 256 MiB of Argon2 working memory across four active derivations;
32 callers may wait up to ten seconds. Overload returns `resources busy`.
These limits bound KDF work, not total process memory or independent processes.

A resource-policy error is distinct from a wrong passphrase. Repeated retries,
HTTP/MCP calls and automatic zero-key healing do not enable historical budgets.
The entire Argon2 recipient set is checked before derivation: at most four
stanzas and total cost no greater than 128 MiB times four passes.

To migrate a trusted older local vault:

```sh
symvault --vault /path/to/vault migrate kdf --allow-legacy-kdf
```

The command prompts for the existing passphrase and confirmation. `--yes`
skips only confirmation. It permits one exclusive historical Argon2 read with
the retained maximum of 2 GiB, 16 passes and 16 lanes, so the local host must
have enough memory for that identity. No global override is created. A Scrypt
identity with high configured future Argon2 parameters uses this route too.

The command verifies the original passphrase, encrypts and verifies the same
identity with current defaults, and preserves the original encrypted identity
and configuration as `identity.age.bak` and `config.yaml.bak`. It preserves
unknown configuration fields, sets format version 2 and default Argon2 values,
and removes the obsolete Scrypt work factor. A missing config remains absent.
Different existing backups are refused; preserve them before retrying.
Declining or supplying the wrong passphrase leaves both files unchanged.
The migration does not start services or populate indexes.

A late config-write failure restores both originals and retains the backups.
Each file replacement is atomic; the pair is not a filesystem transaction.
After a crash, stop vault services and other writers, retain copies of current
files, and restore **both** encrypted identity and config from the matching
backups before reopening with a compatible executable. Restoring only the
executable does not restore data. Keep backups until a normal unlock confirms
the migrated identity, and protect them as vault material.

Decision and compatibility rationale: [ADR 0007](adr/0007-argon2-resource-policy.md).
