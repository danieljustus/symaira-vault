# Consumer handoff: config loader rejects what it used to discard, 2026-09-15

Status: **for consumer review before this line is released.** Nothing here is
implemented in any consumer repository, and no consumer document has been
changed. This file states what the Vault side changed and what, if anything, a
consumer has to do.

Vault side: `aa21ec4e`, CFG-003 step two. Decision paper and the measurements
behind it: `cfg-003-acceptance-adjudication.md`.

## What changed

Two inputs that both implementations used to accept are now rejected by both.

| Input | Before | After |
|---|---|---|
| `sessionTimeout: -5m` (also `0s`, and the same for `sessionMaxLifetime`) | loaded; the value was discarded and the **default** used instead | `Load` fails |
| a config file with a second YAML document after `---` | loaded; everything after the first document was **dropped without a word** | `Load` fails |

An absent key is unchanged: it still means "use the default". Only a key the
operator actually wrote and set to a non-positive value is rejected. The loader
now tracks which top-level keys the document carries, because Go's zero value
cannot tell "absent" from an explicit `0s` on its own.

## Why

Both were silent discards, which is the wrong failure mode for a password
manager: the operator believes a setting is in force when it is not. In the
duration case the rule already existed — `Validate` states it — but the merge
step threw the value away before `Validate` could see it, so the rule was
unreachable code. This makes it reachable.

The second-document case is the sharper one: an entire document of
restrictions could vanish, and nothing said so.

## Who is affected

**No API migration.** `internal/config` is an `internal` package, so nothing
outside `github.com/danieljustus/symaira-vault` imports it, and the Rust crates
are all `publish = false`. The impact is entirely behavioural: a config file
that used to load may now stop loading.

**The failure is a startup failure.** If a deployed config file contains either
input, the CLI refuses to start rather than running with a silently substituted
value. This is deliberate, and it is the reason this change was staged rather
than shipped alongside the alignment work: for a password manager, a config
file that stops loading can lock an operator out of their own vault.

What is *not* affected: the writer has never emitted either form. A
`config.yaml` that `symvault` produced itself cannot contain them, so only
hand-edited files are at risk.

## What a consumer should do

1. **Before upgrading, scan deployed config files.** Both patterns are cheap to
   grep for:

   ```
   grep -nE '^(sessionTimeout|sessionMaxLifetime):[[:space:]]*(-|0)' config.yaml
   grep -n '^---' config.yaml
   ```

   A leading `---` on the *first* line is a document start, not a second
   document, and is fine.

2. **Fix what turns up.** Either remove the key (the default then applies,
   which is what the old build was silently doing anyway) or set a positive
   value. For a multi-document file, split it or delete everything after the
   separator — the old build was only ever reading the first document.

3. **Nothing else.** No code change, no dependency bump, no regeneration.

## Recovering from the lockout

The rejection names the field and the remedy, for example:

```
sessionTimeout: must be greater than 0, got -5m0s (default: 15m, configure sessionTimeout in config.yaml)
```

`symvault admin config` detects a failing config file and offers to open it in
`$EDITOR`. Note that its deterministic auto-fix for `sessionTimeout` only runs
for a *validation* error, not a *load* error, so this case currently reaches
the editor path rather than the one-keystroke fix. Extending the auto-fix to
load errors is a reasonable follow-up; it is not part of this change, and it is
recorded here rather than implemented so the handoff describes the build as it
actually is.

## Contract evidence

`testdata/port/config/bytes.json` at oracle `aa21ec4e` carries the four inputs
(`negative_duration`, `zero_duration`, `negative_max_lifetime`,
`multiple_documents`) as rejected, and
`crates/symvault-core/tests/config_bytes_contract.rs` asserts that both
implementations reject them. The divergence set
`ACCEPTANCE_PENDING_ADJUDICATION` is empty and asserted exactly, so it can
neither grow nor shrink unnoticed.
