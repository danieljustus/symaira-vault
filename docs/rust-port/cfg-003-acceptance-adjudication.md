# CFG-003: adjudicating four acceptance divergences

Status: **decision required.** Nothing here is implemented. The divergences are
pinned by `crates/symvault-core/tests/config_bytes_contract.rs`, whose
`ACCEPTANCE_PENDING_ADJUDICATION` set may neither grow nor shrink unnoticed, so
this question stays visible until it is answered.

Measured against `main` at `cb7e2a3a`. Fixture: `testdata/port/config/bytes.json`.

## The four inputs

For all four, Go accepts and Rust rejects.

| # | Input | Go | Rust |
|---|---|---|---|
| 1 | `sessionTimeout: -5m` | accepted, value becomes the **default 15m** | rejected: `sessionTimeout has invalid duration "-5m"` |
| 2 | `agents:\n  custom:\n    canWrite: "yes"` | accepted, the field is **discarded** | rejected: `canWrite must be a boolean` |
| 3 | `defaultAgent: a\n---\ndefaultAgent: b` | accepted, **only the first document** is read | rejected: more than one document unsupported |
| 4 | `null` | accepted, yields the defaults | rejected: `invalid type: unit value` |

## Why the pinned oracle is not automatically right here

In 1–3, Go's leniency means configuration the operator wrote is silently
discarded. For a password manager that is the wrong failure mode: the operator
believes a permission or a timeout is in force when it is not.

### 1 is not a contract question at all — it is a bug

Go already has the rule. `config_validate.go:130`:

```go
if c.SessionTimeout <= 0 {
    errs = errors.Join(errs, errors.New("sessionTimeout: must be greater than 0 (...)"))
}
```

It never fires from a config file, because `config_merge.go:64` discards the
value first:

```go
if raw.SessionTimeout > 0 {
    cfg.SessionTimeout = raw.SessionTimeout
}
```

Measured: `sessionTimeout: -5m` loads and yields 15m, while setting `-5m`
directly on the struct and calling `Validate()` produces exactly that error.
The same holds for `0s` and for `sessionMaxLifetime: -1h`.

The validation is unreachable. Making it reachable restores the behaviour the
code already states it wants.

### 2 and 3 are genuine security footguns

A permission written with the wrong scalar type, or an entire second document,
vanishing without a word is the failure mode that lets an operator believe a
restriction is active when it is not.

### 4 points the other way

`null` is an empty document. Go already treats an empty file as "use the
defaults", so accepting `null` is consistent and rejecting it is not. The
stakes are low either way, but consistency argues for Go's behaviour.

## Recommendation

**Adopt Rust's strictness for 1–3, and Go's leniency for 4** — not a blanket
"the stricter side wins", but per case.

That leaves the question of *when*, and it matters more than usual: if a config
file stops loading, the CLI refuses to start, and for a password manager that
means an operator can be locked out of their vault by an upgrade.

### Recommended path: align on warn-and-accept now, reject together later

1. **Now:** both implementations warn and continue for 1–3, using the
   `warnf` mechanism already used for the `envWhitelist` deprecation. Rust
   relaxes to match; Go gains the warnings. The silent discard — the actual
   danger — ends immediately, and the two implementations stay aligned, which
   is the point of the port. For 4, Rust relaxes to accept.
2. **Next minor release:** both flip to rejecting 1–3 together, announced in
   the release notes and the consumer handoff.

The contract is re-pinned at each step, so parity is never an open question in
between.

### Alternative: reject immediately

Cleaner contract, and defensible on the grounds that these configs never did
what the operator wrote. Rejected as the recommendation only because of the
lockout risk on upgrade. If you prefer it, it should ship with a release note
and an explicit `symvault doctor` check that names the offending key and line.

## Consumer impact

Under the recommended path, step 1 adds warnings and breaks nothing, so no
consumer action is required. Step 2 is a breaking change for config files that
contain any of 1–3 and belongs in its own consumer handoff, alongside a way to
find affected files.

## What I would implement on approval

- Remove the `> 0` merge guards so explicitly present durations reach
  `Validate` (1).
- Add warnings in Go for the wrong-scalar-type and multi-document cases (2, 3).
- Relax Rust to warn-and-accept for 1–3 and to accept `null` (4).
- Extend the CFG-003 fixture with the warning-bearing cases and empty
  `ACCEPTANCE_PENDING_ADJUDICATION`.
- Prepare the step-2 consumer handoff without implementing it.
