# CFG-003: adjudicating four acceptance divergences

Status: **decided and implemented in full.** Both steps of the recommended path
have shipped. The paper is kept as the record of what was measured and why the
split decision was made; the sections below are the original analysis, unchanged
except for the correction note and this header.

- **Step one**, `addce896`: Rust adopted Go's YAML 1.1 booleans (case 2) and its
  treatment of an explicit `null` (case 4); both sides warned and accepted for
  cases 1 and 3, using identical pinned texts.
- **Step two**, `aa21ec4e`: both sides now **reject** cases 1 and 3. The warning
  texts are gone, replaced by rejections. Consumer handoff:
  `consumer-handoff-config-20260915.md`.

`ACCEPTANCE_PENDING_ADJUDICATION` in
`crates/symvault-core/tests/config_bytes_contract.rs` is empty and asserted
exactly, so the two implementations can no longer diverge here unnoticed.

Measured against `main` at `cb7e2a3a`. Fixture: `testdata/port/config/bytes.json`.

## The four inputs

For all four, Go accepts and Rust rejects.

| # | Input | Go | Rust |
|---|---|---|---|
| 1 | `sessionTimeout: -5m` | accepted, value becomes the **default 15m** | rejected: `sessionTimeout has invalid duration "-5m"` |
| 2 | `agents:\n  custom:\n    canWrite: "yes"` | accepted as **`true`** | rejected: `canWrite must be a boolean` |
| 3 | `defaultAgent: a\n---\ndefaultAgent: b` | accepted, **only the first document** is read | rejected: more than one document unsupported |
| 4 | `null` | accepted, yields the defaults | rejected: `invalid type: unit value` |

## Why the pinned oracle is not automatically right here

> **Correction, 2026-09-15.** An earlier revision of this paper described case
> 2 as a permission being silently discarded, and grouped it with 1 and 3 as a
> security footgun. That was asserted without being measured, and it is wrong.
> Go reads `canWrite: "yes"` as `true` and honours it. The corrected analysis is
> below; the recommendation for case 2 is reversed as a result.

In 1 and 3, Go's leniency means configuration the operator wrote is silently
discarded. For a password manager that is the wrong failure mode: the operator
believes a setting is in force when it is not. Case 2 is a different thing
entirely — a YAML version compatibility gap — and case 4 points the other way.

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

### 3 is a genuine security footgun

An entire second document vanishing without a word is the failure mode that
lets an operator believe a restriction is active when it is not.

### 2 is a YAML 1.1 compatibility gap, not a discard

Measured across spellings, Go accepts the YAML 1.1 booleans — `yes`, `no`,
`on`, `off`, in any case, quoted or bare — and resolves them correctly:

| written | Go |
|---|---|
| `yes` / `"yes"` / `Yes` / `YES` / `on` | `true` |
| `no` / `"no"` / `off` | `false` |
| `true` / `false` | as written |
| `"true"` / `"false"` | **rejected** |
| `1` / `"banana"` | rejected |

So nothing is discarded: an operator writing `canWrite: no` gets `false`. Rust
rejects all of these outright, which would refuse to load config files that Go
reads correctly. (The rejection of quoted `"true"` while quoted `"yes"` is
accepted is a yaml.v3 quirk, not a design; it is recorded here because the
contract pins it either way.)

Rust is not dangerous here — it fails loudly rather than silently — but it is
incompatible with valid, idiomatic YAML.

### 4 points the other way

`null` is an empty document. Go already treats an empty file as "use the
defaults", so accepting `null` is consistent and rejecting it is not. The
stakes are low either way, but consistency argues for Go's behaviour.

## Recommendation

**Adopt Rust's strictness for 1 and 3, and Go's behaviour for 2 and 4** — not a
blanket "the stricter side wins", but per case. The split is even, which is
itself the argument against deciding this by picking a winner.

That leaves the question of *when*, and it matters more than usual: if a config
file stops loading, the CLI refuses to start, and for a password manager that
means an operator can be locked out of their vault by an upgrade.

### Recommended path: align on warn-and-accept now, reject together later

1. **Now:** both implementations warn and continue for 1 and 3, using the
   `warnf` mechanism already used for the `envWhitelist` deprecation. Rust
   relaxes to match; Go gains the warnings. The silent discard — the actual
   danger — ends immediately, and the two implementations stay aligned, which
   is the point of the port.
   For 2 and 4 there is nothing to stage: Rust simply adopts Go's behaviour,
   accepting YAML 1.1 booleans and an explicit `null`.
2. **Next minor release:** both flip to rejecting 1 and 3 together, announced
   in the release notes and the consumer handoff.

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
contain 1 or 3 and belongs in its own consumer handoff, alongside a way to find
affected files. Cases 2 and 4 never become breaking: they are Rust catching up
to Go.

## What I would implement on approval

- Add a warning in Go for a negative duration, which currently falls back to
  the default without a word (1), and for documents after the first (3).
  Removing the `> 0` merge guard belongs to step 2, not here: it would make Go
  reject immediately.
- Give Rust a warning channel and relax it to warn-and-accept for 1 and 3.
- Make Rust accept YAML 1.1 booleans (2) and an explicit `null` (4).
- Extend the CFG-003 fixture with the warning-bearing cases and empty
  `ACCEPTANCE_PENDING_ADJUDICATION`.
- Prepare the step-2 consumer handoff without implementing it.

## What was actually implemented

All of the above, plus one thing the plan did not anticipate.

Go's zero value cannot distinguish an absent `sessionTimeout` from an explicit
`sessionTimeout: 0s`, so a naive "reject non-positive" rule would either miss
`0s` or break every config file that omits the key. The loader therefore records
which top-level keys the document carries, and only rejects a key the operator
wrote. Rust already had this for free, because it reads the mapping directly.

That also closed a divergence the fixture had not caught: before step two, Go
was silent on `0s` while Rust warned, because Go's `< 0` guard never saw it. The
fixture now carries `zero_duration` and `negative_max_lifetime` alongside the
original `negative_duration`, so the rule is pinned across both fields and both
non-positive forms.
