# Consumer handoff: policy path-matching contract, 2026-09-15

Status: **for consumer review before this line is integrated.** Nothing here is
implemented in any consumer repository, and no consumer document has been
changed. This file states what the Vault side changed and what, if anything,
a consumer has to do.

Vault side: branch `migration/claude-vault-policy-20260915`, adjudicated
contract at `f195aab`, described in `contract-matrix.md` under
"POLICY-001 path-matching adjudication".

## Who is actually affected

Less than the phrase "breaking change" suggests. Two surfaces were checked:

- **Go.** `internal/policy` is an `internal` package, so no repository outside
  `github.com/danieljustus/symaira-vault` can import it. Every production call
  site (`internal/mcp/server/server_authorize.go`,
  `internal/policy/authorizer.go`) builds its context through
  `ContextProvider.BuildContext`, which this change updated. There is
  therefore **no Go API migration for any consumer.**
- **Rust.** Every crate under `crates/` is `publish = false`. `EvalContext`
  gained a `home_dir` field, which is a source-level break only for something
  that vendors this repository and constructs `EvalContext` literally.

What does reach consumers is **behaviour**: how existing policy rules evaluate.
That is the whole of the impact, and it needs no code change on the consumer
side — but it can change authorization outcomes, so it must be reviewed.

## The four behavioural changes

### 1. Malformed glob patterns are now rejected at load time

A pattern such as `secrets/[` is not a valid glob. Previously it matched
nothing and the policy loaded normally, so a **deny rule written that way
silently stopped denying**. `Policy.Validate` now rejects it and the policy
fails to load.

*Consumer impact:* a policy file that has been loading for months may now fail
to load. That is the intended outcome — it was not doing what it claimed — but
it surfaces as a hard failure rather than a silent one.

*Detection:* any `path:` or `working_dir:` value containing `[` without a
matching `]`.

### 2. A pattern with a glob metacharacter is no longer also a literal name

The bare directory-prefix convenience used to apply whenever the pattern
contained no `*`. So `fixture/?` was simultaneously a glob **and** a literal
directory named `?`. The guard now covers `*`, `?` and `[`, and such a pattern
is matched as a glob only.

*Consumer impact:* a rule whose pattern contains `?` or `[` and which was
relied upon to match a directory *literally* named that will no longer match.
This narrows allow rules (safer) and narrows deny rules (less safe), which is
why both directions are kept as fixture counterexamples.

*Detection:* `path:` values containing `?` or `[` where a real directory of
that literal name exists.

### 3. Slash-written patterns now match on Windows

Matching is defined over slash-separated logical paths and the native
separator is converted once, at the runtime boundary. Previously a rule
written as `~/work/*` simply stopped matching on Windows, because the value
carried backslashes and the pattern did not.

*Consumer impact:* this is a **fail-open repair**. A deny rule that was
silently inert on Windows now denies. Any Windows deployment should expect
rules to start applying that previously did not.

*Detection:* any deny rule with a slash-separated path pattern, on Windows.

### 4. Home expansion uses an explicit home

`~/` now expands from `EvalContext.HomeDir`, supplied by the caller, instead of
the matcher calling `os.UserHomeDir()` itself. `BuildContext` populates it, so
runtime behaviour is unchanged for normal use. Evaluation is now deterministic
and free of runtime discovery.

*Consumer impact:* none at runtime. Relevant only to in-tree code that
constructs an `EvalContext` directly; without `HomeDir`, `~/` patterns stay
literal rather than silently resolving against the process environment.

## What a consumer should do

1. Review existing policy files against items 1 and 2 above. Both are
   mechanical to detect.
2. On Windows, expect item 3 to activate rules that were previously inert, and
   confirm that is wanted before rolling forward.
3. No code change. No dependency bump beyond taking the new Vault line.

## What is deliberately not done here

No consumer repository was modified and no central consumer document was
rewritten. If a consumer contract does need to change, that belongs in its own
handoff, owned by that repository.
