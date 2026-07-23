# Local Secret-Leak Detection

> **Scope:** Output-scanning redaction applied to command output
> (`run_command`, `execute_with_secret`) and MCP tool response payloads
> before they leave the Symaira Vault process — implemented in
> `internal/redact`. This is a separate, narrower mechanism from the
> prompt-injection defenses covered in [threat-model.md](threat-model.md);
> see that document for the broader trust-boundary picture.

## What this protects against

Symaira Vault scans text it is about to hand back across the MCP process
boundary — subprocess stdout/stderr from `run_command` and
`execute_with_secret`, and other MCP tool response payloads — for secret
material, and rewrites any match before the text can be displayed to an
agent or persisted (e.g. to the audit log). Three independent detectors run
in a fixed pipeline, each tagged with a confidence tier:

| Tier | Detector | What it catches |
|---|---|---|
| **Exact match** (high confidence) | known-value matching | Literal occurrences of a currently-unlocked vault secret value that the caller resolved for this call (e.g. an `env`/`files` reference on `run_command`) |
| **Pattern match** (high confidence) | credential-shaped patterns | Explicit, well-known secret formats — AWS access keys, GitHub/Slack/Stripe/OpenAI tokens, PEM private keys, bearer tokens, JWTs, and similar (see `internal/mcp/masking.DefaultPatterns`) |
| **Entropy heuristic** (low confidence) | conservative last resort | Long (20+ character), high-Shannon-entropy token-shaped substrings that don't match a known value or an explicit pattern, but look randomly generated |

Every match — regardless of tier — is replaced with a single fixed marker,
`[REDACTED]`. The marker never contains any substring, prefix, length hint,
or hash of the original value: knowing the marker tells you nothing about
what was removed.

Detection **fails closed**: if a detector itself errors while scanning, the
affected output is withheld entirely (replaced with a fixed
`[REDACTED: output withheld]` marker) rather than returned unscanned. A
scanner bug can cause you to see less output than expected; it cannot cause
an unscanned value to slip through.

## What this explicitly does not protect against

This is a **process-boundary output filter**, not a general secrets-leak
prevention system. In particular, it does **not**:

- Protect against a secret being visible in a **screenshot** or captured by
  screen recording — the redaction happens on the data flowing through this
  process, not on anything rendered by other applications.
- Protect against secrets already visible in an **external application** —
  a terminal emulator, editor, or browser that independently displays the
  same command output outside of Symaira Vault's control.
- Redact secrets from **already-persisted third-party chat history** — if a
  secret reached an MCP host's own logs or a chat transcript before this
  feature was enabled (or through a path this feature doesn't cover), this
  feature cannot retroactively scrub it.
- Transmit anything it detects **anywhere remote** — all scanning happens
  in-process, synchronously, with no network calls. Detected values are
  never sent off-host for classification or analysis.
- **Log or persist the matched value itself**, in any form — not the raw
  value, not a prefix, not a hash, not a length. Audit events (below)
  record only that a detection occurred, never what was detected.
- Guarantee it catches **every** possible secret shape. The pattern
  detector only knows the formats it's been given; the entropy heuristic is
  deliberately tuned to avoid flagging ordinary long identifiers (temp
  paths, UUIDs, test/run IDs), which means it also misses some real
  secrets — see [Detection limits](#detection-limits-and-known-false-positivenegative-classes)
  below.

## Redact vs. block: what strict mode changes

By default, a detection is **redacted**: the matched text is replaced with
`[REDACTED]` in place, and the rest of the output (with the match removed)
is still delivered. This is the "detect and warn" behavior.

An opt-in **strict mode** changes this for high-confidence detections only:
when a **high-confidence** match (exact-value or pattern-match tier) fires
in strict mode, the entire affected output stream (e.g. all of stdout, or
all of stderr) is withheld and replaced with a fixed
`[REDACTED: output withheld]` marker instead of being redacted in place.
This is the "detect and block" behavior — it exists for deployments that
want a harder guarantee that a high-confidence secret never reaches the
agent, even partially.

Low-confidence (entropy heuristic) detections are **never** blocked, even
in strict mode — they are always redacted in place. This keeps the
last-resort heuristic's inherent false-positive risk from being able to
silently withhold legitimate output; only findings from the two
high-precision detectors can trigger a block.

### Enabling / disabling strict mode

Strict mode is opt-in and disabled by default. Set the environment variable
`SYMVAULT_REDACT_STRICT_MODE` to a truthy value (`1`, `true`, `yes`, `on`;
case-insensitive) for the `symvault` process (MCP server or CLI) to enable
it:

```bash
export SYMVAULT_REDACT_STRICT_MODE=true
```

Unset the variable, or set it to anything else (e.g. `0`, `false`, or leave
it empty), to return to the default redact-and-continue behavior.

## Inspecting audit events

Every detection — whether redacted or blocked — emits one audit event to
Symaira Vault's normal audit log (action `leak_detection`), containing
**metadata only**:

- which detector fired (`exact_value`, `credential_pattern`, or
  `entropy_heuristic`)
- the channel it fired on (e.g. `stdout`, `stderr`)
- its confidence tier (`high` or `low`)
- how many matches were redacted
- whether the finding caused a block (`blocked=true`/`false`)
- a correlation ID tying the event back to the specific `run_command` /
  `execute_with_secret` call that produced it (the same correlation ID is
  shared by an stdout and stderr scan from the same call)

The event **never** contains the matched value, a prefix of it, or a hash
of it. Inspect these events the same way you inspect any other Symaira
Vault audit entry — see [Audit event schema](audit-schema.md) and
[Audit retention & integrity](audit-retention.md) for the log format and
verification tooling.

## Detection limits and known false-positive/negative classes

The entropy heuristic is deliberately tuned so that false-positive
resistance wins over recall — see `internal/redact/entropy_test.go`'s
`TestEntropyDetector_DocumentedFalsePositiveClasses` for the authoritative,
executable record of these trade-offs. As of this writing:

| Shape | Flagged? | Why |
|---|---|---|
| Mixed-case/digit/symbol random secret (32+ chars) | Yes | High empirical entropy across a large alphabet |
| Base64-encoded payload (secret or not) | Yes | High entropy by construction — a known false-positive source for *non-secret* base64 blobs |
| Hex-encoded hash (e.g. SHA-256 digest) | No | Only a 16-symbol alphabet keeps empirical entropy below the floor — a known false-negative for hex-only secrets |
| UUID (hyphenated) | No | Split into short hex runs at each `-`, each below the minimum token length |
| Long purely-numeric identifier | No | Small 10-symbol alphabet keeps entropy below the floor |
| Filesystem paths, temp-dir names, test/run identifiers | No | Split at each `/`, and the entropy floor is calibrated above typical identifier entropy |

These are accepted, documented limitations of a conservative last-resort
layer — they are not "bugs" to be silently tuned away, since loosening the
thresholds to catch more of the false-negative classes above would
reintroduce false positives on ordinary tool output (paths, identifiers,
hashes) that are far more common than the secrets being missed.

The exact-value and pattern-match tiers do not have this trade-off in the
same way: they only match a bounded, explicit set of values/formats, so
they carry effectively no false-positive risk, but also cannot catch a
secret whose value isn't currently resolved for the call, or whose format
isn't in the known pattern list.
