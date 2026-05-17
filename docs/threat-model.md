# OpenPass Threat Model

> **Scope:** The MCP server surface where LLM agents read and write vault
> credentials. Other surfaces (CLI, file-format crypto, OS keyring) are
> covered by `SECURITY.md`.

## Why this document exists

OpenPass is a password manager that exposes vault credentials to LLM agents via
its MCP server. That makes it a primary target for prompt-injection attacks
in two flavors:

- **Direct prompt injection** — the user (or a compromised user-facing channel)
  asks the agent to do something destructive.
- **Indirect prompt injection** — vault content, command output, or imported
  data carries adversarial instructions that the LLM may interpret as user
  intent.

OpenPass implements multiple, overlapping defenses. This document maps those
defenses to recognized threat catalogs so an external reviewer can assess
coverage without reading the codebase.

## Threat catalog mapping

| Standard | Section | OpenPass coverage |
|---|---|---|
| OWASP LLM 2025 | LLM01 Prompt Injection | §1, §2, §3 |
| OWASP LLM 2025 | LLM02 Sensitive Information Disclosure | §4, §5 |
| OWASP LLM 2025 | LLM06 Excessive Agency | §6 |
| OWASP LLM 2025 | LLM07 System Prompt Leakage | §1 (statically-defined tool descriptions) |
| MITRE ATLAS | AML.T0051 LLM Prompt Injection | §1, §2 |
| MITRE ATLAS | AML.T0057 LLM Jailbreak via Indirect Prompt Injection | §2, §3 |
| MITRE ATLAS | AML.T0024 Exfiltration via ML Inference API | §4, §5, §6 |

## Trust boundaries

```
┌─────────────────────────────┐
│  LLM agent (untrusted)      │  ← may be jailbroken, malicious, or buggy
└────────────┬────────────────┘
             │ MCP (stdio/HTTP)
             │  • bearer token + scope check
             │  • rate limit (60 req/min)
             ▼
┌─────────────────────────────┐
│  OpenPass MCP server        │  ← trusted, enforces policy
│  • agent profile            │
│  • approval (TTY)           │
│  • taint system             │
│  • output chokepoint        │
└────────────┬────────────────┘
             │
   ┌─────────┴──────────┐
   ▼                    ▼
┌────────┐         ┌────────────┐
│ Vault  │         │ Subprocess │  ← isolated env, masked stdout
│ (age)  │         │            │
└────────┘         └────────────┘
```

The LLM agent sits **outside** every trust boundary — every prompt, tool call,
and field value it sees is treated as adversarial.

---

## §1 — Direct prompt injection via tool descriptions

**Threat:** A compromised MCP server (or a server with dynamic, content-derived
tool descriptions) could change what the LLM sees as "available tools," using
that to coerce the agent.

**OpenPass defenses:**

- **Statically hardcoded tool descriptions.** All 34+ MCP tools live in
  `internal/mcp/tool_registry.go` with literal description strings. No vault
  content, agent input, or env data flows into them.
- **Risk-classified tools.** Each tool carries a `RiskLevel` (Low / Medium /
  High / Critical). Critical tools (`set_entry_field`, `delete_entry`,
  `execute_api_request`, `secure_input`, `request_credential`) bypass the
  session approval cache — they require a fresh out-of-band approval every
  time.
- **Token-scoped tool allowlist.** `ScopedToken.AllowedTools` is a whitelist
  per token (or `"*"`). `isToolAllowed()` in `tool_registry.go` enforces the
  allowlist at dispatch time and applies alias resolution so a single
  whitelist entry covers both canonical names and aliases.
- **Per-agent tool blocking.** `ExposeValueTools=false` filters
  `get_entry_value` out of `tools/list` entirely — the LLM never even sees
  the tool exists.

**Known limitations:** A future "dynamic tool description" feature would
re-open this surface. See backlog item O-10 (tool-description integrity hash
in tokens).

---

## §2 — Indirect prompt injection via vault content

**Threat:** Vault entries are written by humans, agents, or import jobs.
Tags, `usage_hint`, `notes`, custom fields, and field values can all carry
prompt-injection payloads that reach the LLM when an agent reads the entry.

**OpenPass defenses:**

- **Central output chokepoint.** Every MCP tool response passes through
  `globalChokepoint.SanitizeForMCP()` in `internal/mcp/render.go` before it
  reaches the LLM. The chokepoint is wired into `callToolResultPayload` in
  `tool_registry.go` so no handler can opt out.
- **Three-phase sanitizer:**
  1. **NFKC normalization** — decomposes fullwidth and compatibility
     characters to ASCII so subsequent byte-level checks catch
     `＜ｓｃｒｉｐｔ＞`-style smuggling.
  2. **Dangerous Unicode strip** — removes bidirectional overrides
     (U+202A–202E, U+2066–2069), zero-width characters (ZWSP/ZWNJ/ZWJ), BOM,
     soft hyphen, combining grapheme joiner, word joiner.
  3. **Byte-level scanner** — strips ANSI escape sequences (CSI, OSC),
     OSC-8 hyperlinks, control characters, neutralizes XML closing tags
     (`</data>` → `</ data >`) and HTML comment closers (`-->` → `-- >`).
- **Defense-in-depth per handler.** `tools_get.go` sanitizes `usage_hint`
  and `tags` again before JSON marshal — so even if the final chokepoint
  is bypassed in some future code path, the structured response is still
  clean.
- **`EmbedAsData` for untrusted slot values.** Slash-command prompts wrap
  user/agent-provided strings (service name, path, query, target agent,
  TTL, field name) in `<!-- DATA_xxxxxxxx label=NAME -->…<!-- /DATA_xxxxxxxx -->`
  envelopes with 64-bit random closing markers. The marker is unforgeable by
  content, so the LLM can reliably tell where untrusted data ends.
- **Subprocess output hardening.** `sanitizeRunOutput()` in
  `tools_sanitize.go` runs both (a) known-secret masking and (b) the MCP
  chokepoint on stdout/stderr before they reach the LLM, so command output
  cannot smuggle injection payloads even if it lands in a structured JSON
  envelope.

**Compile-time enforcement:**

- **Taint system** (`internal/vault/taint/`). `Untrusted` is a typed wrapper
  with provenance metadata. Its `Format()` method emits `<untrusted:Source>`
  for any `%s/%v/%q` use — accidentally stringifying an `Untrusted` value
  surfaces immediately instead of leaking content. `Untrusted.Render(target)`
  applies target-specific sanitizers (terminal vs MCP).
- **`passlint`** (`cmd/passlint/`) — custom go/analysis linter that fails CI
  if an `Untrusted` value is converted to `string` without going through
  `Render()`.

**Known limitations:** OpenPass strips **structural** injection vectors
(Bidi, ANSI, XML tags) but does **not** detect **semantic** prompt injection
(e.g. natural-language "ignore previous instructions"). See backlog item
O-2 (opt-in semantic heuristic).

---

## §3 — Tool poisoning / cross-server confusion / rug pulls

**Threat:** A malicious MCP server in the same agent session impersonates
OpenPass tools, or the OpenPass server itself is swapped for a malicious
binary at runtime.

**OpenPass defenses:**

- **Bearer token + constant-time comparison.** `BearerAuthMiddleware` in
  `auth.go` uses `subtle.ConstantTimeCompare` for legacy tokens and SHA-256
  hash lookup for scoped tokens — neither path is timing-attackable.
- **127.0.0.1 binding by default.** HTTP transport binds to loopback unless
  the operator opts into a non-loopback address via TLS-required mode.
- **Token rotation.** `mcp-token-rotate` CLI command supports zero-downtime
  rotation. Revocation is tracked in the token registry and consulted on
  every request.
- **Refresh-token flow.** Long-lived bearer tokens are discouraged in favor
  of short-lived access tokens with refresh tokens (`token.go`
  `RefreshToken*`).

**Known limitations:** OpenPass does not currently sign its tool
descriptions, so a man-in-the-middle attacker between the agent and the
MCP server could in principle alter them. See backlog item O-10.

---

## §4 — Sensitive information disclosure

**Threat:** Vault credentials leak to the LLM beyond what was asked for.

**OpenPass defenses:**

- **Sealing for high-classification secrets.** Entries with
  `Classification ≥ taint.Secret` are returned as opaque
  `SecretHandle` (`op://path/field`) — the LLM receives a handle, not the
  value. To unseal, the agent must explicitly call `secret_unseal`, which
  requires its own approval and counts against `MaxSecretsInSession`.
  `AutoUnseal=false` makes this the default.
- **`CanReadValues` guard.** When false, even `get_entry_value` requires
  out-of-band approval per call.
- **Field redaction.** `RedactFields` patterns (exact, dotted, wildcard) are
  applied in `redactEntry()` (`server_authorize.go`) before any value-bearing
  response is built.
- **Per-session secret budget.** `MaxSecretsInSession` caps how many secret
  fields a single agent session can ever read.
- **Subprocess masking.** `masking.SanitizeWithKnownSecrets` substitutes
  known secret values with `***` in stdout/stderr.
- **Subprocess env whitelist.** `internal/envfilter` strips all parent
  process env vars except a small whitelist before spawning, so vault
  secrets cannot leak via PATH-shadowing or other env-inheritance attacks.
- **Scalar-only `secret_unseal`.** Non-scalar fields (maps, slices) are
  refused with a clear error instead of leaking Go's map representation
  (`map[issuer:GitHub secret:JBSW...]`).
- **No fmt-leaks.** `Untrusted` panics in fmt verbs so accidental
  `Sprintf("%v", secret)` is impossible to land in production.

---

## §5 — Path traversal & scope bypass

**Threat:** An agent uses `..`, double slashes, or whitespace to access
entries outside its authorized prefix.

**OpenPass defenses:**

- **`normalizeScopePath()`** in `server_authorize.go` runs `filepath.Clean`
  (after `FromSlash` + `TrimSpace`) on both the requested path and every
  allowed prefix. `..` and `.` are normalized before comparison.
- **All MCP handlers** call `checkScope()` as the first action after
  parameter parsing.
- **Approval cache key normalization** — `approvalCacheKey()` runs the
  same normalization so equivalent path forms collapse to the same cached
  approval, removing a side-channel where an adversarial agent could vary
  the path form to force repeated prompts.
- **Importer path hardening** — `NormalizePath()` in
  `internal/importer/importer.go` strips Windows-invalid characters and
  replaces `..` segments with `-` before any imported entry hits the
  vault namespace.

---

## §6 — Excessive agency

**Threat:** A jailbroken or buggy agent uses its legitimate tool access to
take destructive actions (deletion, command execution, share approval) on a
scale or in a context the user never intended.

**OpenPass defenses:**

- **Out-of-band approval for critical actions.** TTY-based approval prompt
  (`approval.go`) for all Critical-tier tools. The TTY is a separate
  channel from the MCP transport — the LLM cannot satisfy its own
  approval.
- **Rich approval context.** The prompt shows agent name, risk level
  (with emoji), working dir, git branch, project type, and total secrets
  accessed so far in this session, so the human can spot anomalies.
- **`approvalMode: deny`** — for fully-automated agent profiles that must
  never approve. All critical actions auto-fail.
- **Self-approval prevention for shares.** `tools_sharing.go` blocks an
  agent from approving a share it itself requested.
- **Anomaly detection.** `internal/anomaly/detector.go` triggers
  desktop notifications and invalidates the approval cache on:
  - **Canary** access (Critical) — agent touched a honeytoken entry.
  - **Sweep** (Medium) — 10+ unique paths in 60s.
  - **Rate anomaly** (Medium) — 30+ requests in 60s.
  - **Off-hours** (Low) — 22:00–06:00 local time.
- **Comprehensive audit log.** Every tool call records agent, action,
  path, transport, OK/reason, session ID, request ID, token ID. Logs
  live at `~/.openpass/audit-<agent>.log` and never contain field values.

**Known limitations:**

- No allowlist of permitted executables for `run_command` /
  `execute_with_secret`. Any agent with `canRunCommands=true` can run any
  binary on `PATH`. See backlog item F-7.
- No write-time provenance metadata on `set_entry_field`. An entry
  modified by Agent A is indistinguishable from one written by a human
  when later read by Agent B. See backlog item F-3.

---

## Verification recipes

Reviewers can verify the defenses claimed here without reading the code in
depth:

```bash
# Output chokepoint is centrally wired
grep -n "globalChokepoint.SanitizeForMCP" internal/mcp/tool_registry.go

# Three sanitization phases
grep -n "^func sanitize\|^func stripDangerous" internal/mcp/render.go

# Taint system Untrusted Format() panic-on-stringify
grep -n "func (u Untrusted) Format" internal/vault/taint/taint.go

# All MCP handlers call checkScope before any value-bearing operation
grep -nL "checkScope\|toolName" internal/mcp/tools_*.go | grep -v _test

# Anomaly detector rules
grep -n "^func.*detect\|^func.*Check" internal/anomaly/detector.go

# Token allowlist enforcement
grep -n "isToolAllowed\|IsToolAllowed" internal/mcp/token.go internal/mcp/tool_registry.go
```

## Open work

The following items are tracked as separate issues, not closed in this
threat-model document:

- **F-2 / O-1** — systematic `EmbedAsData` wrapping of high-risk untrusted
  fields (`notes`, `description`, custom imported fields).
- **F-3** — provenance metadata on `set_entry_field` writes.
- **F-4 / O-3** — per-field length cap and provenance tag for importer
  entries.
- **F-7** — per-agent executable allowlist for `run_command`.
- **F-8** — `EmbedAsData` wrapping for `generate_template` output.
- **O-2** — opt-in semantic prompt-injection heuristic.
- **O-4** — per-tool `redactFields` (not just per-agent).
- **O-5** — anomaly rule for tool-chains that read `notes` then run a
  command.
- **O-6** — `passlint` rules for MCP handler patterns (missing
  `checkScope`, direct string cast on `Untrusted`).
- **O-9** — quarantine path for newly imported entries pending manual
  review.
- **O-10** — tool-description integrity hash in scoped tokens.

These are improvements over an already-strong baseline, not fixes for
fundamental flaws.

## References

- OWASP Top 10 for LLM Applications 2025 — <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- Anthropic prompt-injection guidance — <https://docs.anthropic.com/en/docs/test-and-evaluate/strengthen-guardrails/mitigate-jailbreaks>
