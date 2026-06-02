# Audit Event Schema

**Stability**: Stable for the `v0.x` release line. No breaking changes without a
major version bump. New optional fields may be added in minor releases.

**Scope**: Public self-hosted Symaira Vault core. Cloud Pro features (SIEM
export, managed retention, compliance reporting, tenant audit storage) are
excluded — see [Cloud Pro Boundary](#cloud-pro-boundary).

## Overview

Symaira Vault records a structured audit event for every MCP tool call and CLI
agent operation. Events are written as JSONL (one JSON object per line) to
per-agent log files at `~/.symvault/audit-<agent>.log`. Each event carries an
HMAC integrity hash that chains to the previous entry, enabling tamper
detection.

## LogEntry Schema

```go
// internal/audit/audit.go
type LogEntry struct {
    Timestamp   string `json:"ts"`              // RFC 3339 UTC timestamp
    Agent       string `json:"agent"`            // Agent name (e.g. "claude-code")
    Action      string `json:"action"`           // Action category (see table below)
    Path        string `json:"path,omitempty"`   // Vault entry path, or "<reason>" for denials
    Field       string `json:"field,omitempty"`  // Field name only — NEVER contains the value
    Transport   string `json:"transport,omitempty"` // "stdio" or "http"
    Reason      string `json:"reason,omitempty"`    // Human-readable failure reason
    ShareID     string `json:"share_id,omitempty"`  // Share grant ID (sharing events)
    FromAgent   string `json:"from_agent,omitempty"` // Sharing source agent
    ToAgent     string `json:"to_agent,omitempty"`   // Sharing target agent
    ShareAction string `json:"share_action,omitempty"` // Share operation type
    DurMs       int64  `json:"dur_ms,omitempty"`      // Operation duration in milliseconds
    TokenID     string `json:"token_id,omitempty"`     // MCP bearer token ID
    RequestID   string `json:"req_id,omitempty"`       // Unique request identifier
    SessionID   string `json:"sess_id,omitempty"`      // MCP session identifier
    HMAC        string `json:"hmac,omitempty"`         // Hex-encoded SHA-256 HMAC (see below)
    OK          bool   `json:"ok"`                     // true = success, false = denial/error
}
```

### Field Semantics

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ts` | string (RFC 3339) | Always | When the event occurred. Auto-filled if omitted. |
| `agent` | string | Always | Agent name from `config.yaml` or `SYMVAULT_AGENT`. |
| `action` | string | Always | Action category. See the [Actions table](#actions). |
| `path` | string | Conditional | Vault entry path the action targets. May be `<reason>` for denials before path resolution. |
| `field` | string | Conditional | Field name targeted (e.g. `password`, `totp.secret`). **Field values are never recorded.** |
| `transport` | string | Conditional | `stdio` for CLI and MCP stdio, `http` for MCP HTTP. |
| `reason` | string | Conditional | Human-readable reason for failure (`ok: false`). For denials, typically the action name itself (e.g. `scope_denied`, `write_denied`). |
| `share_id` | string | Optional | Share grant ID for sharing-related events. |
| `from_agent` | string | Optional | Source agent in a share operation. |
| `to_agent` | string | Optional | Target agent in a share operation. |
| `share_action` | string | Optional | Share operation type (e.g. `share_request`, `share_approve`, `share_revoke`). |
| `dur_ms` | int64 | Optional | Measured operation duration in milliseconds. |
| `token_id` | string | Optional | MCP bearer token ID from `TokenFromContext`. |
| `req_id` | string | Optional | Unique request ID from `RequestIDFromContext`. |
| `sess_id` | string | Optional | MCP session identifier for correlation. |
| `hmac` | string | Conditional | Hex-encoded SHA-256 HMAC. Present when a key is available. See [HMAC chain](#hmac-integrity-chain). |
| `ok` | bool | Always | `true` for successful operations, `false` for denials or errors. |

### Redaction Guarantees

The `Field` field records **only field names** — never field values. The audit
log never contains:
- Entry field values (passwords, TOTP secrets, API keys, notes)
- Environment variable values from `run_command` or `execute_with_secret`
- Response bodies from `execute_api_request`
- Token secrets or bearer token values
- Any data classified as a secret by the vault

Path values may contain the entry path (e.g. `secret/github`) because paths are
metadata, not secrets. Path segments that happen to be passwords (e.g.
`passwords/bank`) are recorded as-is — the path itself is directory structure,
not a secret value.

### Transport Types

| Transport | Meaning |
|-----------|---------|
| `stdio` | MCP server running in stdio mode (typical for Claude Code, OpenCode, Hermes CLI) |
| `http` | MCP server running in HTTP mode (bound to 127.0.0.1) |

## Actions

Every audit event has an `action` field that categorizes the operation. The
following actions are used in the public self-hosted core:

### Entry Operations

| Action | Description | OK=true means |
|--------|-------------|---------------|
| `get` | Generic entry retrieval (metadata + fields) | Entry returned |
| `get_value` | Retrieve a specific field value | Value returned (redacted in audit) |
| `get_metadata` | Retrieve entry metadata only | Metadata returned |
| `set` | Create or update an entry field | Write completed |
| `set_entry_field` | Set a single field via MCP tool | Field set |
| `delete` | Delete an entry | Entry deleted |
| `list` | List entries matching a prefix | Entries listed |
| `find` | Search for entries by query | Results returned |
| `generate` | Generate a random password | Password generated |

### Authorization & Enforcement

| Action | Description | OK=true means |
|--------|-------------|---------------|
| `read` | Read authorization granted | Access allowed |
| `write` | Write authorization granted | Access allowed |
| `scope_denied` | Request outside agent allowed paths | — (always false) |
| `write_denied` | Write request from read-only agent | — (always false) |
| `approval_required` | Write requires human approval (deny mode) | — (always false) |
| `policy_denied` | Rejected by policy engine | — (always false) |
| `policy_prompt` | Policy requires approval prompt | — (always false) |
| `policy_biometry` | Policy requires biometric verification | — (always false) |
| `policy_biometry_passed` | Biometric verification succeeded | Biometry passed |
| `policy_biometry_failed` | Biometric verification failed | — (always false) |
| `policy_biometry_unavailable` | Biometric verification unavailable | — (always false) |
| `tool_scope_denied` | Tool outside agent scope | — (always false) |
| `agent_tool_denied` | Tool blocked by agent tier | — (always false) |
| `tool_registry_drift` | Tool registered but no handler | — (always false) |
| `post_call_hook_error` | Post-call hook failed | — (always false) |
| `approval.<action>.denied` | Approval explicitly denied | — (always false) |
| `approval.<action>.granted` | Approval granted | Approved |
| `approval.<action>.requested` | Approval prompt requested | Prompt shown |
| `approval.<action>.remembered` | Approval remembered from prior grant | Remembered |
| `quarantine_block` | Entry blocked by quarantine | — (always false) |

### Tool Invocations

| Action | Description | OK=true means |
|--------|-------------|---------------|
| `copy_to_clipboard` | Copy value to system clipboard | Copied |
| `autotype` | Auto-type value into focused app | Typed |
| `generate_totp` | Generate TOTP code | Code generated |
| `generate_totp.clipboard` | Generate TOTP and copy to clipboard | Copied |
| `generate_totp.autotype` | Generate TOTP and auto-type | Typed |
| `generate_totp.return` | Generate TOTP and return directly | Returned |
| `run_command` | Execute a command with secrets as env vars | Command completed (exit 0) |
| `execute_with_secret` | Execute a command with secrets injected | Command completed (exit 0) |
| `execute_api_request` | Execute an API request via template | Response received (status < 400) |
| `secret_unseal` | Decrypt and surface an entry value | Unsealed |
| `secret_unseal_remembered` | Unseal with remembered approval | Unsealed |
| `secure_input` | Collect credential via native dialog | Collected |
| `sanitize_output` | Sanitize output for injection patterns | Sanitized |
| `perplexity_search` | Perplexity API search | Results returned |
| `perplexity_ask` | Perplexity API ask | Answer returned |
| `search_openai` | OpenAI web search | Results returned |
| `fetch_openai` | OpenAI fetch URL | Content retrieved |
| `template_generated` | Template engine generated output | Generated |
| `template_written` | Template engine wrote output to file | Written |
| `template_failed` | Template engine failed | — (always false) |

### Sharing Operations

| Action | Description | OK=true means |
|--------|-------------|---------------|
| `share_request` | Request access to another agent's entry | Requested |
| `share_approve` | Approve a share request | Approved |
| `share_approve_denied` | Share approval denied | — (always false) |
| `share_reject` | Reject a share request | Rejected |
| `share_revoke` | Revoke an existing share | Revoked |
| `share_list` | List active shares | Listed |
| `share_grant` | Grant access via share | Granted |
| `share_expired` | Share grant has expired | — (always false) |

### Authentication & Administration

| Action | Description | OK=true means |
|--------|-------------|---------------|
| `auth_failure` | MCP token authentication failed | — (always false) |
| `auth_config` | Auth method configuration changed | Configured |
| `auth_config_denied` | Auth config blocked by tier | — (always false) |
| `auth_method_biometric_failed` | Biometric auth method failed | — (always false) |
| `rotate-passphrase` | Vault passphrase rotated | Rotated |
| `token_cleanup` | Expired token cleanup job | Cleaned |
| `tool_invocation` | Generic tool invocation hook | Invoked |

### Anomaly Detection

| Action | Description | OK=true means |
|--------|-------------|---------------|
| `anomaly_<type>` | Anomaly alert from metrics system | Alert recorded |

## OK/Reason Semantics

- `ok: true` — The operation completed successfully. `reason` is typically
  empty.
- `ok: false` — The operation was denied or failed. `reason` contains a
  human-readable explanation. For authorization denials, the `action` name
  itself is used as the `reason` (e.g. action=`write_denied`, reason=
  `write_denied`).

For error entries, the `GetErrors()` method on the logger returns a filtered,
redacted subset containing only `ok: false` entries with `ts`, `action`, and
`reason`.

## JSONL Format

Audit log files use JSONL (JSON Lines) format:
- One complete JSON object per line, terminated by `\n`
- No trailing commas, no array wrapper
- Each line is a valid, self-contained `LogEntry`

Example file content:
```jsonl
{"ts":"2026-04-27T10:30:00Z","agent":"claude-code","action":"get","path":"dev/api-key","transport":"stdio","token_id":"tok_abc123","req_id":"req_001","sess_id":"sess_001","ok":true,"hmac":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
{"ts":"2026-04-27T10:31:00Z","agent":"claude-code","action":"set","path":"secret/key","field":"password","transport":"stdio","token_id":"tok_abc123","req_id":"req_002","sess_id":"sess_001","hmac":"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3","ok":false,"reason":"write_denied"}
{"ts":"2026-04-27T10:32:00Z","agent":"claude-code","action":"list","path":"dev/","transport":"stdio","token_id":"tok_abc123","req_id":"req_003","sess_id":"sess_001","ok":true,"hmac":"c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"}
```

### Malformed Lines

When reading log files programmatically via `lastNEntries()` or
`parseTailEntries()`, malformed JSON lines are silently skipped. This means a
corrupted line in the log does not block reading the remaining valid entries.

## HMAC Integrity Chain

Each audit entry (when an HMAC key is loaded) carries a chained SHA-256 HMAC
that cryptographically links it to the previous entry. This provides tamper
detection for the entire log file.

### How It Works

1. An HMAC key (32 bytes, generated by `crypto/rand`) is loaded from the OS
   keyring or fallback file at `~/.symvault/audit-hmac-key`.
2. For each new entry, the HMAC is computed as:
   ```
   HMAC-SHA256(key, prevHMAC || canonicalJSON(entry))
   ```
   where `canonicalJSON(entry)` is the JSON serialization of the entry with the
   `hmac` field set to empty string.
3. The resulting HMAC is written as the `hmac` field of the entry and becomes
   the `prevHMAC` for the next entry.
4. On logger re-open, the last entry's HMAC is read and used as the initial
   chain state.

### Integrity Verification

Use `VerifyLog()` to check a log file's integrity:

```go
result, err := audit.VerifyLog("/path/to/audit-claude-code.log", hmacKey)
// result.Valid       bool   — true if all entries verify
// result.Total       int    — total entries parsed
// result.Verified    int    — entries with valid HMACs
// result.Legacy      int    — entries without HMAC (pre-v0.4 format)
// result.Tampered    int    — entries with invalid HMACs
// result.FirstBadIdx int    — index of first tampered entry (-1 if none)
```

See [audit-retention.md](audit-retention.md) for the CLI command
`symvault audit verify` and HMAC key rotation.

## Version Compatibility

The `LogEntry` schema is stable for the `v0.x` release line:

- **No field removal** — Existing fields will not be removed in `v0.x`.
- **No field renames** — Field names and JSON keys will not change.
- **Optional field additions** — New `omitempty` fields may be added in minor
  releases without a breaking change.
- **JSONL format** — The one-JSON-object-per-line format is permanent.
- **HMAC scheme** — The chained HMAC-SHA256 scheme is permanent. Key rotation
  is supported without format changes.

Breaking schema changes, if ever needed, will only arrive with a `v1.0` major
release and will be documented in the changelog.

## Cloud Pro Boundary

The public self-hosted Symaira Vault core provides local audit logging with
HMAC integrity verification. The private Symaira Vault Pro repository extends
audit capabilities with:

- **SIEM export** — Streaming audit events to external SIEM platforms
- **Managed long-term retention** — Cloud-backed retention policies beyond local
  rotation
- **Compliance reporting** — Audit reports for SOC 2, ISO 27001, etc.
- **Tenant audit storage** — Multi-tenant audit log partitioning and access
  controls
- **Centralized audit search** — Cross-agent, cross-vault audit event search

None of these Pro features are included in the public self-hosted product. The
local audit system documented here is fully functional and useful on its own
for self-hosted deployments.

## Related Documentation

- [Audit Retention & Integrity](audit-retention.md) — Retention configuration,
  key rotation, integrity verification
- [Error Tracking Strategy](error-tracking-strategy.md) — Audit system overview
  in the error tracking context
- [Security Policy](../SECURITY.md#audit-logs) — Audit log privacy and
  configuration
- [Runbook](../docs/runbook.md#audit-log-hmac-key-rotation) — HMAC key rotation
  procedures
- `internal/audit/audit.go` — Implementation
