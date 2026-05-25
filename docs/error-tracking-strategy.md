# Error Tracking Strategy for Symaira Vault

**Status**: DECIDED - No External Telemetry
**Last Updated**: 2026-04-27

## Decision

Symaira Vault does **NOT** use external error tracking services (Sentry, Datadog, Crashlytics, etc.) for the following reasons:

1. **Privacy-First**: As a password manager, Symaira Vault handles highly sensitive data. External telemetry services create unacceptable data exposure risks.
2. **Secret Safety**: Even with redaction, error reports from a password manager could inadvertently leak sensitive patterns.
3. **GDPR Compliance**: External telemetry would require explicit user consent and data processing agreements.
4. **User Trust**: Password manager users expect minimal network activity and no data exfiltration.

## Current Capabilities

The following audit, diagnostic, and redaction capabilities are **already implemented**:

### Audit Logging (internal/audit)

Symaira Vault maintains comprehensive audit logs for MCP operations:

| Feature | Implementation | Location |
|---------|---------------|----------|
| JSONL audit logs | Per-agent log files | `~/.openpass/audit-<agent>.log` |
| Log rotation | By size (100MB) and age (30 days) | Automatic on write |
| Retention policy | Configurable backup count | Default: 5 backups |
| Health monitoring | `HealthCheck()` function | `internal/audit/audit.go` |
| Error retrieval | `GetErrors()` function | Returns redacted error entries |
| Thread safety | Mutex-protected writes | Safe for concurrent use |

**Configuration via Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENPASS_AUDIT_MAX_SIZE_MB` | 100 | Max log file size before rotation |
| `OPENPASS_AUDIT_MAX_BACKUPS` | 5 | Number of rotated backups to retain |
| `OPENPASS_AUDIT_MAX_AGE_DAYS` | 30 | Max age of rotated files before deletion |

**Audit Log Content:**
- Only action metadata (agent, action, path, field, transport, success/failure)
- **No field values or secrets ever logged**
- Duration, timestamp, and error reasons (redacted)

See also:
- `SECURITY.md` § Audit Logs for privacy details
- `internal/audit/audit.go` for implementation

### Redaction Capabilities

Field-level redaction is implemented for MCP agent responses:

| Redaction Feature | Implementation | Usage |
|-------------------|----------------|-------|
| Agent field redaction | `redactFields` config | `~/.openpass/config.yaml` |
| Token redaction in config | `--redact` flag | `symvault mcp-config <agent> --redact` |
| Wildcard patterns | `*` and `prefix.*` | Redact all or nested fields |

**Example Agent Configuration:**
```yaml
agents:
  readonly-agent:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["totp.secret", "password"]
```

When `totp.secret` is redacted, the agent receives `[REDACTED]` instead of the actual TOTP seed. The `generate_totp` tool continues to work normally.

See also:
- `SECURITY.md` § Field Redaction for Sensitive Data
- `internal/mcp/server.go` § `redactEntry()`, `redactValue()`

### Troubleshooting & Diagnostics

Operational diagnostic capabilities exist:

| Resource | Purpose | Location |
|----------|---------|----------|
| Troubleshooting guide | Common issues and fixes | `docs/troubleshooting.md` |
| Operational runbook | Incident response, token rotation | `docs/runbook.md` |
| MCP API docs | Error handling, rate limiting | `docs/mcp-api.md` |
| Security policy | Privacy, telemetry, audit info | `SECURITY.md` |
| Basic diagnostics | Version, list, unlock | `symvault --version`, `symvault list`, `symvault unlock` |

### Error Categories and Exit Codes

| Code | Category | Description |
|------|----------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | General Error | Unclassified error |
| 2 | Vault Error | Vault file corruption, missing identity, etc. |
| 3 | Crypto Error | Encryption/decryption failures, age errors |
| 4 | Config Error | Invalid configuration, missing config file |
| 5 | Keyring Error | OS keyring access failures |
| 6 | Git Error | Git operation failures |
| 7 | Network Error | HTTP/MCP network issues |
| 8 | Permission Error | File/directory permission issues |
| 9 | Validation Error | Input validation failures |
| 10 | MCP Error | MCP server or protocol errors |
| 11 | Audit Error | Audit logging failures |

### CLI Error Output Format

```
Error: failed to decrypt entry
Category: crypto_error (exit code 3)
Suggestion: This may indicate vault corruption. Check vault permissions and try listing entries.
```

### MCP Error Responses

MCP errors include sanitized error data:

```json
{
  "error": {
    "code": "CRYPTO_ERROR",
    "message": "decryption failed",
    "category": 3,
    "suggestion": "Check vault permissions and verify entry files exist"
  }
}
```

## Future Enhancements

The following capabilities are **NOT YET IMPLEMENTED** but identified for future work:

### 1. Local Error Bundle Command

A CLI command to gather diagnostic information for issue reporting:

```bash
# Hypothetical future command
symvault diagnostics --bundle
```

**Purpose:** Collect version info, config (sanitized), audit error summary, and environment details into a shareable bundle.

**Gap:** Users must currently gather diagnostics manually (see "Manual Diagnostics" below).

### 2. Redaction Utilities for Error Reports

A utility to redact sensitive data from arbitrary error outputs:

```bash
# Hypothetical future command
symvault diagnostics --redact < raw-output.log
```

**Purpose:** Apply redaction rules (field values, paths, tokens) to any text intended for sharing.

**Gap:** Current redaction only applies to:
- MCP `get_entry` responses (via `redactFields`)
- Token display in `mcp-config --redact`

There is no general-purpose error report redaction tool.

### 3. Audit Log Export with Redaction

A command to export audit logs with filtering/redaction:

```bash
# Hypothetical future commands
symvault audit export --since 2026-04-01 --redact-paths
symvault audit errors --limit 50
```

**Purpose:** Export audit data for analysis while applying redaction rules.

**Gap:** Audit logs are currently only accessible by reading the JSONL files directly or using the `GetErrors()` API internally.

### Manual Diagnostics (Current Workaround)

Until the above features are implemented, users can gather diagnostics manually:

```bash
# Basic diagnostics
symvault --version
symvault list

# Check vault permissions
ls -la ~/.openpass/
ls -la ~/.openpass/entries/

# Check config (review for secrets before sharing)
cat ~/.openpass/config.yaml

# Check audit log health (via health endpoint)
curl -s http://127.0.0.1:8080/health
```

When reporting issues, include:
- Symaira Vault version and Go version
- OS/platform information
- Error message and exit code
- Steps to reproduce

## Redaction Rules for Future Error Reports

When the error bundle/export features are implemented, they MUST apply these redaction rules:

| Data Type | Redaction Rule |
|-----------|----------------|
| Field values | Replaced with `[REDACTED]` |
| Entry paths | Only parent directories exposed, entry names redacted |
| Field names | Normalized to generic names (e.g., `field.0`, `field.1`) |
| Header values | All headers redacted except content-type |
| Tokens/secrets | Always redacted, never exported |
| File contents | Never included in error reports |

## Implementation Status Summary

| Capability | Status | Reference |
|------------|--------|-----------|
| Error category enum | ✅ Implemented | Exit codes table above |
| Exit codes | ✅ Implemented | Exit codes table above |
| MCP error response format | ✅ Implemented | MCP Error Responses section above |
| Audit logging system | ✅ Implemented | `internal/audit/`, `SECURITY.md` |
| Log rotation | ✅ Implemented | `internal/audit/audit.go` |
| Log retention | ✅ Implemented | `internal/audit/audit.go` |
| Field redaction (MCP) | ✅ Implemented | `SECURITY.md`, `internal/mcp/server.go` |
| Token redaction (config) | ✅ Implemented | `SECURITY.md` |
| Troubleshooting docs | ✅ Implemented | `docs/troubleshooting.md`, `docs/runbook.md` |
| Local error bundle command | ❌ **Future** | Manual diagnostics only |
| Redaction utilities for error reports | ❌ **Future** | Partial: MCP redaction only |
| Audit log export with redaction | ❌ **Future** | Read JSONL files directly |

## Related Documentation

- `SECURITY.md` - Privacy policy, audit log details, redaction configuration
- `docs/troubleshooting.md` - Common issues and diagnostic steps
- `docs/runbook.md` - Operational procedures, incident response
- `docs/mcp-api.md` - MCP error handling, rate limiting
- `internal/audit/audit.go` - Audit logging implementation