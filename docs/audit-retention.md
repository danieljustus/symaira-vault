# Audit Retention & Integrity

**Scope**: Public self-hosted Symaira Vault core. Cloud Pro management is
separate (see [Cloud Pro Boundary](audit-schema.md#cloud-pro-boundary)).

## Retention Configuration

Symaira Vault audit logs are stored per-agent at
`~/.symvault/audit-<agent>.log`. The retention system automatically rotates
logs and prunes old files based on configurable limits.

### Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SYMVAULT_AUDIT_MAX_SIZE_MB` | `100` | Maximum log file size in megabytes before rotation |
| `SYMVAULT_AUDIT_MAX_BACKUPS` | `5` | Maximum number of rotated backup files to retain |
| `SYMVAULT_AUDIT_MAX_AGE_DAYS` | `30` | Maximum age in days before rotated files are deleted |

Legacy `OPENPASS_AUDIT_*` variants are also accepted for backward
compatibility. `SYMVAULT_*` takes precedence when both are set.

### Configuration via config.yaml

The audit section in `~/.symvault/config.yaml` can also set these values:

```yaml
audit:
  maxFileSize: 200   # MB, overrides env var
  maxBackups: 10
  maxAgeDays: 90
```

Environment variables always take precedence over config file values.

### Setting Values

```bash
# Set via environment (session)
export SYMVAULT_AUDIT_MAX_SIZE_MB=200
export SYMVAULT_AUDIT_MAX_BACKUPS=10
export SYMVAULT_AUDIT_MAX_AGE_DAYS=90

# Or export in your shell profile (~/.zshrc, ~/.bashrc) for persistence
```

## Rotation Algorithm

Rotation runs on every new logger creation (when an agent first connects) and
is checked before every write via `rotateIfNeeded()`.

### Triggers

Rotation is triggered when **either**:
1. **Size limit**: The current log file exceeds `SYMVAULT_AUDIT_MAX_SIZE_MB`
   megabytes.
2. **Age limit**: The current log file's modification time is older than
   `SYMVAULT_AUDIT_MAX_AGE_DAYS` days.

### Rotation Process

1. The current log file is closed.
2. It is renamed to `audit-<agent>.log.rotated.<YYYYMMDD-HHMMSS>` in the same
   directory.
3. A new empty `audit-<agent>.log` file is opened for append.
4. If rename fails (e.g. file locked), the rotation is skipped gracefully and
   writing continues to the same file.

Rotation is thread-safe and does not lose log entries — entries written during
rotation go to the new file.

### Retention Enforcement

`EnforceRetention()` runs the cleanup policy on rotated files:

1. **Backup count**: If more than `MaxBackups` rotated files exist, the oldest
   are deleted first until the count is within the limit.
2. **Age cleanup**: Any rotated file older than `MaxAgeDays` is deleted.

Files are sorted by modification time; the newest files are preserved. This
means with `MaxBackups=3`, the 3 most recently rotated files survive.

Retention enforcement is called manually via `EnforceRetention()`. It is not
triggered automatically on every write — callers should invoke it periodically
or after rotation events.

## Common Retention Policies

### Minimal Retention (limited disk space)

```bash
export SYMVAULT_AUDIT_MAX_SIZE_MB=50
export SYMVAULT_AUDIT_MAX_BACKUPS=2
export SYMVAULT_AUDIT_MAX_AGE_DAYS=7
```

Disk usage: ~150MB maximum (50MB current + 2×50MB backups).

### Default (recommended)

```bash
export SYMVAULT_AUDIT_MAX_SIZE_MB=100
export SYMVAULT_AUDIT_MAX_BACKUPS=5
export SYMVAULT_AUDIT_MAX_AGE_DAYS=30
```

Disk usage: ~600MB maximum (100MB current + 5×100MB backups).

### Long-Term Retention (compliance)

```bash
export SYMVAULT_AUDIT_MAX_SIZE_MB=200
export SYMVAULT_AUDIT_MAX_BACKUPS=20
export SYMVAULT_AUDIT_MAX_AGE_DAYS=365
```

Disk usage: ~4.2GB maximum (200MB current + 20×200MB backups).

### Disable Retention (keep everything)

```bash
export SYMVAULT_AUDIT_MAX_BACKUPS=0
export SYMVAULT_AUDIT_MAX_AGE_DAYS=0
```

> **Warning**: With `MaxBackups=0`, all rotated files are immediately deleted.
> Use large values like `999999` to effectively disable cleanup while keeping
> backups.

### Audit Log Health

Check audit log health programmatically:

```go
status, err := logger.HealthCheck()
// status.LogFilePath      — path to current log file
// status.LogFileSize      — current file size in bytes
// status.TotalAuditSize   — total size of all files (current + rotated)
// status.LogFileAge       — age of current file (e.g. "2h30m")
// status.NeedsRotation    — true if rotation is due
// status.NeedsRetention   — true if cleanup is due
// status.ErrorCount       — count of ok:false entries in last 100
// status.WriteAccessible  — true if file is writable
```

## HMAC Key Management

### Key Storage

The audit HMAC key is a 32-byte random key stored in:
- **Primary**: OS keyring (service: `symaira`, account: `audit-hmac-key:<vault-dir>`)
- **Fallback**: File at `~/.symvault/audit-hmac-key` (permissions `0o600`)

The key is generated on first use and loaded on subsequent logger creation.

### Key Rotation

When the HMAC key may have been compromised, rotate it:

```bash
symvault audit rotate-key
```

This command:
1. Generates a new 32-byte random HMAC key using `crypto/rand`.
2. Archives the current key to `audit-hmac-key.rotated.YYYY-MM-DD` in the
   vault directory.
3. Stores the new key in the OS keyring and fallback file.
4. Future audit entries use the new key for HMAC computation.

**Important**: The archived key file is essential for verifying historical
audit logs. Back it up alongside your vault.

### Verifying with Archived Keys

After rotation, verify logs with both the current and archived keys:

```bash
# Verify with current key
symvault audit verify

# Verify with an archived key
symvault audit verify --key-file ~/.symvault/audit-hmac-key.rotated.2026-05-28
```

### Key Loss

If all HMAC keys are lost (no archived copies, OS keyring cleared):
1. Generate a fresh key: `symvault audit rotate-key`
2. All future entries use the new HMAC chain
3. Existing log entries remain readable but their HMACs cannot be verified
4. Any tampering that occurred before key loss is undetectable

## Integrity Verification

### VerifyLog Function

`VerifyLog()` checks the HMAC chain of an entire audit log file:

```go
func VerifyLog(logFilePath string, key []byte) (*VerifyResult, error)
```

**Parameters**:
- `logFilePath` — Absolute path to the audit log file
- `key` — The HMAC key bytes (from `Keystore.LoadHMACKey()`)

**Returns**:

```go
type VerifyResult struct {
    Valid       bool  // true if ALL entries pass verification
    Total       int   // total entries parsed from the log
    Verified    int   // entries with correct HMAC
    Legacy      int   // entries without HMAC (pre-v0.4 format)
    Tampered    int   // entries with incorrect HMAC (tampered)
    FirstBadIdx int   // index of first tampered entry (-1 if none)
}
```

### What It Detects

HMAC chain verification detects:
- **Entry modification** — Any change to an entry's fields (action, path, ok, etc.)
- **Entry insertion** — New entries inserted between existing entries
- **Entry deletion** — Removal of entries from the chain
- **Entry reordering** — Moving entries within the log file

### What It Does Not Detect

- **Truncation at end** — If the last N entries are deleted, the remaining
  chain is still valid. Mitigate with off-site backup or external monitoring.
- **Full log replacement** — If the entire log file is replaced with a validly
  chained alternative. Mitigate with file integrity monitoring or periodic
  verification snapshots.

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/danieljustus/symaira-vault/internal/audit"
)

func main() {
    ks := audit.NewKeystore("/path/to/vault", nil)
    key, err := ks.LoadHMACKey()
    if err != nil {
        panic(err)
    }

    result, err := audit.VerifyLog("/path/to/vault/audit-claude-code.log", key)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Valid: %v\n", result.Valid)
    fmt.Printf("Total: %d, Verified: %d, Legacy: %d, Tampered: %d\n",
        result.Total, result.Verified, result.Legacy, result.Tampered)
    if result.FirstBadIdx >= 0 {
        fmt.Printf("First tampered entry at index: %d\n", result.FirstBadIdx)
    }
}
```

### CLI Verification

```bash
# Verify all agent audit logs
symvault audit verify

# Verify a specific agent's log
symvault audit verify --agent claude-code

# Verify with an archived HMAC key
symvault audit verify --key-file ~/.symvault/audit-hmac-key.rotated.2026-05-28
```

### Legacy Logs

Entries without an `hmac` field (written before v0.4 or when no HMAC key was
available) are counted as `Legacy`. They are skipped during verification and do
not invalidate the chain. When a legacy entry appears, the previous HMAC state
is reset, so the next HMAC-bearing entry starts a fresh chain.

## Related Documentation

- [Audit Event Schema](audit-schema.md) — Schema, actions, HMAC chain design
- [Error Tracking Strategy](error-tracking-strategy.md) — Audit system in
  diagnostic context
- [Security Policy](../SECURITY.md#audit-logs) — Audit log privacy
- [Runbook](../docs/runbook.md#audit-log-hmac-key-rotation) — Incident response
  procedures
- `internal/audit/audit.go` — Implementation
- `internal/audit/keystore.go` — HMAC key storage
