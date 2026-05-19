# Security Policy

## Supported Versions

OpenPass v1.0.0 is the first stable release. Security reports are accepted for
the latest stable 1.x release. Snapshots and local builds are unsupported except
where a maintainer explicitly requests reproduction details for a current fix.

| Version                   | Supported         | Notes                                                   |
| ------------------------- | ----------------- | ------------------------------------------------------- |
| v1.x                      | :white_check_mark: | Latest stable release line                              |
| Snapshots and local builds | :x:               | Reproduce on the latest stable release before reporting |

### Stable Security Support

We prioritize vulnerability fixes based on impact. Fixes may ship as a patch
release, documentation update, or configuration guidance. Unsupported snapshots
and local builds do not receive maintenance releases or backports.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### Reporting Process

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Submit a private vulnerability report via [GitHub Security Advisories](https://github.com/danieljustus/OpenPass/security/advisories/new)
3. Include the following in your report:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact of the vulnerability
   - Any suggested fixes (optional)

### What to Expect

- **Initial Response**: Within 48 hours, we will acknowledge receipt of your report
- **Status Update**: We aim to provide a timeline for when a fix will be available
- **Credit**: With your permission, we will credit you in the security advisory (if public)
- **Disclosure**: We follow a coordinated disclosure process

### Scope

The following are within scope for vulnerability reports:
- Encryption implementation (age X25519 + ChaCha20-Poly1305)
- Passphrase handling and storage
- Session management and keyring integration
- MCP server security (stdio and HTTP modes)
- Vault file format and entry encryption

The following are **out of scope**:
- Social engineering attacks
- Physical security of the user's machine
- Third-party dependencies (report to their respective maintainers)

## Known Vulnerabilities

**No known vulnerabilities at this time.**

For historical security advisories, see the [Security Advisories](https://github.com/danieljustus/OpenPass/security/advisories) page.

## Release Artifact Verification

OpenPass releases publish SHA-256 checksums for downloadable artifacts. To verify
a downloaded artifact:

```bash
sha256sum --check OpenPass_VERSION_checksums.txt
```

On macOS, use `shasum -a 256 --check OpenPass_VERSION_checksums.txt` if
`sha256sum` is not installed.

## Security-Related Configuration

### Update Checker TLS Configuration

The `openpass update check` command queries the GitHub API for the latest release.
All outbound HTTPS connections from the update checker enforce **TLS 1.3** as the
minimum protocol version. Connections to servers that do not support TLS 1.3
will be rejected.

TLS certificate verification errors produce a user-friendly error message:

```
update check failed: TLS certificate verification error - ...
```

This ensures that:
- Downgrade attacks to TLS 1.2 or earlier are prevented
- Certificate validation failures are clearly communicated
- The update channel cannot be intercepted by malicious endpoints with weak TLS configurations

### Vault Permissions

Ensure your vault directory has appropriate access controls:

```bash
# Restrict vault directory access (Unix-like systems)
chmod 700 ~/.openpass
chmod 600 ~/.openpass/identity.age
```

### Prompt Injection & Agent Safety

OpenPass exposes vault credentials to LLM agents via the MCP server. That
makes prompt injection (OWASP LLM01, MITRE ATLAS AML.T0051) the primary
threat class for this surface. The full threat model — covering direct and
indirect prompt injection, tool poisoning, sensitive-information disclosure,
path traversal, and excessive agency — lives in
[`docs/threat-model.md`](docs/threat-model.md).

Headline defenses:

- **Central output chokepoint** — every MCP tool response passes through
  a three-phase sanitizer (Unicode NFKC, dangerous-Unicode strip, byte-level
  ANSI/XML/HTML scrubber) in `internal/mcp/render.go` before reaching the
  LLM. Implemented as a single chokepoint so no handler can opt out.
- **Out-of-band TTY approval** for all Critical-tier tools (`set_entry_field`,
  `delete_entry`, `execute_api_request`, `secure_input`,
  `request_credential`). The TTY is a separate channel from the MCP
  transport so a jailbroken agent cannot self-approve.
- **Sealing** for high-classification secrets — agents receive an opaque
  `op://path/field` handle by default and must explicitly call
  `secret_unseal` (with its own approval) to reveal a value.
- **Compile-time taint system** (`internal/vault/taint/`, enforced by the
  custom `passlint` linter) — `Untrusted` values cannot be stringified by
  accident; the type's `Format()` emits `<untrusted:Source>` instead of
  content for any `%s/%v/%q`.
- **Token-scoped tool & path allowlists**, constant-time token comparison,
  rate-limiting, and audit logging on every call.
- **Anomaly detection** — desktop notifications for canary access, sweep
  patterns, request-rate spikes, and off-hours activity.

If you are integrating an agent profile, start from
[`docs/agent-integration.md`](docs/agent-integration.md) (metadata-first
adoption pattern) and review the [`hermes-safe-adoption.md`](docs/hermes-safe-adoption.md) gates.

### MCP Server Security

#### Stdio Mode (Recommended for Local Agents)

- Uses process isolation; no network exposure
- Agent permissions controlled via `approvalMode` setting

#### HTTP Mode

- Binds to `127.0.0.1` only (localhost) — not exposed to network
- Bearer token authentication required
- Token auto-generated and stored at `<vault>/mcp-token`
- Agent identified per-request via `X-OpenPass-Agent` header
- Max request body size: 1MB (requests exceeding this return 413 Request Entity Too Large)

**Security recommendations for HTTP mode:**
- Never expose the MCP server port to the network
- Use `approvalMode: deny` or `approvalMode: prompt` for untrusted agents

#### Metrics Endpoint

The `/metrics` endpoint exposes Prometheus-format metrics for **local monitoring only**. This is not outbound telemetry — metrics are served on-request to local monitoring tools and never transmitted to external services.

- On loopback binds (`127.0.0.1`, `::1`, `localhost`), `/metrics` is accessible without authentication
- On non-loopback binds, `/metrics` requires bearer token authentication by default
- This behavior is controlled via the `metrics_auth_required` config option:

```yaml
mcp:
  metrics_auth_required: true   # default: require auth on non-loopback binds
```

Setting `metrics_auth_required: false` allows anonymous access to `/metrics` when bound to non-local addresses. Only disable this if you have other access controls (e.g., firewall rules or reverse-proxy auth) in place.

#### Token Rotation

Bearer tokens can be rotated using the `mcp-token-rotate` command:

```bash
openpass mcp-token-rotate
```

This invalidates the previous token and generates a new one. Any MCP clients using the old token will need to be updated with the new token.

#### Safer Token Export

When generating MCP configurations that may be displayed in terminals or committed to version control, use the `--redact` flag:

```bash
openpass mcp-config claude-code --http --redact
```

This outputs `env:OPENPASS_MCP_TOKEN` instead of the actual token value. Clients using redacted configs must set the `OPENPASS_MCP_TOKEN` environment variable.

For scripts that need the raw token:

```bash
openpass mcp-config <agent> --token-only
```

### Multi-User Vaults and MCP

When using shared vaults with recipients (multiple people who can decrypt entries), MCP write operations (`set_entry_field`) preserve multi-recipient encryption. Unlike a plain `vault.WriteEntry` which only encrypts for the current user, MCP writes use `MergeEntryWithRecipients` (for updates) or `WriteEntryWithRecipients` (for new entries) to ensure all configured recipients can continue to decrypt the entry.

This means agents can safely update shared vault entries without breaking access for other recipients.

### Agent Configuration Security

```yaml
# ~/.openpass/config.yaml
agents:
  # Trusted local agents
  claude-code:
    allowedPaths: ["*"]
    canWrite: true
    approvalMode: none

  # Untrusted or external agents
  external-agent:
    allowedPaths: ["public/*", "work/*"]
    canWrite: false
    approvalMode: deny
```

#### Field Redaction for Sensitive Data

Agents can be configured to have sensitive fields redacted from `get_entry` responses using `redactFields`:

```yaml
agents:
  # Agent that should not see TOTP secrets
  readonly-agent:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["totp.secret"]
```

When `totp.secret` is redacted, the agent receives `[REDACTED]` instead of the actual TOTP seed. The `generate_totp` tool continues to work normally for generating TOTP codes.

Supported patterns:
- `"totp.secret"` - redacts the TOTP secret field specifically
- `"*"` - redacts all fields (use with caution)

**Recommendation**: For agents that only need TOTP codes, configure `redactFields: ["totp.secret"]` and use the `generate_totp` tool instead of `get_entry`.

### Touch ID / Biometric Authentication (macOS)

OpenPass supports optional Touch ID authentication for vault unlock on macOS. When enabled, Touch ID is used instead of typing your passphrase for unlock, while still maintaining secure keyring-cached session storage.

#### Setup

Set the auth method with the CLI:

```bash
openpass auth set touchid
```

Or add to your config (`~/.openpass/config.yaml` or vault `config.yaml`):

```yaml
authMethod: touchid
```

Legacy `useTouchID: true` and `vault.useTouchID: true` are still accepted for
backward compatibility. Prefer `authMethod: touchid` for new configs.

You can switch back at any time:

```bash
openpass auth set passphrase
```

#### How It Works

1. Enabling Touch ID validates your passphrase or active session
2. The passphrase is stored in a biometric-protected macOS Keychain item
3. On subsequent unlocks, Touch ID prompts instead of passphrase
4. If Touch ID succeeds, the passphrase is retrieved from Keychain
5. If Touch ID fails or is cancelled, interactive CLI commands fall back to a passphrase prompt

#### Limitations

- **macOS only**: Touch ID requires macOS with Touch ID hardware. Non-macOS builds use passphrase-only unlock.
- **Keychain dependency**: Touch ID authentication accesses the macOS Keychain, which itself may require user password on first Keychain access per session
- **Not a replacement for passphrase**: The passphrase is still the ultimate factor; Touch ID is a convenience layer accessing the same keyring-cached session
- **Biometric availability**: Touch ID must be configured and available on the system for `useTouchID: true` to work

#### Threat Model Considerations

- Touch ID provides convenience, not additional cryptographic protection
- The Keychain already requires user authentication to access secrets
- Touch ID allows faster access to the cached session, reducing friction but not weakening security
- Physical access to an unlocked session still bypasses Touch ID (same as passphrase)
- For highest security, use `sessionTimeout: 0` to disable session caching entirely

### Environment Variables

| Variable                    | Purpose                                      | Security Note                      |
| --------------------------- | -------------------------------------------- | ---------------------------------- |
| `OPENPASS_VAULT`            | Override vault location                      | Ensure path has proper permissions |
| `OPENPASS_PASSPHRASE`       | Non-interactive vault unlock                 | **Unset after reading** to prevent leakage to child processes |
| `OPENPASS_MCP_TOKEN`        | Override MCP bearer token (HTTP mode)        | **Unset after reading** to prevent leakage to child processes |
| `OPENPASS_AUDIT_MAX_SIZE_MB` | Max audit log file size in MB                | Higher values increase disk usage  |
| `OPENPASS_AUDIT_MAX_BACKUPS` | Number of audit backups to retain           | More backups use more disk space   |
| `OPENPASS_AUDIT_MAX_AGE_DAYS` | Days before audit backups are deleted       | Longer retention uses more space   |

## Security Best Practices

1. **Keep backups**: Regularly backup your vault directory
2. **Use strong passphrases**: Use `openpass generate --length 32 --symbols`
3. **Lock sessions**: Use `openpass lock` when leaving your terminal
4. **Review agent permissions**: Only grant `canWrite: true` to trusted agents
5. **Rotate tokens**: Periodically rotate MCP bearer tokens in HTTP mode
6. **Secure your Git repository**: If using Git sync, ensure your remote is secure

## Encryption Details

OpenPass uses [age](https://age-encryption.org/) for encryption:

- **Key Exchange**: X25519 (Curve25519 elliptic curve Diffie-Hellman)
- **Encryption**: ChaCha20-Poly1305 (authenticated encryption)
- **Identity File**: Encrypted with the identity's own public key, protected by scrypt (passphrase)

Each vault entry is encrypted individually as a standalone `.age` file, ensuring:
- No compound encryption failures
- Efficient partial access patterns
- Git history contains only ciphertext

### KDF Migration Path (scrypt → argon2id)

OpenPass currently uses **scrypt** (N=262144, r=8, p=1 — work factor 18) for
passphrase-based key derivation. While scrypt provides reasonable protection,
**argon2id** is the industry-standard memory-hard KDF (RFC 9106) and provides
stronger resistance against GPU/ASIC-based attacks.

#### Current Status (v1.x)

| Vault Format | KDF    | Work Factor | Doctor Check         |
|-------------|--------|-------------|---------------------|
| v1 (current) | scrypt | 18          | `crypto.kdf.modern` warns |
| v2 (planned) | argon2id | TBD       | `crypto.kdf.modern` OK    |

#### Migration Plan

A future release will provide:
- `openpass migrate kdf` command to re-encrypt vault entries with argon2id
- Automatic detection of vault format version
- Doctor check `crypto.kdf.modern` to track migration status

#### Preparing for Migration

1. **Back up your vault** before any migration:
   ```bash
   cp -r ~/.openpass ~/.openpass.backup
   ```
2. Run `openpass doctor` to check current KDF status
3. Wait for the migration command to be available in a future release

#### Why argon2id?

- **Memory-hard**: Resistant to GPU, FPGA, and ASIC acceleration
- **Side-channel resistant**: argon2id mode resists both timing and cache-timing attacks
- **Industry standard**: Winner of the 2015 Password Hashing Competition (PHC)
- **RFC 9106**: Standardized by the IETF
- **Broader ecosystem**: Used by major password managers and security tools

## Privacy & Telemetry

OpenPass does **NOT** collect any product analytics, error reports, or usage telemetry.

### Our Privacy Commitment

As a password manager handling highly sensitive credentials, we believe telemetry would create unacceptable privacy and security risks:

- **No external telemetry services**: We don't use Sentry, Datadog, Crashlytics, or similar services
- **No in-app analytics**: We don't track user behavior, command usage, or feature adoption
- **No error reporting services**: User errors stay local; no data exfiltration to third parties
- **No network phoning home**: OpenPass operates entirely offline after installation
- **Local metrics only**: The `/metrics` endpoint serves Prometheus metrics locally on request; no metrics are pushed or transmitted to external services

### What Stays Local

All data remains on your device:
- **Vault contents**: Your passwords, TOTP secrets, and notes are never transmitted
- **Audit logs**: Stored locally in `~/.openpass/audit-*.log` with rotation and retention limits
- **Error information**: Diagnostic commands like `openpass --version` and `openpass list` stay on your machine
- **Session data**: Cached via OS keyring, never transmitted

### Audit Logs

OpenPass maintains local audit logs for MCP tool calls (see `internal/audit/audit.go`). These logs:
- Are stored in `~/.openpass/audit-<agent>.log`
- Rotate when they exceed 100MB per file or 30 days old
- Are retained up to 5 backup files before oldest are pruned
- Contain only action metadata, no field values or secrets

#### Audit Log Configuration

Audit log rotation is configurable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENPASS_AUDIT_MAX_SIZE_MB` | 100 | Max size in MB per audit log file before rotation |
| `OPENPASS_AUDIT_MAX_BACKUPS` | 5 | Number of rotated backup files to retain |
| `OPENPASS_AUDIT_MAX_AGE_DAYS` | 30 | Max age in days before rotated files are deleted |

### GDPR Compliance

OpenPass is GDPR-compliant by design:
- No personal data is collected
- No data is processed by third parties
- No consent dialogs required for telemetry (because there is no telemetry)

For more details on error tracking strategy, see [docs/error-tracking-strategy.md](docs/error-tracking-strategy.md).

## Contact

- **GitHub Security Advisories**: https://github.com/danieljustus/OpenPass/security/advisories/new
- **Public Security Advisories**: https://github.com/danieljustus/OpenPass/security/advisories

For non-security issues, please use the [public issue tracker](https://github.com/danieljustus/OpenPass/issues).
