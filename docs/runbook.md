# Symaira Vault Launch & Incident Response Runbook

**Maintainer**: Symaira Vault Team
**Security Contact**: https://github.com/danieljustus/symaira-vault/security/advisories/new
**Repository**: https://github.com/danieljustus/symaira-vault

## Table of Contents

1. [CI/CD Overview](#cicd-overview)
2. [govulncheck Failures](#govulncheck-failures)
3. [Dependabot Alerts](#dependabot-alerts)
4. [Release Workflow Errors](#release-workflow-errors)
5. [Backup & Recovery](#backup--recovery)
6. [Security Incident Response](#security-incident-response)
7. [Post-Release Checklist](#post-release-checklist)

---

## CI/CD Overview

Symaira Vault uses GitHub Actions for CI/CD:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push to main, PRs | Tests, lint, govulncheck, builds |
| `release.yml` | Version tags (`v*`) | Release artifacts, checksums |

### CI Pipeline Jobs

1. **govulncheck** - Vulnerability scanning
2. **lint** - Code quality checks (golangci-lint)
3. **test** - Unit and integration tests
4. **build** - Cross-platform binary builds
5. **integration-test** - Integration test suite

### Release Pipeline Jobs

1. **lint** - Format check, golangci-lint, gosec SAST (mirrors CI gates)
2. **test** - Pre-release validation
3. **govulncheck** - Final vulnerability scan
4. **release** - GoReleaser artifact publishing (depends on all above)

---

## govulncheck Failures

### What This Means

`govulncheck` found vulnerabilities in Symaira Vault dependencies (not in Symaira Vault code itself).

### Response Matrix

| Severity | CVSS | Action | SLA |
|----------|------|--------|-----|
| Critical | 9.0-10.0 | Patch release within 48h | Immediate |
| High | 7.0-8.9 | Patch release within 7 days | 48 hours |
| Medium | 4.0-6.9 | Next minor release | 2 weeks |
| Low | 0.1-3.9 | Next minor release | Next cycle |

### Investigation Steps

1. **Identify the vulnerable package**:
   ```bash
   # Local check
   go run golang.org/x/vuln/cmd/govulncheck@latest ./...

   # Check which package has the CVE
   ```

2. **Check if the vulnerable function is actually called**:
   - govulncheck may report false positives
   - Verify the call chain reaches the vulnerable code path

3. **Check for fixed version**:
   ```bash
   go list -m -versions <package>
   go get <package>@<fixed-version>
   ```

4. **If no fix available**:
   - Monitor the dependency for updates
   - Consider vendoring or forking if critical
   - Document in issue tracker

### Update Process

```bash
# Update dependency
go get <package>@latest
go mod tidy
go mod verify

# Test thoroughly
go test -v ./...
GOWORK=off go test -v -tags smoke ./...

# Commit with conventional message
git commit -m "fix(deps): update <package> to fix CVE-XXXX-XXXX"
```

---

## Dependabot Alerts

### What This Means

Dependabot detected outdated dependencies with known vulnerabilities.

### Response Steps

1. **Review the alert** in GitHub → Security → Dependabot alerts

2. **Check if update is safe**:
   - Major version updates may have breaking changes
   - Check changelog for breaking changes
   - Test locally first

3. **Merge or dismiss**:
   - **Safe to merge**: Click "Merge pull request"
   - **False positive**: Click "Dismiss" with reason
   - **Needs investigation**: Comment and assign to maintainer

4. **For security updates**: Prioritize merging within 24-48 hours

### Handling Major Updates

```bash
# Create feature branch
git checkout -b dependabot/<package>-<version>

# Check for breaking changes
go mod why <package>  # Why is this dependency needed?

# Test with new version
go get <package>@latest
go mod tidy
```

---

## Release Workflow Errors

### Common Failure Points

| Job | Common Failure | Resolution |
|-----|---------------|------------|
| test | Flaky integration test | Re-run, check test isolation |
| govulncheck | New CVE published | Update dependency to fixed version |
| release | GitHub token issues | Verify workflow permissions |
| goreleaser | Asset size limit | Check artifact sizes |

### GoReleaser Failures

1. **Check .goreleaser.yaml** syntax
2. **Verify workflow permissions** include `contents: write`
3. **Check artifact sizes** - GitHub has 10GB total limit
4. **Check GitHub release publishing** if asset upload fails

### Re-running Release

```bash
# Push the tag again (if no changes needed)
git push origin v1.x.x

# Or create a release manually if CI is broken
# See: https://docs.github.com/en/repositories/releasing-projects-on-github/creating-releases
```

---

## MCP Token Operations

### Token Lifecycle Management

The MCP token (`mcp-token`) is auto-generated on first server start and stored in the vault directory. Proper token management is critical for security and availability.

### Token Rotation Schedule

| Environment | Rotation Frequency | Trigger |
|-------------|-------------------|---------|
| Production | Every 90 days | Scheduled maintenance |
| Development | Every 180 days | Scheduled or ad-hoc |
| After security incident | Immediate | Incident response |
| After personnel changes | Immediate | Team changes |

### Operational Token Rotation

**Prerequisites**:
- Access to vault directory
- Ability to restart MCP server
- Updated agent configurations ready

**Step-by-Step Rotation**:

```bash
#!/bin/bash
# token-rotate.sh - Production token rotation procedure

set -euo pipefail

VAULT_DIR="${SYMVAULT_VAULT:-$HOME/.symvault}"
SERVER_PORT="${MCP_PORT:-8080}"
BACKUP_DIR="$VAULT_DIR/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 1. Pre-rotation checks
echo "=== Pre-Rotation Checks ==="
if ! curl -sf http://127.0.0.1:$SERVER_PORT/health; then
    echo "ERROR: Server not healthy, aborting rotation"
    exit 1
fi

# 2. Backup current token
mkdir -p "$BACKUP_DIR"
cp "$VAULT_DIR/mcp-token" "$BACKUP_DIR/mcp-token.$TIMESTAMP"
echo "Token backed up to $BACKUP_DIR/mcp-token.$TIMESTAMP"

# 3. Stop server
echo "=== Stopping Server ==="
pkill -f "symvault serve" || true
sleep 2

# 4. Remove old token
echo "=== Removing Old Token ==="
rm -f "$VAULT_DIR/mcp-token"

# 5. Start server (generates new token)
echo "=== Starting Server ==="
nohup symvault serve --port $SERVER_PORT > "$VAULT_DIR/mcp-server.log" 2>&1 &
sleep 3

# 6. Verify health
echo "=== Verification ==="
if curl -sf http://127.0.0.1:$SERVER_PORT/health; then
    echo "Server healthy with new token"
else
    echo "ERROR: Server failed to start"
    exit 1
fi

# 7. Display new token (for manual configuration update)
echo "=== New Token ==="
echo "Token file: $VAULT_DIR/mcp-token"
echo "Token hash: $(md5 -q "$VAULT_DIR/mcp-token")"

echo "=== Rotation Complete ==="
echo "ACTION REQUIRED: Update all agent configurations with new token"
```

### Token Recovery After Accidental Deletion

**Immediate Response**:

1. Check if backup exists:
   ```bash
   ls -la ~/.symvault/backups/mcp-token.*
   ```

2. If backup exists, restore and verify:
   ```bash
   cp ~/.symvault/backups/mcp-token.latest ~/.symvault/mcp-token
   chmod 600 ~/.symvault/mcp-token
   ```

3. If no backup, regenerate:
   ```bash
   # Stop server
   pkill -f "symvault serve"
   
   # Remove corrupted/missing token
   rm -f ~/.symvault/mcp-token
   
   # Restart (auto-generates new token)
   symvault serve --port 8080
   
   # Get new token
   cat ~/.symvault/mcp-token
   ```

4. Update all agent configurations with new token

### Vault Integrity Check

Verify that all entries are accessible:

```bash
# 1. List all entries
ENTRY_COUNT=$(symvault list | wc -l)

# 2. Count entry files
FILE_COUNT=$(find ~/.symvault/entries -name "*.age" | wc -l)

# 3. Compare
echo "Listed entries: $ENTRY_COUNT, Files: $FILE_COUNT"
symvault serve --port 8080
```

### Prevention Checklist

- [ ] Token file permissions: `chmod 600 ~/.symvault/mcp-token`
- [ ] Token excluded from version control (in `.gitignore`)
- [ ] Automated backup of token file
- [ ] Rotation schedule documented and followed
- [ ] Index excluded from version control
- [ ] Regular index integrity checks
- [ ] Monitoring for unexpected token changes

---

## Audit Log HMAC Key Rotation

The audit log uses an HMAC key to provide integrity guarantees (tamper detection via
chained HMACs). If the HMAC key is compromised, all historical audit log integrity
verification is void. Rotate the key periodically and after any suspected compromise.

### Rotating the HMAC Key

```bash
symvault audit rotate-key
```

This command:

1. Generates a new 32-byte HMAC key using `crypto/rand`
2. Archives the current key to `audit-hmac-key.rotated.YYYY-MM-DD` in the vault directory
3. Stores the new key in the OS keyring (or encrypted file on unsupported platforms)
4. A new audit log file starts with the next audit write

### Key Backup Requirements

- **Archive files** (`audit-hmac-key.rotated.*`) must be backed up alongside the vault.
  Without the archived key, historical audit log verification is impossible.
- Store backup keys **separately** from the vault backup to avoid single-point compromise.
- **Rotate after key exposure**: If the HMAC key may have been exposed (compromised machine,
  shared access token, keyring extraction), rotate immediately and verify the audit log
  integrity with both the old and new keys.
- **Rotation frequency**: Rotate at least annually, or immediately after any security
  incident involving the vault directory or OS keyring access.

### Verifying After Rotation

After rotation, verify the audit log with both keys:

```bash
# Verify with current key (auto-detected)
symvault audit verify

# Manually verify rotated files with archived keys
symvault audit verify --key-file ~/.symvault/audit-hmac-key.rotated.2026-05-28
```

### Recovery from Key Loss

If all HMAC keys are lost (no archived copies, keyring cleared), audit log entries
become unverifiable but remain readable. To recover:

1. Generate a fresh key: `symvault audit rotate-key`
2. All future entries will use the new HMAC chain
3. Historical entries can be read but integrity cannot be verified
4. Document the key loss event in the incident log

---

## Backup & Recovery

### Vault Backup Strategy

Symaira Vault stores all data in a vault directory. The vault contains:

```
<vault>/
├── identity.age      # Your encrypted age identity (private key)
├── config.yaml       # Vault configuration
├── mcp-token         # Bearer token for HTTP MCP (auto-generated)
├── entries/          # Encrypted password entries (one .age file per entry)
│   ├── github.age
│   └── work/
│       └── aws.age
└── .git/             # Git repository (if enabled)
```

### CLI Backup and Restore (Recommended)

The `symvault backup` and `symvault restore` commands are the primary method for vault backup and recovery:

```bash
# Create a backup archive
symvault backup ~/backups/symvault-$(date +%Y%m%d_%H%M%S).tar.gz

# Exclude .git directory to reduce archive size
symvault backup ~/backups/symvault-$(date +%Y%m%d_%H%M%S).tar.gz --exclude-git

# Restore from backup
symvault restore ~/backups/symvault-20260427_120000.tar.gz
```

**Security notes**:
- Backup archives contain encrypted vault files (identity.age, config.yaml, entries, mcp-token). Treat archives with the same care as the vault itself.
- Always test restore procedures on a separate system or directory before relying on backups for critical recovery.
- Store backups in a location separate from the vault (3-2-1 rule: 3 copies, 2 media types, 1 offsite).

### Backup Methods

| Method | Pros | Cons |
|--------|------|------|
| **CLI backup** | Built-in, verified, includes integrity checks | Requires Symaira Vault binary |
| **Git auto-sync** | Automatic, versioned, distributed | Requires remote push, .git can grow large |
| **Manual copy** | Simple, full control | No incremental history, manual effort |
| **age encryption** | Entries are individually encrypted, portable | Must secure identity.age separately |
| **Export to file** | Portable text format | Requires manual re-import |

### Git Auto-Sync Backup (Recommended)

Symaira Vault commits vault changes automatically. Ensure remote is configured:

```bash
# Check remote configuration
git remote -v
# origin  git@github.com:user/private-vault.git (push)

# Force a new backup commit (even if no changes)
symvault git commit -m "Backup trigger"

# Manual push if auto_push is disabled
symvault git push
```

To enable a remote for an existing vault:

```bash
cd ~/.symvault  # or your vault path
git remote add origin git@github.com:user/backup-repo.git
git push -u origin main
```

### Manual Vault Backup

```bash
# Create timestamped backup
VAULT_DIR=~/.symvault
BACKUP_DIR=~/backups/symvault
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/vault_$TIMESTAMP.tar.gz" -C ~ "$VAULT_DIR"

# Verify backup integrity
tar -tzf "$BACKUP_DIR/vault_$TIMESTAMP.tar.gz" | head -20
```

### Restoring from Backup

```bash
# Extract backup to temporary location
tar -xzf ~/backups/symvault/vault_20260420_120000.tar.gz -C /tmp/

# Verify identity file
ls -la /tmp/.symvault/identity.age

# Move to vault location
mv ~/.symvault ~/.symvault_old
mv /tmp/.symvault ~/

# Verify vault opens
symvault list
```

### Recovery from Git

```bash
# Clone backup repository
git clone git@github.com:user/backup-repo.git ~/.symvault

# Unlock vault
symvault unlock

# Verify entries
symvault list
```

### Emergency Recovery: Identity Loss

If `identity.age` is lost, **there is no recovery**. The identity is the private key for all encrypted entries.

**Prevention**:
1. Keep `identity.age` in a secure location (hardware backup, safety deposit box)
2. Export the age identity:
   ```bash
   # Export identity (creates unencrypted copy - keep secure!)
   age-keygen -o /tmp/identity.pem
   # Convert back to age format if needed
   ```
3. Use a hardware security key for key storage

### Recovery After System Failure

1. Reinstall Symaira Vault:
   ```bash
   go install github.com/danieljustus/symaira-vault@latest
   ```

2. Restore vault from backup (see above)

3. Verify functionality:
   ```bash
   symvault list
   symvault get test-entry.password
   ```

### Disaster Recovery Checklist

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Restore vault directory | `ls -la ~/.symvault/` shows identity.age and entries/ |
| 2 | Unlock vault | `symvault unlock` succeeds |
| 3 | Verify entries | `symvault list` returns expected entries |
| 4 | Test entry retrieval | `symvault get <entry>` returns password |
| 5 | Verify MCP server | `symvault serve --stdio --agent default` starts |

### Backup Rotation

For critical vaults, use the 3-2-1 rule:
- **3** copies of data
- **2** different media types
- **1** offsite location

Example:
```bash
# Daily incremental backup to external drive
rsync -av --delete ~/.symvault/ /Volumes/Backup/symvault/

# Weekly full backup to cloud storage
rclone sync ~/.symvault/ backblaze:symvault-vaults/$(hostname)/
```

---

## MCP Server Operations

This section covers operational procedures for managing the Symaira Vault MCP server in production environments.

### Health Check Procedures

#### Automated Health Checks

Set up periodic health monitoring:

```bash
#!/bin/bash
# health-check.sh - Run from cron every minute

HEALTH_URL="http://127.0.0.1:8080/health"
LOG_FILE="/var/log/symvault-health.log"
ALERT_EMAIL="ops@example.com"

if ! curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
    echo "$(date): CRITICAL - Symaira Vault MCP server unhealthy" >> "$LOG_FILE"
    echo "Symaira Vault MCP server is down on $(hostname)" | mail -s "Symaira Vault Alert" "$ALERT_EMAIL"
    
    # Attempt automatic recovery
    pkill -f "symvault serve"
    sleep 2
    nohup symvault serve --port 8080 > /dev/null 2>&1 &
fi
```

#### Manual Health Verification

```bash
# 1. Basic health endpoint
curl -s http://127.0.0.1:8080/health | jq .
# Expected: {"status": "healthy", "timestamp": "...", "version": "x.y.z"}

# 2. MCP tool health test
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $(cat ~/.symvault/mcp-token)" \
  -H "X-Symaira Vault-Agent: default" \
  -H "Content-Type: application/json" \
  -d '{"tool": "health", "arguments": {}}'

# 3. End-to-end test (list entries)
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $(cat ~/.symvault/mcp-token)" \
  -H "X-Symaira Vault-Agent: default" \
  -H "Content-Type: application/json" \
  -d '{"tool": "list_entries", "arguments": {}}' | jq '.entries | length'
# Expected: Number of vault entries (0 or more)
```

#### Expected Health Outputs

| Check | Success | Failure |
|-------|---------|---------|
| HTTP Health | `{"status": "healthy"}` | Connection refused, timeout |
| MCP Health | Same as HTTP | Error response or timeout |
| List Test | JSON with entries array | Auth error, vault locked |

### Agent Profile Misconfiguration Recovery

#### Symptoms

- Agent receives "access_denied" errors
- Operations fail with "Agent not recognized"
- Write operations rejected despite `canWrite: true`

#### Diagnostic Steps

1. Check agent profile exists:
   ```bash
   cat ~/.symvault/config.yaml | grep -A 5 "agents:"
   ```

2. Verify profile name matches:
   ```bash
   # In config.yaml
   agents:
     my-agent:
       allowedPaths: ["*"]
   
   # MCP server must use same name
   symvault serve --agent my-agent
   ```

3. Check profile permissions:
   ```bash
   cat ~/.symvault/config.yaml | yq '.agents.<agent-name>'
   ```

#### Recovery Procedures

**Scenario 1: Profile Does Not Exist**

```bash
# Add the missing profile to config.yaml
cat >> ~/.symvault/config.yaml << 'EOF'

agents:
  missing-agent:
    allowedPaths: ["*"]
    canWrite: true
    approvalMode: none
EOF

# Restart server
pkill -f "symvault serve"
symvault serve --port 8080
```

**Scenario 2: Incorrect Permissions**

```bash
# Backup current config
cp ~/.symvault/config.yaml ~/.symvault/config.yaml.bak

# Edit to fix permissions
# Change canWrite: false to true for write operations
# Update allowedPaths to include required paths

# Validate config
symvault --vault ~/.symvault list

# Restart server
pkill -f "symvault serve"
symvault serve --port 8080
```

**Scenario 3: Path Restriction Too Strict**

```bash
# Current (too restrictive):
# allowedPaths: ["work/production/*"]

# Fixed (allows required access):
# allowedPaths: ["work/*", "personal/*"]
```

### Rate Limiter Overflow Handling

#### Understanding Rate Limits

| Operation Type | Limit | Window |
|----------------|-------|--------|
| Read operations | 100 | 60 seconds |
| Write operations | 20 | 60 seconds |
| Password generation | 50 | 60 seconds |

#### Symptoms of Rate Limiting

```json
{
  "error": {
    "code": "rate_limited",
    "message": "Rate limit exceeded. Retry after 30 seconds.",
    "details": {
      "retry_after": 30
    }
  }
}
```

#### Immediate Response

1. **Identify the source**:
   ```bash
   # Check logs for agent activity
   grep "rate_limit" /var/log/symvault.log | tail -20
   ```

2. **Implement exponential backoff** (for automated clients):
   ```python
   import time
   
   def call_with_backoff(func, max_retries=5):
       for i in range(max_retries):
           try:
               return func()
           except RateLimitError as e:
               wait = min(2 ** i, 60)  # Exponential backoff, max 60s
               time.sleep(wait)
       raise Exception("Max retries exceeded")
   ```

3. **Temporary rate limit increase** (emergency only):
   - No runtime adjustment available
   - Restart server to reset counters
   - Plan for longer-term solution

#### Prevention Strategies

1. **Implement caching**:
   - Cache credentials for their TTL
   - Use `get_entry_metadata` to check versions

2. **Batch operations**:
   - Minimize individual tool calls
   - Cache `list_entries` results

3. **Monitor usage patterns**:
   ```bash
   # Track request rates
   tail -f /var/log/symvault.log | grep "mcp_request" | wc -l
   ```

### Emergency Shutdown Procedures

#### Graceful Shutdown

**For HTTP mode**:

```bash
# 1. Stop accepting new connections
pkill -f "symvault serve"

# 2. Verify shutdown
if ! pgrep -f "symvault serve" > /dev/null; then
    echo "MCP server stopped successfully"
else
    echo "Failed to stop server, forcing..."
    pkill -9 -f "symvault serve"
fi

# 3. Verify no orphaned processes
ps aux | grep symvault
```

**For Stdio mode**:

```bash
# Stdio server stops when parent process disconnects
# To force stop a background stdio server:
pkill -f "symvault serve --stdio"
```

#### Emergency Lockdown

If security incident suspected:

```bash
#!/bin/bash
# emergency-lockdown.sh

echo "=== SYMVAULT EMERGENCY LOCKDOWN ==="

# 1. Stop MCP server
pkill -f "symvault serve"
echo "[1/4] MCP server stopped"

# 2. Lock vault
symvault lock
echo "[2/4] Vault locked"

# 3. Invalidate current token (rotate)
mv ~/.symvault/mcp-token ~/.symvault/mcp-token.compromised.$(date +%Y%m%d_%H%M%S)
echo "[3/4] Token invalidated (backup created)"

# 4. Disable auto-start (if using LaunchAgent/systemd)
# macOS LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.example.symvault-mcp.plist 2>/dev/null || true
echo "[4/4] Auto-start disabled"

echo ""
echo "EMERGENCY LOCKDOWN COMPLETE"
echo "Actions required:"
echo "- Investigate security incident"
echo "- Generate new token when safe"
echo "- Review access logs"
echo "- Restart server after verification"
```

#### Post-Incident Restart

After incident resolution:

```bash
# 1. Verify vault integrity
symvault unlock
symvault list

# 2. Generate new token (if rotated)
rm -f ~/.symvault/mcp-token
symvault serve --port 8080 &
sleep 2
NEW_TOKEN=$(cat ~/.symvault/mcp-token)

# 3. Update all agent configurations
symvault mcp-config claude-code --http --include-token

# 4. Verify health
curl -H "Authorization: Bearer $NEW_TOKEN" \
     -H "X-Symaira Vault-Agent: claude-code" \
     http://127.0.0.1:8080/health

# 5. Enable auto-start if previously disabled
launchctl load ~/Library/LaunchAgents/com.example.symvault-mcp.plist
```

### Token Invalidation Procedures

#### Planned Invalidation

For planned token changes (rotation, personnel changes):

```bash
# 1. Notify users of upcoming change
# 2. Schedule during low-usage window
# 3. Follow token rotation procedure (see MCP Token Operations)
# 4. Update all configurations
# 5. Verify all agents reconnect successfully
```

#### Emergency Invalidation

If token compromise suspected:

```bash
# Immediate actions (within 5 minutes)

# 1. Stop server
pkill -f "symvault serve"

# 2. Backup and remove compromised token
mv ~/.symvault/mcp-token ~/.symvault/mcp-token.compromised.$(date +%Y%m%d_%H%M%S)

# 3. Start server with new token
symvault serve --port 8080 &

# 4. Verify new token generated
cat ~/.symvault/mcp-token

# 5. Update critical agent configs immediately
# (Other agents can wait for scheduled maintenance)
```

### Escalation Procedures

| Severity | Response Time | Actions | Escalation |
|----------|--------------|---------|------------|
| **P1 - Critical** | 15 min | Full lockdown, revoke tokens, preserve logs | Security team, on-call engineer |
| **P2 - High** | 1 hour | Partial restrictions, token rotation | Engineering lead |
| **P3 - Medium** | 4 hours | Monitoring increase, planned remediation | Operations team |
| **P4 - Low** | 24 hours | Document, schedule fix | Next sprint |

**Escalation Triggers**:
- Unauthorized access detected in logs
- Token used from unexpected IP/location
- Multiple failed auth attempts
- Vault corruption detected
- Rate limiting affecting critical operations

### Monitoring and Alerting

#### Key Metrics

Monitor these metrics for operational health:

```bash
# Request rate
curl -s http://127.0.0.1:8080/metrics | grep "symvault_mcp_requests_total"

# Error rate
curl -s http://127.0.0.1:8080/metrics | grep "symvault_mcp_requests_total{status=\"error\"}"

# Auth denials
curl -s http://127.0.0.1:8080/metrics | grep "symvault_mcp_auth_denials_total"

# Vault operations
curl -s http://127.0.0.1:8080/metrics | grep "symvault_vault_operations_total"
```

#### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Error rate | > 1% | > 5% |
| Auth denials/min | > 10 | > 50 |
| Request latency (p95) | > 500ms | > 2000ms |
| Vault operations failures | > 0 | > 5 |

---

## Security Incident Response

### Reporting Process

1. **Receive report** via [GitHub Security Advisories](https://github.com/danieljustus/symaira-vault/security/advisories/new)
2. **Acknowledge within 48 hours**
3. **Assess severity and impact**
4. **Develop mitigation**
5. **Coordinate disclosure**

### Severity Classification

| Severity | Definition | Response Time |
|----------|------------|---------------|
| Critical | RCE, vault decryption bypass | 24 hours |
| High | Privilege escalation, data exfiltration | 48 hours |
| Medium | Information disclosure, DoS | 7 days |
| Low | Security best practice violation | Next release |

### Incident Response Steps

1. **Triage** (0-24h)
   - Confirm the vulnerability exists
   - Assess impact on users
   - Determine affected versions

2. **Containment** (24-48h)
   - Prepare patch or workaround
   - Identify fix in code
   - Test fix thoroughly

3. **Disclosure** (48-72h)
   - Notify maintainers
   - Prepare security advisory
   - Draft GitHub security advisory (draft mode)

4. **Release** (48-72h for critical)
   - Tag patch release
   - Publish security advisory
   - Notify users via GitHub

5. **Post-Incident**
   - Document lessons learned
   - Add regression tests
   - Update documentation if needed

### Patch Release Process

```bash
# Create patch branch from last release tag
git checkout v1.0.0
git checkout -b security-patch-v1.0.x

# Apply fix
git cherry-pick <commit>
# OR manually apply changes

# Test
go test -v ./...

# Tag and push
git tag v1.0.x
git push origin v1.0.x
```

---

## Post-Release Checklist

After every release, verify:

### Artifact Verification

```bash
# 1. Download artifacts from GitHub Releases
# https://github.com/danieljustus/symaira-vault/releases/tag/vX.Y.Z

# 2. Verify checksums
sha256sum -c symaira-vault_X.Y.Z_checksums.txt --ignore-missing
# or on macOS:
shasum -a 256 --check symaira-vault_X.Y.Z_checksums.txt --ignore-missing

# 3. Verify binary (Linux example)
./symaira-vault_X.Y.Z_linux_amd64/symvault version
# Should match tag version
```

### Installation Smoke Test

```bash
# 1. Install on clean system or in container
docker run -it ubuntu:latest bash

# 2. Install dependencies
apt-get update && apt-get install -y curl gpg

# 3. Download and verify release
curl -fsSLO https://github.com/danieljustus/symaira-vault/releases/download/vX.Y.Z/symaira-vault_X.Y.Z_linux_amd64.tar.gz
curl -fsSLO https://github.com/danieljustus/symaira-vault/releases/download/vX.Y.Z/symaira-vault_X.Y.Z_checksums.txt
sha256sum -c symaira-vault_X.Y.Z_checksums.txt --ignore-missing
tar xzf symaira-vault_X.Y.Z_linux_amd64.tar.gz
cp symaira-vault_X.Y.Z_linux_amd64/symvault ./symvault

# 4. Check binary works
chmod +x symvault
./symvault version

# 5. Initialize test vault
./symvault init /tmp/test-vault
./symvault add test --value "smoke-test"
./symvault get test
./symvault lock

# 6. Cleanup
rm -rf /tmp/test-vault
```

### GitHub Release Page

- [ ] Release title matches tag
- [ ] Description includes changelog
- [ ] All assets present (binaries for each platform)
- [ ] Checksums file present
- [ ] Security advisory linked (if applicable)

---

## Contact & Resources

| Purpose | Contact |
|---------|---------|
| Security Issues | [GitHub Security Advisories](https://github.com/danieljustus/symaira-vault/security/advisories/new) |
| General Issues | [GitHub Issues](https://github.com/danieljustus/symaira-vault/issues) |
| Release Verification | See post-release checklist above |

### Useful Links

- [Security Policy](SECURITY.md)
- [Release Process Documentation](.github/workflows/release.yml)
- [GoReleaser Configuration](.goreleaser.yaml)
- [Vulnerability Database](https://pkg.go.dev/golang.org/x/vuln)
