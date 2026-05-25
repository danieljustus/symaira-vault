# Symaira Vault Troubleshooting Guide

This guide covers common issues you may encounter when using Symaira Vault and provides diagnostic steps and solutions.

## Table of Contents

1. [Quick Fixes](#quick-fixes)
2. [Vault Access Issues](#vault-access-issues)
3. [MCP Connection Problems](#mcp-connection-problems)
4. [Git Sync Issues](#git-sync-issues)
5. [Platform-Specific Issues](#platform-specific-issues)
6. [Performance Issues](#performance-issues)
7. [Diagnostic Commands Reference](#diagnostic-commands-reference)
8. [Before You Open an Issue](#before-you-open-an-issue)

---

## Quick Fixes

Before diving into detailed diagnostics, try these common solutions:

| Issue | Quick Fix |
|-------|-----------|
| Agent can't connect | Restart the MCP server: `symvault serve --stdio --agent default` |
| Permission denied | Check agent profile in `~/.openpass/config.yaml` |
| Vault locked | Run `symvault unlock` and enter your passphrase |
| Slow response | Check if vault has too many entries; consider organizing into subdirectories |
| Token invalid | Regenerate with `symvault mcp-config <agent> --http` |
| Changes not syncing | Run `symvault git push` manually |

**General restart sequence:**
```bash
symvault lock          # Clear cached passphrase
symvault unlock        # Re-authenticate
symvault serve --stdio --agent default  # Restart MCP server
```

---

## Vault Access Issues

### Symptom: "Vault locked" or "Failed to decrypt identity"

**Diagnostic steps:**

1. Check if vault is initialized:
   ```bash
   ls -la ~/.openpass/
   ```
   You should see `identity.age`, `config.yaml`, and `entries/` directory.

2. Verify identity file exists and is readable:
   ```bash
   ls -la ~/.openpass/identity.age
   file ~/.openpass/identity.age
   ```

3. Test passphrase entry:
   ```bash
   symvault unlock
   ```

**Solutions:**

| Problem | Solution |
|---------|----------|
| Vault not initialized | Run `symvault init` to create a new vault |
| Wrong passphrase | Try again carefully; if forgotten, restore from backup |
| Corrupted `identity.age` | Restore from backup; without backup, vault is unrecoverable |
| Missing `identity.age` | Check if vault path is correct: `symvault --vault /path get test` |
| Permission denied on identity file | Fix permissions: `chmod 600 ~/.openpass/identity.age` |

**Session caching issues:**
- If `symvault unlock` works but MCP server still reports locked, the session cache may have expired
- Default TTL is 15 minutes; extend with: `symvault unlock --ttl 30m`
- Clear cache and retry: `symvault lock && symvault unlock`

---

## Vault Backup and Recovery

### Creating Backups

Use the built-in CLI commands to create and restore vault backups:

```bash
# Create a backup archive
symvault backup ~/backups/symvault-$(date +%Y%m%d).tar.gz

# Exclude .git directory to reduce archive size
symvault backup ~/backups/symvault-$(date +%Y%m%d).tar.gz --exclude-git
```

### Restoring from Backup

```bash
# Restore vault from a backup archive
symvault restore ~/backups/symvault-20260427.tar.gz
```

After restore, verify the vault is accessible:
```bash
symvault unlock
symvault list
```

### Important Warnings

- **Sensitive data**: Backup archives contain encrypted vault files (identity.age, entries, mcp-token). Treat archives with the same care as the vault itself.
- **Test restores**: Always verify that restore works before relying on backups. An untested backup is not a backup.
- **Git history caution**: If your vault is committed to Git, be aware that Git history may contain sensitive files that were tracked before being added to `.gitignore`. The `mcp-token` and other runtime files should never be committed.

### Recovery Without Backup

If `identity.age` is lost, **there is no recovery**. The identity file is the private key for all encrypted entries. Without a tested backup, your vault is unrecoverable.

---

## MCP Connection Problems

### Symptom: Agent can't connect to Symaira Vault

**Diagnostic steps:**

1. **Verify MCP server is running:**
   ```bash
   # For stdio mode
   symvault serve --stdio --agent default
   
   # For HTTP mode
   symvault serve --port 8080
   ```

2. **Check HTTP server health:**
   ```bash
   curl -s http://127.0.0.1:8080/health
   ```

3. **Verify token file exists (HTTP mode):**
   ```bash
   ls -la ~/.openpass/mcp-token
   cat ~/.openpass/mcp-token
   ```

4. **Check agent profile configuration:**
   ```bash
   cat ~/.openpass/config.yaml | grep -A 5 "agents:"
   ```

5. **Verify agent name matches:**
   - The `--agent` flag must match a profile in `config.yaml`
   - For HTTP mode, the `X-Symaira Vault-Agent` header must match a profile

**Common MCP issues and solutions:**

| Problem | Solution |
|---------|----------|
| "Agent not recognized" | Verify agent name in `--agent` flag matches `config.yaml` profile |
| "Invalid bearer token" | Regenerate token: `symvault mcp-config <agent> --http` |
| "Connection refused" | Ensure server is running on correct port; check firewall |
| "Port already in use" | Use different port: `symvault serve --port 8081` |
| Stdio mode hangs | Ensure no other process is reading from stdin |
| HTTP mode timeout | Check if vault is unlocked; server needs unlocked vault |

**Testing MCP connection:**
```bash
# Test HTTP endpoint
curl -H "Authorization: Bearer $(cat ~/.openpass/mcp-token)" \
     -H "X-Symaira Vault-Agent: default" \
     http://127.0.0.1:8080/mcp

# Generate config for testing
symvault mcp-config default --http
```

---

## Git Sync Issues

### Symptom: Changes not pushed or pull fails

**Diagnostic steps:**

1. Check git status in vault:
   ```bash
   cd ~/.openpass && git status
   ```

2. View recent commits:
   ```bash
   symvault git log
   ```

3. Check remote configuration:
   ```bash
   cd ~/.openpass && git remote -v
   ```

4. Test connectivity:
   ```bash
   cd ~/.openpass && git fetch origin
   ```

**Common Git issues:**

| Problem | Solution |
|---------|----------|
| "Merge conflict" | Resolve manually in vault directory, then commit |
| "Push rejected" | Pull first: `symvault git pull`, resolve conflicts, then push |
| "No remote configured" | Add remote: `cd ~/.openpass && git remote add origin <url>` |
| "Authentication failed" | Check SSH keys or HTTPS credentials |
| Changes not auto-pushed | Check `auto_push: true` in `config.yaml` |

**Removing accidentally tracked artifacts:**
If sensitive runtime artifacts like `mcp-token` or `.runtime-port` were accidentally committed to your vault repository before they were added to `.gitignore`, you can remove them from the history while keeping the local files:

```bash
cd ~/.openpass
# Remove from git index but keep local file
git rm --cached mcp-token .runtime-port
# Commit the removal
git commit -m "Remove sensitive runtime artifacts from tracking"
# Push changes
git push origin main
```

**Manual sync procedure:**
```bash
cd ~/.openpass
git pull origin main
# Resolve any conflicts
git add .
git commit -m "Resolve sync conflicts"
git push origin main
```

---

## Platform-Specific Issues

### macOS

**Keychain access issues:**
- If passphrase caching fails, check Keychain Access app for "Symaira Vault" entries
- Reset keychain: `symvault lock` then `symvault unlock` (re-creates entry)
- Gatekeeper may block unsigned binaries; allow in System Preferences > Security

**LaunchAgent issues:**
- Check logs: `tail -f ~/Library/Logs/openpass-mcp.log`
- Verify plist syntax: `plutil -lint ~/Library/LaunchAgents/com.example.openpass-mcp.plist`
- Reload agent: `launchctl unload ~/Library/LaunchAgents/com.example.openpass-mcp.plist && launchctl load ~/Library/LaunchAgents/com.example.openpass-mcp.plist`

### Linux

**D-Bus / Secret Service issues:**
- Ensure `gnome-keyring` or `kwallet` is running
- Check D-Bus session: `echo $DBUS_SESSION_BUS_ADDRESS`
- Install required libraries: `libsecret-1-0` (Debian/Ubuntu) or `libsecret` (Arch)

**Systemd service:**
```bash
# Check service status
systemctl --user status symvault-mcp

# View logs
journalctl --user -u symvault-mcp -f
```

**File permissions:**
```bash
# Ensure proper ownership
ls -la ~/.openpass/
# Should be owned by your user, not root
```

### FreeBSD

**Session caching uses in-memory fallback in prebuilt binaries:**

Symaira Vault release binaries (including those from GitHub Releases and `go install`) are built with `CGO_ENABLED=0`. On FreeBSD, the `zalando/go-keyring` dependency requires CGO to access the D-Bus Secret Service API. When CGO is disabled, Symaira Vault falls back to an **in-memory encrypted session cache**.

**Behavior:**

- **`symvault unlock`** caches the passphrase in process memory (encrypted with AES-256-GCM)
- **Subsequent commands** use the cached passphrase without prompting (within the TTL period)
- **Cache TTL** defaults to 15 minutes; override with `--ttl` flag or config
- **`symvault lock`** clears the in-memory cache and securely zeroes the memory
- **Process exit** clears all cached sessions automatically

**Security note:** The in-memory cache is less secure than the OS keyring because:
- Sessions exist in process memory (not in a separate keyring process)
- Memory could potentially be read by other processes with the same user privileges (e.g., via `/proc/<pid>/mem` on systems where it is accessible, or via debuggers)
- No system-level access control beyond standard Unix permissions

For higher security, build from source with CGO enabled to use the native OS keyring.

**User impact:**

| Scenario | Behavior |
|----------|----------|
| `symvault unlock` | Caches passphrase in memory; prompts again after TTL expires |
| `symvault lock` | Clears cached passphrase from memory |
| `symvault get <entry>` | Uses cached passphrase if within TTL; prompts otherwise |
| MCP server | Uses cached passphrase across requests while process is running |

**Options:**

1. **Use the prebuilt binary with in-memory cache** (default, works out of the box):
   ```bash
   symvault unlock
   symvault get github.password  # uses cached passphrase
   ```

2. **Build from source with CGO enabled** (requires a FreeBSD desktop environment with D-Bus and a Secret Service provider such as GNOME Keyring or KWallet):
   ```bash
   CGO_ENABLED=1 go build -o symvault .
   ```

**Verification status:**

The in-memory fallback is implemented in `internal/session/memory.go` (build tag `//go:build !cgo`). We do not have a physical FreeBSD environment to test runtime behavior; if you observe different behavior on FreeBSD, please open an issue.

### Windows

**Credential Manager issues:**
- Open Credential Manager > Windows Credentials
- Look for "Symaira Vault" entries
- If missing, run `symvault unlock` to recreate

**PATH issues:**
- Ensure `openpass.exe` directory is in PATH
- Use full path if needed: `C:\Users\You\bin\openpass.exe`

**WSL considerations:**
- WSL uses Linux keyring (D-Bus), not Windows Credential Manager
- Ensure WSL has D-Bus running: `sudo service dbus start`

---

## Performance Issues

### Symptom: Slow vault operations or high memory usage

**Diagnostic steps:**

1. Check vault size:
   ```bash
   du -sh ~/.openpass/
   du -sh ~/.openpass/entries/
   ```

2. Count entries:
   ```bash
   find ~/.openpass/entries -name "*.age" | wc -l
   ```

3. Check for large entries:
   ```bash
   ls -laS ~/.openpass/entries/ | head -20
   ```

4. Monitor system resources:
   ```bash
   # macOS
   top -o cpu | grep symvault
   
   # Linux
   ps aux | grep symvault
   ```

**Optimization tips:**

| Issue | Solution |
|-------|----------|
| Too many entries in root | Organize into subdirectories: `work/`, `personal/` |
| Large entry files | Avoid storing large notes; keep entries focused |
| Slow listing | Use prefix filter: `symvault list work/` instead of `symvault list` |
| High memory | Restart MCP server periodically; check for memory leaks |
| Slow git operations | Exclude large files; use `.gitignore` for non-essential files |

---

## Diagnostic Commands Reference

### Quick status check
```bash
symvault version                    # Show version
symvault --vault ~/.openpass list   # Test vault access
symvault unlock                     # Verify passphrase
```

### MCP diagnostics
```bash
# HTTP mode
curl -s http://127.0.0.1:8080/health
curl -H "Authorization: Bearer $(cat ~/.openpass/mcp-token)" \
     -H "X-Symaira Vault-Agent: default" \
     http://127.0.0.1:8080/mcp

# Config generation
symvault mcp-config default --http
symvault mcp-config default
```

### Vault diagnostics
```bash
ls -la ~/.openpass/                 # Check vault structure
file ~/.openpass/identity.age       # Verify identity file
symvault git log                    # Check sync status
cat ~/.openpass/config.yaml         # Review configuration
```

### System diagnostics
```bash
# Process check
ps aux | grep symvault

# Port check (macOS/Linux)
lsof -i :8080

# Port check (all platforms)
netstat -an | grep 8080
```

---

## Before You Open an Issue

Please complete this checklist before opening a GitHub issue:

- [ ] I am running the latest version of Symaira Vault (`symvault version`)
- [ ] I have checked this troubleshooting guide for my issue
- [ ] My vault is initialized and unlocked (`symvault unlock` works)
- [ ] The MCP server is running (for agent issues)
- [ ] I am using the correct agent profile name
- [ ] I have tried the [Quick Fixes](#quick-fixes) section
- [ ] I can reproduce the issue consistently
- [ ] I have included my OS and version (e.g., macOS 14.2, Ubuntu 22.04)
- [ ] I have included output of `symvault version`
- [ ] I have sanitized my config (removed tokens/secrets) if sharing

**Information to include:**
1. Symaira Vault version
2. Operating system and version
3. Go version (if building from source)
4. Steps to reproduce
5. Expected behavior
6. Actual behavior
7. Relevant error messages (redact sensitive info)
8. Output of diagnostic commands above

**For security issues:**
Do NOT open public issues. Submit a private report via [GitHub Security Advisories](https://github.com/danieljustus/symaira-vault/security/advisories/new).

---

## Token and Index Recovery

### Accidental mcp-token Deletion

If the `mcp-token` file is accidentally deleted, the MCP HTTP server will regenerate it on the next start.

**Regeneration Procedure**:

1. Stop the MCP server if running:
   ```bash
   # If running in background
   pkill -f "symvault serve"
   ```

2. Remove the old token file (if partially corrupted):
   ```bash
   rm -f ~/.openpass/mcp-token
   ```

3. Restart the server to generate a new token:
   ```bash
   symvault serve --port 8080
   ```

4. Retrieve the new token:
   ```bash
   cat ~/.openpass/mcp-token
   ```

5. Update agent configurations with the new token:
   ```bash
   symvault mcp-config claude-code --http --include-token
   ```

**Impact**: All existing agent connections will be invalidated. Agents must be reconfigured with the new token.

### Zero-Downtime Token Rotation

For production environments requiring continuous availability:

**Preparation**:
1. Ensure you have access to regenerate the token
2. Prepare updated agent configurations in advance
3. Schedule during low-usage period

**Rotation Steps**:

```bash
# 1. Generate new token (server creates it automatically on restart)
# Save the current token as backup
cp ~/.openpass/mcp-token ~/.openpass/mcp-token.backup

# 2. Stop the server gracefully
pkill -f "symvault serve"

# 3. Remove the old token
rm ~/.openpass/mcp-token

# 4. Start the server (generates new token)
symvault serve --port 8080 &

# 5. Wait for server to be ready
sleep 2
curl -s http://127.0.0.1:8080/health

# 6. Get the new token
NEW_TOKEN=$(cat ~/.openpass/mcp-token)
echo "New token generated"

# 7. Update all agent configurations
symvault mcp-config claude-code --http --include-token
# Repeat for each agent

# 8. Verify new configuration works
curl -H "Authorization: Bearer $NEW_TOKEN" \
     -H "X-Symaira Vault-Agent: claude-code" \
     http://127.0.0.1:8080/mcp

# 9. Remove backup token after verification
rm ~/.openpass/mcp-token.backup
```

**Note**: During rotation (steps 2-7), agents cannot connect. Keep this window minimal.

### Prevention Recommendations

1. **Regular Backups**: Include `mcp-token` in your vault backup strategy
   ```bash
   # Add to backup script
cp ~/.openpass/mcp-token ~/backups/symvault/
   ```

2. **Version Control Exclusion**: Ensure runtime files are in `.gitignore`:
   ```gitignore
   # Symaira Vault runtime files
   mcp-token
   .runtime-port
   ```

3. **Token Permissions**: Set restrictive permissions on the token file:
   ```bash
   chmod 600 ~/.openpass/mcp-token
   ```

4. **Monitor File Integrity**: Set up alerts for unexpected file changes:
   ```bash
   # Check file hash daily
   md5 ~/.openpass/mcp-token >> ~/logs/mcp-token.hash
   ```

5. **Use Stdio Mode for Local Agents**: Stdio mode doesn't require token management:
   ```bash
   symvault serve --stdio --agent claude-code
   ```

---

## Structured Logging

Symaira Vault uses Go's standard `log/slog` package for structured logging. All logs are written to `stderr` to keep `stdout` clean for stdio MCP transport.

### Enabling Debug Logging

Set the environment variable before running any Symaira Vault command:

```bash
OPENPASS_LOG_LEVEL=debug symvault serve --stdio --agent claude-code
```

Available levels (from most to least verbose):
- `debug` — Detailed internal state and operations
- `info` — Normal operational messages
- `warn` — Warnings and recoverable issues (default)
- `error` — Errors only

### JSON Format

For machine-readable output (e.g., when piping to log aggregation):

```bash
OPENPASS_LOG_LEVEL=info OPENPASS_LOG_FORMAT=json symvault serve --http
```

### Common Log Messages

| Message | Level | Meaning |
|---------|-------|---------|
| `OS keyring unavailable` | warn | Falling back to memory-only session cache |
| `Using memory-only session cache` | warn | Sessions cannot be shared across processes on this platform/build |
| `rate limiter cleaned expired entries` | debug | Periodic cleanup of stale rate limit entries |

### MCP Stdio Protocol Cleanliness

If JSON-RPC messages are being interleaved with log output, verify:
1. `OPENPASS_LOG_FORMAT` is set to `text` or `json` (not a custom format)
2. You're using a version with structured logging support
3. stdout is not being redirected to a file that also captures stderr

### Related Documentation

- [Agent Integration Guide](agent-integration.md) - MCP setup and configuration
- [Runbook](runbook.md) - Operational procedures and incident response
- [Error Tracking Strategy](error-tracking-strategy.md) - Error handling and reporting
- [MCP API Documentation](mcp-api.md) - Complete MCP API reference
- [README](../README.md) - General usage and installation
