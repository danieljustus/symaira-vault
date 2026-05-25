# Upgrade Guide: v3.x to v4.0

Symaira Vault v4.0 restructures the CLI for AI-agent integration, introduces a tier
system for agent profiles, and ships per-agent skill packages. This guide covers
the migration from v3.x to v4.0.

If you are on v2.x or earlier, upgrade to the latest v3.x first, then follow
this guide.

---

## Overview

v4.0 makes three major changes:

1. **CLI consolidation.** All AI-integration commands move under
   `symvault agent`. The old `symvault mcp` and `symvault agent setup` commands
   are replaced. Deprecation stubs remain in v4.0 and will be removed in v4.1.
2. **Tier system.** Agent profiles now have a `tier` field
   (`safe` / `standard` / `admin`) that governs which MCP tools and capabilities
   the agent has. Default for new installs is `safe`.
3. **Per-agent skill packages.** Skill files are now embedded in the Symaira Vault
   binary and install alongside the MCP config. Each agent gets a tailored skill
   file with its own tool prefix and tier hints.

The changes are additive for most users. Existing agent profiles still work
after migration. The `symvault serve` MCP server and vault operations (`get`,
`set`, `list`, `find`, etc.) are unchanged.

---

## Before you start

Back up your vault and configuration before migrating.

```bash
# Backup the full vault directory
cp -a ~/.openpass ~/.openpass.backup.$(date +%Y%m%d)

# Or use the built-in backup command
symvault backup ~/backups/symvault-pre-v4-$(date +%Y%m%d).tar.gz
```

Confirm your v3.x version:

```bash
symvault version
```

v3.0.0 or later is supported as a migration source. If you are on an earlier
v3 release, upgrade to the latest v3 first (or jump straight to v4 — the
migration helper handles any v3.x profile):

```bash
# macOS (Homebrew)
brew upgrade symvault

# macOS / Linux (install script)
curl -sSfL https://raw.githubusercontent.com/danieljustus/symaira-vault/main/scripts/install.sh | sh

# Windows (Scoop)
scoop update symvault
```

---

## Automated migration

v4.0 ships with a built-in migration helper. It reads your existing config,
classifies each agent profile into a tier, backs up the old config, and writes
the migrated config.

### Preview (recommended first step)

```bash
symvault migrate v4 --dry-run
```

This prints a summary of what will change without writing anything:

```
Agent      Inferred Tier  Notes
─────────  ─────────────  ─────────────────────────────────────
default    safe           was already metadata-only
hermes     standard       canWrite=true, canUseClipboard=true
claude     admin          canRunCommands=true
legacy     custom         redactFields differ from any preset
```

It also shows per-agent skill drift:

```
Agent      Skill Path                          Action
─────────  ──────────────────────────────────  ───────────
hermes     ~/.hermes/skills/symvault/SKILL.md  create
claude     ~/.claude/skills/symvault/SKILL.md  refresh (drift)
openclaw   (none)                              create
```

### Apply

```bash
symvault migrate v4
```

Review the summary, then confirm. The tool will:

1. Back up `config.yaml` to `config.yaml.bak.v3-<timestamp>`
2. Add `tier`, `skill_path`, and `skill_version` fields to each agent profile
3. Re-render and install per-agent skill packages
4. Re-validate the token registry
5. Print a summary with next-step hints

### Non-interactive mode

For automated setups or CI:

```bash
symvault migrate v4 --yes
```

### Idempotency

The migration is idempotent. Running it again on an already-migrated config is a
no-op. The tool detects existing `tier` fields and skips re-classification. You
can safely re-run `symvault migrate v4 --dry-run` to verify.

---

## Manual migration

If you prefer to update your configuration by hand, follow these steps.

### Config file changes

Each agent profile in `~/.openpass/config.yaml` gains three new fields:

```yaml
# v3 format (before)
agents:
  hermes:
    allowedPaths: ["agents/providers/"]
    canWrite: false
    canRunCommands: false
    canUseClipboard: false
    canUseAutotype: false
    approvalMode: deny

# v4 format (after)
agents:
  hermes:
    tier: safe                    # NEW: one of safe|standard|admin|custom
    skill_path: ~/.hermes/skills/symvault/SKILL.md  # NEW: installed skill location
    skill_version: "4.0.0"        # NEW: version that rendered the skill
    allowedPaths: ["agents/providers/"]
    canWrite: false
    canRunCommands: false
    canUseClipboard: false
    canUseAutotype: false
    approvalMode: deny
```

#### Tier classification rules

If you are adding `tier` by hand, use these rules:

| If the profile has... | Set tier to |
|---|---|
| `canRunCommands: true` | `admin` |
| `canWrite: true` and `canUseClipboard: true` | `standard` |
| Metadata-only access (neither of the above) | `safe` |
| Custom `redactFields` that do not match a tier preset | `custom` |

The `custom` tier preserves your exact settings without tier enforcement. The
other three tiers (`safe`, `standard`, `admin`) have frozen defaults for
allowed tools, capabilities, and quotas. See the
[configuration reference](configuration.md#agent-profile-options) for the full
tier breakdown.

### Command renames

Replace these old commands in your scripts and documentation:

| Old command | New command |
|---|---|
| `symvault agent setup <name>` | `symvault agent install <name>` |
| `symvault mcp install <name>` | `symvault agent install <name>` |
| `symvault mcp install --auto-detect` | `symvault agent install --auto-detect` |
| `symvault mcp-config <agent>` | `symvault agent install <agent> --config-only` |
| `symvault mcp token create` | `symvault agent token <name> new` |
| `symvault mcp token list` | `symvault agent token list` |
| `symvault mcp token revoke` | `symvault agent token revoke` |
| `symvault mcp-token-rotate` | `symvault agent token <name> rotate` |

Deprecation stubs are in place for v4.0. Calling any of the old commands prints
the replacement and exits with code 2. The stubs will be removed in v4.1.

---

## Command mapping

The full mapping of deprecated commands to their v4.0 replacements:

| v3.x command | v4.0 replacement | Notes |
|---|---|---|
| `symvault agent setup <name>` | `symvault agent install <name>` | Adds `--tier` flag (default: safe) |
| `symvault mcp install <name>` | `symvault agent install <name>` | Same flags: `--tier`, `--http`, `--force` |
| `symvault mcp install --auto-detect` | `symvault agent install --auto-detect` | Detects all installed agents |
| `symvault mcp-config <agent>` | `symvault agent install <agent> --config-only` | MCP config only, no skill |
| `symvault mcp token create` | `symvault agent token <name> new` | Scope and expiry flags unchanged |
| `symvault mcp token list` | `symvault agent token list` | Output unchanged |
| `symvault mcp token revoke <id>` | `symvault agent token revoke <id>` | Output unchanged |
| `symvault mcp-token-rotate` | `symvault agent token <name> rotate` | Output unchanged |
| `symvault mcp` (any subcommand) | Folded into `symvault agent` | See rows above |

### New commands in v4.0

These have no v3 equivalent:

| Command | Purpose |
|---|---|
| `symvault agent upgrade <name> --tier <new-tier>` | Change an agent's tier with interactive diff and audit trail |
| `symvault agent uninstall <name>` | Remove profile, token, skill, and MCP entry |
| `symvault agent doctor <name>` | End-to-end debug for one integration |
| `symvault agent audit <name>` | Per-agent audit log |
| `symvault agent profile edit <name>` | Edit profile in `$EDITOR` |
| `symvault agent skill export <agent>` | Pack skill for drop-in distribution |
| `symvault agent whoami` | CLI form of the `openpass_whoami` MCP tool |

---

## Behavioral changes

### Token scope semantics

In v3.x, a token with `tools: ["*"]` granted access to every tool the server
knew about. In v4.0, `tools: ["*"]` is interpreted as "inherit from the agent
profile." This means the effective tool set is determined by the profile's tier,
not the token's tool list. Non-empty concrete tool lists still further restrict.

Practical effect: profile downgrades (e.g., `safe` to `standard`) take effect
immediately on the next MCP call. You no longer need to re-issue tokens after a
profile change, unless you want to rotate the token itself.

### MCP server lean mode

By default, `tools/list` returns only 7 essential tools:

- `openpass_whoami`
- `openpass_search`
- `health`
- `find_entries`
- `get_entry_metadata`
- `request_credential`
- `openpass_audit_self`

This reduces initial context consumption by roughly 83% compared to exposing
the full tool list at connect time (about 5 KB instead of 30 KB). The full tool
list is available by passing `include_all_tools: true` in the MCP init
handshake or calling `openpass_search` with an intent string.

The `openpass_search` tool lets agents discover and on-demand-load tools by
describing what they want to do. For example, an agent that needs clipboard
access can call `openpass_search({"intent": "put a password on the clipboard"})`
and receive the `copy_to_clipboard` spec and its `cli_alternative`.

### Default tier is safe

New agent installs default to `safe` tier. In v3.x, the effective permissions
for a new profile depended on the config template. In v4.0, `safe` is the
explicit default:

- Metadata tools only (no secret values)
- No write access
- No clipboard or autotype
- No command execution

To grant more access, run:

```bash
symvault agent upgrade <name> --tier standard
symvault agent upgrade <name> --tier admin
```

Tier upgrades require interactive confirmation (or `--yes --reason "..."` for
automation).

### Exit codes are structured

All v4.0 commands return structured exit codes that agents can branch on without
parsing stderr:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error |
| 2 | Usage error (bad flags) |
| 10 | Vault locked / auth required |
| 11 | Permission denied (profile/tier) |
| 12 | Not found (path/entry/agent) |
| 13 | Conflict (e.g. agent already exists) |
| 14 | Quota exceeded |
| 15 | Approval denied or timed out |

This applies to both the CLI (via `OPENPASS_AGENT` environment variable) and
MCP responses.

### MCP tool `openpass_delete` removed

The `openpass_delete` tool (a deprecated alias for `delete_entry` since v2.x)
is removed. Callers receive `ERR_TOOL_NOT_FOUND`. Use `delete_entry` instead.

---

## CI and automation fixups

### Script updates

If your scripts use the old `symvault mcp` commands, replace them:

```bash
# Before
symvault mcp install hermes
symvault mcp token create --agent hermes --tools list_entries --expires 24h

# After
symvault agent install hermes
symvault agent token hermes new --tools list_entries --expires 24h
```

### Configuration management (GitOps)

If you version-control `config.yaml`, the migration adds three fields per agent
profile. Commit the migrated config after running `symvault migrate v4`:

```bash
symvault migrate v4 --yes
git add ~/.openpass/config.yaml
git commit -m "migrate to v4 agent profile schema"
```

### Non-interactive tier upgrades

Automation scripts that need to upgrade an agent tier must pass `--reason`:

```bash
symvault agent upgrade hermes --tier standard --yes --reason "ticket OPS-1234"
```

The reason is stored in the audit event. `--yes` without `--reason` is rejected.

---

## Rollback

If something goes wrong, you can revert to your v3 configuration.

### Restore config backup

The migration creates a backup before writing:

```bash
# List backups
ls -la ~/.openpass/config.yaml.bak.v3-*

# Restore the most recent one
cp ~/.openpass/config.yaml.bak.v3-$(ls -t ~/.openpass/config.yaml.bak.v3-* | head -1 | xargs basename | sed 's/config.yaml.bak.//') ~/.openpass/config.yaml
```

### Restore vault backup

If you backed up the full vault directory before migrating:

```bash
# Stop any running Symaira Vault processes first
pkill symvault 2>/dev/null || true

# Restore
rm -rf ~/.openpass
cp -a ~/.openpass.backup.20260518 ~/.openpass
```

### Downgrade Symaira Vault

If you need to go back to v3.x:

```bash
# macOS (Homebrew)
brew install symvault@3

# Manual install from GitHub releases
# Download v3.0.0 from https://github.com/danieljustus/symaira-vault/releases/tag/v3.0.0
```

The v3.x binary reads the old config format. If you already ran the migration,
restore the backup first.

### What is NOT rolled back

- Per-agent skill files (`.skills/symvault/SKILL.md`) that were written during
  migration are not automatically removed. You can delete them manually or run
  `symvault agent uninstall <name>` after reinstalling v3.x to clean them up.
- Audit events written during the migration remain in the audit log.
- Tokens issued by the v4.0 binary remain valid if you downgrade, but v3.x
  ignores the new token metadata fields.

---

## Next steps

After migration:

1. **Verify your agents still work.** Run `symvault agent doctor <name>` for
   each agent.
2. **Review tier assignments.** Run `symvault agent list` to see each agent's
   tier. Upgrade if needed:
   ```bash
   symvault agent upgrade hermes --tier standard
   ```
3. **Explore new commands.** Try `symvault agent audit hermes`, `symvault agent
   whoami`, or `symvault agent skill export hermes`.
4. **Update your documentation.** Replace any v3 command references with the v4
   equivalents from the mapping table above.

For the full v4.0 changelog, see the
[CHANGELOG](https://github.com/danieljustus/symaira-vault/releases/tag/v4.0.0).
