---
name: symvault-upgrade-to-v4
description: AI-agent-ready prompt to upgrade an Symaira Vault installation from v3.x to v4.0 cleanly and safely.
---

# Symaira Vault v3 → v4 Upgrade Prompt (for AI agents)

This file is a **self-contained prompt** an AI assistant can follow to upgrade
a user's Symaira Vault installation from v3.x to v4.0 without losing data or
introducing security regressions. It is also readable as a human checklist.

If you are a user, you can copy the entire content of this file into your AI
assistant and add: *"Run this upgrade on my machine."* The assistant will then
execute the steps below in order, asking for confirmation at the destructive
points.

---

## Mission

Upgrade the user's Symaira Vault from v3.x to v4.0. Preserve the vault, all
existing agent profiles, all scoped tokens, and the audit log. Introduce the
new tier system, embedded skill packages, and lean MCP mode. Verify each
installed agent still works after the upgrade.

## Operating principles

- **One step at a time.** Do not chain destructive commands.
- **Show before write.** Use `--dry-run` first wherever it exists.
- **Confirm before destructive ops.** Backup, profile rewrites, and tier
  upgrades require user OK.
- **Never echo secrets.** Do not print token values, passphrases, or vault
  contents to chat. Use the structured `--output json` form for parsing
  metadata, but redact secret-bearing fields before showing them back.
- **Stop on the first hard error.** If a command exits non-zero with code
  10/11/12/13/14/15, surface the structured error to the user and ask how to
  proceed. Do not retry silently.

---

## Step 1 — Detect current state

```bash
symvault version --output json
symvault auth status --output json
symvault agent list --output json   # may not exist on pre-v4 binaries; tolerate failure
```

From the output, determine:
- Installed version (semver). If `>= 4.0.0`, jump to Step 7 (post-migration
  verification only).
- Whether the vault is unlocked.
- Which agents are configured.

Also list any legacy config commands that the user's shell history references
(`symvault mcp install`, `symvault mcp-config`, `symvault mcp token …`,
`symvault mcp-token-rotate`, `symvault agent setup`). These will need to be
replaced in user scripts after the upgrade.

---

## Step 2 — Back up vault and config

Confirm with the user before running. This is the only step that cannot be
re-done after the upgrade succeeds and the v3 backup is overwritten.

```bash
symvault backup ~/symvault-backup-pre-v4-$(date +%Y%m%d-%H%M%S).tar.gz
```

If `symvault backup` is unavailable, fall back to:

```bash
cp -a ~/.symvault ~/.symvault.backup.pre-v4.$(date +%Y%m%d-%H%M%S)
```

Verify the backup file exists and is non-empty before continuing.

---

## Step 3 — Install Symaira Vault v4

Pick the method that matches the user's install path. Detect by checking what
is on `PATH` and what package managers are present.

| Install method | Command |
|---|---|
| Homebrew (macOS, Linux) | `brew upgrade symvault` |
| Install script (macOS/Linux) | `curl -sSfL https://raw.githubusercontent.com/danieljustus/symaira-vault/main/scripts/install.sh \| sh` |
| Scoop (Windows) | `scoop update symvault` |
| Nix | `nix profile upgrade symvault` (or rebuild the flake input) |
| Binary download | Download v4.0.0 asset for the platform from <https://github.com/danieljustus/symaira-vault/releases/tag/v4.0.0>, replace the binary, verify checksum |

Verify the new version is in place:

```bash
symvault version --output json
# expect: "version": "4.0.0..." or similar
```

Do **not** proceed if the version is still v3.x.

---

## Step 4 — Preview the migration

```bash
symvault migrate v4 --dry-run
```

Read the output carefully. It will show:
- Per-agent inferred tier (`safe` / `standard` / `admin` / `custom`).
- Per-agent skill drift (`create` / `refresh (drift)` / `manual install`).
- The exact backup filename that will be written.

Summarize the planned changes for the user in plain language. Ask if anything
looks wrong before applying.

If a profile is classified `custom`, point out which fields differ from any
preset (commonly `redactFields` or non-standard `allowedExecutables`). The
`custom` tier preserves the user's exact settings.

---

## Step 5 — Apply the migration

```bash
symvault migrate v4
```

The command is interactive by default. Confirm `y` when prompted. The tool
will:

1. Back up `~/.symvault/config.yaml` to `config.yaml.bak.v3-<timestamp>`.
2. Add `tier`, `skill_path`, and `skill_version` fields to each agent profile.
3. Re-render and install per-agent skill packages with the v4 sentinel header.
4. Re-validate the token registry.
5. Print a structured summary.

For non-interactive contexts (CI, dotfile sync hooks), use `--yes`:

```bash
symvault migrate v4 --yes
```

If the command fails mid-flight: restore the backup
(`cp ~/.symvault/config.yaml.bak.v3-<timestamp> ~/.symvault/config.yaml`) and
ask the user to share the error. Do not retry blindly.

---

## Step 6 — Run doctor on each agent

```bash
symvault agent list --output json
symvault agent doctor --all
```

For each agent that comes back with warnings or errors:

- **Skill drift** — re-render in place:
  `symvault agent install <name> --skill-only --force`
- **Missing MCP config entry** — re-inject:
  `symvault agent install <name> --config-only`
- **Token invalid / expired** — rotate:
  `symvault agent token <name> rotate`
- **Profile classified `custom` but user wants a preset** — explicit upgrade:
  `symvault agent upgrade <name> --tier <safe|standard|admin>` (interactive)

Run `symvault agent whoami --output json` (or
`OPENPASS_AGENT=<name> symvault agent whoami --output json`) to confirm the
agent's effective permissions match what you expect.

---

## Step 7 — Update user scripts

Search the user's shell history, dotfiles, and project scripts for legacy
commands. Show the user any matches and propose replacements before editing.

| Legacy (v3) | Replacement (v4) |
|---|---|
| `symvault agent setup <name>` | `symvault agent install <name>` |
| `symvault mcp install <name>` | `symvault agent install <name>` |
| `symvault mcp install --auto-detect` | `symvault agent install --auto-detect` |
| `symvault mcp-config <agent>` | `symvault agent install <agent> --config-only` |
| `symvault mcp token create …` | `symvault agent token <name> new …` |
| `symvault mcp token list` | `symvault agent token list` |
| `symvault mcp token revoke <id>` | `symvault agent token revoke <id>` |
| `symvault mcp-token-rotate` | `symvault agent token <name> rotate` |

For CI/automation scripts that upgrade tiers, add `--reason` (now required
with `--yes`):

```bash
# Before
symvault agent setup hermes --tier admin

# After
symvault agent upgrade hermes --tier admin --yes --reason "<ticket-or-context>"
```

---

## Step 8 — Optional: enable CLI agent mode

v4 lets agents drive the CLI with the same enforcement as MCP. For each
configured agent, propose adding to the agent's launch script:

```bash
export OPENPASS_AGENT=<name>
```

Then the agent can call `symvault list --output json`,
`symvault get path/to/entry --metadata-only --output json`, etc., and Symaira Vault
applies the profile's allowed paths, redactions, quotas, and audit — the same
way it would for an MCP call. This reduces context-window usage substantially
for read-heavy work.

Reserve MCP for operations that need OS mediation: `request_credential`,
`secure_input`, `copy_to_clipboard`, `autotype`, write-with-approval,
`run_command`.

---

## Step 9 — Verify and report

End the upgrade by printing a short summary to the user:

- New version installed
- Number of agent profiles migrated, with tier breakdown
- Skill files written or refreshed
- Audit-log location: `~/.symvault/audit/`
- Backup location (Step 2)
- Any agents that still need attention (failed doctor checks)

Recommend a follow-up after a few days:

```bash
symvault agent audit self --since 7d --output json
```

…to confirm the agents are behaving within expected tier/quota bounds.

---

## What you must not do

- Do not delete `config.yaml.bak.v3-*` files. They are the rollback path.
- Do not silently elevate any agent from `safe` to `standard`/`admin`. Tier
  upgrades require explicit user consent (interactive) or a `--reason` (CI).
- Do not write profile fields you do not understand. If `symvault migrate v4`
  classified a profile as `custom`, leave it `custom` unless the user
  explicitly requests a preset.
- Do not echo, log, or attach any token values, passphrases, or vault
  contents. Use redacted summaries.
- Do not run `--force` on `agent install` unless the user explicitly accepted
  that the conflicting file (skill or config) will be overwritten without a
  sentinel check.

---

## Rollback

If the user wants to undo the upgrade:

1. Stop any running Symaira Vault processes: `pkill symvault` (best-effort).
2. Reinstall v3.0.0 (or the version they were on):
   ```bash
   # macOS Homebrew: install legacy formula or download from releases
   # Download from https://github.com/danieljustus/symaira-vault/releases/tag/v3.0.0
   ```
3. Restore config:
   ```bash
   cp ~/.symvault/config.yaml.bak.v3-<timestamp> ~/.symvault/config.yaml
   ```
4. If skills were written to agent dirs and the user wants them gone, list
   them with `find ~ -path '*/skills/symvault/SKILL.md'` and remove only the
   ones with `managed_by: symvault` in their frontmatter.
5. Tokens issued by v4 remain valid under v3 but v3 ignores the new metadata
   fields. The user can rotate them with `symvault mcp-token-rotate` on v3.

---

## Reference

- Migration guide (human-readable):
  [`docs/migration-v3-to-v4.md`](../../migration-v3-to-v4.md)
- Architecture decision: [`docs/adr/0004-cli-agent-optimization-v4.md`](../../adr/0004-cli-agent-optimization-v4.md)
- Full v4 changelog: [`CHANGELOG.md`](../../../CHANGELOG.md)
- Release notes:
  <https://github.com/danieljustus/symaira-vault/releases/tag/v4.0.0>
