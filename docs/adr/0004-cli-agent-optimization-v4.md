# Symaira Vault v4.0 — CLI & AI-Agent Optimization Design

- **Status:** Accepted
- **Date:** 2026-05-17
- **Accepted:** 2026-05-21
- **Target release:** v4.0.0
- **Author:** Daniel + Claude
- **Scope:** CLI restructuring, MCP server runtime, agent skills, security defaults, dual-surface (CLI + MCP) integration

---

## 0. Summary

Symaira Vault v3 ships strong AI-agent support via MCP (stdio + HTTP, OAuth/DCR, scoped tokens, per-agent profiles). But three setup commands overlap (`mcp-config`, `mcp install`, `agent setup`), the MCP tool surface (21+) burns context tokens at connect-time, and the skill story is a single static `SKILL.md` without per-agent packaging.

v4.0 makes a clean break:

1. **CLI consolidation** — `symvault agent <verb>` becomes the *only* surface for AI integration. `mcp-config`, `mcp install`, `mcp-token-rotate`, `agent setup` are removed (with deprecation stubs in 4.0, full removal in 4.1).
2. **Single install command** — `symvault agent install <name>` produces profile + scoped token + MCP config injection + drop-in skill package + smoke test in one step. Default tier is `safe`.
3. **Embedded skill packages** — Per-agent skill files (Claude Code, Hermes, Codex, OpenCode, OpenClaw) ship inside the binary via `embed.FS`, render with templated context, install with managed-by sentinel headers.
4. **Runtime UX** — New `openpass_whoami` and `openpass_audit_self` MCP tools, structured error codes (`ERR_*`), richer LLM-aimed tool descriptions, lean-mode `tools/list` default.
5. **Tier system formalized** — Three named tiers (`safe`, `standard`, `admin`) with frozen snapshots. Tier upgrades require interactive confirmation + audit-logged diff.
6. **Dual-surface** — CLI becomes a first-class agent interface via `OPENPASS_AGENT=<name>` env-var, applying the same profile/quota/audit logic as MCP. Skills tell agents to prefer CLI for read-heavy ops, MCP for OS-mediated ops (clipboard, dialogs, approval).
7. **Migration helper** — `symvault migrate v4` classifies existing v3 profiles into tiers and renders skill packages.

The dual-surface direction (Section 8) is a deliberate response to documented MCP context-window pollution: a typical 3-server MCP install consumes ~143K of 200K tokens before user input, MCP costs 4–32× more tokens than CLI for identical reads, and OpenClaw's creator publicly called MCP "a mistake" in early 2026. Symaira Vault uniquely fits the MCP-wins case (per-agent auth + audit + approval), so we keep MCP — but stop fattening it and give agents a first-class shell path.

---

## 1. CLI Architecture & Command Tree

### 1.1 Principles

- **Verb-first.** Top-level verbs reflect user intent (`init`, `agent`, `serve`).
- **Single owner per concern.** All AI-integration concerns live under `symvault agent`.
- **JSON parity.** `--output text|json|yaml` works on every command. JSON output is the contract for agent-driven CLI calls.
- **Structured exit codes.** Agents parse codes, not error strings.

### 1.2 Command tree

```
symvault init                          # vault initialization (unchanged)
symvault setup                         # interactive wizard (unchanged)

symvault agent                         # umbrella for AI-integration
  install <name>                       # NEW: replaces mcp install + mcp-config + agent setup
    --auto-detect                      # detect all installed agents
    --tier <safe|standard|admin>       # default: safe
    --http                             # default: stdio
    --dry-run
    --skill-only                       # NEW: only drop skill, no MCP config
    --config-only                      # NEW: only MCP config, no skill
    --force                            # overwrite existing Symaira Vault entries
    --output json|yaml|text
  upgrade <name> --tier <new>          # NEW: explicit tier change with diff prompt
    --dry-run
    --yes --reason "..."               # non-interactive (reason required)
    --rotate-token                     # optionally rotate scoped token on upgrade
  uninstall <name>                     # NEW: remove profile, token, skill, MCP entry
  list                                 # show all installed agents (tier, token, last-seen)
  doctor <name>                        # NEW: end-to-end debug for one integration
    --all                              # run doctor across all installed agents
  token <name>                         # subsumes mcp token
    new | list | revoke | rotate
  audit <name>                         # NEW: per-agent audit log
    --since <duration>
    --format table|json
  audit self                           # equivalent of openpass_audit_self for CLI
  profile <name>                       # subsumes profile management for agents
    show | edit | export
  prompt <path>.<field>                # NEW: CLI form of secure_input
  request <path>.<field> --reason "…"  # NEW: CLI form of request_credential
  skill                                # skill package management
    export <agent> [-o file.tar.gz]    # NEW: pack for drop-in distribution
    refresh <agent>                    # NEW: re-render in place
  whoami --output json                 # NEW: CLI form of openpass_whoami

symvault serve                         # MCP server (unchanged)
  --stdio --agent <name>
  --port <n>
```

### 1.3 Removed commands

| v3 | v4.0 replacement | v4.0 stub | v4.1 |
|---|---|---|---|
| `symvault mcp-config <agent>` | `symvault agent install <agent> --config-only` | error stub printing replacement, exit 2 | removed |
| `symvault mcp install <agent>` | `symvault agent install <agent>` | stub, exit 2 | removed |
| `symvault mcp install --auto-detect` | `symvault agent install --auto-detect` | stub, exit 2 | removed |
| `symvault mcp token create` | `symvault agent token new <name>` | stub, exit 2 | removed |
| `symvault mcp token list` | `symvault agent token list` | stub, exit 2 | removed |
| `symvault mcp token revoke` | `symvault agent token revoke` | stub, exit 2 | removed |
| `symvault mcp-token-rotate` | `symvault agent token rotate <name>` | stub, exit 2 | removed |
| `symvault agent setup <name>` | `symvault agent install <name>` (tier override) | stub, exit 2 | removed |
| `symvault mcp` (subcommand tree) | folded into `symvault agent` | stub on each subcommand, exit 2 | removed |

### 1.4 Global flags

- `--output text|json|yaml` (default: text) — must function on every command
- `--quiet` — suppress non-error output
- `--verbose` — debug-level logging
- `--vault <path>` (unchanged)
- `--profile <name>` (unchanged — vault profile, not agent profile)

### 1.5 Standardized exit codes

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

Agent-driven callers can branch on exit code without parsing stderr.

---

## 2. Agent Install Flow

### 2.1 End-to-end steps

`symvault agent install <name>` executes:

| Step | Action | Failure handling |
|------|--------|------------------|
| 1 | Validate vault exists, identity readable | exit 10 (locked) or 11 |
| 2 | Detect agent (binary in PATH ∪ config-file present) | exit 1 if not found, hint at install URL |
| 3 | Load/create `config.yaml`, create profile `<name>` | dry-run prints diff, doesn't write |
| 4 | Apply tier preset (default: safe) | deterministic, no IO |
| 5 | Generate scoped token in registry; SHA-256 hash | in-memory until step 9 |
| 6 | Backup agent config file → `<path>.bak.<timestamp>` | silent skip if file absent |
| 7 | Inject MCP server entry into agent config | restore backup on error |
| 8 | Copy embedded skill package to agent's skill dir | restore + delete token on error |
| 9 | Persist token to OS keyring (fallback: file with 0600) | rollback profile if fails |
| 10 | Smoke test: spawn `symvault serve --stdio --agent <name>`, call `tools/list`, expect `openpass_whoami` | warn-only, don't rollback (transport quirks happen) |
| 11 | Print structured summary | — |

### 2.2 Per-agent paths

| Agent | MCP config file | Skill target | Format |
|---|---|---|---|
| `hermes` | `~/.hermes/config.yaml` (`mcp_servers.openpass`) | `~/.hermes/skills/symvault/SKILL.md` + `manifest.yaml` | YAML |
| `claude-code` | `~/.claude.json` (`mcpServers.symvault`) or project `.mcp.json` | `~/.claude/skills/symvault/SKILL.md` | JSON + Markdown |
| `codex` | `~/.codex/config.toml` (`mcp.servers.openpass`) | `~/.codex/skills/symvault/SKILL.md` (or AGENTS.md if Codex prefers) | TOML |
| `opencode` | `~/.config/opencode/opencode.json` (`mcp.openpass`) | `~/.opencode/skills/symvault/SKILL.md` | JSON |
| `openclaw` | `~/.openclaw/mcp.yaml` | `~/.openclaw/skills/symvault/` | YAML |

The exact paths for Codex/OpenClaw will be verified during implementation against current upstream conventions; existing `internal/mcp/install/` has v3 paths to start from.

### 2.3 Flag semantics

| Flag | Effect |
|---|---|
| `--auto-detect` | Iterate over known agents, run flow for each `Detected=true` |
| `--tier <safe\|standard\|admin>` | Override default safe-tier; `standard`/`admin` require TTY confirmation with diff (Section 5.3) |
| `--http` | Generate HTTP URL + token entry; assumes `symvault serve --port` is running; warn with LaunchAgent/systemd hint if not |
| `--dry-run` | Print every file operation as diff, write nothing |
| `--skill-only` | Drop skill only — for setups where MCP config is manually managed |
| `--config-only` | MCP config only — for setups where skills are distributed via org sync |
| `--force` | Overwrite existing Symaira Vault entries without prompting |

### 2.4 Summary output

```
✓ Hermes configured for Symaira Vault MCP
  Profile:       hermes (tier=safe, paths=*)
  Token:         opt_tok_a1b2 (OS keyring)
  MCP config:    ~/.hermes/config.yaml
  Skill:         ~/.hermes/skills/symvault/SKILL.md
  Smoke test:    PASS (4 tools discovered)
  Backup:        ~/.hermes/config.yaml.bak.20260517-151203

Next steps:
  1. Restart Hermes (or run `hermes mcp reload symvault`)
  2. Try in Hermes: "list my vault entries"
  3. To enable get_entry/clipboard: symvault agent upgrade hermes --tier standard
  4. CLI mode: export OPENPASS_AGENT=hermes  (see ~/.hermes/skills/symvault/SKILL.md)
```

`--output json` returns the same data as a structured map for agent-driven installs (e.g., Hermes itself shell-calling `symvault agent install hermes --output json` and parsing the result).

### 2.5 Three integration paths supported

- **User-driven (push):** `symvault agent install hermes` from user's shell
- **Agent-driven (pull):** Hermes invokes `symvault agent install hermes --output json` via its Bash tool
- **Drop-in skill:** `symvault agent skill export hermes > symvault-hermes-skill.tar.gz` packs the rendered skill for org distribution; receiver runs `symvault agent token new hermes` separately for the token

---

## 3. Skill Packaging

### 3.1 Storage layout

```
internal/agentskill/
├── skill.go              # template rendering, integrity checks
├── manifest.go           # version, hash, sentinel handling
├── install.go            # write to disk, idempotency, uninstall
└── assets/               # embed.FS root
    ├── common/
    │   └── SKILL.md.tmpl # reused base content
    ├── hermes/
    │   ├── manifest.yaml.tmpl
    │   └── SKILL.md.tmpl
    ├── claude-code/
    │   └── SKILL.md.tmpl
    ├── codex/
    │   └── AGENTS.md.tmpl
    ├── opencode/
    │   └── SKILL.md.tmpl
    └── openclaw/
        └── SKILL.md.tmpl
```

Existing `docs/skills/openpass-agent/SKILL.md` content is migrated into `internal/agentskill/assets/common/SKILL.md.tmpl`. Per-agent overlays configure tool prefix, slash prefix, and agent-specific notes.

### 3.2 Template variables

| Variable | Example values |
|---|---|
| `.AgentName` | `hermes`, `claude-code`, `codex`, … |
| `.ToolPrefix` | `mcp_openpass_` (Hermes), `mcp__openpass__` (Claude Code) |
| `.SlashPrefix` | `/mcp__openpass__` (Claude Code), `/symvault:` (Hermes), empty (Codex) |
| `.OpenPassVersion` | `4.0.0` |
| `.ProfileTier` | `safe`, `standard`, `admin`, `custom` |
| `.VaultPath` | `~/.openpass` (or chosen vault path) |
| `.InstalledAt` | RFC3339 timestamp |
| `.SkillSchemaVersion` | `1` |

Templates render deterministically (no `now()` outside `.InstalledAt`) so byte-diff comparison between current file and re-render is sound.

### 3.3 Skill header (sentinel + frontmatter)

```markdown
---
name: symvault
description: Use Symaira Vault as the credential manager via native MCP tools and CLI.
managed_by: symvault
managed_version: 4.0.0
managed_hash: sha256:abc123…
managed_installed_at: 2026-05-17T15:12:03Z
managed_profile_tier: safe
---

<!-- DO NOT EDIT. Managed by Symaira Vault. Run `symvault agent install <agent> --skill-only` to refresh. -->
```

- `managed_by: symvault` is the **sentinel**. Uninstall + refresh touch only files with the sentinel; user-edited skills never get destroyed.
- `managed_hash` is SHA-256 of the rendered body without frontmatter. `symvault agent doctor` detects user modifications via hash mismatch.
- `managed_version` enables compatibility checks.

### 3.4 Lifecycle

**Install** (Section 2.1 Step 8):

1. `agentskill.Render(agentName, ctx)` → in-memory bytes
2. Determine target path (per Section 2.2)
3. If exists + sentinel matches + hash unchanged → no-op
4. If exists + sentinel matches + hash differs → backup + overwrite
5. If exists + **no sentinel** → abort with `ERR_SKILL_EXISTS_UNMANAGED`; hint `--force`
6. If absent → write 0644 (skill files must be readable; never contain secrets)

**Refresh** (`symvault update` post-hook + manual `symvault agent install <name> --skill-only`):

- Iterate all agents with `installed_skill_path` field
- Re-render with current binary
- If hash differs → replace (with backup)

**Uninstall:**

- Read frontmatter
- If `managed_by: symvault` → delete
- Otherwise → warn, leave file

### 3.5 Skill content (what's actually inside)

Skills are short and imperative. v4.0 content includes:

- **Bootstrap block:** "First call `{{.ToolPrefix}}openpass_whoami` to learn your permissions."
- **Tier hint:** If `ProfileTier == safe`, explicit guidance: "You only have metadata tools. For `get_entry` access, ask the user to run `symvault agent upgrade {{.AgentName}} --tier standard`."
- **Error code map:** Table of structured error codes with agent-side reactions.
- **Decision matrix:** When to use CLI vs MCP (Section 8.4).
- **Anti-patterns:** "Never echo a secret value in chat — not even to confirm. Never `cat` vault files. Never `git log` the vault."

### 3.6 Export for drop-in

`symvault agent skill export <agent> [-o file.tar.gz]` packs rendered files as a TAR archive for org-wide distribution:

- Skill file(s) with rendered content
- `INSTALL.md` with manual install steps
- Note that the token must be created separately via `symvault agent token new <name>`

### 3.7 Signing (deferred)

For v4.0 skills are unsigned. Trust anchor is the signed Symaira Vault binary (goreleaser + macOS notarization + SLSA attestation). A skill file without a sentinel is user-managed; the install flow refuses to overwrite without `--force`.

### 3.8 Version drift handling

`symvault agent doctor <name>` shows:

```
⚠ Skill version drift detected for hermes
    Installed: 3.9.0 (hash: …a3d2)
    Current:   4.0.0 (hash: …e711)
  Run: symvault agent install hermes --skill-only --refresh
```

`symvault update` post-hook prints: "Run `symvault agent install --refresh-all` to update skill packages for X installed agents."

---

## 4. Runtime UX (MCP Tools)

### 4.1 New tool: `openpass_whoami`

Available in **every** tier (including safe). Typical call pattern: agent calls it once per session. Response schema:

```json
{
  "agent": "hermes",
  "openpass_version": "4.0.0",
  "profile": {
    "name": "hermes",
    "tier": "safe",
    "allowed_paths": ["agents/providers/", "projects/local-dev/"],
    "approval_mode": "deny",
    "can_write": false,
    "can_run_commands": false,
    "can_use_clipboard": false,
    "can_use_autotype": false,
    "redact_fields": ["totp.secret", "recovery_codes"]
  },
  "tools": {
    "available": ["openpass_whoami", "openpass_search", "health", "list_entries", "find_entries", "get_entry_metadata", "request_credential"],
    "unavailable": [
      { "name": "get_entry", "code": "ERR_TOOL_NOT_ALLOWED",
        "reason": "tier=safe; ask user to run `symvault agent upgrade hermes --tier standard`" },
      { "name": "run_command", "code": "ERR_TOOL_NOT_ALLOWED",
        "reason": "canRunCommands=false; requires admin tier and per-task approval" }
    ]
  },
  "quotas": {
    "reads_per_hour": { "used": 3, "limit": 60 },
    "reads_per_day":  { "used": 12, "limit": 200 },
    "secrets_per_session": { "used": 0, "limit": 0 }
  },
  "vault": { "unlocked": true, "entries_count": 47 },
  "cli_alternative_hint": "OPENPASS_AGENT=hermes symvault <command> --output json",
  "errors_doc": "https://openpass.dev/v4/errors",
  "tier_upgrade_hint": "symvault agent upgrade hermes --tier standard"
}
```

### 4.2 Structured errors

Every failed MCP response returns:

```json
{
  "error": {
    "code": "ERR_PATH_FORBIDDEN",
    "message": "Path 'infra/aws/prod' is not in this agent's allowedPaths",
    "hint": "Within your scope ['agents/providers/', 'projects/local-dev/']. Ask user to scope further or call openpass_whoami to confirm.",
    "details": {
      "requested_path": "infra/aws/prod",
      "allowed_paths": ["agents/providers/", "projects/local-dev/"],
      "agent": "hermes"
    },
    "doc": "https://openpass.dev/v4/errors#err_path_forbidden"
  }
}
```

**Error code set:**

| Code | Trigger | Agent reaction hint |
|---|---|---|
| `ERR_AUTH_REQUIRED` | Vault locked | Tell user to run `symvault unlock` |
| `ERR_PATH_FORBIDDEN` | Path outside allowedPaths | Try alternative path or ask user to broaden profile |
| `ERR_TOOL_NOT_ALLOWED` | Tool not in agent's tier | Surface `tier_upgrade_hint` to user |
| `ERR_APPROVAL_DENIED` | User declined prompt | Abort task, politely re-ask |
| `ERR_APPROVAL_TIMEOUT` | Prompt TTL hit | Retry or alternative strategy |
| `ERR_APPROVAL_UNAVAILABLE` | No TTY and no GUI backend | Defer task or notify user async |
| `ERR_ENTRY_NOT_FOUND` | Path doesn't exist | Call `request_credential` if appropriate |
| `ERR_FIELD_NOT_FOUND` | Entry exists, field missing | Inspect entry layout, try another field name |
| `ERR_FIELD_REDACTED` | Profile redacts this field | Use another tool (e.g. `generate_totp` instead of reading `totp.secret`) |
| `ERR_QUOTA_EXCEEDED` | Rate limit reached | Pause or request quota increase |
| `ERR_TOKEN_EXPIRED` | Scoped token TTL expired | Tell user to rotate via `symvault agent token rotate <name>` |
| `ERR_INVALID_INPUT` | Schema validation failed | Re-check tool schema |
| `ERR_DRY_RUN` | Call was in dry-run mode | Confirmation that call would have succeeded |
| `ERR_TIER_UPGRADE_NO_TTY` | Install attempted higher tier without TTY | Run interactively or use `--tier safe` and upgrade later |
| `ERR_CONFIG_EXISTS_UNMANAGED` | Agent config / skill file exists without Symaira Vault sentinel | Use `--force` or manual cleanup |
| `ERR_TOOL_NOT_FOUND` | Tool name unknown | Check `tools/list` or call `openpass_search` |

Codes live in `internal/mcp/errors/codes.go` as constants. Tests verify every triggered error uses a code from this set.

### 4.3 Tool descriptions for LLMs

Tool descriptions are restructured for in-context affordance:

```
Tool: find_entries

Search vault for entries by query string.

USE WHEN:
  - User describes a credential by service name, brand, URL, or fuzzy keyword
  - You don't have the exact path
  - You want to confirm an entry exists before reading it

DON'T USE WHEN:
  - You already have the exact path → use get_entry_metadata or get_entry
  - You're checking if vault is unlocked → use openpass_whoami or health

INPUT:
  query (string, required): keyword(s) to match against paths and indexed fields
  limit (int, optional, default 20): max results
  mode (string, optional, "fuzzy"|"exact", default "fuzzy")

OUTPUT:
  array of { path, name, updated, version, score }

COMBINES WELL WITH:
  - get_entry_metadata (verify match details before read)
  - get_entry (read full content)
  - copy_to_clipboard (consume without revealing)

EXAMPLE:
  {"query": "github", "limit": 5}
  → [{"path": "github/personal", "name": "GitHub", "updated": "2026-04-21T...", "version": 5, "score": 0.95}, ...]
```

Descriptions live in `internal/mcp/tooldocs/<toolname>.md` and render via `internal/mcp/render.go`.

### 4.4 Tool surface adjustments (v4.0)

| Tool | v3.x | v4.0 |
|---|---|---|
| `openpass_delete` | deprecated alias for `delete_entry` | **REMOVED** |
| `get_entry_metadata` | separate tool | retained (safe-tier permitted; `get_entry` is not safe) |
| `secure_input` | low-level | retained; docs state "prefer `request_credential`" |
| `request_credential` | primary surfaced in skill | unchanged |
| `find_entries` | basic search | expanded: `limit`, `cursor`, `mode=fuzzy\|exact`, returns mini-metadata per hit |
| `list_entries` | unchanged | expanded: optional `path_prefix`, `since`, `output_format` |
| `generate_password` | unchanged | expanded: `passphrase_mode` (diceware as additional mode, no extra tool) |
| `health` | unchanged | unchanged |
| `get_auth_status` | unchanged | unchanged |
| **NEW `openpass_whoami`** | — | Section 4.1 |
| **NEW `openpass_audit_self`** | — | Section 4.7 |
| **NEW `openpass_search`** | — | Section 8.3 |

No composite tools (e.g., `find_and_copy`) — surface remains tractable, patterns documented in skill.

### 4.5 `find_entries` output

Before (v3):

```json
{ "results": ["github/personal", "github/work", "github/oauth"] }
```

After (v4.0):

```json
{
  "results": [
    { "path": "github/personal", "name": "GitHub Personal", "updated": "2026-04-21T09:45:00Z", "version": 5, "score": 0.95 },
    { "path": "github/work",     "name": "GitHub Work",     "updated": "2026-03-12T11:01:00Z", "version": 2, "score": 0.82 }
  ],
  "next_cursor": null
}
```

Saves 3+ `get_entry_metadata` round-trips per query.

### 4.6 Approval flow in daemonized setup

In service mode (LaunchAgent, systemd) TTY is unavailable. v4.0 falls back to the `secureui` backend (osascript / zenity / Get-Credential) for approval prompts. If `OPENPASS_SECUREUI=none` and no TTY, returns `ERR_APPROVAL_UNAVAILABLE` so agent knows user is unreachable.

### 4.7 New tool: `openpass_audit_self`

Available in safe-tier and above. Returns the agent's own recent audit events:

```json
{ "events": [
    { "ts": "2026-05-17T15:10:11Z", "tool": "get_entry_metadata", "path": "agents/providers/openai", "status": "success" },
    { "ts": "2026-05-17T15:11:02Z", "tool": "get_entry", "path": "infra/aws/prod", "status": "denied", "code": "ERR_PATH_FORBIDDEN" }
] }
```

Agents only see their own events; other agents' audit trails are not exposed.

---

## 5. Tier System & Upgrade Flow

### 5.1 Three tiers

| Property | `safe` (default) | `standard` | `admin` |
|---|---|---|---|
| **Tools** | `openpass_whoami`, `openpass_audit_self`, `openpass_search`, `health`, `get_auth_status`, `list_entries`, `find_entries`, `get_entry_metadata`, `request_credential` | safe + `get_entry`, `get_entry_value`, `copy_to_clipboard`, `autotype`, `set_entry_field`, `generate_password`, `generate_totp`, `secure_input`, `share_request`, `share_list` | standard + `run_command`, `execute_with_secret`, `delete_entry`, `set_auth_method`, `share_approve`, `share_revoke` |
| **canWrite** | false | true | true |
| **canRunCommands** | false | false | true |
| **canUseClipboard** | false | true | true |
| **canUseAutotype** | false | true | true |
| **canManageConfig** | false | false | true (own profile only) |
| **approvalMode** | `deny` | `prompt` (writes & destructive) | `prompt` (all destructive) |
| **redactFields** (default) | `totp.secret`, `recovery_codes`, `private_key`, `*.secret` | `totp.secret`, `recovery_codes` | (empty) |
| **max_reads_per_hour** | 60 | 200 | unlimited |
| **max_reads_per_day** | 200 | 1000 | unlimited |
| **max_secrets_in_session** | 0 | 5 | unlimited |

Presets in `internal/config/tier_presets.go` (extending current `ApplyTierPreset`). Snapshot tests prevent silent drift.

### 5.2 Initial tier on install

- Default `safe`. Applies to user-CLI, agent-driven, and auto-detect installs alike.
- `--tier standard` or `--tier admin` triggers interactive TTY confirmation with the diff from 5.3.
- Without TTY plus `--tier standard|admin`: install fails with `ERR_TIER_UPGRADE_NO_TTY` — agent-driven installs cannot silently grant elevated tiers.

### 5.3 Upgrade flow

`symvault agent upgrade hermes --tier standard`:

```
Upgrading agent profile: hermes
  Current tier:  safe
  Target tier:   standard
  Issued at:     2026-05-17 15:30:12 UTC
  Last seen:     2026-05-17 14:55:01 UTC (on get_entry_metadata)

The following will CHANGE:

  ▌ Tools added (11):
      + get_entry              read secret values
      + get_entry_value        read single field value
      + copy_to_clipboard      put secret on system clipboard (auto-clears 30s)
      + autotype               type secret into focused window
      + set_entry_field        create/update vault entries
      + generate_password      generate strong passwords
      + generate_totp          generate TOTP codes
      + secure_input           prompt user for secret via dialog
      + share_request          request a share grant
      + share_list             list outstanding shares

  ▌ Capabilities:
      canWrite:        false → true
      canUseClipboard: false → true
      canUseAutotype:  false → true
      approvalMode:    deny → prompt (writes & destructive ops require user OK)

  ▌ Redaction relaxed:
      Now visible: private_key, *.secret
      Still hidden: totp.secret, recovery_codes

  ▌ Quotas raised:
      reads_per_hour:        60 → 200
      reads_per_day:         200 → 1000
      max_secrets_in_session: 0 → 5

This grants hermes the ability to:
  - read secret values (currently only metadata)
  - write/update vault entries
  - use clipboard and autotype (secrets leave Symaira Vault via OS)
  - prompt the user for sensitive input

Recommended: review last 7d of hermes activity:
  symvault agent audit hermes --since 7d --format table

Confirm upgrade to 'standard'? [y/N]: _
```

On `y`:

- Profile updated
- `AGENT_TIER_CHANGED` audit event written (with `from`, `to`, `actor`, `confirmed_at`, optional `reason`)
- Skill file re-rendered (Section 3) reflecting new tier hints
- `--rotate-token` optionally rotates the scoped token
- Print success: `✓ hermes is now 'standard' tier. Skill refreshed. Restart hermes if needed.`

On `N` or timeout: no write; `AGENT_TIER_CHANGE_DENIED` event with `would_have_been=<tier>`.

### 5.4 Non-interactive upgrade

```
symvault agent upgrade hermes --tier standard --yes --reason "ticket OPS-1234"
```

`--yes` requires `--reason` — automation scripts cannot silently elevate. Reason is stored in the audit event.

### 5.5 Dry-run preview

`symvault agent upgrade hermes --tier standard --dry-run` prints the 5.3 diff without writing.

### 5.6 Custom profiles

`symvault agent profile edit hermes` opens the profile in `$EDITOR`. On save: schema validation → diff → confirmation prompt (same as 5.3). Same audit trail.

`symvault agent profile show hermes --output yaml` exports the rendered profile for GitOps workflows.

### 5.7 Tier indicators in output

`openpass_whoami` returns `tier` and `tier_upgrade_hint`. Every `ERR_TOOL_NOT_ALLOWED` response embeds the same hint.

### 5.8 Audit event types (new in v4.0)

| Event | Payload |
|---|---|
| `AGENT_INSTALLED` | agent, tier, transport, performer, ts |
| `AGENT_TIER_CHANGED` | agent, from, to, actor, reason, ts |
| `AGENT_TIER_CHANGE_DENIED` | agent, would_have_been, actor, ts |
| `AGENT_TOKEN_ROTATED` | agent, old_token_id, new_token_id, actor, ts |
| `AGENT_UNINSTALLED` | agent, performer, ts |
| `AGENT_QUOTA_HIT` | agent, quota_type, limit, ts |

### 5.9 Per-agent default tiers

Not implemented in v4.0. Default tier is uniformly `safe` for all agents. Practice-driven overrides happen via the docs/Quickstart, not by silent agent-specific defaults.

---

## 6. Migration & Backwards-Compat

### 6.1 Release line

| Version | Content |
|---|---|
| **v3.9.0** | Last v3 minor: (a) deprecation warnings on removed-in-v4 commands; (b) ships `symvault migrate v4 --dry-run`; (c) doc reference to `docs/migration-v3-to-v4.md` |
| **v4.0.0-beta.1** | Full v4 build. Deprecation stubs print replacements + exit 2 |
| **v4.0.0-rc.1, rc.2** | Bug-fix iterations |
| **v4.0.0** | GA. Deprecation stubs remain |
| **v4.1.0** | Deprecation stubs removed |

### 6.2 What disappears

See Section 1.3 for CLI command removal table. Plus:

| MCP tool | Status |
|---|---|
| `openpass_delete` | Removed in v4.0; was alias since v3.x. `tools/list` doesn't list it. Callers receive `ERR_TOOL_NOT_FOUND` |

All other v3 tools persist. Section 4.4 expansions are additive.

### 6.3 Config schema migration

`AgentProfile` gains three fields:

```yaml
agents:
  hermes:
    tier: safe                  # NEW: tier name (safe|standard|admin|custom)
    skill_path: ~/.hermes/skills/symvault/SKILL.md   # NEW: location of installed skill
    skill_version: 4.0.0        # NEW: Symaira Vault version that rendered it
    # …existing fields preserved
```

On first v4 start, `internal/config/migrate.go`:

1. Detects missing `tier` field
2. Classifies the existing profile:
   - `canRunCommands=true` → `admin`
   - `canWrite=true` and `canUseClipboard=true` → `standard`
   - Otherwise → `safe`
3. Writes `tier` back with `# auto-migrated from v3 by symvault v4.0.0`
4. Backs up `config.yaml` → `config.yaml.bak.v3-<timestamp>`
5. Audit event `CONFIG_MIGRATED_V3_V4` with diff

Profiles with exotic overrides (e.g., custom `redactFields` not matching any preset) get classified `custom`; the explicit fields remain authoritative.

### 6.4 Token registry migration

Tokens gain two fields (additive):

- `issued_for_tier` — informational
- `min_protocol_version` — `4.0.0` for v4-issued tokens

**Critical behavior change:** `tools: ["*"]` is now interpreted as "inherit from profile" rather than "all tools ever". Non-empty concrete tool lists still further restrict. This binds tokens to the *current* profile permissions, so profile downgrades take effect immediately. Documented in `docs/mcp-api.md`.

### 6.5 `symvault migrate v4` helper

```
symvault migrate v4 [--dry-run] [--yes]

Steps:
  1. Read existing config.yaml
  2. For each agent profile: classify tier, compute diff
  3. Show summary:

       Agent      Inferred Tier  Notes
       ─────────  ─────────────  ─────────────────────────────────────
       hermes     safe           was already metadata-only
       claude     standard       canWrite=true, canUseClipboard=true
       legacy     custom         redactFields differ from any preset
       openclaw   admin          canRunCommands=true

  4. Per-skill drift:

       Agent      Skill Path                          Action
       ─────────  ──────────────────────────────────  ───────────
       hermes     ~/.hermes/skills/symvault/SKILL.md  create
       claude     ~/.claude/skills/symvault/SKILL.md  refresh (drift)
       openclaw   (none — manual pre-v4 install)      create

  5. Confirm? [y/N]
  6. Apply:
       - Backup config.yaml → config.yaml.bak.v3-…
       - Write migrated profiles
       - Render and install skill packages for each agent
       - Re-validate token registry
       - Print summary + next-step hints
```

### 6.6 CHANGELOG skeleton

```markdown
## v4.0.0 — 2026-Q3

### BREAKING CHANGES

- `symvault mcp` subcommand tree replaced by `symvault agent`.
  See docs/migration-v3-to-v4.md for the mapping table.
- MCP tool `openpass_delete` removed (was alias for `delete_entry` since v2.x).
- Default tier for `symvault agent install` is now `safe` (was implicit `standard`).
  Upgrade explicitly with `symvault agent upgrade <name> --tier standard`.
- Token `tools: ["*"]` is now interpreted as "inherit from profile" — profile
  changes take effect on next call.

### MIGRATION

Run `symvault migrate v4 --dry-run` to preview, then `symvault migrate v4`.

### NEW

- `symvault agent install` — single command for all agent integrations.
- `symvault agent upgrade --tier` — explicit, audited tier changes.
- Skill packages now ship inside the binary and install per-agent.
- New MCP tools: `openpass_whoami`, `openpass_audit_self`, `openpass_search`.
- Structured error codes (`ERR_*`) in all MCP responses.
- `find_entries` returns metadata inline (saves round-trips).
- CLI agent-mode: `OPENPASS_AGENT=<name>` env-var applies agent profile to
  CLI calls. Same paths, redactions, quotas, audit as MCP.
- Lean-mode `tools/list` default exposes 7 essential tools;
  `openpass_search` discovers the rest on demand.

### DEPRECATIONS REMOVED FROM CLI

Deprecated stubs remain in v4.0 with an error message pointing to the new
command. Stubs will be removed in v4.1.

### SECURITY

- Safe-tier profiles are now the default for fresh agent installs.
- Tier upgrades require interactive TTY confirmation (or `--yes --reason "…"`).
- Tier changes are logged with full diff to the audit log.
```

### 6.7 Migration doc

`docs/migration-v3-to-v4.md` covers:

- Command mapping (Section 1.3 table)
- Behavioral changes (default tier, token semantics, `OPENPASS_AGENT`)
- Migration steps (copy-paste commands for typical setups)
- CI/automation fixup snippets

### 6.8 Pre-release tests

- `symvault migrate v4` idempotent on a v3 test vault in `testdata/v3-snapshot/`
- Roundtrip: v3 config → migrate → v4 config → re-migrate (no-op)
- Profile classification matrix tests
- Per-agent E2E: simulate v3 install, migrate, `symvault agent doctor <name>` PASSes

---

## 7. Testing Strategy

### 7.1 Tier-preset snapshot tests

`internal/config/tier_presets_test.go` — frozen snapshots of all three tiers. Any preset change forces test update and code review.

### 7.2 Tool-surface manifest test

`internal/mcp/server_test.go`:

- `tools/list` per tier returns *exactly* the spec'd list (Sections 4.4, 5.1)
- Every tool has a description in `internal/mcp/tooldocs/<tool>.md`
- Every triggered error uses a code from `internal/mcp/errors/codes.go` (grep-based linter test)

### 7.3 Agent-install integration tests

Per supported agent (hermes, claude-code, codex, opencode, openclaw): one test in `internal/mcp/install/integration_test.go`.

```go
func TestInstall_Hermes_Safe(t *testing.T) {
    tmpHome := t.TempDir()
    t.Setenv("HOME", tmpHome)
    vault := setupTestVault(t, tmpHome)
    seedHermesConfig(t, tmpHome)

    err := installCmd("hermes", InstallOpts{Tier: "safe"})
    require.NoError(t, err)

    assertConfigContains(t, tmpHome+"/.hermes/config.yaml", "mcp_servers.openpass")
    assertSkillExists(t, tmpHome+"/.hermes/skills/symvault/SKILL.md")
    assertSkillFrontmatter(t, ..., "managed_by", "openpass")
    assertSkillFrontmatter(t, ..., "managed_profile_tier", "safe")
    assertTokenInRegistry(t, vault, "hermes")
    assertProfileExists(t, vault, "hermes", "safe")
    assertAuditEvent(t, vault, "AGENT_INSTALLED", "hermes")
}
```

Negative tests:

- `TestInstall_Hermes_NotDetected` — neither binary nor config → clear error with install hint
- `TestInstall_Hermes_ConfigExistsUnmanaged` — Symaira Vault entry without sentinel → abort with `ERR_CONFIG_EXISTS_UNMANAGED`

### 7.4 Skill-rendering tests

`internal/agentskill/skill_test.go`:

- Golden-file tests per agent (`testdata/skills/<agent>/SKILL.md.golden`)
- Template references all 3.2 variables (Parse-tree reflection)
- Frontmatter sentinel + hash byte-identical on re-render (deterministic)
- Uninstall only deletes files with sentinel (fixture with non-sentinel file → not deleted)

### 7.5 Tier-upgrade flow tests

`cmd/agent_upgrade_test.go`:

- Diff output snapshot
- `--dry-run` makes no writes
- `--yes --reason "X"` non-interactive works
- `--yes` without `--reason` fails
- Audit event written
- Skill re-rendered after upgrade
- "n" input → no write, `AGENT_TIER_CHANGE_DENIED` event

### 7.6 Migration tests (v3→v4)

`internal/config/migrate_test.go`:

- Fixture dir `testdata/v3-snapshots/` with ~6 typical v3 configs
- Per fixture: migrate → tier classification asserted, all v3 settings preserved, backup written
- Roundtrip idempotency
- Conflict test: unusual v3 flag combos → classified `custom`

### 7.7 Cross-platform smoke

CI matrix runs on macOS, Linux, Windows. Per agent: config-path resolution tests across platform variants.

### 7.8 Security regression tests

`internal/mcp/security_test.go` — CI-blocker required:

- `TestSafeTier_CannotCallGetEntry` — safe-tier call to `get_entry` → `ERR_TOOL_NOT_ALLOWED`
- `TestSafeTier_RedactsTOTPSecret` — `get_entry_metadata` with totp.secret → `[REDACTED]`
- `TestPathForbidden_OutsideAllowedPaths` — `ERR_PATH_FORBIDDEN`
- `TestQuotaEnforced` — 61st read at limit=60 → `ERR_QUOTA_EXCEEDED`
- `TestTokenScopedToProfile` — token with `tools: ["*"]` + safe-tier profile → effective tool list = safe-tier
- `TestAuditLogged` — success + failure + approval-denial → three distinct entries

### 7.9 E2E test with real binary

`cmd/binary_e2e_test.go`:

- `TestE2E_AgentInstall_Hermes_Safe` — build binary, simulate Hermes setup, subprocess call to `./symvault agent install hermes`, verify files + JSON output
- `TestE2E_AgentUpgrade`
- `TestE2E_AgentDoctor`

Build-tagged with `e2e`, runs in `main` merge CI, not on every PR.

### 7.10 Out of scope

- Real agent binaries (hermes/claude-code/codex) not installed in CI; simulated via fixtures
- Token crypto properties (trust Go stdlib + existing tests)
- OAuth/DCR flow (existing v3 tests carry over)

### 7.11 CI configuration

`.github/workflows/ci.yml`:

- `test:unit` (all platforms) — required
- `test:integration` (all platforms) — required
- `test:security` (Linux, OS-keyring dependent) — required
- `test:e2e` (Linux + macOS) — required for main, not per PR
- `test:cli-agent` (NEW — Section 8.8) — required

### 7.12 Manual release checklist

`docs/release-checklist-v4.md` — release manager ticks before `git tag v4.0.0`:

- [ ] macOS: install hermes, upgrade to standard, run real Hermes session, verify get_entry works
- [ ] Linux: install claude-code, basic vault ops
- [ ] Windows: install codex, verify path handling
- [ ] macOS: `symvault migrate v4` on a real v3 vault, verify roundtrip
- [ ] OAuth flow with opencode end-to-end
- [ ] LaunchAgent HTTP setup on macOS, verify GUI approval prompt pops
- [ ] Skill drift detection: edit a SKILL.md, run doctor, verify drift reported

---

## 8. Dual-Surface: CLI as First-Class Agent Interface

Rationale: measured MCP context-window pollution is severe (a typical 3-server install consumes ~143K of 200K tokens before user input; MCP costs 4–32× more tokens than CLI for identical reads). OpenClaw's creator publicly called MCP "a mistake" in early 2026. Symaira Vault's value props (per-agent auth, audit, approval) keep MCP relevant — but we stop treating it as the only path.

### 8.1 `OPENPASS_AGENT` env-var

```bash
OPENPASS_AGENT=hermes symvault get github/personal --field password --output json
```

When `OPENPASS_AGENT` is set, the CLI:

1. Loads `agents.<name>` profile from `config.yaml`
2. Applies `allowedPaths`, `redactFields`, `canWrite`, tier-tool-filter — identical logic to MCP
3. Bumps quotas (shared counter, Section 8.5)
4. Writes audit event with `actor=cli:agent:<name>` (plus PID, parent PID, TTY)
5. Returns structured errors with codes (`ERR_PATH_FORBIDDEN`, `ERR_TOOL_NOT_ALLOWED`, …) on stderr in the same JSON shape as MCP

A `symvault get` call without `get_entry` in the agent's tier (e.g., safe-tier) returns `ERR_TOOL_NOT_ALLOWED` and exit 11.

### 8.2 CLI ↔ MCP tool mapping

| MCP tool | CLI equivalent |
|---|---|
| `list_entries` | `symvault list [--path-prefix X] [--since T] --output json` |
| `find_entries` | `symvault find <query> [--limit N] [--mode fuzzy\|exact] --output json` |
| `get_entry_metadata` | `symvault get <path> --metadata-only --output json` |
| `get_entry` | `symvault get <path> --output json` |
| `get_entry_value` | `symvault get <path> --field <field>` (raw stdout) |
| `set_entry_field` | `symvault set <path>.<field> --value "..."` |
| `delete_entry` | `symvault delete <path>` |
| `generate_password` | `symvault generate --length N --symbols --output json` |
| `generate_totp` | `symvault totp <path>` |
| `copy_to_clipboard` | `symvault get <path>.<field> --clip` |
| `autotype` | `symvault get <path>.<field> --autotype` |
| `run_command` / `execute_with_secret` | `symvault run --env X=path.field -- cmd args` |
| `secure_input` | `symvault agent prompt <path>.<field>` |
| `request_credential` | `symvault agent request <path>.<field> --reason "..."` |
| `openpass_whoami` | `symvault agent whoami --output json` |
| `openpass_audit_self` | `symvault agent audit self --since 24h --output json` |
| `health` | `symvault doctor --quick --output json` |
| `get_auth_status` | `symvault auth status --output json` |
| `share_*` | `symvault share request\|list\|approve\|revoke` |

Every entry must function under `OPENPASS_AGENT` with: profile enforcement, JSON output, structured errors.

### 8.3 Lean-MCP default

Default `tools/list` returns **7 tools**:

```
openpass_whoami       Self-introspection: tier, allowed paths, quotas, available tools
openpass_search       Discover and on-demand-load more tools by intent
health                Server health
find_entries          Search vault by query
get_entry_metadata    Read entry metadata (safe-tier permitted)
request_credential    Prompt user for missing credential via native dialog
openpass_audit_self   Read own recent audit events
```

This is ~5 KB of initial context vs ~30 KB for the full list — ~83% reduction.

**`openpass_search` spec:**

```
Input:
  intent  (string): describe what you want to do
  return  (string, optional): "spec" (default) | "names"

Output:
  matched_tools: [
    { name, description, input_schema, when_to_use, when_not_to_use, examples },
    ...
  ]
  cli_alternative: { command, example }
  tier_required: "standard"
```

Example:

1. Agent: `openpass_search({"intent": "put a password on the clipboard"})`
2. Server: returns `copy_to_clipboard` spec inline + `cli_alternative: symvault get <path>.password --clip`

Full tools list available via `tools/list?include=all` or `include_all_tools: true` in the init handshake.

### 8.4 Skill decision matrix

Skill content includes:

```markdown
## Choose your interface

For read-heavy, deterministic operations: prefer the CLI via Bash.
  - List entries:        symvault list --output json
  - Search:              symvault find "github" --output json
  - Read metadata:       symvault get path/to/entry --metadata-only --output json
  - Read a value:        symvault get path/to/entry --field password
  - Generate password:   symvault generate --length 32 --output json
  - Generate TOTP code:  symvault totp path/to/entry
  - Health check:        symvault doctor --quick --output json
  - Vault unlocked?:     symvault auth status --output json
  - Audit your own log:  symvault agent audit self --since 24h --output json

For operations that need server-mediated UX, use MCP:
  - request_credential   — needs native OS dialog
  - secure_input         — needs hidden TTY/dialog input
  - copy_to_clipboard    — needs the running Symaira Vault process to schedule auto-clear
  - autotype             — needs cross-process OS hooks
  - write with approval  — needs synchronous user confirmation prompt
  - run_command          — needs masked subprocess pipes

Always set OPENPASS_AGENT={{.AgentName}} when invoking the CLI.
The CLI applies your profile (paths, redactions, quotas) just like MCP.
```

### 8.5 Shared state between CLI and MCP

- **Audit log:** Both paths append to `~/.openpass/audit/agent-<name>.log` (append-only, fsync). MCP server need not be running for CLI calls to be logged — profile read directly from `config.yaml`.
- **Quota counter:** `~/.openpass/state/quotas/<agent>.json` with atomic-write-and-rename. CLI and MCP serialize via filelock. Counter increments before tool execution, decrements on `ERR_QUOTA_EXCEEDED` failure.
- **Tier state:** Static in `config.yaml`. Both paths read fresh per call. Mid-session tier upgrades take effect on the next call.

### 8.6 Security threat model: CLI vs MCP

| Concern | MCP | CLI with `OPENPASS_AGENT` |
|---|---|---|
| Per-agent profile enforcement | ✓ | ✓ (new in v4.0) |
| Approval prompts | ✓ blocking | ✓ blocking (TTY or GUI fallback) |
| Per-agent audit | ✓ | ✓ (shared log, Section 8.5) |
| Redact fields | ✓ | ✓ |
| Quotas | ✓ in-memory | ✓ filebased shared (8.5) |
| Token / auth material | scoped tokens via header | **`OPENPASS_AGENT` is unauthenticated** — any local process can claim to be agent X |
| Replay / off-host | scoped token + OAuth | CLI requires shell access = local |

**On the unauthenticated env-var:** any local process claiming `OPENPASS_AGENT=hermes` is constrained to the hermes profile. The profile's permissions are *capability limits*, not secrets. A local attacker pretending to be hermes can do nothing hermes itself couldn't do; the audit log captures the impersonation context (PID, parent PID, TTY). For threat models where strong agent attribution is required (e.g., Hermes as an external service), MCP+OAuth remains the path. CLI agent-mode is a local convenience, not an authentication mechanism.

### 8.7 Code changes

- **`internal/agentctx/`** (new): Loads profile from `OPENPASS_AGENT`, returns `*AgentContext` with `EnforcePath`, `EnforceTool`, `RecordAudit`, `BumpQuota` methods
- **`cmd/root.go`**: `PersistentPreRun` checks `OPENPASS_AGENT` and loads context. Agent-relevant commands invoke `agentctx.Enforce*`
- **`internal/mcp/server_dispatch.go`**: Refactored to use the same `agentctx` package — eliminates duplication
- **`internal/mcp/leanmode.go`** (new): `tools/list` filter for default vs `include=all`
- **`internal/mcp/tools/openpass_search.go`** (new): Tool discovery with intent matching (simple keyword/embedding search over tool-description index — no LLM call)
- **`internal/audit/`**: Locking + atomic append for CLI+MCP shared writes
- **`internal/quotas/`** (new): Shared filelock-based quota counter

### 8.8 Tests (delta to Section 7)

- `TestCLI_AgentMode_RespectsTierSafe` — `OPENPASS_AGENT=safe-agent symvault get foo --field password` → exit 11, `ERR_TOOL_NOT_ALLOWED`
- `TestCLI_AgentMode_RespectsPathRestriction` — path-based variant
- `TestCLI_AgentMode_BumpsQuotaSharedWithMCP` — CLI call bumps counter, subsequent MCP call sees higher count
- `TestCLI_AgentMode_AuditEvent` — call writes event with `actor=cli:agent:X`, PID, parent PID
- `TestMCP_LeanMode_ToolsList` — default connect returns 7 tools, `include=all` returns full list
- `TestMCP_OpenpassSearch_FindsCopyToClipboard` — `openpass_search({"intent": "clipboard"})` matches `copy_to_clipboard`

---

## 9. Out of scope / explicitly deferred

The following ideas surfaced during brainstorming but are not part of v4.0. Each will be filed as a separate GitHub issue post-spec:

- **Symaira Vault SDK (Go/Python/TS) for in-process consumption** (Approach 2 from brainstorming). Cost of cross-language API maintenance and bypass of MCP audit path outweigh near-term benefits. Revisit if a major agent platform requests it.
- **Reference handles for opaque secrets** (Approach 3 from brainstorming): `request_handle` / `execute_with_handle` / `autotype_handle` flow where agents never see plaintext. Stronger security model but multi-month effort and migration burden. Filed as a follow-up RFC.
- **Capability negotiation as a parallel surface to MCP `tools/list`** (Approach 3 sub-idea).
- **Composite tools** (`find_and_copy`, `find_and_execute`) — defer until skill-level documentation proves insufficient.
- **Per-agent default tiers** (Section 5.9) — uniform `safe` default in v4.0; if practice shows certain agents always get upgraded, revisit.
- **Skill signing** (Section 3.7) — trust anchor is the signed Symaira Vault binary in v4.0.
- **Code Execution with MCP** (Anthropic 2025-11 pattern) — agents writing code that calls MCP tools. Worth a separate spec once `openpass_search` lands and we see real usage patterns.

---

## 10. Acceptance criteria

v4.0.0 is releasable when:

- [ ] All commands in Section 1.2 are implemented and tested
- [ ] All commands in Section 1.3 are deprecated stubs that print replacements + exit 2
- [ ] Per-agent install (Section 2) succeeds end-to-end for hermes, claude-code, codex, opencode, openclaw on macOS + Linux + Windows (paths verified)
- [ ] Skill packages render byte-deterministically and install with sentinel; uninstall preserves user-edited files (Section 3)
- [ ] `openpass_whoami`, `openpass_audit_self`, `openpass_search` are functional MCP tools (Sections 4, 8)
- [ ] All MCP error responses use codes from `internal/mcp/errors/codes.go` (Section 4.2)
- [ ] Three tier presets are snapshot-tested (Section 5.1)
- [ ] `symvault agent upgrade --tier` shows the spec'd diff and writes audit events (Section 5.3)
- [ ] `symvault migrate v4` is idempotent and lossless on the v3-snapshot fixtures (Section 6.5)
- [ ] `OPENPASS_AGENT` env-var enforces profile on all CLI commands listed in Section 8.2
- [ ] Lean-mode `tools/list` returns exactly the 7 tools in Section 8.3 by default
- [ ] CLI and MCP share audit log + quota counter (Section 8.5)
- [ ] Security regression test suite (Section 7.8) passes
- [ ] Manual release checklist (Section 7.12) is ticked
- [ ] `docs/migration-v3-to-v4.md` is published

---

## 11. References

The dual-surface direction (Section 8) is informed by these 2026 sources:

- [MCP vs CLI: Benchmarking AI Agent Cost & Reliability](https://www.scalekit.com/blog/mcp-vs-cli-use) — quantifies the 4–32× token cost gap
- [Your MCP Server Is Eating Your Context Window](https://www.apideck.com/blog/mcp-server-eating-context-window-cli-alternative) — the 143K-of-200K-tokens benchmark
- [Anthropic — Code execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp) — the "tools as code APIs" pattern, 98.7% token reduction
- [Anthropic downplays MCPs — Daniel Miessler](https://danielmiessler.com/blog/anthropic-downplays-mcps) — Anthropic's filesystem-based Skills shift
- [MCP vs. CLI for AI agents — A Practical Decision Framework for 2026](https://manveerc.substack.com/p/mcp-vs-cli-ai-agents)
- [Why CLIs Beat MCP for AI Agents — Rentier Digital](https://medium.com/@rentierdigital/why-clis-beat-mcp-for-ai-agents-and-how-to-build-your-own-cli-army-6c27b0aec969)
- [Is MCP Dead? MCP vs CLI vs Agent Skills Compared — Milvus](https://milvus.io/blog/is-mcp-dead-cli-and-skills-for-ai-agents.md)
- [MCP in 2026: Rise, Fall, and What Every AI User Must Know](https://andrewbaker.ninja/2026/03/22/mcp-in-2026-rise-security-flaws-what-comes-next/)
- [Optimizing Context with MCP Tool Search — Plaban Nayak](https://nayakpplaban.medium.com/optimizing-context-with-mcp-tool-search-solving-the-context-pollution-crisis-with-dynamic-loading-224a9df57245)
- [The Skills vs MCP Debate — Maxim AI](https://www.getmaxim.ai/blog/the-skills-vs-mcp-debate-understanding-two-layers-of-the-same-stack/)
