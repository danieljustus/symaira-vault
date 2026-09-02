# Configuration Reference

Global config is stored at `~/.symvault/config.yaml`. Vault-specific config is stored in the vault directory.
Use [`config.yaml.example`](../config.yaml.example) as a commented starting point.

## Environment Variables

- `SYMVAULT_VAULT` — Path to vault directory (default: `~/.symvault`)

Or use the `--vault` flag to override for any command:
```bash
symvault --vault ~/work-vault get aws.secret
```

## config.yaml

```yaml
# ~/.symvault/config.yaml — Global configuration

# Default vault directory
vaultDir: ~/.symvault

# Default agent for MCP (can be overridden via --agent flag)
defaultAgent: default

# Session timeout for OS keyring cache (default: 15m)
sessionTimeout: 15m

# Absolute maximum lifetime for a cached session (default: 8h)
sessionMaxLifetime: 8h

# Unlock method: passphrase or touchid
authMethod: passphrase

# Agent profiles for MCP server
agents:
  default:
    allowedPaths: ["*"]
    canWrite: false
    canManageConfig: false
    approvalMode: none
  claude-code:
    allowedPaths: ["*"]
    canWrite: true
    approvalMode: none

# Vault-specific configuration (optional, can also be in vault/config.yaml)
vault:
  path: ~/my-vault
  default_recipients:
    - age1...

# Git configuration
git:
  auto_push: true
  commit_template: "Update from Symaira Vault"

# MCP server configuration
mcp:
  port: 8080
  bind: 127.0.0.1
  stdio: false
  httpTokenFile: auto
```

## Config Options

| Option | Default | Description |
|--------|---------|-------------|
| `vaultDir` | `~/.symvault` | Default vault directory |
| `defaultAgent` | `default` | Default MCP agent profile |
| `sessionTimeout` | `15m` | OS keyring cache TTL |
| `sessionMaxLifetime` | `8h` | Absolute maximum lifetime of an OS keyring session |
| `authMethod` | `passphrase` | Unlock method: `passphrase` or macOS `touchid` |

## Agent Profile Options

| Option | Description |
|--------|-------------|
| `allowedPaths` | Path patterns the agent can access (prefix patterns, `*` for all) |
| `canWrite` | Whether the agent can create/update/delete entries |
| `canManageConfig` | Whether the agent can change Symaira Vault auth/config settings via MCP |
| `approvalMode` | `none` (allow all), `deny` (reject writes), `prompt` (degrades to deny with no approval device enrolled; blocks on a paired phone's decision once one is — see [Approval devices](approval-devices.md)) |

## Vault Config Options

| Option | Description |
|--------|-------------|
| `path` | Vault directory path |
| `default_recipients` | Default age recipients for new entries |
| `confirm_remove` | Ask for confirmation before removing recipients |
| `authMethod` | Optional per-vault override: `passphrase` or `touchid` |
| `argon2id_time` | Argon2id time cost parameter (default: 3, floor: 2, ceiling: 16) |
| `argon2id_memory` | Argon2id memory cost parameter in KiB (default: 65536, floor: 19456, ceiling: 2097152) |
| `argon2id_threads` | Argon2id parallelism parameter (default: 4, floor: 1, ceiling: 16) |

## Sync Config Options (filesystem sync / iCloud Drive)

Symaira Vault supports replicating a vault across devices through a filesystem
sync engine (currently iCloud Drive) instead of the built-in git backend. The
Go CLI writes a plain vault directory, so an iCloud container path simply works
as the vault directory — no Apple framework integration is required. This is
what makes the vault usable from the CLI and the clients without operating any
service (ADR 0006, D3/F4).

Enable it with a `sync` block in the vault-specific config:

```yaml
# <vault>/config.yaml
sync:
  method: icloud-drive   # or "git" (default)
```

| Option | Default | Description |
|--------|---------|-------------|
| `sync.method` | `git` | Replication backend: `git` (default, in-tree `.git`) or `icloud-drive` (filesystem sync engine) |

Behavior when `method: icloud-drive`:

- **`.git` stays out of the synced folder.** The git repository is relocated to
  a local-only directory (derived from `XDG_DATA_HOME`), so the sync engine never
  replicates git internals. This reuses the separate-git-directory support from
  #863; the CLI remains the source of truth.
- **Manifest verification on load.** `VerifyManifestIntegrity` and
  `DetectOutOfBandEntries` run when the vault is opened. Out-of-band entries
  (`.age` files present on disk but not in the manifest) are surfaced via
  `Vault.SyncReport` rather than silently rebuilt, so the user can inspect
  changes made directly in the synced folder.
- **Deterministic conflict resolution.** When two devices edit the same entry,
  the higher `EntryMetadata.Version` wins (last-writer-wins). The losing copy
  is preserved as a conflict copy (`<name>.conflict-<timestamp>.age`) so no
  data is ever lost.
- **Keep `.git` out of the synced folder** is the only requirement; the macOS
  and iOS clients consume the same vault directory. Non-Apple platforms continue
  to use the git path.

CloudKit is intentionally not used.

Use `symvault auth status` to inspect the current unlock method and session
cache backend. Use `symvault auth set touchid` on macOS to enable Touch ID
unlock, or `symvault auth set passphrase` to return to passphrase-only unlock.

Touch ID is a convenience layer over the vault passphrase: the passphrase
remains the cryptographic secret and is stored in a biometric-protected macOS
Keychain item when Touch ID is enabled.

## Git Config Options

| Option | Default | Description |
|--------|---------|-------------|
| `auto_push` | `true` | Automatically push after commit |
| `commit_template` | `"Update from Symaira Vault"` | Commit message template |

## MCP Config Options

| Option | Default | Description |
|--------|---------|-------------|
| `port` | `8080` | HTTP server port |
| `bind` | `127.0.0.1` | Bind address |
| `stdio` | `false` | Enable stdio transport |
| `httpTokenFile` | `auto` | Bearer token file path |

## Clipboard Config Options

| Option | Default | Description |
|--------|---------|-------------|
| `auto_clear_duration` | `30` | Seconds before copied secrets are cleared; `0` disables auto-clear |
| `copyByDefault` | `true` | Copy field values to the clipboard by default on a TTY; set `false` to print to stdout |

## Logging Config Options

Logging is configured via environment variables. A `logging` block in `config.yaml` is reserved for future file-based configuration.

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SYMVAULT_LOG_LEVEL` | `warn` | Log level: `debug`, `info`, `warn`, `error` |
| `SYMVAULT_LOG_FORMAT` | `text` | Output format: `text` or `json` |

All log output is written to `os.Stderr` to keep `stdout` clean for stdio MCP transport.

**Example:**
```bash
SYMVAULT_LOG_LEVEL=debug SYMVAULT_LOG_FORMAT=json symvault mcp --stdio
```

## Profiles

Profiles allow switching between multiple vaults without manually specifying paths each time.

### Configuration

Add profiles to your `config.yaml`:

```yaml
profiles:
  work:
    vault: ~/.symvault-work
  family:
    vault: ~/vaults/family
defaultProfile: work
```

### Resolution Order

Vault selection follows this priority, from highest to lowest:

1. `--vault` flag
2. `SYMVAULT_VAULT` environment variable
3. `--profile` flag
4. `SYMVAULT_PROFILE` environment variable
5. `defaultProfile` from config
6. Default `~/.symvault`

### Commands

```bash
# List profiles
symvault profile list

# Add a profile
symvault profile add work --vault ~/.symvault-work

# Set default profile
symvault profile use work
```

## Entry Format & Conventions

Vault entry data is stored as a flexible map of key-value pairs (`map[string]any`). While keys are free-form, several well-known keys follow standard conventions across CLI commands, MCP integrations, and client extensions.

### Well-Known Field: `url`

The `url` key associates credentials with web services, domains, or internal network endpoints. It is used by `symvault find --url <value>` and platform integrations (such as iOS AutoFill, ADR 0006 D4) to match stored credentials to requested services.

- **Validation**: URLs must be non-empty, contain no illegal whitespace or control characters, and resolve to a valid hostname or IP address.
- **Scheme Defaulting**: If a scheme is omitted (e.g. `github.com` or `gitlab.company.internal/login`), `https://` is assumed by default.
- **Host Lowercasing**: Hostnames are case-insensitive and normalized to lowercase (e.g. `GITHUB.COM` is stored and indexed as `github.com`).
- **Port Handling**: Default protocol ports (`80` for `http`/`ws`, `443` for `https`/`wss`, `22` for `ssh`/`sftp`, `21` for `ftp`) are stripped during normalization (e.g. `https://github.com:443` normalizes to `github.com`). Non-standard ports (e.g. `http://localhost:3000`, `https://example.com:8443`) are preserved in host matching.
- **Same-Host Matching**: Service lookups match against the normalized host representation, allowing scheme-insensitive and port-normalized queries to find corresponding entries.
- **Encrypted Index**: Host mappings are indexed within the vault's encrypted search index (`.search-index`), preventing unencrypted plaintext leakage of service names on disk.

## Validation

Symaira Vault validates your configuration file on load. You can also manually validate it:

```bash
symvault config validate
```

Use structured JSON output for scripts or CI checks:

```bash
symvault config validate --json
```

### Validation Rules

The following rules are checked:

| Rule | Description |
|------|-------------|
| `vaultDir` | Must not be empty |
| `sessionTimeout` | Must be greater than 0 |
| `sessionMaxLifetime` | Must be greater than 0 |
| `defaultAgent` | Must reference an agent that exists in `agents` |
| `agents.*.approvalMode` | Must be one of: `none`, `deny`, `prompt`, `auto` |
| `agents.*.allowedPaths` | Each path must be a valid glob pattern |
| `audit.maxFileSize` | Must be greater than 0, if the audit section is present |
| `clipboard.autoClearDuration` | Must be non-negative, if the clipboard section is present |

### JSON Schema

A JSON Schema for editor autocompletion is available at `docs/symvault-config.schema.json`.

For VS Code with the Red Hat YAML extension, add this to `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "docs/symvault-config.schema.json": "config.yaml"
  }
}
```
