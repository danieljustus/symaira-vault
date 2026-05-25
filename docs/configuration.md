# Configuration Reference

Global config is stored at `~/.openpass/config.yaml`. Vault-specific config is stored in the vault directory.
Use [`config.yaml.example`](../config.yaml.example) as a commented starting point.

## Environment Variables

- `OPENPASS_VAULT` — Path to vault directory (default: `~/.openpass`)

Or use the `--vault` flag to override for any command:
```bash
symvault --vault ~/work-vault get aws.secret
```

## config.yaml

```yaml
# ~/.openpass/config.yaml — Global configuration

# Default vault directory
vaultDir: ~/.openpass

# Default agent for MCP (can be overridden via --agent flag)
defaultAgent: default

# Session timeout for OS keyring cache (default: 15m)
sessionTimeout: 15m

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
| `vaultDir` | `~/.openpass` | Default vault directory |
| `defaultAgent` | `default` | Default MCP agent profile |
| `sessionTimeout` | `15m` | OS keyring cache TTL |
| `authMethod` | `passphrase` | Unlock method: `passphrase` or macOS `touchid` |

## Agent Profile Options

| Option | Description |
|--------|-------------|
| `allowedPaths` | Path patterns the agent can access (prefix patterns, `*` for all) |
| `canWrite` | Whether the agent can create/update/delete entries |
| `canManageConfig` | Whether the agent can change Symaira Vault auth/config settings via MCP |
| `approvalMode` | `none` (allow all), `deny` (reject writes), `prompt` (degrades to deny in MCP) |

## Vault Config Options

| Option | Description |
|--------|-------------|
| `path` | Vault directory path |
| `default_recipients` | Default age recipients for new entries |
| `confirm_remove` | Ask for confirmation before removing recipients |
| `authMethod` | Optional per-vault override: `passphrase` or `touchid` |

## Authentication

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

## Logging Config Options

Logging is configured via environment variables. A `logging` block in `config.yaml` is reserved for future file-based configuration.

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `OPENPASS_LOG_LEVEL` | `warn` | Log level: `debug`, `info`, `warn`, `error` |
| `OPENPASS_LOG_FORMAT` | `text` | Output format: `text` or `json` |

All log output is written to `os.Stderr` to keep `stdout` clean for stdio MCP transport.

**Example:**
```bash
OPENPASS_LOG_LEVEL=debug OPENPASS_LOG_FORMAT=json symvault serve --stdio
```

## Profiles

Profiles allow switching between multiple vaults without manually specifying paths each time.

### Configuration

Add profiles to your `config.yaml`:

```yaml
profiles:
  work:
    vault: ~/.openpass-work
  family:
    vault: ~/vaults/family
defaultProfile: work
```

### Resolution Order

Vault selection follows this priority, from highest to lowest:

1. `--vault` flag
2. `OPENPASS_VAULT` environment variable
3. `--profile` flag
4. `OPENPASS_PROFILE` environment variable
5. `defaultProfile` from config
6. Default `~/.openpass`

### Commands

```bash
# List profiles
symvault profile list

# Add a profile
symvault profile add work --vault ~/.openpass-work

# Set default profile
symvault profile use work
```

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
| `defaultAgent` | Must reference an agent that exists in `agents` |
| `agents.*.approvalMode` | Must be one of: `none`, `deny`, `prompt`, `auto` |
| `agents.*.allowedPaths` | Each path must be a valid glob pattern |
| `audit.maxFileSize` | Must be greater than 0, if the audit section is present |
| `clipboard.autoClearDuration` | Must be non-negative, if the clipboard section is present |

### JSON Schema

A JSON Schema for editor autocompletion is available at `docs/openpass-config.schema.json`.

For VS Code with the Red Hat YAML extension, add this to `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "docs/openpass-config.schema.json": "config.yaml"
  }
}
```
