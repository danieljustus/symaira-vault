# Symaira Vault Architecture

This document describes the system architecture of Symaira Vault, a modern command-line password manager written in Go.

## Overview

Symaira Vault is a CLI password manager that uses [age](https://age-encryption.org/) encryption for securing vault entries. It provides a traditional command-line interface for human users and an MCP (Model Context Protocol) server for AI agent integration.

```mermaid
graph TB
    subgraph CLI["CLI Layer (cmd/)"]
        get["get"]
        set["set"]
        list["list"]
        find["find"]
        generate["generate"]
        edit["edit"]
        delete["delete"]
        init["init"]
        lock["lock"]
        unlock["unlock"]
        serve["serve"]
        git["git"]
        mcp_config["mcp_config"]
    end

    subgraph Internal["Internal Packages"]
        vault["vault/"]
        crypto["crypto/"]
        session["session/"]
        config["config/"]
        git["git/"]
        mcp["mcp/"]
        audit["audit/"]
    end

    subgraph External["External Services"]
        keyring["OS Keyring"]
        git_remote["Git Remote"]
        mcp_host["MCP Host"]
    end

    CLI --> vault
    CLI --> crypto
    CLI --> session
    CLI --> config
    vault --> crypto
    vault --> git
    vault --> config
    mcp --> vault
    mcp --> audit
    session --> keyring
    serve --> mcp
    serve --> mcp_host
```

## Package Structure

```
main.go → cmd/ → internal/
```

### `cmd/` — CLI Commands

The `cmd/` package implements the Cobra CLI interface. Each file represents a command:

| Command | File | Description |
|---------|------|-------------|
| `get` | `get.go` | Retrieve password entries |
| `set` | `set.go` | Create/update entries |
| `list` | `list.go` | List vault entries |
| `find` | `find.go` | Search entries |
| `generate` | `generate.go` | Generate secure passwords |
| `delete` | `delete.go` | Delete entries |
| `edit` | `edit.go` | Edit entries in $EDITOR |
| `init` | `init.go` | Initialize new vault |
| `lock` | `lock.go` | Clear cached passphrase |
| `unlock` | `unlock.go` | Unlock vault |
| `serve` | `serve.go` | Start MCP server |
| `git` | `git.go` | Git operations |
| `recipients` | `recipients.go` | Manage recipient keys |
| `mcp_config` | `mcp_config.go` | Generate MCP config |
| `add` | `add.go` | Add new entries |
| `root.go` | `root.go` | Shared `unlockVault` helper |

### `internal/vault/` — Core Vault

The vault package is the central abstraction for encrypted storage.

```mermaid
classDiagram
    class Vault {
        +Dir string
        +Identity *age.X25519Identity
        +Config *config.Config
        +Init()
        +Open()
        +OpenWithPassphrase()
        +InitWithPassphrase()
        +EntryPath()
        +GetRecipient()
        +AutoCommit()
    }
    class Entry {
        +Path string
        +Values map[string]string
        +Save()
        +Load()
    }

    Vault --> Entry : manages
```

**Key functions:**
- `Init(vaultDir, identity, config)` — Create new vault
- `Open(vaultDir, identity)` — Open existing vault
- `OpenWithPassphrase(vaultDir, passphrase)` — Open with passphrase
- `InitWithPassphrase(vaultDir, passphrase, config)` — Create with passphrase
- `EntryPath(vault, path)` — Get entry file path

**Entry storage:** Each entry is stored as an individually encrypted `.age` file under `<vault>/entries/<path>.age`. Older root-level entries are migrated into `entries/` when the vault opens and remain readable/listable for compatibility.

### `internal/crypto/` — Encryption Layer

Wraps [filippo.io/age](https://pkg.go.dev/filippo.io/age) for X25519+ChaCha20-Poly1305 encryption.

**Key functions:**
- `Encrypt(plaintext, recipient)` — Encrypt for single recipient
- `EncryptWithRecipients(plaintext, ...recipients)` — Multi-recipient encryption
- `Decrypt(ciphertext, identity)` — Decrypt with identity
- `EncryptWithPassphrase(plaintext, passphrase)` — Passphrase encryption (scrypt)
- `DecryptWithPassphrase(ciphertext, passphrase)` — Passphrase decryption
- `GenerateIdentity()` — Generate new X25519 identity
- `LoadIdentity(path, passphrase)` — Load passphrase-protected identity
- `SaveIdentity(identity, path, passphrase)` — Save identity with passphrase

### `internal/session/` — Session Management

OS keyring integration for passphrase caching.

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Session
    participant Keyring

    User->>CLI: symvault unlock
    CLI->>Session: LoadPassphrase(vaultDir)
    Session->>Keyring: Get(vaultDir)
    alt passphrase cached
        Keyring-->>Session: passphrase
        Session-->>CLI: passphrase
    else passphrase not cached
        CLI->>User: Enter passphrase
        User->>CLI: passphrase
        CLI->>Session: SavePassphrase(vaultDir, passphrase, TTL)
        Session->>Keyring: Set(vaultDir, passphrase, TTL)
    end
```

**Default TTL:** 15 minutes

### `internal/config/` — Configuration

YAML-based configuration at `~/.config/symaira-vault/config.yaml` (XDG default). Installs created before the XDG layout continue to read from the legacy `~/.symvault/config.yaml`.

**Config structure:**
```yaml
vaultDir: ~/.local/share/symaira-vault   # XDG default; legacy installs: ~/.symvault
defaultAgent: claude-code
agents:
  claude-code:
    allowedPaths: ["*"]
    canWrite: true
    approvalMode: none
  readonly-agent:
    allowedPaths: ["work/*", "personal/*"]
    canWrite: false
    approvalMode: deny
git:
  autoCommit: true
  autoPush: false
  commitTemplate: ""
```

### `internal/git/` — Git Integration

Thin wrapper around `go-git` for automatic version control.

- `AutoCommitAndPush(dir, message, autoPush)` — Commit changes and optionally push
- Called automatically on vault modifications via `vault.AutoCommit()`

### `internal/mcp/` — MCP Server

Model Context Protocol server for AI agent access.

**Transports:**
- **stdio** (`--stdio --agent <name>`) — Fixed agent at startup
- **HTTP** (`--port 8080`) — Bearer token auth + per-request agent resolution

```mermaid
graph LR
    subgraph Stdio["Stdio Transport"]
        mcp_host_stdio["MCP Host"]
        stdio_transport["transport.go"]
    end

    subgraph HTTP["HTTP Transport"]
        mcp_host_http["MCP Host"]
        http_transport["protocol.go"]
    end

    subgraph Server["MCP Server"]
        server["server.go"]
        tools["tools.go"]
        approval["approval.go"]
        audit["audit.go"]
        auth["auth.go"]
        token["token.go"]
    end

    stdio_transport --> server
    http_transport --> server
    server --> tools
    server --> approval
    server --> auth
    tools --> vault["vault/"]
    approval --> config["config/"]
    auth --> vault
    audit --> audit["audit/"]
```

**Agent permissions:**
- `AllowedPaths` — Path glob patterns for entry access
- `CanWrite` — Whether write operations are allowed
- `ApprovalMode` — `none`, `deny`, or `prompt` (degrades to deny in MCP)

**Available tools (34 registered, excluding the deprecated `symaira_delete` alias):**

Vault operations:
- `list_entries` — List vault entries matching a prefix
- `get_entry` — Get entry metadata (fields, type) without secrets
- `get_entry_value` — Get actual secret values
- `get_entry_metadata` — Get metadata without sensitive data
- `set_entry_field` — Set a field on an entry
- `delete_entry` — Delete an entry by path
- `find_entries` — Search entries by query
- `generate_password` — Generate a secure password
- `generate_totp` — Generate a TOTP code

Secret execution:
- `run_command` — Execute a command with secrets injected as env vars
- `execute_with_secret` — Execute command with op:// secret references
- `execute_api_request` — Execute HTTP API request with template-injected credentials
- `secret_unseal` — Unseal a secret handle to reveal its value

Agent & session:
- `symaira_whoami` — Return agent profile, tool availability, quotas
- `symaira_search` — Discover tools by intent matching
- `symaira_audit_self` — Return recent audit events for this agent
- `get_auth_status` — Return vault unlock authentication status
- `set_auth_method` — Set unlock authentication method
- `health` — Return MCP server health information

Sharing:
- `request_share` — Request to share a secret with another agent
- `approve_share` — Approve a pending share request
- `revoke_share` — Revoke an active share grant
- `list_shares` — List share grants with filters

Input/Output:
- `request_credential` — Prompt user to securely enter a credential (native dialog)
- `secure_input` — Prompt user for sensitive data via TTY/GUI dialog
- `copy_to_clipboard` — Copy entry field to clipboard without exposing value
- `autotype` — Type entry field as keyboard input into focused application
- `sanitize_output` — Scan text for secrets and mask them

Web & AI:
- `perplexity_search` — Search the web via Perplexity AI
- `perplexity_ask` — Ask Perplexity AI a question with vault context
- `search` — Search vault entries (OpenAI-compatible)
- `fetch` — Fetch vault entry by path (OpenAI-compatible)

Templates:
- `generate_template` — Generate config file from template (env, docker-compose, k8s, etc.)

### `internal/audit/` — Audit Logger

Logs all MCP tool calls with:
- Agent name
- Action (read/write)
- Path accessed
- Transport used
- Timestamp
- Success/failure

### `internal/testutil/` — Test Helpers

Shared utilities for testing.

### `internal/clipboard/` — Clipboard Application Logic

Application-level clipboard utilities: auto-clear timer, countdown display, and cross-platform clipboard integration. Imported by CLI commands (e.g., `cmd/get.go`) as `clipboardapp`.

### Additional `internal/` Packages

| Package | Purpose |
|---------|---------|
| `internal/agentctx` | Agent context propagation through MCP call chain |
| `internal/agentskill` | Agent skill management and version compatibility |
| `internal/anomaly` | Anomaly detection for vault operations |
| `internal/authguard` | Authorization guard layer for MCP tool access |
| `internal/autotype` | Cross-platform keyboard autotype backend |
| `internal/cli` | CLI helper utilities (vault path, output, with-vault) |
| `internal/daemon` | Background service management |
| `internal/dynamicsecret` | Dynamic secret generation with time-limited leases |
| `internal/envutil` | Environment variable utilities |
| `internal/errors` | Structured error types and CLI error formatting |
| `internal/exporter` | Vault entry export (CSV, JSON) |
| `internal/fsutil` | Filesystem utilities (safe read/write, traversal checks) |
| `internal/health` | Vault health check logic |
| `internal/i18n` | Internationalization and localization |
| `internal/importer` | Import from other password managers |
| `internal/logging` | Structured logging infrastructure |
| `internal/metrics` | Operational metrics collection |
| `internal/notify` | Desktop notification support |
| `internal/pairing` | Device pairing protocol |
| `internal/policy` | Declarative vault policy engine |
| `internal/quotas` | MCP tool usage quotas and rate limiting |
| `internal/secrets` | Secret handle resolution and sealed-ref management |
| `internal/secureedit` | Secure in-place entry editing |
| `internal/secureui` | Native OS dialog integration for secure input |
| `internal/template` | Configuration template generation |
| `internal/ui` | Terminal UI (TUI) rendering |
| `internal/update` | Self-update mechanism |


## Data Flow

### Vault Entry Read

```mermaid
sequenceDiagram
    participant CLI
    participant Vault
    participant Crypto
    participant FS

    CLI->>Vault: GetEntry(path)
    Vault->>FS: ReadFile(entries/path.age)
    FS-->>Vault: ciphertext
    Vault->>Crypto: Decrypt(ciphertext, identity)
    Crypto-->>Vault: plaintext (YAML)
    Vault-->>CLI: Entry
```

### Vault Entry Write

```mermaid
sequenceDiagram
    participant CLI
    participant Vault
    participant Crypto
    participant Git
    participant FS

    CLI->>Vault: SetEntry(path, data)
    Vault->>Crypto: Encrypt(YAML, recipient)
    Crypto-->>Vault: ciphertext
    Vault->>FS: WriteFile(entries/path.age, ciphertext)
    Vault->>Git: AutoCommit(message)
    Git->>FS: git add && git commit
```

### MCP Tool Call (stdio)

```mermaid
sequenceDiagram
    participant MCP_Host
    participant StdioTransport
    participant Protocol
    participant Server
    participant Tools
    participant Vault
    participant Audit

    MCP_Host->>StdioTransport: JSON-RPC request
    StdioTransport->>Protocol: Parse message
    Protocol->>Server: Handle request
    Server->>Tools: Execute tool
    Tools->>Vault: Vault operations
    Vault-->>Tools: Result
    Tools-->>Server: Tool result
    Server->>Audit: Log entry
    Audit-->>Server: OK
    Server-->>Protocol: JSON-RPC response
    Protocol-->>StdioTransport: Response
    StdioTransport-->>MCP_Host: Response
```

## Security Architecture

### Encryption

- **Algorithm:** age (X25519 key exchange + ChaCha20-Poly1305)
- **Identity protection:** `identity.age` encrypted with passphrase via scrypt
- **Entry encryption:** Each entry encrypted with vault's X25519 recipient
- **Multi-recipient:** Entries can be encrypted for additional recipients (shared access)

### Session Security

```mermaid
graph TD
    subgraph Sources["Passphrase Sources"]
        interactive["Interactive prompt"]
        env["SYMVAULT_PASSPHRASE"]
        keyring["OS Keyring"]
    end

    subgraph Verification["Identity Verification"]
        load["Load identity.age"]
        decrypt["Decrypt with passphrase"]
        compare["Compare with provided"]
    end

    interactive --> load
    env --> load
    keyring --> load
    load --> decrypt
    decrypt --> compare
    compare -->|"match"| OK["Vault unlocked"]
    compare -->|"mismatch"| Fail["Error"]
```

### MCP Security

- **Stdio:** Agent fixed at startup; process isolation provides security
- **HTTP:** Bearer token required; agent identified per-request via `X-Symaira-Agent` header
- **Path restrictions:** Agents can only access allowed path patterns
- **Write restrictions:** `CanWrite: false` blocks all write operations
- **Approval modes:** `deny` blocks writes; `prompt` degrades to deny (no stdin)

## Vault Structure

```
~/.local/share/symaira-vault/   # XDG data dir (legacy installs: ~/.symvault/)
├── identity.age      # Encrypted age identity
├── config.yaml       # Vault configuration
├── mcp-token         # Bearer token for HTTP MCP (auto-generated)
├── entries/          # Encrypted password entries
│   ├── github.age
│   └── work/
│       └── aws.age
└── .git/             # Git repository
```

Vaults created with the older root-level entry layout are migrated to `entries/` on open. Root-level encrypted entries remain readable and listable for compatibility.

## Key Design Decisions

1. **Individual entry encryption:** Each `.age` file is self-contained and decryptable independently
2. **Identity self-encryption:** `identity.age` is encrypted with the identity's own public key, protected by passphrase at the scrypt layer
3. **Passphrase never stored:** Only cached in OS keyring with TTL
4. **Build-tagged clipboard:** `internal/clipboard/` uses `//go:build` tags to switch between real clipboard (`!test_headless`) and no-op stub (`test_headless`)
5. **HTTP MCP token:** Auto-generated, stored at `<vault>/mcp-token`

## Tool Addition Review

Symaira Vault caps the MCP tool registry at `MaxToolDefinitions` (34, defined in `internal/mcp/server/tool_registry.go`). Each tool is a potential prompt injection vector — an attacker-controlled agent can exploit any exposed tool. The cap forces deliberate tradeoffs: every new tool must displace another or justify raising the limit.

**Adding a new tool** requires:

1. A written rationale (commit message or design doc) covering:
   - What user/agent need the tool addresses
   - Why existing tools cannot satisfy the need
   - The tool's risk level (Low/Medium/High/Critical per `RiskLevel`)
   - Which agent tiers may access the tool

2. If the cap is reached, choose ONE of:
   - Deprecate an existing tool (add `Deprecated: true` and an `AliasFor` migration path)
   - Raise `MaxToolDefinitions` with explicit justification (e.g., deprecated tools count as half-weight)
   - Split into core/admin MCP servers with separate token scopes

3. Update `docs/threat-model.md` under "Tool Descriptions & Injection" to reflect the new tool's risk profile.

The cap is enforced at init-time: exceeding `MaxToolDefinitions` panics before any MCP handler runs, preventing deployment of an unbounded tool surface.

## Dependencies

| Package | Purpose |
|---------|---------|
| filippo.io/age | Encryption (X25519 + ChaCha20-Poly1305) |
| spf13/cobra | CLI framework |
| zalando/go-keyring | OS keyring integration |
| go-git/go-git | Git integration |
| (internal/mcp) | MCP protocol — Symaira Vault implements its own MCP layer; no external mcp-go library is used |
| atotto/clipboard | Clipboard support |
