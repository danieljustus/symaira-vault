# Symaira Vault Agent Integration

Symaira Vault is easiest for AI agents to use through MCP. Prefer MCP over shell
commands for credential reads and writes: it gives agents structured tools,
per-agent access control, bearer auth for HTTP, and audit logs.

## Recommended Setup

Use a dedicated agent profile instead of sharing a human CLI profile. Start with
metadata/read-only access, narrow `allowedPaths`, and an explicit tool allowlist;
do not give broad/default profiles wildcard paths, write access, or command
execution by default.

For a conservative Hermes or local-agent rollout, see the adoption packet in
[`docs/hermes-safe-adoption.md`](hermes-safe-adoption.md). It covers a
metadata-first profile, separate runner profiles, stdio-vs-HTTP defaults, and the
human approval gates required before live config changes or secret migration.

Example first profile:

```yaml
agents:
  hermes-metadata:
    allowedPaths:
      - agents/providers/
      - projects/local-dev/
    canWrite: false
    canRunCommands: false
    canManageConfig: false
    canUseClipboard: false
    canUseAutotype: false
    approvalMode: deny
    allowed_tools:
      - health
      - get_auth_status
      - list_entries
      - find_entries
      - get_entry_metadata
```

Use narrower `allowedPaths` for agents that should only access one area of the
vault, for example `["paperless-ngx/", "homeassistant/"]`. Add `get_entry`, write
tools, clipboard/autotype, or command execution only in separate profiles with an
explicit reason and review trail.

## Hermes

Hermes has a native MCP client. For a local first trial, prefer stdio over HTTP
so Symaira Vault does not expose a listening socket and Hermes does not need a bearer
token in config:

```bash
symvault --vault ~/.symvault agent install hermes --config-only
```

Add the output under `mcp_servers` in `~/.hermes/config.yaml` only after the
human adoption gate approves a live Hermes config change, then restart Hermes or
reload MCP tools from Hermes. Verify the connection:

```bash
hermes mcp test symvault
```

When connected, Hermes registers the tools with the `mcp_symvault_` prefix, for
example `mcp_symvault_list_entries`, `mcp_symvault_get_entry`, and
`mcp_symvault_set_entry_field`. Early Hermes profiles should expose only the
metadata-first tool subset from `hermes-safe-adoption.md`.

If HTTP transport is needed later, Symaira Vault binds to loopback (`127.0.0.1`) by
default with a self-signed TLS certificate auto-generated on first serve. Use a
custom certificate by setting `MCP.tls_cert_file` and `MCP.tls_key_file` in
`config.yaml`. For cases where TLS is not feasible (e.g., containerized proxy
terminates TLS externally), set `MCP.allow_insecure_bind: true` — this requires
explicit confirmation at startup and logs a warning about cleartext tokens and
loopback sniffing risk. Keep token values out of committed config and chat
transcripts in all configurations.

### Available MCP Tools

Symaira Vault exposes the following MCP tools for agent integration:

**Read Operations**:
- `list_entries` — List all vault entries
- `get_entry` — Retrieve entry contents (respects `redactFields`)
- `get_entry_metadata` — Get entry metadata without sensitive data
- `find_entries` — Search entries by query string
- `generate_password` — Generate secure passwords
- `generate_totp` — Generate TOTP codes (returns code, not secret)

**Write Operations**:
- `set_entry_field` — Store or update a field in an entry
- `delete_entry` — Delete an entry
- `secure_input` — Prompt user for sensitive data via TTY or native GUI dialog
- `request_credential` — Agent-initiated: pop a native dialog when an expected vault entry is missing, store the user's input, never see the value

**Automation** (v2.2.0+):
- `run_command` — Execute commands with vault secrets injected as environment variables
- `copy_to_clipboard` — Copy entry password to system clipboard (auto-clears after 30s)
- `autotype` — Type entry field as keyboard input into focused application

**Management**:
- `health` — Check server health status
- `get_auth_status` — Check unlock authentication status
- `set_auth_method` — Change unlock method (passphrase / touchid)

## OpenClaw and Other Local Agents

For agents that support stdio MCP, use:

```bash
symvault agent install openclaw --config-only
```

For agents that support HTTP MCP with custom headers, use:

```bash
symvault --vault ~/.symvault agent install openclaw --http --config-only
```

HTTP mode requires a running Symaira Vault server:

```bash
symvault --vault ~/.symvault serve --port 8090
```

By default, the HTTP server starts with a self-signed TLS certificate auto-generated
on first run. The certificate is stored in the vault directory as `mcp-cert.pem` and
`mcp-key.pem`. For a custom certificate, set `mcp.tls_cert_file` and
`mcp.tls_key_file` in `config.yaml` or pass `--tls-cert` and `--tls-key` flags:

```bash
symvault serve --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

To run without TLS, set `mcp.allow_insecure_bind: true` in `config.yaml`. This
requires explicit confirmation at startup and logs a warning: bearer tokens travel
in cleartext and are vulnerable to loopback sniffing by local processes on the
same machine. Prefer TLS in all production and multi-user environments.

## LaunchAgent

On macOS, run the HTTP MCP server persistently with a LaunchAgent. Adjust paths
and port as needed:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.symvault-mcp</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/symvault</string>
    <string>--vault</string>
    <string>/Users/USER/.symvault</string>
    <string>serve</string>
    <string>--port</string>
    <string>8090</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/USER/Library/Logs/symvault-mcp.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/USER/Library/Logs/symvault-mcp.err</string>
</dict>
</plist>
```

The vault must be unlockable non-interactively. Run `symvault unlock` once so
the passphrase is cached in the OS keyring, or provide a controlled environment
for `SYMVAULT_PASSPHRASE`.

## Token Management

### Scoped Tokens (v2.2.0+)

Create fine-grained access tokens with restricted tool access and optional expiration:

```bash
# Create a token limited to specific tools
symvault agent token hermes new --tools list_entries,get_entry --expires 24h

# List all active tokens
symvault agent token list

# Revoke a token
symvault agent token hermes revoke <token-id>
```

Scoped tokens are stored with SHA-256 hashing and can be restricted to specific MCP tools
and time windows. This is safer than the global bearer token for multi-agent setups.

### Token Rotation

If you suspect your MCP token has been compromised, rotate it:

```bash
symvault agent token hermes rotate
```

This invalidates the old token and generates a new one. Update any agent configurations
with the new token.

### Safer Token Export

When generating MCP configurations that might be displayed in terminals or committed
to version control, use the `--redact` flag:

```bash
symvault agent install claude-code --http --config-only
```

This outputs `env:SYMVAULT_MCP_TOKEN` instead of the actual token. Agents using
redacted configs must have `SYMVAULT_MCP_TOKEN` set in their environment.

For automated scripts that need the raw token:

```bash
TOKEN=$(symvault agent token <agent> new --tools list_entries --expires 24h --json | jq -r .token)
```

## OAuth Dynamic Client Registration

Symaira Vault supports OAuth 2.1 + PKCE + Dynamic Client Registration (DCR) for MCP
clients that implement the DCR flow. This allows clients to automatically
register and obtain scoped tokens without manual bearer token setup.

### Supported Features

- **DCR (RFC 7591)**: Clients register via `POST /oauth/register` and receive a
  `client_id`. Registrations persist across server restarts.
- **PKCE (RFC 7636)**: Authorization code flow with S256 code challenge method.
- **Authorization Code Grant (RFC 6749 §4.1)**: User consent required via TTY
  prompt before issuing tokens.
- **Refresh Token Grant (RFC 6749 §6)**: Clients receive refresh tokens alongside
  access tokens. Token rotation invalidates previous tokens (single-use pattern).

### opencode Configuration

For opencode (and other DCR-capable clients), configure the MCP server with
OAuth enabled:

```json
{
  "mcpServers": {
    "symvault": {
      "type": "remote",
      "url": "http://127.0.0.1:8080/mcp",
      "oauth": true
    }
  }
}
```

Run `opencode mcp auth symvault` to start the DCR flow. The client will:
1. Discover the authorization server metadata from well-known endpoints
2. Register a client via DCR
3. Walk through the PKCE authorization flow (TTY user consent)
4. Receive scoped access and refresh tokens
5. Automatically refresh tokens when they expire

### Configuration

Token TTLs can be customized in `config.yaml`:

```yaml
mcp:
  oauth:
    access_token_ttl: 1h     # how long access tokens are valid (default: 24h)
    refresh_token_ttl: 720h  # how long refresh tokens are valid (default: 30d)
```

### Benefits Over Bearer Tokens

- **No manual token setup** — clients self-register
- **Scoped tokens** — each OAuth-issued token is independently revocable
- **Automatic rotation** — refresh tokens keep connections alive without
  re-authentication
- **Persistent registration** — survives server restarts

## Credential Cache Validation

### Cache Invalidation with Metadata

For agents that cache credentials locally, use `get_entry_metadata` to check if
cached credentials are stale before fetching the full entry:

```json
// Request
{
  "tool": "get_entry_metadata",
  "arguments": {
    "path": "api/kimi-key"
  }
}

// Response
{
  "path": "api/kimi-key",
  "exists": true,
  "created": "2026-01-15T14:32:00Z",
  "updated": "2026-04-21T09:45:00Z",
  "version": 5
}
```

Compare the `version` field with your cached version. If different, fetch the
fresh credential with `get_entry`.

### Including Metadata in get_entry

For one-call cache validation, use `include_metadata=true`:

```json
// Request
{
  "tool": "get_entry",
  "arguments": {
    "path": "api/kimi-key",
    "include_metadata": "true"
  }
}

// Response
{
  "data": {
    "api_key": "kimi-..."
  },
  "meta": {
    "created": "2026-01-15T14:32:00Z",
    "updated": "2026-04-21T09:45:00Z",
    "version": 5
  }
}
```

This pattern is useful for agents implementing automatic credential refresh on
HTTP 401 errors. When an API call fails with 401:

1. Call `get_entry_metadata` to check if the vault version differs from cache
2. If version changed, fetch fresh credentials with `get_entry`
3. Retry the API call with the fresh credentials
4. Only fall back to alternative providers if retry also fails

## TOTP Handling

### Code-Only TOTP Access (Recommended)

For agents that only need TOTP codes, configure field redaction to prevent access
to TOTP secrets while still allowing code generation:

```yaml
agents:
  readonly-agent:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["totp.secret"]
```

This configuration:
- Redacts `totp.secret` from `get_entry` responses (shows `[REDACTED]`)
- Still allows `generate_totp` to work normally
- Prevents agents from reading raw TOTP seeds

Agents can then use `generate_totp` to get time-based codes without ever accessing
the underlying secret.

For the full syntax of `redactFields` (including wildcard patterns and nested field paths),
see the [Field Redaction section in mcp-api.md](mcp-api.md#field-redaction-with-redactfields).

## Slash Commands & Auto-Credential-Capture

Symaira Vault advertises the MCP **prompts** capability. In Claude Code, OpenCode,
Hermes and any other MCP client that surfaces prompts as slash commands, four
guided workflows become available once the server is connected:

| Command | What it does |
|---------|--------------|
| `add-credential` | Walks the agent through adding a new vault entry. Sensitive fields are collected via `request_credential` (native dialog) so the value never enters the chat. |
| `rotate-credential` | Generates a new password, stores it at the existing path, and reminds you to update the value on the remote service. |
| `find-and-use` | Searches the vault for a query, then picks the right consumption tool (`copy_to_clipboard`, `autotype`, or `execute_with_secret`) based on the stated task. |
| `share-credential` | Creates a share grant for another agent and explains the human-approval flow. |

In Claude Code these appear as `/mcp__symvault__add-credential` etc. Pass
prompt arguments via the slash-command UI (e.g. `service_name: GitHub`).

### Auto-Credential-Capture flow

When an agent is mid-task and discovers a credential is missing, the
recommended pattern is:

1. Agent runs `find_entries` / `get_entry` for an expected path.
2. Tool returns nothing.
3. Agent calls `request_credential` with `path`, `field`, and a `reason`
   (shown verbatim to the user).
4. Symaira Vault opens a native OS dialog:
   - macOS: `osascript display dialog` with hidden answer field
   - Linux: `zenity --entry --hide-text` (or `kdialog --password`)
   - Windows: `Get-Credential` window
   - Terminal-attached run: TTY box (existing behavior)
5. User types the value into the dialog. The agent only sees a success
   confirmation; the value is encrypted and stored at the requested path.
6. Agent continues the task using `execute_with_secret`, `copy_to_clipboard`,
   etc.

### Choosing the secure-input backend

`secure_input` and `request_credential` are advertised in `tools/list` whenever
**any** backend is reachable — TTY (if attached) or a native GUI dialog.
Override with:

| `SYMVAULT_SECUREUI` | Behavior |
|---------------------|----------|
| (unset) | TTY if attached, else native GUI |
| `tty` | Force TTY; if unavailable, tools disappear from the list |
| `gui` | Force GUI; if unavailable, tools disappear from the list |
| `none` | Disable both |

This matters for daemonized setups (LaunchAgent, systemd unit). The
LaunchAgent example above has no TTY — set `SYMVAULT_SECUREUI=gui` to make the
secure-input tools available there and they will pop a native dialog on the
logged-in user's screen.

## Agent Skill

The skill template in `docs/skills/symaira-agent/SKILL.md` can be copied into an
agent skill directory. It tells the agent to prefer native MCP tools and to
avoid terminal-based credential operations.

## Migrating Credentials From Markdown

Use a two-phase migration:

1. Create entries through MCP or the CLI using temporary test paths.
2. Read back each entry through MCP and compare field names, not secrets in
   chat logs.
3. Move entries to final paths, then delete the old Markdown file securely.
4. Rotate any credential that was pasted into chat, logs, shell history, or
   version control during the migration.

Avoid putting tokens, passphrases, and passwords in prompts. If that happens,
consider them exposed and rotate them.

## Perplexity AI Integration

Symaira Vault provides two MCP tools for using Perplexity AI's search and question-answering
capabilities directly from AI agents, without requiring an MCP server from Perplexity.

### Tools

- **`perplexity_search`**: Accepts a natural language query and returns synthesized search
  results with citations from the web.
- **`perplexity_ask`**: Accepts a question with optional vault entry context and returns an
  AI-generated answer with citations.

### Setup

1. **Create a Perplexity API key** at [perplexity.ai/settings/api](https://www.perplexity.ai/settings/api).

2. **Store the API key** using one of two methods:

   **Option A: Vault entry (recommended)**:
   ```bash
   symvault set perplexity.credential --value "pplx-..."
   symvault add perplexity --fields credential
   ```

   **Option B: Config file** (`~/.symvault/config.yaml`):
   ```yaml
   mcp:
     perplexity:
       api_key: "pplx-..."
       base_url: "https://api.perplexity.ai"  # optional, default
       rate_limit_per_min: 10                  # optional, default
   ```

3. **Verify the integration**:
   ```bash
   symvault mcp test perplexity_search --args '{"query": "latest AI developments"}'
   ```

### API Template

Perplexity is also available as an `execute_api_request` template using the vault entry
`perplexity`:

```yaml
template: perplexity
endpoint: /chat/completions
method: POST
body: '{"model":"sonar-pro","messages":[{"role":"user","content":"your query"}]}'
```

### Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mcp.perplexity.api_key` | string | — | Perplexity API key (prefer vault entry) |
| `mcp.perplexity.base_url` | string | `https://api.perplexity.ai` | Custom API endpoint |
| `mcp.perplexity.rate_limit_per_min` | int | `10` | Max API requests per minute |

### Audit Logging

All Perplexity API calls are logged to the audit log with the action, query/question
summary, model used, citation count, and success status.

## Metrics and Observability

Symaira Vault exposes Prometheus metrics for monitoring MCP server health, request
patterns, and security events.

### Endpoints

**`/health`** — JSON health check (no auth required)

```bash
curl -s http://127.0.0.1:8080/health | jq .
```

```json
{
  "status": "healthy",
  "timestamp": "2026-04-21T10:30:00Z",
  "version": "1.0.0"
}
```

**`/metrics`** — Prometheus metrics (no auth required)

```bash
curl -s http://127.0.0.1:8080/metrics
```

Returns metrics in Prometheus text format. Use with Prometheus, Grafana, or
any compatible monitoring system.

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `symvault_mcp_requests_total` | Counter | tool, agent, status | Total MCP tool requests |
| `symvault_mcp_request_duration_seconds` | Histogram | tool, agent | Tool request latency |
| `symvault_mcp_auth_denials_total` | Counter | reason, agent | Auth/authorization denials |
| `symvault_mcp_approvals_total` | Counter | agent, outcome | Write approval outcomes |
| `symvault_vault_operations_total` | Counter | operation, status | Vault read/write/delete ops |

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'symvault'
    scrape_interval: 15s
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: /metrics
```

### Example Prometheus Queries

**Request rate by tool:**
```promql
rate(symvault_mcp_requests_total[5m])
```

**Error rate:**
```promql
rate(symvault_mcp_requests_total{status="error"}[5m])
```

**P95 request latency:**
```promql
histogram_quantile(0.95, rate(symvault_mcp_request_duration_seconds_bucket[5m]))
```

**Auth denials by reason:**
```promql
symvault_mcp_auth_denials_total
```

**Vault operation success rate:**
```promql
rate(symvault_vault_operations_total{status="success"}[5m])
/
rate(symvault_vault_operations_total[5m])
```

### Grafana Dashboard

Import these panels for a basic Symaira Vault dashboard:

1. **Request Rate** — `rate(symvault_mcp_requests_total[5m])`
2. **Error Rate** — `rate(symvault_mcp_requests_total{status="error"}[5m])`
3. **Latency P95** — `histogram_quantile(0.95, rate(symvault_mcp_request_duration_seconds_bucket[5m]))`
4. **Auth Denials** — `symvault_mcp_auth_denials_total`
5. **Vault Operations** — `rate(symvault_vault_operations_total[5m])`
