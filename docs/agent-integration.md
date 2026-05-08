# OpenPass Agent Integration

OpenPass is easiest for AI agents to use through MCP. Prefer MCP over shell
commands for credential reads and writes: it gives agents structured tools,
per-agent access control, bearer auth for HTTP, and audit logs.

## Recommended Setup

Use a dedicated agent profile instead of sharing a human CLI profile. Start with
metadata/read-only access, narrow `allowedPaths`, and an explicit tool allowlist;
do not give broad/default profiles wildcard paths, write access, or command
execution by default.

For Hermes and OpenClaw, see the conservative adoption packet in
[`docs/hermes-safe-adoption.md`](hermes-safe-adoption.md). It covers a
metadata-first profile, separate runner profiles, stdio-vs-HTTP defaults, and the
human approval gates required before live config changes or secret migration.

Example first profile:

```yaml
agents:
  hermes-metadata:
    allowedPaths:
      - hermes/providers/
      - openclaw/local-dev/
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
so OpenPass does not expose a listening socket and Hermes does not need a bearer
token in config:

```bash
openpass --vault ~/.openpass-vault mcp-config hermes --format hermes
```

Add the output under `mcp_servers` in `~/.hermes/config.yaml` only after the
human adoption gate approves a live Hermes config change, then restart Hermes or
reload MCP tools from Hermes. Verify the connection:

```bash
hermes mcp test openpass
```

When connected, Hermes registers the tools with the `mcp_openpass_` prefix, for
example `mcp_openpass_list_entries`, `mcp_openpass_get_entry`, and
`mcp_openpass_set_entry_field`. Early Hermes profiles should expose only the
metadata-first tool subset from `hermes-safe-adoption.md`.

If HTTP transport is needed later, bind OpenPass to loopback only
(`127.0.0.1`), use scoped short-lived tokens, and keep token values out of
committed config and chat transcripts.

### Available MCP Tools

OpenPass exposes the following MCP tools for agent integration:

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
- `secure_input` — Prompt user for sensitive data via TTY

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
openpass mcp-config openclaw
```

For agents that support HTTP MCP with custom headers, use:

```bash
openpass --vault ~/.openpass-vault mcp-config openclaw --http
```

HTTP mode requires a running OpenPass server:

```bash
openpass --vault ~/.openpass-vault serve --port 8090
```

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
  <string>com.example.openpass-mcp</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/openpass</string>
    <string>--vault</string>
    <string>/Users/USER/.openpass-vault</string>
    <string>serve</string>
    <string>--port</string>
    <string>8090</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/USER/Library/Logs/openpass-mcp.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/USER/Library/Logs/openpass-mcp.err</string>
</dict>
</plist>
```

The vault must be unlockable non-interactively. Run `openpass unlock` once so
the passphrase is cached in the OS keyring, or provide a controlled environment
for `OPENPASS_PASSPHRASE`.

## Token Management

### Scoped Tokens (v2.2.0+)

Create fine-grained access tokens with restricted tool access and optional expiration:

```bash
# Create a token limited to specific tools
openpass mcp token create --agent hermes --tools list_entries,get_entry --expires 24h

# List all active tokens
openpass mcp token list

# Revoke a token
openpass mcp token revoke <token-id>
```

Scoped tokens are stored with SHA-256 hashing and can be restricted to specific MCP tools
and time windows. This is safer than the global bearer token for multi-agent setups.

### Token Rotation

If you suspect your MCP token has been compromised, rotate it:

```bash
openpass mcp-token-rotate
```

This invalidates the old token and generates a new one. Update any agent configurations
with the new token.

### Safer Token Export

When generating MCP configurations that might be displayed in terminals or committed
to version control, use the `--redact` flag:

```bash
openpass mcp-config claude-code --http --redact
```

This outputs `env:OPENPASS_MCP_TOKEN` instead of the actual token. Agents using
redacted configs must have `OPENPASS_MCP_TOKEN` set in their environment.

For automated scripts that need the raw token:

```bash
TOKEN=$(openpass mcp-config <agent> --token-only)
```

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

## Agent Skill

The skill template in `docs/skills/openpass-agent/SKILL.md` can be copied into an
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

## Metrics and Observability

OpenPass exposes Prometheus metrics for monitoring MCP server health, request
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
| `openpass_mcp_requests_total` | Counter | tool, agent, status | Total MCP tool requests |
| `openpass_mcp_request_duration_seconds` | Histogram | tool, agent | Tool request latency |
| `openpass_mcp_auth_denials_total` | Counter | reason, agent | Auth/authorization denials |
| `openpass_mcp_approvals_total` | Counter | agent, outcome | Write approval outcomes |
| `openpass_vault_operations_total` | Counter | operation, status | Vault read/write/delete ops |

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'openpass'
    scrape_interval: 15s
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: /metrics
```

### Example Prometheus Queries

**Request rate by tool:**
```promql
rate(openpass_mcp_requests_total[5m])
```

**Error rate:**
```promql
rate(openpass_mcp_requests_total{status="error"}[5m])
```

**P95 request latency:**
```promql
histogram_quantile(0.95, rate(openpass_mcp_request_duration_seconds_bucket[5m]))
```

**Auth denials by reason:**
```promql
openpass_mcp_auth_denials_total
```

**Vault operation success rate:**
```promql
rate(openpass_vault_operations_total{status="success"}[5m])
/
rate(openpass_vault_operations_total[5m])
```

### Grafana Dashboard

Import these panels for a basic OpenPass dashboard:

1. **Request Rate** — `rate(openpass_mcp_requests_total[5m])`
2. **Error Rate** — `rate(openpass_mcp_requests_total{status="error"}[5m])`
3. **Latency P95** — `histogram_quantile(0.95, rate(openpass_mcp_request_duration_seconds_bucket[5m]))`
4. **Auth Denials** — `openpass_mcp_auth_denials_total`
5. **Vault Operations** — `rate(openpass_vault_operations_total[5m])`
