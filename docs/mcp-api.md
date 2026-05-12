# OpenPass MCP API Documentation

This document provides comprehensive API documentation for the OpenPass Model Context Protocol (MCP) server, enabling agent developers to integrate with OpenPass securely.

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Transport Modes](#transport-modes)
4. [Tool Reference](#tool-reference)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Agent Configuration](#agent-configuration)
8. [Field Redaction with redactFields](#field-redaction-with-redactfields)
9. [Examples](#examples)

---

## Overview

OpenPass exposes a Model Context Protocol (MCP) server that allows AI agents to securely read and optionally write password vault entries. The MCP server supports both stdio (standard input/output) and HTTP transports.

### Key Features

- **Structured API**: Type-safe tool invocations with JSON schemas
- **Per-Agent Access Control**: Each agent can have different permissions
- **Bearer Authentication**: HTTP mode uses token-based auth
- **Audit Logging**: All operations are logged for security monitoring
- **Metadata Support**: Version tracking for credential caching

### Available Tools

| Tool | Description | Write Operation |
|------|-------------|-----------------|
| `health` | Check server health status | No |
| `get_auth_status` | Check OpenPass unlock auth status | No |
| `set_auth_method` | Change unlock auth method | Config write |
| `list_entries` | List all vault entries | No |
| `get_entry` | Retrieve entry contents | No |
| `get_entry_metadata` | Get entry metadata without sensitive data | No |
| `find_entries` | Search entries by path | No |
| `generate_password` | Generate secure passwords | No |
| `generate_totp` | Generate TOTP codes | No |
| `copy_to_clipboard` | Copy entry password to system clipboard (auto-clears) | No |
| `autotype` | Type entry field as keyboard input into focused app | No |
| `set_entry_field` | Store or update a field | **Yes** |
| `run_command` | Execute command with secret env injection | **Yes** |
| `delete_entry` | Delete an entry | **Yes** |
| `openpass_delete` | Deprecated alias for delete_entry | **Yes** |
| `secure_input` | Prompt user for sensitive data via TTY or native GUI dialog | **Yes** |
| `request_credential` | Agent-initiated: native dialog for a missing credential, stored without exposure | **Yes** |

---

## Authentication

### HTTP Mode

HTTP mode requires bearer token authentication. The token is auto-generated on first server start.

#### Token Location

```
<vault>/mcp-token
```

#### Authentication Header

```
Authorization: Bearer <token>
```

#### Agent Identification Header

```
X-OpenPass-Agent: <agent-profile-name>
```

#### Example Request

```bash
curl -H "Authorization: Bearer $(cat ~/.openpass/mcp-token)" \
     -H "X-OpenPass-Agent: claude-code" \
     -H "Content-Type: application/json" \
     -X POST \
     -d '{"tool": "list_entries", "arguments": {}}' \
     http://127.0.0.1:8080/mcp
```

### Stdio Mode

Stdio mode does not use HTTP authentication. The agent is identified via the `--agent` flag:

```bash
openpass serve --stdio --agent claude-code
```

The agent name must match a profile in the vault configuration.

---

## OAuth Well-Known Endpoints

OpenPass exposes OAuth well-known endpoints for MCP client discovery. These endpoints comply with RFC 9728 (OAuth Protected Resource Metadata) and RFC 8414 (OAuth Authorization Server Metadata). They exist so that OAuth-only MCP clients (such as opencode) can discover server capabilities without crashing on JSON parse errors during auto-discovery.

### Endpoint Reference

| Endpoint | Method | Status | Description |
|----------|--------|--------|-------------|
| `/.well-known/oauth-protected-resource` | GET | 200 | Protected resource metadata (RFC 9728) |
| `/.well-known/oauth-authorization-server` | GET | 200 | Authorization server metadata (RFC 8414) |
| `/mcp/oauth/authorize` | POST | 501 | OAuth authorization stub |
| `/mcp/oauth/token` | POST | 501 | OAuth token exchange stub |

### Well-Known Endpoint Responses

The two well-known discovery endpoints return static metadata that describes how OpenPass handles OAuth:

```json
GET /.well-known/oauth-protected-resource
HTTP/1.1 200 OK
Content-Type: application/json

{
  "resource": "http://127.0.0.1:8080/mcp",
  "bearer_methods_supported": ["header"],
  "resource_name": "OpenPass MCP Server"
}
```

```json
GET /.well-known/oauth-authorization-server
HTTP/1.1 200 OK
Content-Type: application/json

{
  "issuer": "http://127.0.0.1:8080",
  "authorization_endpoint": "http://127.0.0.1:8080/mcp/oauth/authorize",
  "token_endpoint": "http://127.0.0.1:8080/mcp/oauth/token",
  "response_types_supported": ["code"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "grant_types_supported": ["authorization_code", "refresh_token"]
}
```

The authorization and token endpoints return 501 Not Implemented:

```json
POST /mcp/oauth/authorize
HTTP/1.1 501 Not Implemented
Content-Type: application/json

{
  "error": "not_implemented",
  "error_description": "OAuth authorization is not yet implemented. Use bearer token authentication."
}
```

### OpenCode Integration Guide

OpenPass uses bearer token authentication, not OAuth. The well-known endpoints exist only to prevent client crashes during auto-discovery. They are not used for actual OAuth flows.

To configure opencode to use OpenPass as an MCP server with bearer token auth:

```json
{
  "mcp": {
    "openpass": {
      "type": "remote",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_OPENPASS_TOKEN",
        "X-OpenPass-Agent": "opencode"
      },
      "oauth": false
    }
  }
}
```

With this configuration, `opencode mcp auth openpass` will no longer crash with a JSON parse error. The client discovers the well-known endpoints, reads the bearer token metadata, and falls back to the supplied `Authorization` header instead of attempting an OAuth flow.

---

## Transport Modes

### Stdio Mode (Recommended for Local Agents)

**Best for**: Local AI agents with direct process communication.

**Advantages**:
- No network exposure
- Simpler configuration
- Lower latency
- No token management

**Start the server**:

```bash
openpass serve --stdio --agent <profile-name>
```

**Generate configuration**:

```bash
openpass mcp-config <agent-name>
```

### HTTP Mode

**Best for**: Remote agents, multiple clients, or service integration.

**Advantages**:
- Network accessible
- Multiple concurrent clients
- Compatible with HTTP-based tools

**Start the server**:

```bash
openpass serve --port 8080 --agent <profile-name>
```

**Generate configuration** (token redacted by default):

```bash
openpass mcp-config <agent-name> --http
```

**Include token in output**:

```bash
openpass mcp-config <agent-name> --http --include-token
```

---

## Tool Reference

### health

Check the MCP server health status.

**Request**:

```json
{
  "tool": "health",
  "arguments": {}
}
```

**Response**:

```json
{
  "status": "healthy",
  "timestamp": "2026-04-21T10:30:00Z",
  "version": "1.0.0"
}
```

**HTTP Endpoint**: `GET /health` (no authentication required)

---

### get_auth_status

Return the configured unlock method, Touch ID availability, and session cache
backend.

**Request**:

```json
{
  "tool": "get_auth_status",
  "arguments": {}
}
```

---

### set_auth_method

Set the unlock method to `passphrase` or `touchid`. The calling agent profile
must set `canManageConfig: true`. MCP never accepts a passphrase from the agent;
Touch ID setup requires an already active OpenPass session.

**Request**:

```json
{
  "tool": "set_auth_method",
  "arguments": {
    "method": "touchid"
  }
}
```

---

### list_entries

List all password entries in the vault.

**Request**:

```json
{
  "tool": "list_entries",
  "arguments": {}
}
```

**Response**:

```json
{
  "entries": [
    {
      "path": "github",
      "modified": "2026-01-15T14:32:00Z"
    },
    {
      "path": "work/aws",
      "modified": "2026-02-20T09:15:00Z"
    }
  ]
}
```

**Notes**:
- Returns paths relative to vault root
- Does not include entry contents
- Sorted by path

---

### get_entry

Retrieve the contents of a password entry.

**Request**:

```json
{
  "tool": "get_entry",
  "arguments": {
    "path": "github",
    "include_metadata": false
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Entry path (e.g., "github" or "work/aws") |
| `include_metadata` | boolean | No | Include creation/update metadata |

**Response** (without metadata):

```json
{
  "path": "github",
  "data": {
    "password": "mysecretpassword",
    "username": "myuser",
    "url": "https://github.com"
  }
}
```

**Response** (with metadata):

```json
{
  "path": "github",
  "data": {
    "password": "mysecretpassword",
    "username": "myuser",
    "url": "https://github.com"
  },
  "meta": {
    "created": "2026-01-15T14:32:00Z",
    "updated": "2026-04-21T09:45:00Z",
    "version": 5
  }
}
```

**Errors**:
- `not_found`: Entry does not exist
- `access_denied`: Agent profile restricts access to this path
- `vault_locked`: Vault is locked, run `openpass unlock`

---

### get_entry_metadata

Get entry metadata without retrieving sensitive data. Useful for cache validation.

**Request**:

```json
{
  "tool": "get_entry_metadata",
  "arguments": {
    "path": "api/kimi-key"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Entry path |

**Response**:

```json
{
  "path": "api/kimi-key",
  "exists": true,
  "created": "2026-01-15T14:32:00Z",
  "updated": "2026-04-21T09:45:00Z",
  "version": 5
}
```

**Use Case**: Credential Cache Validation

Agents can compare the `version` field with their cached version to determine if credentials need refresh:

```json
// Check if cached credentials are stale
{
  "tool": "get_entry_metadata",
  "arguments": {
    "path": "api/kimi-key"
  }
}
```

---

### find_entries

Search for entries by path substring.

**Request**:

```json
{
  "tool": "find_entries",
  "arguments": {
    "query": "aws"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search string to match against entry paths |

**Response**:

```json
{
  "entries": [
    {
      "path": "work/aws",
      "modified": "2026-02-20T09:15:00Z"
    },
    {
      "path": "work/aws-staging",
      "modified": "2026-03-10T11:20:00Z"
    }
  ]
}
```

---

### generate_password

Generate a cryptographically secure password.

**Request**:

```json
{
  "tool": "generate_password",
  "arguments": {
    "length": 20,
    "include_symbols": true
  }
}
```

**Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `length` | integer | No | 16 | Password length (8-128) |
| `symbols` | boolean | No | true | Include special characters |

**Response**:

```json
{
  "password": "xK9#mP2$vL7@nQ4!aB8&"
}
```

---

### generate_totp

Generate a Time-based One-Time Password (TOTP) code from a stored TOTP secret.

**Request**:

```json
{
  "tool": "generate_totp",
  "arguments": {
    "path": "github"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Entry path containing TOTP secret |

**Response**:

```json
{
  "code": "123456",
  "expires_at": "2026-04-21T10:35:00Z",
  "period": 30
}
```

**Security Note**: This tool only returns the generated code, not the underlying TOTP secret. Use `redactFields` in agent configuration to prevent access to raw secrets while still allowing code generation.

---

### copy_to_clipboard

Copy a vault entry's password field to the system clipboard without exposing the value to the agent. The clipboard auto-clears after 30 seconds.

**Request**:

```json
{
  "tool": "copy_to_clipboard",
  "arguments": {
    "path": "github"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Entry path whose password field to copy |

**Response**:

```json
{
  "success": true,
  "path": "github",
  "clears_at": "2026-05-05T15:30:00Z"
}
```

**Notes**:
- Requires `canUseClipboard: true` in agent profile (separate from `canWrite`)
- The password value is never exposed in the MCP response
- Clipboard is automatically cleared after 30 seconds
- Only copies the `password` field of the entry

**Errors**:
- `clipboard_denied`: Agent profile has `canUseClipboard: false`
- `not_found`: Entry does not exist

---

### autotype

Type a vault entry's field value as keyboard input into the currently focused application without exposing the value to the agent.

**Request**:

```json
{
  "tool": "autotype",
  "arguments": {
    "path": "github",
    "field": "password"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `path` | string | Yes | - | Entry path |
| `field` | string | No | `password` | Field name to type (e.g., `password`, `username`) |

**Response**:

```json
{
  "success": true,
  "path": "github",
  "field": "password"
}
```

**Notes**:
- Requires `canUseAutotype: true` in agent profile (separate from `canWrite`)
- The field value is never exposed in the MCP response
- Types into the currently focused application window
- Cross-platform: macOS, Linux (via xdotool), Windows (via AutoIt)
- Falls back gracefully on unsupported platforms

**Errors**:
- `autotype_denied`: Agent profile has `canUseAutotype: false`
- `not_found`: Entry or field does not exist

---

### secure_input

Prompt the user for sensitive data via an interactive TTY and store it without exposing the value to the agent. Only available in stdio mode with a TTY.

**Request**:

```json
{
  "tool": "secure_input",
  "arguments": {
    "path": "new-service",
    "field": "password",
    "description": "Enter the password for new-service"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Entry path to store the value |
| `field` | string | Yes | Field name to store the value under |
| `description` | string | No | Optional description shown to the user in the prompt |

**Response**:

```json
{
  "success": true,
  "path": "new-service",
  "field": "password"
}
```

**Notes**:
- Available whenever any secure-input backend is reachable: an interactive TTY
  (stdio mode), or a native GUI dialog (macOS `osascript`, Linux
  `zenity`/`kdialog`, Windows `Get-Credential`). Set `OPENPASS_SECUREUI=tty|gui|none`
  to override the auto-detected backend.
- The agent never sees the value being stored
- Requires `canWrite: true` in agent profile
- Triggers automatic git commit (if enabled)

---

### request_credential

Agent-initiated counterpart to `secure_input`. Use this when, during a task, the
agent discovers an expected vault entry is missing. The user gets a native
input dialog with the agent's stated reason; the value is stored at the
requested path and never returned to the agent.

**Request**:

```json
{
  "tool": "request_credential",
  "arguments": {
    "path": "github/api-token",
    "field": "token",
    "reason": "Needed to push to main on the openpass repo"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Vault path to store the new credential |
| `field` | string | Yes | Field name (e.g. `token`, `password`, `api_key`) |
| `reason` | string | Yes | Short reason shown verbatim in the dialog |

**Response**:

```json
{
  "success": true,
  "path": "github/api-token",
  "field": "token"
}
```

**Notes**:
- Same backend rules as `secure_input` (TTY or native GUI; `OPENPASS_SECUREUI`
  override applies)
- `reason` is shown to the user — agents should write it as a clear,
  human-readable sentence
- Recommended call site: after `find_entries` / `get_entry` returns nothing
  for an expected path, instead of asking the user for the secret in chat

---

### set_entry_field

Store or update a single field in an entry. Requires write permission.

**Request**:

```json
{
  "tool": "set_entry_field",
  "arguments": {
    "path": "new-service",
    "field": "password",
    "value": "secure-password-here"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Entry path |
| `field` | string | Yes | Field name (e.g., "password", "username", "api_key") |
| `value` | string | Yes | Field value |

**Response**:

```json
{
  "success": true,
  "path": "new-service",
  "field": "password",
  "version": 6
}
```

**Notes**:
- Creates entry if it doesn't exist
- Updates existing field or adds new one
- Triggers automatic git commit (if enabled)
- Requires `canWrite: true` in agent profile

**Errors**:
- `access_denied`: Agent profile has `canWrite: false`
- `approval_required`: Agent profile has `approvalMode: prompt` (degrades to deny in MCP)

---

### run_command

Execute a command on the host with secrets injected as environment variables.

**Request**:

```json
{
  "tool": "run_command",
  "arguments": {
    "command": ["curl", "-H", "Authorization: Bearer $API_KEY", "https://api.github.com/user"],
    "env": {
      "API_KEY": "github.api_key"
    },
    "working_dir": "/tmp",
    "timeout": 30
  }
}
```

**Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `command` | array | Yes | - | Command and arguments as strings |
| `env` | object | No | `{}` | Map of env var names to secret refs (e.g. `{"API_KEY": "github.api_key"}`) |
| `working_dir` | string | No | current dir | Working directory for the command |
| `timeout` | number | No | 30 | Timeout in seconds |

**Response**:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "duration_ms": 245
}
```

**Notes**:
- Requires `canRunCommands: true` in agent profile (separate from `canWrite`)
- Each secret ref is scope-checked individually
- Secret values are never exposed in the MCP response or audit logs
- Output is capped at 100KB per stream to prevent context bloat
- Timeout kills the process with exit code `-1`

**Errors**:
- `run_denied`: Agent profile has `canRunCommands: false`
- `scope_denied`: Secret ref path is outside agent's allowed scope
- `approval_required`: Agent profile requires approval

---

### delete_entry

Delete a password entry. Requires write permission.

**Request**:

```json
{
  "tool": "delete_entry",
  "arguments": {
    "path": "old-service"
  }
}
```

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Entry path to delete |

**Response**:

```json
{
  "success": true,
  "path": "old-service",
  "deleted_at": "2026-04-21T10:30:00Z"
}
```

**Notes**:
- Permanent deletion (no recycle bin)
- Triggers automatic git commit (if enabled)
- Requires `canWrite: true` in agent profile

---

### openpass_delete

**Deprecated**: Use `delete_entry` instead. This is a legacy alias maintained for backward compatibility.

---

## MCP Prompts

OpenPass advertises the MCP `prompts` capability. In MCP clients that surface
prompts as slash commands (Claude Code, OpenCode, Hermes, …) four guided
credential workflows become available once the server is connected. The server
implements the standard `prompts/list` and `prompts/get` JSON-RPC methods.

### prompts/list

Returns all available prompts with their argument schemas.

**Request**:

```json
{"jsonrpc": "2.0", "id": 1, "method": "prompts/list"}
```

**Response**:

```json
{
  "prompts": [
    {
      "name": "add-credential",
      "description": "Guided workflow to add a new credential …",
      "arguments": [
        {"name": "service_name", "description": "…", "required": false},
        {"name": "path", "description": "…", "required": false}
      ]
    },
    ...
  ]
}
```

### prompts/get

Renders the prompt body for a given prompt and argument map. The MCP client
injects the returned messages into the conversation.

**Request**:

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "prompts/get",
  "params": {
    "name": "add-credential",
    "arguments": {"service_name": "GitHub"}
  }
}
```

**Response**:

```json
{
  "description": "Guided workflow to add a new credential …",
  "messages": [
    {"role": "user", "content": {"type": "text", "text": "Add a new credential …"}}
  ]
}
```

### Available Prompts

| Name | Required args | Description |
|------|---------------|-------------|
| `add-credential` | – | Walks the agent through adding a vault entry. Sensitive fields routed through `request_credential`. Optional args: `service_name`, `path`. |
| `rotate-credential` | `path` | Generates a new password, stores it, reminds the user to update the remote service. Optional: `length` (default 32). |
| `find-and-use` | `query` | Searches the vault and suggests the right consumption tool (`copy_to_clipboard`, `autotype`, `execute_with_secret`). Optional: `task`. |
| `share-credential` | `path`, `to_agent` | Creates a share grant and explains the human-approval flow. Optional: `ttl` (default `1h`), `secret_field`. |

In Claude Code the prompts appear as `/mcp__openpass__add-credential` (and
similar). The displayed argument form is generated automatically from each
prompt's argument schema.

---

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "error_code",
    "message": "Human-readable error description",
    "details": {}
  }
}
```

### Error Codes

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `not_found` | 404 | Entry or resource not found | Verify the path exists with `list_entries` |
| `access_denied` | 403 | Agent not authorized for this operation | Check agent profile in `config.yaml` |
| `vault_locked` | 403 | Vault is locked | Run `openpass unlock` |
| `invalid_request` | 400 | Malformed request | Check JSON syntax and parameters |
| `missing_parameter` | 400 | Required parameter missing | Include all required fields |
| `invalid_parameter` | 400 | Parameter value invalid | Check parameter constraints |
| `write_denied` | 403 | Agent cannot write | Set `canWrite: true` in profile |
| `run_denied` | 403 | Agent cannot execute commands | Set `canRunCommands: true` in profile |
| `approval_required` | 403 | Operation requires approval | `approvalMode: prompt` degrades to deny in MCP |
| `rate_limited` | 429 | Too many requests | Wait and retry |
| `internal_error` | 500 | Server error | Check server logs, restart server |
| `not_implemented` | 501 | Tool not available | Verify OpenPass version |

### Common Error Scenarios

#### Vault Locked

```json
{
  "error": {
    "code": "vault_locked",
    "message": "Vault is locked. Please run 'openpass unlock' first.",
    "details": {}
  }
}
```

**Resolution**:
```bash
openpass unlock
# Enter passphrase
```

#### Access Denied

```json
{
  "error": {
    "code": "access_denied",
    "message": "Agent 'readonly-agent' is not allowed to access path 'work/aws'",
    "details": {
      "agent": "readonly-agent",
      "path": "work/aws",
      "allowed_paths": ["personal/*"]
    }
  }
}
```

**Resolution**: Update agent profile `allowedPaths` to include the path pattern.

#### Write Denied

```json
{
  "error": {
    "code": "write_denied",
    "message": "Agent 'claude-code' does not have write permission",
    "details": {}
  }
}
```

**Resolution**: Set `canWrite: true` in the agent profile.

---

## Rate Limiting

OpenPass implements rate limiting to prevent abuse and ensure fair resource usage.

### Limits

| Operation Type | Limit | Window |
|----------------|-------|--------|
| Read operations | 100 | 60 seconds |
| Write operations | 20 | 60 seconds |
| Password generation | 50 | 60 seconds |
| Health checks | Unlimited | - |

### Rate Limit Response

When rate limit is exceeded:

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

### Best Practices

1. **Cache credentials**: Don't fetch the same entry repeatedly
2. **Use metadata for cache validation**: Check `version` before fetching full entry
3. **Batch operations**: Minimize individual tool calls
4. **Handle rate limits gracefully**: Implement exponential backoff

---

## Agent Configuration

Agent profiles are defined in the vault configuration file (`~/.openpass/config.yaml`).

### Configuration Location

```
~/.openpass/config.yaml
```

### Profile Schema

```yaml
agents:
  <profile-name>:
    allowedPaths: ["*"]           # Path patterns agent can access
    canWrite: false               # Whether agent can create/update/delete entries
    canRunCommands: false         # Whether agent can execute commands with secrets
    canUseClipboard: false        # Whether agent can copy passwords to clipboard
    canUseAutotype: false         # Whether agent can type passwords via autotype
    approvalMode: "none"          # Approval behavior: none | deny | prompt
    redactFields: []              # Fields to redact from responses
```

### Field Descriptions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowedPaths` | array | `["*"]` | Path patterns the agent can access. Use `*` for all paths, or prefixes like `["work/", "personal/"]` |
| `canWrite` | boolean | `false` | Whether the agent can modify vault entries |
| `canRunCommands` | boolean | `false` | Whether the agent can execute commands with secret env injection via `run_command` |
| `canUseClipboard` | boolean | `false` | Whether the agent can copy passwords to clipboard via `copy_to_clipboard` |
| `canUseAutotype` | boolean | `false` | Whether the agent can type passwords via keyboard input through `autotype` |
| `approvalMode` | string | `"none"` | Write approval behavior: `none` (allow), `deny` (reject), `prompt` (degrades to deny in MCP) |
| `redactFields` | array | `[]` | Field names to redact from `get_entry` responses (e.g., `["totp.secret"]` shows `[REDACTED]`) |

### Built-in Profiles

OpenPass includes several pre-configured profiles:

| Profile | `allowedPaths` | `canWrite` | `canRunCommands` | `canUseClipboard` | `canUseAutotype` | Use Case |
|---------|----------------|------------|-------------------|-------------------|-------------------|----------|
| `default` | `["*"]` | `false` | `false` | `false` | `false` | Read-only access to all entries |
| `claude-code` | `["*"]` | `true` | `false` | `false` | `false` | Full vault access for Claude Code |
| `codex` | `["*"]` | `false` | `false` | `false` | `false` | Read-only access for Codex |
| `hermes` | `["*"]` | `true` | `false` | `false` | `false` | Full vault access for Hermes |
| `openclaw` | `["*"]` | `true` | `false` | `false` | `false` | Full vault access for OpenClaw |
| `opencode` | `["*"]` | `false` | `false` | `false` | `false` | Read-only access for OpenCode |

### Custom Profile Example

```yaml
agents:
  # Read-only agent for production secrets only
  prod-reader:
    allowedPaths: ["production/*"]
    canWrite: false
    approvalMode: "deny"

  # Write agent for development secrets
  dev-writer:
    allowedPaths: ["development/*", "staging/*"]
    canWrite: true
    approvalMode: "none"

  # TOTP-only agent (cannot read TOTP secrets)
  totp-agent:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["totp.secret"]

  # Clipboard agent (can copy but not read passwords)
  clipboard-agent:
    allowedPaths: ["*"]
    canWrite: false
    canUseClipboard: true

  # Full automation agent (run commands + autotype)
  automation-agent:
    allowedPaths: ["*"]
    canWrite: false
    canRunCommands: true
    canUseAutotype: true
```

### Path Pattern Syntax

| Pattern | Matches |
|---------|---------|
| `*` | All paths |
| `work/*` | All entries under `work/` |
| `work/aws` | Exact path `work/aws` |
| `api/*` | All entries under `api/` |
| `["work/*", "personal/*"]` | Both work and personal directories |

---

## Field Redaction with `redactFields`

The `redactFields` agent profile setting controls which entry fields are hidden from `get_entry` responses. Redacted fields appear as `[REDACTED]` instead of their actual values.

### What Gets Redacted

Redaction is applied **only** to `get_entry` responses. It does **not** affect:
- `list_entries`, `find_entries`, or `get_entry_metadata` (these never return field values)
- `generate_totp` (reads the secret directly from the vault)
- `generate_password` (creates new values)
- Write operations such as `set_entry_field` or `secure_input`

### Pattern Syntax

`redactFields` is an array of field name patterns. Patterns are matched against the fully-qualified field path using dot notation for nested maps.

| Pattern | Matches | Example |
|---------|---------|---------|
| `"password"` | Exact top-level field | `password` |
| `"totp.secret"` | Exact nested field | `totp.secret` |
| `"*"` | **All** fields | everything |
| `"totp.*"` | All fields under the `totp` map | `totp.secret`, `totp.issuer`, `totp.algorithm` |

### TOTP Secret Redaction (Recommended)

The most common use case is preventing agents from reading raw TOTP secrets while still allowing them to generate codes:

```yaml
agents:
  totp-only:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["totp.secret"]
```

With this profile:
- `get_entry github` returns all fields, but `totp.secret` shows `[REDACTED]`
- `generate_totp github` still works normally and returns the current TOTP code
- The agent can use TOTP-based authentication without ever seeing the underlying seed

### Other Common Examples

```yaml
agents:
  # Redact all TOTP-related fields
  totp-redacted:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["totp.*"]

  # Redact password and TOTP secret
  limited-reader:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["password", "totp.secret", "api_key"]

  # Redact everything (metadata-only access)
  metadata-only:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["*"]
```

### Response Example with Redaction

**Profile**:
```yaml
agents:
  readonly-agent:
    allowedPaths: ["*"]
    canWrite: false
    redactFields: ["totp.secret"]
```

**Request**:
```json
{
  "tool": "get_entry",
  "arguments": {
    "path": "github"
  }
}
```

**Response**:
```json
{
  "path": "github",
  "data": {
    "password": "mysecretpassword",
    "username": "myuser",
    "url": "https://github.com",
    "totp": {
      "secret": "[REDACTED]",
      "issuer": "GitHub",
      "algorithm": "SHA1"
    }
  }
}
```

Note that `generate_totp github` continues to work because it reads the TOTP secret directly from the encrypted vault entry, bypassing the `get_entry` redaction layer.

---

## Examples

### Complete Workflow: Read and Update Entry

```json
// 1. List entries
{
  "tool": "list_entries",
  "arguments": {}
}

// 2. Get entry metadata for cache check
{
  "tool": "get_entry_metadata",
  "arguments": {
    "path": "api/service-key"
  }
}

// 3. Get full entry (if cache miss)
{
  "tool": "get_entry",
  "arguments": {
    "path": "api/service-key",
    "include_metadata": true
  }
}

// 4. Update field (requires write permission)
{
  "tool": "set_entry_field",
  "arguments": {
    "path": "api/service-key",
    "field": "api_key",
    "value": "new-api-key-value"
  }
}
```

### HTTP Mode Complete Example

```bash
# Set variables
TOKEN=$(cat ~/.openpass/mcp-token)
AGENT="claude-code"
BASE_URL="http://127.0.0.1:8080"

# Health check
curl -s "$BASE_URL/health" | jq .

# List entries
curl -s -X POST "$BASE_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-OpenPass-Agent: $AGENT" \
  -H "Content-Type: application/json" \
  -d '{"tool": "list_entries", "arguments": {}}' | jq .

# Get entry
curl -s -X POST "$BASE_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-OpenPass-Agent: $AGENT" \
  -H "Content-Type: application/json" \
  -d '{"tool": "get_entry", "arguments": {"path": "github"}}' | jq .

# Generate password
curl -s -X POST "$BASE_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-OpenPass-Agent: $AGENT" \
  -H "Content-Type: application/json" \
  -d '{"tool": "generate_password", "arguments": {"length": 20}}' | jq .
```

### Stdio Mode Complete Example

```bash
# Start the server
openpass serve --stdio --agent claude-code

# Send MCP request (via stdin)
echo '{"tool": "list_entries", "arguments": {}}' | openpass serve --stdio --agent claude-code

# Or with a proper MCP client
# The MCP client handles the JSON-RPC framing
```

### Credential Cache Pattern

```javascript
// Pseudocode for credential caching with OpenPass
async function getCredential(path) {
  const cached = cache.get(path);
  
  // Check if cached version is stale
  const metadata = await mcp.call('get_entry_metadata', { path });
  
  if (!cached || cached.version !== metadata.version) {
    // Fetch fresh credential
    const entry = await mcp.call('get_entry', { 
      path, 
      include_metadata: true 
    });
    
    cache.set(path, {
      data: entry.data,
      version: entry.meta.version
    });
    
    return entry.data;
  }
  
  return cached.data;
}
```

---

## Related Documentation

- [Agent Integration Guide](agent-integration.md) - Detailed setup for specific agents
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [Runbook](runbook.md) - Operational procedures and incident response
- [README](../README.md) - General usage and installation

## Security Considerations

1. **Token Security**: The `mcp-token` file contains authentication credentials. Protect it like a password.

2. **Network Binding**: HTTP mode binds to `127.0.0.1` by default. Do not expose to public networks without additional security.

3. **Agent Isolation**: Use separate agent profiles for different security contexts.

4. **Audit Logging**: All MCP operations are logged. Monitor logs for unauthorized access attempts.

5. **Write Permissions**: Grant write permissions sparingly. Prefer read-only agents when possible.

6. **Credential Rotation**: If an agent may have logged credentials to chat logs or terminals, rotate those credentials immediately.

---

## Changelog

| Version | Changes |
|---------|---------|
| 2.2.0 | Added `copy_to_clipboard`, `autotype`, and `run_command` tools; added `canUseClipboard` and `canUseAutotype` agent permissions; added scoped token management |
| 2.0.0 | Added `run_command` tool, `canRunCommands` permission, and HTTP MCP authentication |
| 1.0.0 | Initial MCP API documentation |

---

**Maintainer**: OpenPass Team  
**Repository**: https://github.com/danieljustus/OpenPass  
**Security**: Report security issues via [GitHub Security Advisories](https://github.com/danieljustus/OpenPass/security/advisories/new)
