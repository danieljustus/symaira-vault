---
name: openpass
description: Use OpenPass as the credential manager for AI agents through native MCP tools. Prefer this when storing, retrieving, generating, or rotating passwords, tokens, API keys, and TOTP codes.
---

# OpenPass

OpenPass is the credential store. Use native MCP tools when they are available.
Do not use terminal commands for credential reads or writes unless the user
explicitly asks for CLI debugging.

## Preferred Tools

Canonical OpenPass MCP tool names:

- `list_entries`
- `find_entries`
- `get_entry`
- `get_entry_metadata` — Get entry metadata (created, updated, version) without sensitive data
- `set_entry_field`
- `generate_password`
- `generate_totp`
- `delete_entry`
- `openpass_delete` (deprecated alias for `delete_entry`)
- `execute_with_secret` — Run a shell command with a vault secret injected as an
  environment variable. The secret value never appears in the command string,
  argv, or chat transcript.
- `execute_api_request` — Make an authenticated HTTP request using a stored
  secret (API key, PAT, bearer token). The secret is attached by the server and
  never revealed to the agent.

Some MCP clients prepend a namespace (for example `mcp_openpass_list_entries`).
If canonical names are unavailable, inspect the client's MCP tool list and map
to these equivalents.

### Safe API Request Example

To call the GitHub API with a stored PAT, use `execute_api_request`:

```json
{
  "template": "github",
  "endpoint": "/repos/owner/repo/issues",
  "method": "GET"
}
```

Do NOT call `get_entry_value` followed by curl — this exposes the token
in the chat transcript.

### Anti-pattern: Manual secret exposure

Never pass a secret as an argv argument or echo it in a shell command.
Use the secret-injecting tools so the value lives only in env vars of
the spawned subprocess.

## Cache Validation for Credential Sync

For agents that cache credentials locally, use `get_entry_metadata` to validate
cache freshness before fetching full entries:

1. Cache the entry version when first retrieving a credential
2. Before using a cached credential, call `get_entry_metadata` to get the current version
3. If versions differ, the credential was updated — fetch fresh data with `get_entry`
4. This prevents using stale credentials that may cause HTTP 401 errors

Example workflow for API key management:
```
1. Get metadata: get_entry_metadata(path="api/kimi-key")
   → {version: 5, updated: "2026-04-21T09:45:00Z"}

2. Compare with cached version
   → If cached version < 5, fetch fresh: get_entry(path="api/kimi-key")

3. Use fresh credential for API call
   → If 401 error still occurs, credential is truly invalid (not just stale)
```

## Usage Rules

- Search or list before reading if the exact path is unknown.
- Read only the entry needed for the task.
- Write credentials with `set_entry_field`; keep paths stable and descriptive.
- Generate passwords with `generate_password` instead of inventing them.
- Generate TOTP codes with `generate_totp`; do not expose the stored TOTP secret.
- Do not echo secrets, tokens, or passphrases in chat unless the user explicitly
  asks to reveal them.
- Prefer dedicated agent profiles such as `hermes` or `openclaw` over a shared
  human CLI profile.

## Missing Credentials

If a task requires a credential that is not in the vault (e.g. `find_entries` or
`get_entry` returns nothing for an expected path), do NOT ask the user to type
the secret in chat. Call the `request_credential` MCP tool instead:

- `path`: where the credential should live (e.g. `github/api-token`)
- `field`: which field (`token`, `password`, `api_key`, …)
- `reason`: a one-sentence human-readable reason — this is shown verbatim in
  the dialog the user sees

OpenPass opens a native dialog (TTY box on terminal-attached runs, OS-native
popup otherwise). The user types the value; you receive only a confirmation,
never the value itself. Continue the task afterwards using `execute_with_secret`,
`copy_to_clipboard`, or `autotype` — never re-derive or re-print the secret.

## Expected Entry Shape

Entries are JSON-like objects. Common fields:

- `username`
- `password`
- `url`
- `notes`
- `totp`

For TOTP setup, `totp` is a JSON object containing the TOTP configuration. For
one-time codes, call `generate_totp` instead of reading the TOTP secret.

## Troubleshooting

- If tools are missing, ask the user to run `hermes mcp test openpass` or the
  equivalent MCP discovery command for their agent.
- If writes are denied, check the OpenPass agent profile: `canWrite` must be
  `true` and `approvalMode` should be `none` for non-interactive agents.
- If terminal commands are blocked by the agent security policy, keep using MCP;
  the terminal policy should not be loosened for normal credential work.
