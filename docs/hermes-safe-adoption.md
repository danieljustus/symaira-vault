# Hermes / OpenClaw safe adoption guide

This guide describes a conservative adoption path for using OpenPass as a local,
agent-facing secrets manager for Hermes and OpenClaw.

It is intentionally not a live migration plan. Do not enable OpenPass in live
Hermes configuration, move existing Hermes secrets, rotate credentials, or
replace Janusz's personal password-management workflow until a human explicitly
approves that later gate.

## Roles and non-goals

- 1Password remains Janusz's personal and canonical human password manager.
- OpenPass is only the local, agent-facing secrets manager used to broker
  narrowly scoped credentials to Hermes/OpenClaw agents.
- OpenPass should not become a broad default profile that lets every Hermes
  session read raw secrets.
- OpenPass should not initially execute commands with injected secrets unless
  the MCP command-output masking fixes have landed, passed regression tests, and
  received independent review.

## Adoption gates

1. Complete and review the OpenPass hardening work, especially masking of
   `run_command` and `execute_with_secret` output on every success and error
   path.
2. Create synthetic-test-only OpenPass agent profiles. Do not import live Hermes
   `.env` values or personal 1Password items.
3. Connect Hermes to a read-only, metadata-first profile and verify tool
   discovery and audit logging.
4. Trial narrow raw-secret reads only for one explicit path scope and one
   explicit task class.
5. Add a separate runner profile only after the masking fix is present and
   reviewed.
6. Ask for final human approval before any live Hermes config change, secret
   migration, credential rotation, external push/upstream PR, or production use.

## Recommended initial OpenPass profile

Start with a dedicated Hermes profile that can inspect metadata and search only
narrow path prefixes. Avoid `allowedPaths: ["*"]` for broad/default profiles.

Example `~/.openpass/config.yaml` fragment:

```yaml
agents:
  hermes-metadata:
    # Replace these with the smallest path prefixes needed for the first trial.
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
    max_reads_per_hour: 60
    max_reads_per_day: 200
    max_secrets_in_session: 0
```

Recommended initial Hermes/OpenPass tool allowlist:

- `health`
- `get_auth_status`
- `list_entries`
- `find_entries`
- `get_entry_metadata`

Do not include these in the first profile:

- `get_entry` for broad/default profiles, because it can expose raw fields unless
  a purpose-built profile redacts or limits them.
- `set_entry_field`, `delete_entry`, `secure_input`, or `set_auth_method`,
  because they mutate vault data or auth/config state.
- `run_command` / `execute_with_secret`, because they inject secrets into a
  subprocess and must wait for the masking-fix review gate.
- `copy_to_clipboard` and `autotype`, because they move secrets outside the MCP
  response channel and are harder to audit.
- `generate_totp` unless the profile is explicitly intended for TOTP use and raw
  TOTP secrets are redacted from `get_entry` responses.

## Optional narrow raw-read profile

After the metadata-only profile is verified, create a separate profile for a
single narrow task that requires reading a secret value. Prefer one profile per
use case rather than granting raw reads to default Hermes profiles.

```yaml
agents:
  hermes-provider-read:
    allowedPaths:
      - hermes/providers/openrouter/
    canWrite: false
    canRunCommands: false
    canManageConfig: false
    canUseClipboard: false
    canUseAutotype: false
    approvalMode: deny
    allowed_tools:
      - health
      - get_auth_status
      - get_entry_metadata
      - get_entry
    # Keep non-required fields redacted. If only a specific key field is needed,
    # model entries so other fields can remain hidden from the agent.
    redactFields:
      - totp.secret
      - recovery_codes
    max_reads_per_hour: 10
    max_reads_per_day: 30
    max_secrets_in_session: 3
```

Use this profile only when a task has a concrete reason to read a secret. The
agent should prefer `get_entry_metadata` for freshness checks and only call
`get_entry` when the metadata shows the local cached credential is stale or when
there is no non-secret alternative.

## Separate runner profile after masking review

Command execution belongs in its own profile, not in the metadata/read profile.
Create it only after the command-output masking work is present, tested, and
reviewed.

```yaml
agents:
  hermes-runner-openrouter-smoke:
    allowedPaths:
      - hermes/providers/openrouter/
    canWrite: false
    canRunCommands: true
    canManageConfig: false
    canUseClipboard: false
    canUseAutotype: false
    approvalMode: deny
    allowed_tools:
      - health
      - get_entry_metadata
      - run_command
      - execute_with_secret
    max_reads_per_hour: 5
    max_reads_per_day: 20
    max_secrets_in_session: 1
```

Runner-profile operating rules:

- Use short-lived tokens for HTTP transport, scoped to only the runner tools and
  path prefix.
- Prefer synthetic or low-impact smoke commands first.
- Record and review audit logs before broadening scope.
- Do not use runner profiles in broad/default Hermes profiles.
- Disable or revoke the runner token when the specific maintenance window ends.

## Hermes MCP transport defaults

Prefer stdio for a local Hermes/OpenClaw integration:

```yaml
# ~/.hermes/config.yaml snippet for a future approved trial only.
# Do not paste this into live config until the human adoption gate approves it.
mcp_servers:
  openpass_metadata:
    command: openpass
    args:
      - --vault
      - /home/openclaw/.openpass-hermes-trial
      - serve
      - --stdio
      - --agent
      - hermes-metadata
    timeout: 60
    connect_timeout: 30
    sampling:
      enabled: false
```

Why stdio first:

- no listening network socket;
- no bearer token in Hermes config;
- simple one-client lifecycle tied to the Hermes process;
- easier audit boundary during early adoption.

Use HTTP only when a shared long-running OpenPass server is genuinely needed. If
HTTP is used, bind loopback only and use a scoped token:

```yaml
# OpenPass side, future approved trial only.
mcp:
  bind: 127.0.0.1
  port: 8090
  httpTokenFile: /home/openclaw/.openpass-hermes-trial/mcp-token
```

```yaml
# Hermes side, future approved trial only.
mcp_servers:
  openpass_metadata:
    url: http://127.0.0.1:8090/mcp
    headers:
      Authorization: env:OPENPASS_MCP_TOKEN
      X-OpenPass-Agent: hermes-metadata
    timeout: 60
    connect_timeout: 30
    sampling:
      enabled: false
```

HTTP safeguards:

- bind to `127.0.0.1`, not `0.0.0.0`;
- keep bearer tokens out of committed files and chat transcripts;
- use short token lifetimes and tool allowlists;
- revoke trial tokens after testing;
- do not expose the HTTP listener through a reverse proxy until a separate
  threat-model review approves it.

## Hermes profile/tooling guidance

Do not attach OpenPass MCP tools to every Hermes profile by default. Create a
separate Hermes profile or explicitly controlled worker profile for adoption
trials. The profile should expose only the OpenPass MCP server and the minimum
Hermes built-in tools needed to validate it.

Recommended first Hermes trial surface:

- OpenPass MCP server: `openpass_metadata`.
- OpenPass MCP tools: `mcp_openpass_metadata_health`,
  `mcp_openpass_metadata_get_auth_status`,
  `mcp_openpass_metadata_list_entries`,
  `mcp_openpass_metadata_find_entries`,
  `mcp_openpass_metadata_get_entry_metadata`.
- Hermes built-in tools: no broad terminal/file/browser tools solely for the
  OpenPass trial unless the task specifically requires them.
- No wildcard MCP tool exposure and no default-profile raw-secret reads.

## Audit checklist for each trial

Before widening access, record:

- OpenPass profile name and exact `allowedPaths`.
- Exact `allowed_tools` list.
- Transport choice: stdio or HTTP; for HTTP, loopback bind and token lifetime.
- Whether `get_entry` is allowed, and why metadata-only is insufficient.
- Whether `canRunCommands` is false; if true, link to masking-fix review evidence.
- Audit-log sample showing expected tool calls and no unexpected raw-secret reads.
- Human approval reference for any live Hermes config change or secret migration.

## Explicit non-approval

This document does not approve live adoption. It does not approve migrating
Hermes `.env` secrets, importing 1Password data, rotating real credentials,
enabling OpenPass MCP in default Hermes profiles, broad wildcard path access,
HTTP exposure beyond loopback, or command execution with injected secrets before
reviewed masking fixes.
