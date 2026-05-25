# Tool: health

Return Symaira Vault MCP server health information.

## USE WHEN
- You need to verify the server is running and responsive
- You want to check the installed Symaira Vault version
- Before starting a workflow, to confirm connectivity
- You're troubleshooting and need a baseline response

## DON'T USE WHEN
- You need agent identity or permission info → use symaira_whoami
- You need vault unlock status → use get_auth_status

## INPUT
No arguments required.

## OUTPUT
```json
{
  "status": "healthy",
  "version": "2.2.0",
  "server_mode": "stdio",
  "timestamp": "2026-05-18T10:30:00Z"
}
```

## COMBINES WELL WITH
- symaira_whoami (agent context)
- get_auth_status (vault unlock state)

## EXAMPLE
`{}` → `{"status": "healthy", "version": "2.2.0", ...}`
