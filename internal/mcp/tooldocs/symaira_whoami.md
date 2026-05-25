# Tool: symaira_whoami

Return the current agent name, tier, and permission summary.

## USE WHEN
- You need to confirm which agent profile is active
- You want to verify your current tier (read-only, standard, admin)
- You're checking whether the vault is accessible before proceeding
- You want to see which capabilities are enabled (write, clipboard, commands, etc.)

## DON'T USE WHEN
- You only need vault health → use health
- You need to check auth status → use get_auth_status

## INPUT
No arguments required.

## OUTPUT
```json
{
  "agent": "claude-code",
  "tier": "standard",
  "capabilities": {
    "can_write": false,
    "can_run_commands": false,
    "can_use_clipboard": true,
    "can_use_autotype": true,
    "can_read_values": true
  },
  "vault_accessible": true
}
```

## COMBINES WELL WITH
- health (overall server status)
- get_auth_status (unlock state)

## EXAMPLE
`{}` → `{"agent": "claude-code", "tier": "standard", ...}`
