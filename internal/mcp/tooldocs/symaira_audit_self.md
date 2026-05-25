# Tool: symaira_audit_self

Return the current session's audit log entries for self-review.

## USE WHEN
- You want to verify your own recent tool usage
- You need to confirm what actions were taken in the current session
- You're debugging an unexpected result and want to trace tool calls

## DON'T USE WHEN
- You need server health → use health
- You need agent identity → use symaira_whoami
- You need system-wide audit logs (requires admin CLI)

## INPUT
- limit (int, optional, default 20): max log entries to return
- since (string, optional): ISO 8601 timestamp to filter entries after

## OUTPUT
```json
{
  "entries": [
    {
      "timestamp": "2026-05-18T10:30:00Z",
      "tool": "get_entry_metadata",
      "path": "github",
      "success": true
    }
  ],
  "total": 1
}
```

## COMBINES WELL WITH
- symaira_whoami (confirm agent identity before auditing)

## EXAMPLE
`{"limit": 5}` → Array of recent audit log entries for the current agent
