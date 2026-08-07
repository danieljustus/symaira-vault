# Tool: secure_input

Prompt the user for sensitive data via TTY or native GUI dialog and store it without exposing the value to the agent.

## USE WHEN
- You need to store a secret that the user can provide (password, API key, token)
- The user should type the value themselves rather than revealing it in chat
- You're setting up a new service or account credential

## DON'T USE WHEN
- The credential already exists in the vault → use find_entries / get_entry
- You already have the value and just need to store it → use set_entry_field
- You're not in an interactive session (no TTY/GUI) → tool will be unavailable
- The user isn't available to type the value → use set_entry_field with an agent-provided value

## INPUT
- path (string, required): entry path to store the value (e.g. "new-service")
- field (string, required): field name to store the value under (e.g. "password", "api_key")
- description (string, optional): description shown to the user in the prompt

## OUTPUT
```json
{
  "success": true,
  "path": "new-service",
  "field": "password"
}
```

## NOTES
- Available whenever any secure-input backend is reachable (TTY or native GUI dialog)
- The agent never sees the value being stored
- Requires `canWrite: true` in agent profile
- Triggers automatic git commit (if enabled)
- Use `SYMVAULT_SECUREUI=tty|gui|none` to override the backend

## COMBINES WELL WITH
- find_entries (verify credential doesn't exist yet)
- request_credential (agent-initiated variant with reason string)

## EXAMPLE
`{"path": "new-service", "field": "password", "description": "Enter the admin password for new-service"}` → user prompted, value stored securely
