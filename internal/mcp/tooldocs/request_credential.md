# Tool: request_credential

Request the user to securely enter a credential the agent needs but cannot find in the vault. Opens a native input dialog (TTY or OS-native popup). The value is stored in the vault and never exposed to the agent.

## USE WHEN
- You searched for an expected credential (find_entries / get_entry) and found nothing
- You need a secret that the user hasn't stored in the vault yet
- Rather than asking the user for the secret in chat (which exposes it in chat history)

## DON'T USE WHEN
- The credential already exists in the vault → find it with find_entries/get_entry
- You just need to store a value you already have → use set_entry_field
- The user is not in an interactive session → will fail gracefully

## INPUT
- path (string, required): vault path to store the new credential (e.g. "github/api-token")
- field (string, required): field name (e.g. "token", "password", "api_key")
- reason (string, required): short human-readable reason shown in the dialog (why the agent needs this)

## OUTPUT
```json
{
  "success": true,
  "path": "github/api-token",
  "field": "token"
}
```

## COMBINES WELL WITH
- find_entries (verify not found before requesting)
- secure_input (same backend, agent-initiated variant)

## EXAMPLE
```json
{
  "path": "github/api-token",
  "field": "token",
  "reason": "Needed to push to main on the symaira repo"
}
```
→ User sees a dialog: "Symaira Vault needs a credential for 'github/api-token': Needed to push to main on the symaira repo"
