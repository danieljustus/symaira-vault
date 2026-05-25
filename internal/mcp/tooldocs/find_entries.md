# Tool: find_entries

Search vault for entries by query string.

## USE WHEN
- User describes a credential by service name, brand, URL, or fuzzy keyword
- You don't have the exact path
- You want to confirm an entry exists before reading it

## DON'T USE WHEN
- You already have the exact path → use get_entry_metadata or get_entry
- You're checking if vault is unlocked → use symaira_whoami or health
- You need full-text search across field content → use symaira_search

## INPUT
- query (string, required): keyword(s) to match against paths and indexed fields
- limit (int, optional, default 20): max results
- mode (string, optional, "fuzzy"|"exact", default "fuzzy")

## OUTPUT
Array of `{ path, name, updated, version, score }`

## COMBINES WELL WITH
- get_entry_metadata (verify match details before read)
- get_entry (read full content)
- copy_to_clipboard (consume without revealing)
- request_credential (capture if not found)

## EXAMPLE
```json
{"query": "github", "limit": 5}
```
→ `[{"path": "github/personal", "name": "GitHub Personal", "updated": "2026-05-01T12:00:00Z", "version": 3, "score": 0.95}]`
