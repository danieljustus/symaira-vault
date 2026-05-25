# Tool: symaira_search

Full-text search across vault entries including indexed field content.

## USE WHEN
- You need to find entries by content (not just path)
- Text search across fields like URL, username, notes
- The query is specific enough to narrow results

## DON'T USE WHEN
- You want to search by path prefix only → use find_entries or list_entries
- You already know the exact path → use get_entry_metadata or get_entry
- A simple path search suffices → use find_entries (faster)

## INPUT
- query (string, required): text to search for in entry paths and indexed fields
- limit (int, optional, default 20): max results

## OUTPUT
Array of `{ path, name, updated, version, match_field, snippet }`

## COMBINES WELL WITH
- get_entry_metadata (verify match before reading)
- get_entry or get_entry_value (read matching entry)
- find_entries (broader path-first search)

## EXAMPLE
`{"query": "aws access key"}` → `[{"path": "work/aws", "match_field": "username", ...}]`
