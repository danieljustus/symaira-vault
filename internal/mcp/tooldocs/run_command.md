# Tool: run_command

Execute a command on the host with secrets injected as environment variables. Requires command execution permission.

## USE WHEN
- You need to run a CLI tool with credentials that are stored in the vault
- You want to avoid exposing secret values in the conversation
- The task requires shelling out (git, curl, terraform, npm, docker, kubectl, etc.)

## DON'T USE WHEN
- You just need to read a credential value → use get_entry_value
- You need HTTP API access with template-based credentials → use execute_api_request
- The command is destructive and could cause damage without user oversight
- The command doesn't need vault secrets → consider if this is the right approach

## INPUT
- command (array, required): command and arguments as strings (e.g. `["gh", "api", "user"]` with `GH_TOKEN` injected)
- env (object, optional): map of env var names to vault secret references (e.g. `{"API_KEY": "github.api_key"}`)
- working_dir (string, optional): working directory for the command
- timeout (number, optional, default 30): timeout in seconds

## OUTPUT
```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "duration_ms": 245
}
```

## NOTES
- Requires `canRunCommands: true` in agent profile
- Arguments are passed directly to the executable; `$VAR` is not expanded. Prefer tools that read their environment. An explicit shell must already be permitted by the executable policy and can expose expanded secrets in subprocess argv.
- Each secret ref is scope-checked individually
- Secret values are never exposed in the MCP response or audit logs
- Output is capped at 100KB per stream
- Timeout kills the process with exit code -1

## COMBINES WELL WITH
- find_entries / get_entry (find secrets to inject)
- execute_with_secret (alternative with op:// references)
- execute_api_request (HTTP-specific alternative with templates)

## EXAMPLE
```json
{
  "command": ["gh", "api", "user"],
  "env": {"GH_TOKEN": "github.api_key"},
  "timeout": 15
}
```
→ Executes gh, which reads the token from GH_TOKEN environment variable
