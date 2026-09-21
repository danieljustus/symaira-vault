# claude-code Symaira Vault Skill — Manual Install

This skill was exported by Symaira Vault v{{VERSION_RAW}}.

## Steps

1. Place SKILL.md in your agent's skill directory.
2. Create a scoped access token:
   symvault agent token new claude-code --tools list_entries,get_entry --ttl 90d
3. Restart your agent.

## Verification

Run the agent's MCP discovery command to verify Symaira Vault tools are available.
