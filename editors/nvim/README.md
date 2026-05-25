# Symaira Vault for Neovim

Neovim plugin for [(Symaira Vault)](https://github.com/danieljustus/symaira-vault) — a modern, secure command-line password manager.

Browse, search, copy, and insert secrets from your (Symaira Vault) vault without leaving Neovim. All secret values are masked as `***` in the UI.

## Prerequisites

- **Symaira Vault CLI** installed and configured (`brew install symvault` or see [installation docs](https://github.com/danieljustus/symaira-vault#installation))
- **Neovim** >= 0.7
- **[plenary.nvim](https://github.com/nvim-lua/plenary.nvim)** — required for HTTP requests
- **Symaira Vault MCP server** running: `symvault serve --port 8080`

## Installation

### lazy.nvim

```lua
{
  dir = "/path/to/symvault/editors/nvim",
  dependencies = { "nvim-lua/plenary.nvim" },
  cmd = { "SymairaList", "SymairaGet", "SymairaCopy", "SymairaGenerate", "SymairaFind", "SymairaGenerateTOTP" },
  opts = {},
}
```

### packer.nvim

```lua
use {
  "/path/to/symvault/editors/nvim",
  requires = { "nvim-lua/plenary.nvim" },
  config = function()
    require("symvault").setup()
  end,
}
```

### Manual

```lua
-- Add to your init.lua
vim.opt.runtimepath:append("/path/to/symvault/editors/nvim")
require("symvault").setup()
```

## Configuration

```lua
require("symvault").setup({
  base_url = "http://127.0.0.1:8080",  -- MCP server URL
  agent_name = "nvim",                  -- Agent identifier sent to server
  timeout_ms = 30000,                   -- HTTP request timeout
  masking_char = "*",                   -- Character used for masking
  preserve_keys = { "path", "meta", "type", "name", "version", "created", "updated" },
})
```

## Commands

| Command | Description |
|---------|-------------|
| `:SymairaList` | Browse vault entries with interactive picker |
| `:SymairaGet [path]` | Insert password at cursor (picker if no path) |
| `:SymairaCopy [path]` | Copy password to clipboard (picker if no path) |
| `:SymairaGenerate [length]` | Generate password and insert at cursor (default: 24) |
| `:SymairaFind [query]` | Search vault entries (prompt if no query) |
| `:SymairaGenerateTOTP [path]` | Generate TOTP code and insert at cursor (picker if no path) |

## Health Check

Run `:checkhealth symvault` to verify:
- MCP token is present
- plenary.nvim is installed
- Symaira Vault CLI is in PATH
- MCP server is reachable

## Usage Tips

- **Picker navigation**: Use `<C-j>`/`<C-k>` or `j`/`k` to move, `<CR>` to select, `<Esc>` to cancel
- **Detail view**: Selecting an entry in `SymairaList` shows masked details in a floating window; press `q` to close
- **Direct access**: `:SymairaGet github.password` inserts directly without the picker
- **Clipboard safety**: `:SymairaCopy` uses the server-side `copy_to_clipboard` tool (auto-clears after Symaira Vault clipboard timeout)

## Security

- All secret values displayed as `***` in the UI
- Secrets never stored in Neovim state, registers, or logs
- Clipboard operations go through `copy_to_clipboard` MCP tool (server-side auto-clear)
- Token read from `~/.openpass/mcp-token` each session; never cached in plugin state

## Development

The plugin uses `plenary.curl` for HTTP and Lua's `vim.json` for JSON-RPC 2.0 encoding. Key modules:

```
lua/symvault/
  init.lua        -- Entry point, setup(), curl helper registration
  config.lua      -- Default configuration
  client.lua      -- JSON-RPC 2.0 client using plenary.curl
  auth.lua        -- Token reading and header construction
  masking.lua     -- Secret masking (***)
  picker.lua      -- vim.ui.select-based vault picker
  commands.lua    -- :Symaira* user commands
  health.lua      -- :checkhealth integration
```

## License

MIT — see [LICENSE](../../LICENSE) in the Symaira Vault repository.
