# OpenPass for Neovim

Neovim plugin for [OpenPass](https://github.com/danieljustus/OpenPass) — a modern, secure command-line password manager.

Browse, search, copy, and insert secrets from your OpenPass vault without leaving Neovim. All secret values are masked as `***` in the UI.

## Prerequisites

- **OpenPass CLI** installed and configured (`brew install openpass` or see [installation docs](https://github.com/danieljustus/OpenPass#installation))
- **Neovim** >= 0.7
- **[plenary.nvim](https://github.com/nvim-lua/plenary.nvim)** — required for HTTP requests
- **OpenPass MCP server** running: `openpass serve --port 8080`

## Installation

### lazy.nvim

```lua
{
  dir = "/path/to/openpass/editors/nvim",
  dependencies = { "nvim-lua/plenary.nvim" },
  cmd = { "OpenPassList", "OpenPassGet", "OpenPassCopy", "OpenPassGenerate", "OpenPassFind", "OpenPassGenerateTOTP" },
  opts = {},
}
```

### packer.nvim

```lua
use {
  "/path/to/openpass/editors/nvim",
  requires = { "nvim-lua/plenary.nvim" },
  config = function()
    require("openpass").setup()
  end,
}
```

### Manual

```lua
-- Add to your init.lua
vim.opt.runtimepath:append("/path/to/openpass/editors/nvim")
require("openpass").setup()
```

## Configuration

```lua
require("openpass").setup({
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
| `:OpenPassList` | Browse vault entries with interactive picker |
| `:OpenPassGet [path]` | Insert password at cursor (picker if no path) |
| `:OpenPassCopy [path]` | Copy password to clipboard (picker if no path) |
| `:OpenPassGenerate [length]` | Generate password and insert at cursor (default: 24) |
| `:OpenPassFind [query]` | Search vault entries (prompt if no query) |
| `:OpenPassGenerateTOTP [path]` | Generate TOTP code and insert at cursor (picker if no path) |

## Health Check

Run `:checkhealth openpass` to verify:
- MCP token is present
- plenary.nvim is installed
- OpenPass CLI is in PATH
- MCP server is reachable

## Usage Tips

- **Picker navigation**: Use `<C-j>`/`<C-k>` or `j`/`k` to move, `<CR>` to select, `<Esc>` to cancel
- **Detail view**: Selecting an entry in `OpenPassList` shows masked details in a floating window; press `q` to close
- **Direct access**: `:OpenPassGet github.password` inserts directly without the picker
- **Clipboard safety**: `:OpenPassCopy` uses the server-side `copy_to_clipboard` tool (auto-clears after OpenPass clipboard timeout)

## Security

- All secret values displayed as `***` in the UI
- Secrets never stored in Neovim state, registers, or logs
- Clipboard operations go through `copy_to_clipboard` MCP tool (server-side auto-clear)
- Token read from `~/.openpass/mcp-token` each session; never cached in plugin state

## Development

The plugin uses `plenary.curl` for HTTP and Lua's `vim.json` for JSON-RPC 2.0 encoding. Key modules:

```
lua/openpass/
  init.lua        -- Entry point, setup(), curl helper registration
  config.lua      -- Default configuration
  client.lua      -- JSON-RPC 2.0 client using plenary.curl
  auth.lua        -- Token reading and header construction
  masking.lua     -- Secret masking (***)
  picker.lua      -- vim.ui.select-based vault picker
  commands.lua    -- :OpenPass* user commands
  health.lua      -- :checkhealth integration
```

## License

MIT — see [LICENSE](../../LICENSE) in the OpenPass repository.
