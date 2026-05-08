# OpenPass Editor Plugins

IDE and editor integrations for OpenPass secret manager.

## Supported Editors

| Editor | Status | Installation |
|--------|--------|--------------|
| VS Code | Ready | `.vsix` or Marketplace |
| Cursor | Ready | `.vsix` |
| Neovim | Ready | lazy.nvim / packer / manual |

## Architecture

All editor plugins communicate with `openpass serve` via HTTP JSON-RPC 2.0 MCP protocol:

```
Editor Plugin <-> HTTP POST 127.0.0.1:8080/mcp <-> OpenPass MCP Server
```

Authentication uses the bearer token from `~/.openpass/mcp-token`.

## Quick Start

### Prerequisites

1. Install OpenPass CLI:
   ```bash
   brew install openpass
   # or see main README for other methods
   ```

2. Initialize vault:
   ```bash
   openpass init
   ```

3. Start MCP server:
   ```bash
   openpass serve --port 8080
   ```

### VS Code

1. Install the `.vsix`:
   ```bash
   code --install-extension openpass-vscode-1.0.0.vsix
   ```

2. Open sidebar: Explorer → "OpenPass Vault"

3. Use commands:
   - `OpenPass: Insert Secret` - Insert secret reference at cursor
   - `OpenPass: Copy to Clipboard` - Copy secret to clipboard
   - `OpenPass: Generate Password` - Generate secure password

### Cursor

1. Install the `.vsix` in Cursor
2. Automatically injects OpenPass context into `.cursorrules`
3. Use `OpenPass: Refresh Context` command to update

### Neovim

With lazy.nvim:
```lua
{
  dir = "/path/to/openpass/editors/nvim",
  opts = {},
  cmd = { "OpenPassList", "OpenPassGet", "OpenPassCopy", "OpenPassGenerate" }
}
```

Commands:
- `:OpenPassList` - Browse vault entries
- `:OpenPassGet <path>` - Insert secret at cursor
- `:OpenPassCopy <path>` - Copy secret to clipboard
- `:OpenPassGenerate [length]` - Generate password

## Security

- All secret values are displayed as `***` in editor UI
- Actual values are only retrieved via MCP `copy_to_clipboard` or `autotype` tools
- Never stored in editor state or logs

## Development

```bash
# Build all plugins
make editors-build

# Test all plugins
make editors-test

# Package for distribution
make editors-package
```
