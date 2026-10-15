# Symaira Vault Editor Plugins

IDE and editor integrations for Symaira Vault secret manager.

## Supported Editors

| Editor | Status | Installation |
|--------|--------|--------------|
| VS Code | Ready | `.vsix` or Marketplace |
| Cursor | Ready | `.vsix` |
| Neovim | Ready | lazy.nvim / packer / manual |

## Architecture

All editor plugins communicate with `symvault mcp` via HTTP JSON-RPC 2.0 MCP protocol:

```
Editor Plugin <-> HTTP POST 127.0.0.1:8080/mcp <-> Symaira Vault MCP Server
```

Authentication uses the bearer token from `~/.symvault/mcp-token`.

## Quick Start

### Prerequisites

1. Install Symaira CLI:
   ```bash
   brew install symvault
   # or see main README for other methods
   ```

2. Initialize vault:
   ```bash
   symvault init
   ```

3. Start MCP server:
   ```bash
   symvault mcp --port 8080
   ```

### VS Code

1. Install the `.vsix`:
   ```bash
   code --install-extension symvault-vscode-1.0.0.vsix
   ```

2. Open sidebar: Explorer → "Symaira Vault"

3. Use commands:
   - `Symaira Vault: Insert Secret` - Insert secret reference at cursor
   - `Symaira Vault: Copy to Clipboard` - Copy secret to clipboard
   - `Symaira Vault: Generate Password` - Generate secure password

### Cursor

1. Install the `.vsix` in Cursor
2. Automatically injects Symaira Vault context into `.cursorrules`
3. Use `Symaira Vault: Refresh Context` command to update

### Neovim

With lazy.nvim:
```lua
{
  dir = "/path/to/symvault/editors/nvim",
  main = "symaira",
  dependencies = { "nvim-lua/plenary.nvim" },
  opts = {},
  cmd = { "SymairaList", "SymairaGet", "SymairaCopy", "SymairaGenerate" }
}
```

Commands:
- `:SymairaList` - Browse vault entries
- `:SymairaGet <path>` - Insert secret at cursor
- `:SymairaCopy <path>` - Copy secret to clipboard
- `:SymairaGenerate [length]` - Generate password

## Security

- Neovim entry details mask secret fields as `***`
- Neovim insertion commands retrieve passwords/generated secrets and intentionally put plaintext in buffers
- Inserted values can enter undo history, swap files, registers, or saved files
- Clipboard operations use the MCP `copy_to_clipboard` tool

## Development

```bash
# Build all plugins
make editors-build

# Test all plugins
make editors-test

# Package for distribution
make editors-package
```
