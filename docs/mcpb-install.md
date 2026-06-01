# MCP Bundle (.mcpb) Installation

The MCP Bundle format (`.mcpb`) packages the Symaira Vault MCP server as a single distributable file for easy installation in Claude Desktop and other MCP clients.

## What is a .mcpb Bundle?

A `.mcpb` file is a ZIP archive containing:

```
bundle.mcpb
├── manifest.json       # MCP Bundle manifest (v0.3)
└── server/
    └── symvault        # Symaira Vault binary
```

The `manifest.json` declares the server metadata and how to launch it:

```json
{
  "manifest_version": "0.3",
  "name": "symvault",
  "version": "<version>",
  "description": "Secure password manager MCP server",
  "author": {"name": "danieljustus"},
  "server": {
    "type": "binary",
    "entry_point": "server/symvault",
    "mcp_config": {
      "command": "${__dirname}/server/symvault",
      "args": ["serve", "--stdio"]
    }
  }
}
```

## Downloading

Download the `.mcpb` file for your platform from the [latest release](https://github.com/danieljustus/symaira-vault/releases/latest):

```bash
# macOS arm64 (Apple Silicon) - recommended for M1/M2/M3 Macs
curl -fLO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_darwin_arm64.mcpb

# macOS amd64 (Intel)
curl -fLO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_darwin_amd64.mcpb

# Linux amd64
curl -fLO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_linux_amd64.mcpb

# Linux arm64
curl -fLO https://github.com/danieljustus/symaira-vault/releases/latest/download/symvault_<version>_linux_arm64.mcpb
```

## Installing in Claude Desktop

### macOS

1. Create the MCP bundles directory if it doesn't exist:
   ```bash
   mkdir -p ~/Library/Application\ Support/Claude/mcp-bundles
   ```

2. Copy the `.mcpb` file:
   ```bash
   cp symvault_*.mcpb ~/Library/Application\ Support/Claude/mcp-bundles/
   ```

3. Restart Claude Desktop. The symvault MCP server will be available automatically.

### Linux

1. Create the MCP bundles directory:
   ```bash
   mkdir -p ~/.config/Claude/mcp-bundles
   ```

2. Copy the `.mcpb` file:
   ```bash
   cp symvault_*.mcpb ~/.config/Claude/mcp-bundles/
   ```

3. Restart Claude Desktop.

### Windows

1. Create the MCP bundles directory:
   ```powershell
   New-Item -ItemType Directory -Force -Path "$env:APPDATA\Claude\mcp-bundles"
   ```

2. Copy the `.mcpb` file:
   ```powershell
   Copy-Item symvault_*.mcpb "$env:APPDATA\Claude\mcp-bundles\"
   ```

3. Restart Claude Desktop.

## Verification

After installing, verify the bundle is correctly set up:

```bash
# Extract and inspect the bundle
unzip -q symvault_*.mcpb -d /tmp/mcpb-verify
cat /tmp/mcpb-verify/manifest.json
/tmp/mcpb-verify/server/symvault version
rm -rf /tmp/mcpb-verify
```

Check that `manifest.json` contains:
- `"manifest_version": "0.3"`
- `"server": {"type": "binary", ...}`
- `"args": ["serve", "--stdio"]`

## Using in Claude Code

Claude Code does not use the `.mcpb` bundle format directly. Instead, configure the MCP server in your `.claude.json`:

```json
{
  "mcpServers": {
    "symvault": {
      "command": "symvault",
      "args": ["serve", "--stdio"]
    }
  }
}
```

Or use the automatic config generator:

```bash
symvault mcp-config claude-code
```

## Building from Source

To build a `.mcpb` bundle from a local build:

```bash
# Build the binary
make build

# Create the .mcpb bundle
scripts/build-mcpb.sh --version "$(git describe --tags --always)" --os "$(go env GOOS)" --arch "$(go env GOARCH)" --binary ./symvault
```

The output file `dist/symvault_<version>_<os>_<arch>.mcpb` can be installed as described above.
