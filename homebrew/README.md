# Symaira Vault Homebrew Formula

Local Homebrew formula support for [Symaira Vault](https://github.com/danieljustus/symaira-vault) - a modern CLI password manager built with Go and age encryption.

## Installation

Use the release binaries from GitHub or install from source with Go. The formula
in this directory is intended for local formula validation and future tap
publishing.

## Testing the v1.0.0 formula locally

The checked-in formula builds from the `v1.0.0` source tag and is intended for local formula testing.

Homebrew 5 requires formula files to live in a tap. From the repository root, create a throwaway local tap and install from it:

```bash
brew tap-new local/symaira || true
cp homebrew/Formula/symaira.rb "$(brew --repository)/Library/Taps/local/homebrew-symaira/Formula/symaira.rb"
brew install --build-from-source local/symaira/symaira
brew test local/symaira/symaira
symaira version
```

To reinstall after editing the formula:

```bash
brew uninstall symaira
cp homebrew/Formula/symaira.rb "$(brew --repository)/Library/Taps/local/homebrew-symaira/Formula/symaira.rb"
brew install --build-from-source local/symaira/symaira
brew test local/symaira/symaira
```

To remove the local test install:

```bash
brew uninstall symaira
brew untap local/symaira
```

## Features

- 🔐 **Age encryption** - Modern, simple, and secure file encryption
- 🖥️ **CLI-first** - Fast, scriptable, and works everywhere
- 🔑 **MCP server** - AI agent integration via Model Context Protocol
- 👥 **Multi-user** - Share vaults with team members
- 🔄 **Git integration** - Version control your passwords
- 🛡️ **TOTP support** - Generate 2FA codes
- 📋 **Clipboard** - Auto-clear for secure copying

## Quick Start

```bash
# Initialize a new vault
symaira init

# Add your first entry
symaira set github.com/username

# Retrieve it
symaira get github.com/username

# Generate a password
symaira generate

# Set up MCP server for AI agents
symaira mcp-config claude-code
```

## Documentation

Full documentation is available at: https://github.com/danieljustus/symaira-vault

## License

MIT License - see https://github.com/danieljustus/symaira-vault/blob/main/LICENSE
