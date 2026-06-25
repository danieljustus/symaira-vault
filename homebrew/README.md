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
brew tap-new local/symvault || true
cp homebrew/Formula/symvault.rb "$(brew --repository)/Library/Taps/local/homebrew-symvault/Formula/symvault.rb"
brew install --build-from-source local/symvault/symvault
brew test local/symvault/symvault
symvault version
```

To reinstall after editing the formula:

```bash
brew uninstall symvault
cp homebrew/Formula/symvault.rb "$(brew --repository)/Library/Taps/local/homebrew-symvault/Formula/symvault.rb"
brew install --build-from-source local/symvault/symvault
brew test local/symvault/symvault
```

To remove the local test install:

```bash
brew uninstall symvault
brew untap local/symvault
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
symvault init

# Add your first entry
symvault set github.com/username

# Retrieve it
symvault get github.com/username

# Generate a password
symvault generate

# Set up MCP server for AI agents
symvault mcp-config claude-code
```

## Documentation

Full documentation is available at: https://github.com/danieljustus/symaira-vault

## License

Apache-2.0 License - see https://github.com/danieljustus/symaira-vault/blob/main/LICENSE
