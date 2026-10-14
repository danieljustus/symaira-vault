# Symaira Vault Homebrew Formula

Local Homebrew formula support for [Symaira Vault](https://github.com/danieljustus/symaira-vault) - a modern CLI password manager built with Go and age encryption.

## Installation

Use the release binaries from GitHub or install from source with Go. The formula
in this directory is intended for local formula validation and future tap
publishing.

## Testing the formula template locally

The checked-in formula is a reference template, not an installable release
formula. Before copying it into a tap, render or replace every `{{ ... }}`
placeholder with the intended source tag, version, source archive SHA-256,
commit and date. Verify the resulting URL (the template already prefixes the
tag with `v`). Only `main.version`, `main.commit` and `main.date` exist in
`main.go`; remove the unsupported `main.builtBy` assignment from the rendered
copy. See `.goreleaser.yml` for the current release formula configuration.

Homebrew 5 requires formula files to live in a tap. From the repository root, create a throwaway local tap and install the prepared formula from it:

```bash
brew tap-new local/symvault || true
cp /path/to/rendered/symvault.rb "$(brew --repository)/Library/Taps/local/homebrew-symvault/Formula/symvault.rb"
brew install --build-from-source local/symvault/symvault
brew test local/symvault/symvault
symvault version
```

To reinstall after editing the rendered formula:

```bash
brew uninstall symvault
cp /path/to/rendered/symvault.rb "$(brew --repository)/Library/Taps/local/homebrew-symvault/Formula/symvault.rb"
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
symvault agent install claude-code --config-only
```

## Documentation

Full documentation is available at: https://github.com/danieljustus/symaira-vault

## License

Apache-2.0 License - see https://github.com/danieljustus/symaira-vault/blob/main/LICENSE
