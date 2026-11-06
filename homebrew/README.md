# Symaira Vault Homebrew Formula

Homebrew formula support for [Symaira Vault](https://github.com/danieljustus/symaira-vault) - a modern CLI password manager built with Rust and age encryption.

## Installation

```bash
brew install danieljustus/tap/symvault
```

`Formula/symvault.rb` in this directory is a rendered reference copy. It installs
the prebuilt Rust release archive (`symaira-vault_<version>_<os>_<arch>.tar.gz`,
which wraps `symvault`, `completions/` and `docs/man/`), not a source build. The
release workflow renders the real tap formula with
`scripts/homebrew-formula.sh VERSION CHECKSUMS_FILE`; the checked-in copy is that
script's output for the placeholder version `X.Y.Z` with all-zero checksums, so
regenerate it instead of editing it:

```bash
scripts/homebrew-formula.sh X.Y.Z placeholder-checksums.txt > homebrew/Formula/symvault.rb
```

## Testing the formula against a locally built archive

Homebrew 5 only loads formulae from a tap, so use a throwaway local tap. Build the
archive layout from a local release binary (`make completions release-manpages`
produce the completions and man pages), point the generator at it with
`SYMVAULT_RELEASE_BASE_URL`, and install:

```bash
# dist/ contains symaira-vault_<v>_darwin_arm64.tar.gz (+ linux archives) and
# symaira-vault_<v>_checksums.txt
SYMVAULT_RELEASE_BASE_URL=file://$PWD/dist \
  scripts/homebrew-formula.sh <v> dist/symaira-vault_<v>_checksums.txt > symvault.rb

brew tap-new local/symvault-test
cp symvault.rb "$(brew --repository)/Library/Taps/local/homebrew-symvault-test/Formula/symvault.rb"
brew install --formula local/symvault-test/symvault
brew test local/symvault-test/symvault   # version + init/set/get round trip
```

If `symvault` is already installed from another tap, give the throwaway copy a
different class/file name (for example `SymvaultTest` / `symvault-test.rb`) and add
`keg_only "local test"` so the existing install is left untouched.

Clean up:

```bash
brew uninstall symvault   # or the renamed test formula
brew untap local/symvault-test
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
