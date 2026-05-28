# Migration Guide: OpenPass → Symaira Vault

This guide covers migrating from **OpenPass** (legacy name) to **Symaira Vault**
(v0.1.0+). Your vault data and configuration remain fully intact — only the
project and CLI binary names change.

---

## Quick Summary

| What changed | Old | New |
|---|---|---|
| **CLI command** | `openpass` | `symvault` |
| **Product name** | OpenPass | Symaira Vault |
| **GitHub repo** | `danieljustus/OpenPass` | `danieljustus/symaira-vault` |
| **Go module** | `github.com/danieljustus/OpenPass` | `github.com/danieljustus/symaira-vault` |
| **Homebrew formula** | `openpass` | `symvault` |
| **Scoop package** | `openpass` | `symvault` |

**Your vault data stays the same.** The rename is cosmetic; no vault migration is
required.

---

## Before You Start

### Verify your current version

```bash
openpass version
# or
symvault version      # if already updated
```

### Back up your vault (recommended)

```bash
# Option 1: Copy the vault directory
cp -a ~/.openpass ~/.openpass.backup.$(date +%Y%m%d)

# Option 2: Use the built-in backup command
openpass backup ~/backups/openpass-pre-rename-$(date +%Y%m%d).tar.gz
```

---

## Migration Steps

### 1. Install the new binary

#### Homebrew (macOS / Linux)

Existing OpenPass Homebrew users:

```bash
brew update
brew upgrade openpass
```

This installs the new `symvault` command and keeps `openpass` as a
backward-compatible alias. To switch to the new formula name later:

```bash
brew uninstall openpass
brew tap danieljustus/tap
brew install symvault
```

New users can install `symvault` directly.

#### Scoop (Windows)

```powershell
# Uninstall old
scoop uninstall openpass

# Install new
scoop install symvault
```

#### Go install

```bash
go install github.com/danieljustus/symaira-vault@latest
```

#### Nix

```bash
# Update the flake input
nix profile upgrade symvault
# or
nix run github:danieljustus/symaira-vault -- --help
```

#### Docker

```bash
docker pull ghcr.io/danieljustus/symaira-vault:latest
```

### 2. Verify the installation

```bash
symvault --help
symvault version
symvault doctor       # Health-check your vault
```

### 3. Confirm your data is intact

```bash
symvault list         # All entries should appear
symvault auth status  # Identity should be recognised
```

Existing OpenPass vaults at `~/.openpass` are detected automatically when no
`~/.symvault` vault exists. New Symaira Vault installations use `~/.symvault` by
default.

### 4. Update shell completions (optional)

If you generated completions for the old binary, regenerate them:

```bash
# Bash
symvault completion bash > /usr/local/etc/bash_completion.d/symvault

# Zsh
symvault completion zsh > "${fpath[1]}/_symvault"

# Fish
symvault completion fish > ~/.config/fish/completions/symvault.fish
```

### 5. Update MCP configuration (if applicable)

If you use the MCP server with AI editors, regenerate the MCP config:

```bash
# For Claude Code
symvault mcp-config claude-code

# For Cursor
symvault mcp-config cursor

# For VS Code / Neovim / etc.
symvault mcp-config <editor>
```

### 6. Update aliases and scripts (optional)

If you have shell aliases or scripts that call `openpass`, update them:

```bash
# In ~/.bashrc, ~/.zshrc, etc.
# Old: alias op='openpass'
# New:
alias op='symvault'
```

Or keep a backward-compatible alias during transition:

```bash
alias openpass='symvault'
```

### 7. Update systemd / launchd services (if applicable)

If you run `symvault serve` as a background service, update the service files:

```bash
# macOS (launchd)
symvault mcp install launchd

# Linux (systemd)
symvault mcp install systemd
```

This will install new service files under the `symvault` name.

### 8. Update editor extensions (if applicable)

If you use the VS Code, Cursor, or Neovim extensions:

1. Uninstall the old extension (e.g., `symaira-vscode` or `openpass-vscode`)
2. Install the new one from the marketplace or build from source:
   ```bash
   make package-vscode
   code --install-extension dist/symvault-vscode-*.vsix
   ```

### 9. Update CI / automation scripts

If you use `openpass` in CI pipelines or automation scripts:

- Replace `openpass` with `symvault` in all scripts
- Update GitHub Actions that reference the old repo name
- Update Docker image tags from `openpass` to `symvault`

---

## Environment Variables

The following environment variables have been renamed:

| Old | New |
|---|---|
| `OPENPASS_VAULT` | `SYMVAULT_VAULT` |
| `OPENPASS_CONFIG` | `SYMVAULT_CONFIG` |
| `OPENPASS_AGENT` | `SYMVAULT_AGENT` |

**Backward compatibility:** If `SYMVAULT_VAULT` is not set, Symaira Vault still
falls back to `OPENPASS_VAULT`. Deprecated `OPENPASS_*` variables emit a warning
and are scheduled for removal three releases after 2026-05-26.

---

## Data Directory

New Symaira Vault installations use `~/.symvault` as the default vault
directory. Existing OpenPass installations continue to work without moving data:
if `~/.openpass` contains a vault and `~/.symvault` does not, `symvault` uses
`~/.openpass` automatically.

If both directories exist, `~/.symvault` wins. Use `--vault`, `SYMVAULT_VAULT`,
or a configured profile to select another vault explicitly.

If you prefer to align the directory name with the new project name:

```bash
# 1. Close any running symvault processes
pkill symvault

# 2. Move the directory
mv ~/.openpass ~/.symvault

# 3. Set the environment variable
export SYMVAULT_VAULT="$HOME/.symvault"

# 4. Add to your shell profile
echo 'export SYMVAULT_VAULT="$HOME/.symvault"' >> ~/.zshrc
```

---

## GitHub Repo Redirect

GitHub automatically redirects the old repo URL:

- `https://github.com/danieljustus/OpenPass` →
  `https://github.com/danieljustus/symaira-vault`

This means:
- Existing Git remotes in cloned repos continue to work
- Old release download URLs redirect
- Old issue and PR links redirect

**Note:** Go module proxy (`proxy.golang.org`) has cached the old module name.
Both `github.com/danieljustus/OpenPass` and
`github.com/danieljustus/symaira-vault` remain resolvable via the proxy.

---

## Rollback

If you need to revert to the old OpenPass binary:

```bash
# Re-install the last OpenPass release
go install github.com/danieljustus/OpenPass@v4.0.0
# or
brew install danieljustus/tap/openpass@4.0.0
```

Your vault data remains compatible. Both binaries read the same vault format.

---

## FAQ

### Q: Do I need to re-initialise my vault?
**A:** No. Your existing vault (`~/.openpass`) works with Symaira Vault without
any changes.

### Q: Will `symvault` create a new vault if I already have one?
**A:** No. If `~/.openpass` exists and `~/.symvault` does not, it will detect and
use the existing OpenPass vault. If both directories exist, `~/.symvault` is the
default; set `SYMVAULT_VAULT="$HOME/.openpass"` or pass `--vault ~/.openpass` to
select the old vault explicitly.

### Q: What happens to my Git sync remote?
**A:** Nothing. The sync remote URL is stored in your vault config and remains
unchanged.

### Q: Can I have both `openpass` and `symvault` installed?
**A:** Yes, but only one should be active at a time. They share the same vault
and could conflict if both try to lock/unlock simultaneously.

### Q: Do I need to regenerate my GPG keys?
**A:** No. Your identity and recipient keys remain valid.

### Q: What about the browser extension?
**A:** The browser extension (if applicable) will be updated separately. Check
the extension's settings page for update instructions.

---

## Troubleshooting

### `symvault` command not found after installation

Ensure the binary is in your `PATH`:

```bash
# Homebrew
export PATH="/opt/homebrew/bin:$PATH"

# Go install
export PATH="$(go env GOPATH)/bin:$PATH"

# Scoop
# Already in PATH by default
```

### Vault directory not found

If `symvault` cannot find your vault:

```bash
# Explicitly point to your old vault
SYMVAULT_VAULT="$HOME/.openpass" symvault list

# Or set permanently
symvault config set vaultDir "$HOME/.openpass"
```

### MCP server not connecting after migration

Regenerate the MCP config for your editor:

```bash
symvault mcp-config <editor>
```

Then restart the editor.

### Completion scripts still reference `openpass`

Remove old completion files and regenerate:

```bash
# Bash
rm -f /usr/local/etc/bash_completion.d/openpass
symvault completion bash > /usr/local/etc/bash_completion.d/symvault

# Zsh
rm -f "${fpath[1]}/_openpass"
symvault completion zsh > "${fpath[1]}/_symvault"

# Fish
rm -f ~/.config/fish/completions/openpass.fish
symvault completion fish > ~/.config/fish/completions/symvault.fish
```

---

## Support

If you encounter issues during migration:

1. Run `symvault doctor` for a self-diagnosis
2. Check the [troubleshooting guide](troubleshooting.md)
3. Open an issue at [github.com/danieljustus/symaira-vault/issues](https://github.com/danieljustus/symaira-vault/issues)

---

*Last updated: 2026-05-25*
