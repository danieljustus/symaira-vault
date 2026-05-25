# TUI Mode

Symaira Vault includes an interactive terminal UI for browsing, filtering, and managing vault entries without memorizing individual commands. Use it when you want a keyboard-driven view of your vault, quick password copying, or lightweight entry management from a terminal session.

## Launching

Start the TUI with:

```bash
symvault ui
```

The TUI uses your configured vault, the same session cache as other Symaira Vault commands, and the same clipboard auto-clear behavior.

## Layout

The interface uses a two-column layout:

| Column | Description |
|--------|-------------|
| Entry list | Shows vault entries and supports keyboard navigation and filtering |
| Entry details | Shows fields for the selected entry, with sensitive values hidden by default |

The selected entry in the list controls what appears in the details column.

## Navigation

| Key | Action |
|-----|--------|
| `Up` / `Down` | Move through entries |
| `j` / `k` | Move down or up through entries |
| `/` | Filter entries |
| `Enter` | Copy the selected entry password to the clipboard |
| `r` | Reveal or hide sensitive fields |
| `e` | Edit the selected entry in `$EDITOR` |
| `d` | Delete the selected entry after confirmation |
| `g` | Generate a new password |
| `?` | Show the help overlay |
| `q` | Quit |

## Security

The TUI is read-first by default: selecting an entry shows its metadata and non-sensitive fields, while secrets remain hidden until you press `r`. Destructive actions such as deletion require confirmation before the vault is modified.

Editing opens the selected entry in `$EDITOR`, so review your editor configuration and temporary file handling if you use a shared system.

## Clipboard

Press `Enter` to copy the selected entry password to the clipboard. Symaira Vault automatically clears copied secrets after the configured clipboard timeout; set `auto_clear_duration` in `~/.openpass/config.yaml` to adjust the timeout or use `0` to disable auto-clear.
