# Accessibility in OpenPass

OpenPass ships a terminal UI plus prompts that traditionally are hostile to
screen readers (box-drawing, ANSI color codes, dense status bars). This page
documents the accessibility hooks the tool exposes and the trade-offs we
have considered.

## Quick reference

| Setting                                | Effect                                                  |
|----------------------------------------|---------------------------------------------------------|
| `OPENPASS_SCREEN_READER=1`             | Skip box-drawing; emit "Label: value" lines             |
| `OPENPASS_ASCII=1`                     | ASCII fallbacks for ✓ ⚠ ✗ ▸ ·                            |
| `--theme highcontrast`                 | Maximum-contrast palette for low vision                 |
| `--theme colorblind`                   | Blue/orange replaces red/green                          |
| `--color=never`                        | No ANSI color at all                                    |
| `--no-pipe-warning`                    | Suppress one-shot stderr warnings (for scripted runs)   |
| `NO_COLOR=1`                           | Standard env (https://no-color.org); same as `--color=never` |

## What's supported today

### Secure-input prompts (`internal/secureui`)

When `OPENPASS_SCREEN_READER=1` is set, `internal/secureui/backend_tty.go`
emits a plain-text prompt instead of the box-drawing variant. NVDA, VoiceOver,
and Orca all speak it intelligibly.

### Themes (`internal/ui/theme`)

`ApplyPreset(PresetHighContrast)` swaps the magenta/cyan palette for a black/
white/yellow/blue set with high luminance contrast. `PresetColorblind` avoids
the red/green axis in favour of blue/orange — safe for deutan, protan, and
tritan vision per the Coblis simulator.

The preset is picked from `--theme` or `OPENPASS_THEME` on every `Execute()`.

### Symbol fallback

`internal/ui/theme.Detect()` falls back to ASCII symbols (`[OK] [!] [X] > .`)
on `LANG=C`, `OPENPASS_ASCII=1`, or any non-UTF-8 locale.

### Output color

`cliout.SetColorMode(ColorNever)` removes all ANSI. The `--color` flag is the
primary surface; `NO_COLOR` is honoured as a standard env.

## What's not supported (and why)

- **Live TUI in screen-reader mode**: the Bubble Tea vault browser still uses
  block characters and live cursor positioning that screen readers cannot
  follow in real time. Users who rely on assistive tech should use the
  non-interactive commands (`openpass get`, `openpass list --output json`,
  `openpass find`) instead, which already produce clean text.
- **OS-native dialogs**: `osascript`, `zenity`, and PowerShell handle their
  own accessibility via the host platform; OpenPass does not set ARIA labels
  beyond what the dialog APIs expose.

## Reporting

If a flow is unreachable for you, please open an issue with the screen
reader you use and the command that broke. We will tag it `a11y` and try
to fix it without breaking the visual UI.
