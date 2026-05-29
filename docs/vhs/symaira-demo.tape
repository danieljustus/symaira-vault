# Symaira Vault demo tape (charmbracelet/vhs)
#
# Renders docs/assets/symvault-demo.gif. Re-render with:
#   go build -o /tmp/symvault . && vhs docs/vhs/symaira-demo.tape
#
# Requires: vhs, ttyd, ffmpeg, and an `symvault` binary on PATH (here: /tmp/symvault).

Output "docs/assets/symvault-demo.gif"

Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 50ms

Env PATH "/tmp:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
Env SYMVAULT_VAULT "/tmp/demo-vault"

Hide
Type "symvault lock >/dev/null 2>&1 || true"
Enter
Sleep 200ms
Type "rm -rf /tmp/demo-vault"
Enter
Sleep 200ms
Type "clear"
Enter
Sleep 200ms
Show

Type "# Symaira Vault — password manager for terminal users and AI agents"
Enter
Sleep 1200ms

Type "symvault init --auth passphrase /tmp/demo-vault"
Enter
Sleep 1500ms
Type "demo-pass-2026"
Enter
Sleep 2500ms

Type "symvault unlock --ttl 5m"
Enter
Sleep 1200ms
Type "demo-pass-2026"
Enter
Sleep 1600ms

Type "symvault add github --username demo@example.com --generate --length 18"
Enter
Sleep 1800ms

Type "symvault get github"
Enter
Sleep 2500ms

Type "symvault generate --length 24 --symbols"
Enter
Sleep 2200ms

Type "symvault agent install codex --config-only --dry-run"
Enter
Sleep 3500ms
