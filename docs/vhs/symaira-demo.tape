# Symaira Vault demo tape (charmbracelet/vhs)
#
# Renders docs/assets/symaira-demo.gif. Re-render with:
#   go build -o /tmp/symvault . && vhs docs/vhs/symaira-demo.tape
#
# Requires: vhs, ttyd, ffmpeg, and an `symvault` binary on PATH (here: /tmp/symvault).

Output "docs/assets/symaira-demo.gif"

Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 50ms

Env PATH "/tmp:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
Env OPENPASS_VAULT "/tmp/demo-vault"
Env OPENPASS_PASSPHRASE "demo-pass-2026"

Hide
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

Type "symvault init /tmp/demo-vault"
Enter
Sleep 1500ms
Type "demo-pass-2026"
Enter
Sleep 2500ms

Type "symvault add github --username demo@example.com --value xK9mP2vL7nQ4"
Enter
Sleep 1800ms

Type "symvault get github"
Enter
Sleep 2500ms

Type "symvault generate --length 24 --symbols"
Enter
Sleep 2200ms

Type "symvault mcp-config claude-code"
Enter
Sleep 3500ms
