package ui

// Keybinding documents a single TUI key/action pair. The list is the source
// of truth for the in-app help text *and* for `openpass ui --print-keybindings`.
// Update this list when you add or change a binding so the docs stay in sync.
type Keybinding struct {
	Key    string
	Action string
}

// Keybindings returns the documented keybindings for the vault-browser TUI.
// The order matters — it controls how `--print-keybindings` displays them.
func Keybindings() []Keybinding {
	return []Keybinding{
		{"↑/↓ or k/j", "Move selection"},
		{"Enter", "Copy selected field to clipboard"},
		{"r", "Toggle reveal/redact sensitive fields"},
		{"e", "Edit selected entry in $EDITOR"},
		{"d", "Delete selected entry (confirm)"},
		{"g", "Generate new password for entry"},
		{"s", "Cycle sort mode (name/updated, asc/desc)"},
		{"t", "Filter by tag"},
		{"/", "Filter by name"},
		{"Esc", "Clear filter / cancel input"},
		{"?", "Toggle full keybinding help"},
		{"q or Ctrl+C", "Quit the TUI"},
	}
}
