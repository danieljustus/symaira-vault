package i18n

// English (default) message catalog. Keys use dot-separated namespaces:
//
//	prompt.*    — user input prompts
//	error.*     — error messages
//	hint.*      — hints/nudges
//	notify.*    — desktop notification titles/bodies
//	pairing.*   — multi-device pairing UX
func init() {
	for k, v := range map[string]string{
		"prompt.passphrase":           "Passphrase: ",
		"prompt.passphrase.new":       "New passphrase: ",
		"prompt.passphrase.confirm":   "Confirm passphrase: ",
		"prompt.value.hidden":         "Enter value (input hidden): ",
		"prompt.value.visible":        "Enter value: ",
		"error.read.input":            "could not read input: %v",
		"error.passphrase.mismatch":   "passphrases did not match",
		"error.vault.locked":          "vault is locked",
		"error.vault.not_initialized": "vault not initialized — run 'openpass init' first",
		"hint.unlock":                 "Unlock with 'openpass unlock', or set OPENPASS_PASSPHRASE for non-interactive use.",
		"hint.find":                   "Try: openpass find <search-term>",
		"hint.first_run":              "Run 'openpass init' for a quick start, or 'openpass setup' for the guided wizard.",
		"notify.security_alert":       "OpenPass security alert",
		"notify.clipboard_cleared":    "Clipboard cleared",
		"pairing.token.expires":       "Token expires in %s",
		"pairing.token.lockout":       "Five wrong tries trigger a 30-second lockout.",
		"capslock.warning":            "Caps Lock is on — your passphrase may be miscased.",
	} {
		Register(LangEN, k, v)
	}
}
