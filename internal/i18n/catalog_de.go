package i18n

// Deutscher Nachrichten-Katalog. Pflegt 1:1 die EN-Schlüssel; was nicht
// übersetzt ist, fällt automatisch auf Englisch zurück (siehe T()).
func init() {
	for k, v := range map[string]string{
		"prompt.passphrase":           "Passphrase: ",
		"prompt.passphrase.new":       "Neue Passphrase: ",
		"prompt.passphrase.confirm":   "Passphrase bestätigen: ",
		"prompt.value.hidden":         "Wert eingeben (versteckt): ",
		"prompt.value.visible":        "Wert eingeben: ",
		"error.read.input":            "konnte Eingabe nicht lesen: %v",
		"error.passphrase.mismatch":   "Passphrasen stimmen nicht überein",
		"error.vault.locked":          "Vault ist gesperrt",
		"error.vault.not_initialized": "Vault nicht initialisiert — führe 'openpass init' aus",
		"hint.unlock":                 "Mit 'openpass unlock' entsperren, oder OPENPASS_PASSPHRASE für nicht-interaktive Nutzung setzen.", //nolint:misspell
		"hint.find":                   "Versuche: openpass find <Suchbegriff>",
		"hint.first_run":              "Führe 'openpass init' für einen schnellen Start aus oder 'openpass setup' für den geführten Assistenten.",
		"notify.security_alert":       "OpenPass Sicherheitswarnung",
		"notify.clipboard_cleared":    "Zwischenablage geleert",
		"pairing.token.expires":       "Token läuft ab in %s",
		"pairing.token.lockout":       "Fünf Fehlversuche lösen eine 30-Sekunden-Sperre aus.",
		"capslock.warning":            "Feststelltaste ist aktiv — die Passphrase könnte falsch gross-/kleingeschrieben sein.",
	} {
		Register(LangDE, k, v)
	}
}
