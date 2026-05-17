package theme

// Symbol set for status indicators across all UI surfaces. The variables are
// populated by applySymbols(), which picks Unicode glyphs on UTF-8-capable
// terminals and ASCII alternatives elsewhere. Callers may read them directly;
// they are stable for the lifetime of the process unless theme.Reset() is
// invoked (used in tests after t.Setenv).
var (
	SymbolSuccess = "✓"
	SymbolWarning = "⚠"
	SymbolError   = "✗"
	SymbolCursor  = "▸"
	SymbolBullet  = "·"
)

// ASCII fallbacks used when terminal capability detection reports ASCIIOnly
// (LANG=C, OPENPASS_ASCII=1, or non-UTF-8 locale).
const (
	asciiSuccess = "[OK]"
	asciiWarning = "[!]"
	asciiError   = "[X]"
	asciiCursor  = ">"
	asciiBullet  = "."
)

func init() {
	applySymbols(detectUncached())
}

func applySymbols(c Capabilities) {
	if c.ASCIIOnly {
		SymbolSuccess = asciiSuccess
		SymbolWarning = asciiWarning
		SymbolError = asciiError
		SymbolCursor = asciiCursor
		SymbolBullet = asciiBullet
		return
	}
	SymbolSuccess = "✓"
	SymbolWarning = "⚠"
	SymbolError = "✗"
	SymbolCursor = "▸"
	SymbolBullet = "·"
}
