// Package i18n provides a minimal message catalog for OpenPass user-facing
// strings. The design is deliberately lightweight — no external dependency,
// no plural rules, no ICU — because the user-facing surface is small (CLI
// prompts and wizard steps), the locales we care about today are EN and DE,
// and we want the runtime cost to be zero on the EN path.
//
// Usage:
//
//	i18n.T("prompt.passphrase")  // "Passphrase: " (EN) / "Passphrase: " (DE)
//	i18n.Tf("error.read", err)    // "could not read %s: %v"
//
// Translation tables live in catalog_*.go files. Adding a new language is
// adding one file plus an init() entry.
package i18n

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Language is an ISO 639-1 code. Empty string means "use the default (EN)".
type Language string

const (
	LangEN Language = "en"
	LangDE Language = "de"
)

var (
	mu      sync.RWMutex
	current = LangEN
	catalog = map[Language]map[string]string{
		LangEN: {},
		LangDE: {},
	}
)

// Register adds a translation entry for a language. Catalog files call this
// from init() so the table is populated before any T() call. Existing entries
// are overwritten, so test code can substitute freely.
func Register(lang Language, key, value string) {
	mu.Lock()
	defer mu.Unlock()
	if catalog[lang] == nil {
		catalog[lang] = map[string]string{}
	}
	catalog[lang][key] = value
}

// SetLanguage switches the active locale. Pass LangEN to fall back to the
// built-in defaults.
func SetLanguage(lang Language) {
	mu.Lock()
	current = lang
	mu.Unlock()
}

// Current returns the active language code.
func Current() Language {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// DetectFromEnv reads LC_ALL / LC_MESSAGES / LANG and picks a known locale
// from the first non-empty match. Falls back to EN when nothing recognizable
// is set; ignores .UTF-8 / .ISO suffixes.
func DetectFromEnv() Language {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.ToLower(os.Getenv(key))
		if v == "" {
			continue
		}
		// Strip encoding suffix (e.g. "de_DE.UTF-8" → "de_de").
		if i := strings.Index(v, "."); i >= 0 {
			v = v[:i]
		}
		// First two chars are the ISO 639-1 code.
		if len(v) >= 2 {
			code := v[:2]
			switch code {
			case "de":
				return LangDE
			case "en":
				return LangEN
			}
		}
	}
	return LangEN
}

// ApplyFromEnv detects and applies the locale in one call. Called from
// cmd/root.go on every Execute().
func ApplyFromEnv() {
	SetLanguage(DetectFromEnv())
}

// T returns the translation for key, falling back to the EN catalog and then
// to the key itself if no entry exists. T is safe for concurrent use.
func T(key string) string {
	mu.RLock()
	defer mu.RUnlock()
	if v, ok := catalog[current][key]; ok && v != "" {
		return v
	}
	if v, ok := catalog[LangEN][key]; ok && v != "" {
		return v
	}
	return key
}

// Tf is the printf-style variant for translations with positional args.
func Tf(key string, args ...any) string {
	return fmt.Sprintf(T(key), args...)
}
