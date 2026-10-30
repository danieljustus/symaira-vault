package git

import "strings"

// stableLocaleEnv returns env with the message locale pinned to C (#1555).
//
// Git and libcurl localize their diagnostics (`Schwerwiegend: konnte nicht auf
// ... zugreifen`), while the push/pull classifiers and the "Everything
// up-to-date" check match English text. LC_ALL=C overrides every LC_*/LANG
// value; LANGUAGE is dropped because GNU gettext consults it ahead of the
// locale name for any non-C locale. Commit messages, porcelain output and
// object data do not depend on the locale, so only diagnostic text changes.
func stableLocaleEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "LC_ALL=") || strings.HasPrefix(kv, "LANGUAGE=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "LC_ALL=C")
}
