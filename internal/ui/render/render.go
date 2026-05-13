// Package render provides target-specific sanitization of untrusted data
// for output contexts (terminal, MCP, etc.). It consumes taint.Untrusted
// values and produces safe strings for the given output target.
package render

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/danieljustus/OpenPass/internal/vault/taint"
)

// ForTerminal strips ANSI escape sequences, OSC-8 hyperlinks, and control
// characters from the untrusted value, returning a string safe for terminal
// output.
func ForTerminal(u taint.Untrusted) string {
	return sanitizeTerminal(u.Render(taint.Terminal).String())
}

// QuoteForTerminal strips ANSI/OSC-8 sequences and then escapes control
// characters that could interfere with quoted terminal output. Unlike
// ForTerminal, control characters are escaped (\\xNN) rather than stripped.
func QuoteForTerminal(u taint.Untrusted) string {
	s := u.Render(taint.Terminal).String()
	s = stripANSIAndOSC(s)
	return escapeForQuote(s)
}

// escapeForQuote escapes characters for safe quoted terminal display.
func escapeForQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\'':
			b.WriteString(`\'`)
		case r == '`':
			b.WriteString("`")
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			_, _ = fmt.Fprintf(&b, `\x%02x`, r)
		case r == 0x7f:
			b.WriteString(`\x7f`)
		case r > 0x7f && !unicode.IsPrint(r):
			_, _ = fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// stripANSIAndOSC strips ANSI escape sequences and OSC-8 hyperlink
// sequences from s. Control characters are preserved.
func stripANSIAndOSC(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])

		if r == 0x1b {
			if i+1 < len(s) && s[i+1] == ']' {
				i += 2
				for i < len(s) {
					if s[i] == 0x07 {
						i++
						break
					}
					if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			}
			if i+1 < len(s) && s[i+1] == '[' {
				i += 2
				for i < len(s) {
					ch := s[i]
					if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
						i++
						break
					}
					if ch == 0x1b {
						break
					}
					i++
				}
				continue
			}
			i += size
			continue
		}

		b.WriteRune(r)
		i += size
	}

	return b.String()
}

// ForTerminalLine strips ANSI/control characters and truncates the result
// to at most max runes. If truncated, the last three characters are replaced
// with "...". This is useful for single-line displays (e.g. lists, summaries).
func ForTerminalLine(u taint.Untrusted, max int) string {
	s := sanitizeTerminal(u.Render(taint.Terminal).String())
	if max < 3 {
		max = 3
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	result := string(runes[:max-3]) + "..."
	return result
}

// sanitizeTerminal removes ANSI escape sequences, OSC-8 hyperlinks, and
// control characters from s.
func sanitizeTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	inEscape := false
	inOSC := false

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])

		if inEscape {
			if r == '[' || (r >= '0' && r <= '9') || r == ';' {
				i += size
				continue
			}
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
				i += size
				continue
			}
			inEscape = false
			continue
		}

		if inOSC {
			if r == 0x07 {
				inOSC = false
				i += size
				continue
			}
			if r == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				inOSC = false
				i += 2
				continue
			}
			i += size
			continue
		}

		if r == 0x1b {
			if i+1 < len(s) && s[i+1] == ']' {
				inOSC = true
				i += 2
				continue
			}
			if i+1 < len(s) && s[i+1] == '[' {
				inEscape = true
				i += 2
				continue
			}
			i += size
			continue
		}

		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			i += size
			continue
		}
		if r == 0x7f {
			i += size
			continue
		}

		b.WriteRune(r)
		i += size
	}

	return b.String()
}
