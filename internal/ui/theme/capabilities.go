package theme

import (
	"os"
	"strings"
	"sync"
)

// ColorMode describes how much color the current terminal can render.
type ColorMode int

const (
	// ColorMono renders no ANSI color. Picked when NO_COLOR is set, $TERM=dumb,
	// or the caller forces ASCII output.
	ColorMono ColorMode = iota
	// Color16 uses the 8/16-color ANSI palette. Safe baseline.
	Color16
	// Color256 uses the xterm-256 palette. The default for modern terminals
	// without truecolor advertised via $COLORTERM.
	Color256
	// ColorTrue uses 24-bit truecolor (#rrggbb).
	ColorTrue
)

// String returns a short identifier for the color mode (used in --term-info
// or logging).
func (m ColorMode) String() string {
	switch m {
	case ColorMono:
		return "mono"
	case Color16:
		return "16"
	case Color256:
		return "256"
	case ColorTrue:
		return "truecolor" //nolint:goconst
	default:
		return "unknown"
	}
}

// Capabilities describes what the current terminal can render. The zero value
// is intentionally conservative (mono + ASCII) so a caller that forgets to
// call Detect still gets safe defaults.
type Capabilities struct {
	Color     ColorMode
	ASCIIOnly bool
}

var (
	capsOnce sync.Once
	capsVal  Capabilities
)

// Detect reads environment variables to determine terminal capabilities.
// Result is cached; call Reset to re-detect after env changes (e.g. in tests).
func Detect() Capabilities {
	capsOnce.Do(func() { capsVal = detectUncached() })
	return capsVal
}

// Reset clears the cached Detect result. Tests use it after t.Setenv.
func Reset() {
	capsOnce = sync.Once{}
	capsVal = Capabilities{}
	applySymbols(detectUncached())
}

func detectUncached() Capabilities {
	c := Capabilities{
		Color:     detectColor(),
		ASCIIOnly: detectASCIIOnly(),
	}
	return c
}

func detectColor() ColorMode {
	// NO_COLOR (https://no-color.org) wins over everything.
	if v := os.Getenv("NO_COLOR"); v != "" {
		return ColorMono
	}

	term := os.Getenv("TERM")
	if term == "dumb" || term == "" && os.Getenv("FORCE_COLOR") == "" {
		// A missing TERM with no FORCE_COLOR is typically a non-interactive
		// CI runner — be conservative.
		if term == "" {
			return ColorMono
		}
		return ColorMono
	}

	// Explicit overrides.
	if v := strings.ToLower(os.Getenv("FORCE_COLOR")); v != "" && v != "0" && v != "false" {
		// FORCE_COLOR=1|true → 16; FORCE_COLOR=2 → 256; FORCE_COLOR=3 → truecolor.
		switch v {
		case "3", "truecolor", "24bit":
			return ColorTrue
		case "2", "256":
			return Color256
		default:
			return Color16
		}
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return Color256
	}

	if strings.ToLower(os.Getenv("COLORTERM")) == "truecolor" ||
		strings.ToLower(os.Getenv("COLORTERM")) == "24bit" {
		return ColorTrue
	}

	if strings.Contains(term, "256color") {
		return Color256
	}
	if strings.Contains(term, "color") || strings.HasPrefix(term, "xterm") ||
		strings.HasPrefix(term, "screen") || strings.HasPrefix(term, "tmux") {
		return Color16
	}
	return ColorMono
}

func detectASCIIOnly() bool {
	if v := os.Getenv("OPENPASS_ASCII"); v != "" && v != "0" && v != "false" {
		return true
	}
	// Best-effort UTF-8 check: most modern environments have UTF-8 locale.
	// A LANG/LC_ALL of POSIX or C indicates an ASCII-only locale.
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		v = strings.ToUpper(v)
		if v == "C" || v == "POSIX" {
			return true
		}
		if strings.Contains(v, "UTF-8") || strings.Contains(v, "UTF8") {
			return false
		}
		return false
	}
	return false
}
