// Package cliout provides consistent colored CLI output that respects
// --quiet and NO_COLOR settings.
package cliout

import (
	"fmt"
	"os"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/danieljustus/OpenPass/internal/ui/theme"
)

// ColorMode controls when ANSI color is emitted, regardless of TTY/NO_COLOR.
type ColorMode int

const (
	// ColorAuto is the default: emit color when stderr is a TTY and NO_COLOR
	// is unset.
	ColorAuto ColorMode = iota
	// ColorAlways forces color on, even when piped (e.g. `openpass list
	// --color=always | less -R`).
	ColorAlways
	// ColorNever suppresses all color, ignoring TTY/FORCE_COLOR/env hints.
	ColorNever
)

// ParseColorMode normalizes the --color flag value. Unknown values fall back
// to ColorAuto with no error so callers can decide whether to warn.
func ParseColorMode(s string) ColorMode {
	switch s {
	case "always", "force", "yes", "on":
		return ColorAlways
	case "never", "no", "off":
		return ColorNever
	default:
		return ColorAuto
	}
}

var (
	quiet     bool
	colorMode ColorMode
	mu        sync.RWMutex
)

// SetQuiet enables or disables quiet mode.
func SetQuiet(v bool) {
	mu.Lock()
	quiet = v
	mu.Unlock()
}

// SetColorMode overrides the color decision. Called from cmd/root.go after
// parsing the --color flag.
func SetColorMode(m ColorMode) {
	mu.Lock()
	colorMode = m
	mu.Unlock()
}

func isQuiet() bool {
	mu.RLock()
	defer mu.RUnlock()
	return quiet
}

func currentColorMode() ColorMode {
	mu.RLock()
	defer mu.RUnlock()
	return colorMode
}

func noColor() bool {
	switch currentColorMode() {
	case ColorAuto:
		// fall through to environment/terminal detection below
	case ColorAlways:
		return false
	case ColorNever:
		return true
	}
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	// Suppress ANSI when stderr is redirected so log files stay readable.
	return !term.IsTerminal(int(os.Stderr.Fd()))
}

func colorize(style lipgloss.Style, format string, args ...any) string {
	if noColor() {
		return fmt.Sprintf(format, args...)
	}
	return style.Render(fmt.Sprintf(format, args...))
}

// Errorf prints a red error message to stderr unless quiet mode is enabled.
func Errorf(format string, args ...any) {
	if isQuiet() {
		return
	}
	fmt.Fprintln(os.Stderr, colorize(theme.ErrorStyle, format, args...))
}

// Warnf prints a yellow warning message to stderr unless quiet mode is enabled.
func Warnf(format string, args ...any) {
	if isQuiet() {
		return
	}
	fmt.Fprintln(os.Stderr, colorize(theme.WarnStyle, format, args...))
}

// Hintf prints a green success hint message to stderr unless quiet mode is enabled.
func Hintf(format string, args ...any) {
	if isQuiet() {
		return
	}
	fmt.Fprintln(os.Stderr, colorize(theme.SuccessStyle, format, args...))
}

// ColorizeSuccess returns text styled with the success/green color.
// It respects NO_COLOR and terminal detection.
func ColorizeSuccess(text string) string {
	if noColor() {
		return text
	}
	return theme.SuccessStyle.Render(text)
}

// ColorizeWarn returns text styled with the warning/yellow color.
// It respects NO_COLOR and terminal detection.
func ColorizeWarn(text string) string {
	if noColor() {
		return text
	}
	return theme.WarnStyle.Render(text)
}

// ColorizeError returns text styled with the error/red color.
// It respects NO_COLOR and terminal detection.
func ColorizeError(text string) string {
	if noColor() {
		return text
	}
	return theme.ErrorStyle.Render(text)
}

// ColorizeDim returns text styled with muted/dim foreground color.
// It respects NO_COLOR and terminal detection.
func ColorizeDim(text string) string {
	if noColor() {
		return text
	}
	return theme.DimStyle.Render(text)
}
