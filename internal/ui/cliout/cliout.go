// Package cliout provides consistent colored CLI output that respects
// --quiet and NO_COLOR settings.
package cliout

import (
	"fmt"
	"os"
	"sync"
)

var (
	quiet bool
	mu    sync.RWMutex
)

// ANSI color codes.
const (
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	blue   = "\033[34m"
	reset  = "\033[0m"
)

// SetQuiet enables or disables quiet mode.
func SetQuiet(v bool) {
	mu.Lock()
	quiet = v
	mu.Unlock()
}

func isQuiet() bool {
	mu.RLock()
	defer mu.RUnlock()
	return quiet
}

func noColor() bool {
	return os.Getenv("NO_COLOR") != ""
}

func colorize(color, format string, args ...any) string {
	if noColor() {
		return fmt.Sprintf(format, args...)
	}
	return color + fmt.Sprintf(format, args...) + reset
}

// Errorf prints a red error message to stderr unless quiet mode is enabled.
func Errorf(format string, args ...any) {
	if isQuiet() {
		return
	}
	fmt.Fprintln(os.Stderr, colorize(red, format, args...))
}

// Warnf prints a yellow warning message to stderr unless quiet mode is enabled.
func Warnf(format string, args ...any) {
	if isQuiet() {
		return
	}
	fmt.Fprintln(os.Stderr, colorize(yellow, format, args...))
}

// Hintf prints a green/blue hint message to stderr unless quiet mode is enabled.
func Hintf(format string, args ...any) {
	if isQuiet() {
		return
	}
	fmt.Fprintln(os.Stderr, colorize(green, format, args...))
}
