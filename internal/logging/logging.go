// Package logging provides structured logging for Symaira Vault using Go's standard
// log/slog package. All log output goes to os.Stderr to keep stdout clean for
// stdio MCP transport.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/danieljustus/symaira-vault/internal/envutil"
)

var (
	defaultLogger *slog.Logger
	initOnce      sync.Once
)

// Default returns the package-default structured logger configured via
// environment variables. It is safe for concurrent use.
//
// Environment variables:
//   - SYMVAULT_LOG_LEVEL: debug, info, warn (default), error
//   - SYMVAULT_LOG_FORMAT: text (default), json
//   - OPENPASS_LOG_LEVEL: legacy alias for SYMVAULT_LOG_LEVEL
//   - OPENPASS_LOG_FORMAT: legacy alias for SYMVAULT_LOG_FORMAT
func Default() *slog.Logger {
	initOnce.Do(func() {
		defaultLogger = NewFromEnv()
	})
	return defaultLogger
}

// NewFromEnv creates a fresh slog.Logger from environment variables.
// Prefer Default() for normal use to avoid creating multiple handlers.
func NewFromEnv() *slog.Logger {
	level := parseLevel(envutil.Getenv("SYMVAULT_LOG_LEVEL", "OPENPASS_LOG_LEVEL"))
	format := strings.ToLower(envutil.Getenv("SYMVAULT_LOG_FORMAT", "OPENPASS_LOG_FORMAT"))
	if format == "" {
		format = "text"
	}

	return New(os.Stderr, level, format)
}

// New creates a slog.Logger with the specified writer, level and format.
// Format must be "text" or "json".
func New(w io.Writer, level slog.Level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "error":
		return slog.LevelError
	case "warn", "warning", "":
		return slog.LevelWarn
	default:
		return slog.LevelWarn
	}
}

// ReplaceLogger allows tests to swap the default logger.
// The returned function restores the previous logger.
func ReplaceLogger(l *slog.Logger) func() {
	old := defaultLogger
	defaultLogger = l
	return func() { defaultLogger = old }
}
