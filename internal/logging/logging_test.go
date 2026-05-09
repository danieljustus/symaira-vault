package logging

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestDefault_ReturnsNonNil(t *testing.T) {
	l := Default()
	if l == nil {
		t.Error("Default() returned nil")
	}
}

func TestDefault_Idempotent(t *testing.T) {
	l1 := Default()
	l2 := Default()
	if l1 != l2 {
		t.Error("Default() should return the same logger each time")
	}
}

func TestNewFromEnv_DefaultLevel(t *testing.T) {
	_ = os.Unsetenv("OPENPASS_LOG_LEVEL")
	_ = os.Unsetenv("OPENPASS_LOG_FORMAT")
	l := NewFromEnv()
	if l == nil {
		t.Error("NewFromEnv() returned nil")
	}
}

func TestNewFromEnv_DebugLevel(t *testing.T) {
	t.Setenv("OPENPASS_LOG_LEVEL", "debug")
	t.Setenv("OPENPASS_LOG_FORMAT", "json")
	l := NewFromEnv()
	if l == nil {
		t.Error("NewFromEnv() with debug level returned nil")
	}
}

func TestNew_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelDebug, "text")
	if l == nil {
		t.Fatal("New() returned nil")
	}
	l.Debug("test message")
	if !strings.Contains(buf.String(), "test message") {
		t.Errorf("expected 'test message' in output, got: %q", buf.String())
	}
}

func TestNew_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelInfo, "json")
	if l == nil {
		t.Fatal("New() returned nil")
	}
	l.Info("json test")
	out := buf.String()
	if !strings.Contains(out, `"msg":"json test"`) {
		t.Errorf("expected JSON output with msg field, got: %q", out)
	}
}

func TestNew_UnknownFormatFallsBackToText(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelWarn, "unknown-format")
	if l == nil {
		t.Fatal("New() returned nil")
	}
	l.Warn("fallback test")
	if !strings.Contains(buf.String(), "fallback test") {
		t.Errorf("expected 'fallback test' in output, got: %q", buf.String())
	}
}

func TestParseLevel_AllLevels(t *testing.T) {
	cases := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"", slog.LevelWarn},
		{"unknown", slog.LevelWarn},
	}
	for _, tc := range cases {
		got := parseLevel(tc.input)
		if got != tc.want {
			t.Errorf("parseLevel(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestReplaceLogger(t *testing.T) {
	original := Default()
	var buf bytes.Buffer
	newLogger := New(&buf, slog.LevelDebug, "text")

	restore := ReplaceLogger(newLogger)
	defer restore()

	if Default() != newLogger {
		t.Error("expected Default() to return replaced logger")
	}

	restore()
	if Default() != original {
		t.Error("expected Default() to return original logger after restore")
	}
}
