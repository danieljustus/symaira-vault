package secureui

import (
	"strings"
	"testing"
)

func TestBuildPlainTTYPrompt_AllFields(t *testing.T) {
	req := PromptRequest{
		Path:        "github",
		Field:       "token",
		Description: "for CI",
	}
	prompt := buildPlainTTYPrompt(req)

	if !strings.Contains(prompt, "Secure input required") {
		t.Error("buildPlainTTYPrompt missing security header")
	}
	if !strings.Contains(prompt, "Entry: github") {
		t.Error("buildPlainTTYPrompt missing Entry field")
	}
	if !strings.Contains(prompt, "Field: token") {
		t.Error("buildPlainTTYPrompt missing Field field")
	}
	if !strings.Contains(prompt, "Details: for CI") {
		t.Error("buildPlainTTYPrompt missing Description field")
	}
	if !strings.Contains(prompt, "input hidden") {
		t.Error("buildPlainTTYPrompt missing input hidden notice")
	}
}

func TestBuildPlainTTYPrompt_EmptyFields(t *testing.T) {
	req := PromptRequest{}
	prompt := buildPlainTTYPrompt(req)

	if !strings.Contains(prompt, "Secure input required") {
		t.Error("buildPlainTTYPrompt missing security header")
	}
	if strings.Contains(prompt, "Entry:") {
		t.Error("buildPlainTTYPrompt should not contain Entry for empty path")
	}
	if strings.Contains(prompt, "Field:") {
		t.Error("buildPlainTTYPrompt should not contain Field for empty field")
	}
	if strings.Contains(prompt, "Details:") {
		t.Error("buildPlainTTYPrompt should not contain Details for empty description")
	}
}

func TestBuildPlainTTYPrompt_PartialFields(t *testing.T) {
	req := PromptRequest{Path: "github"}
	prompt := buildPlainTTYPrompt(req)

	if !strings.Contains(prompt, "Entry: github") {
		t.Error("buildPlainTTYPrompt missing Entry field")
	}
	if strings.Contains(prompt, "Field:") {
		t.Error("buildPlainTTYPrompt should not contain Field for empty field")
	}
}

func TestBuildPlainTTYPrompt_NoBoxDrawing(t *testing.T) {
	req := PromptRequest{Path: "test", Field: "value"}
	prompt := buildPlainTTYPrompt(req)

	// Should not contain box-drawing characters
	for _, ch := range []string{"╔", "═", "║", "╚", "╠"} {
		if strings.Contains(prompt, ch) {
			t.Errorf("buildPlainTTYPrompt contains box-drawing character %q", ch)
		}
	}
}

func TestBuildTTYPrompt_ScreenReaderMode(t *testing.T) {
	// Enable screen reader mode via env var
	t.Setenv("SYMVAULT_SCREEN_READER", "1")

	req := PromptRequest{Path: "github", Field: "token", Description: "for CI"}
	prompt := buildTTYPrompt(req)

	// Should use plain format (no box drawing)
	if strings.Contains(prompt, "╔") {
		t.Error("buildTTYPrompt should not use box drawing in screen reader mode")
	}
	if !strings.Contains(prompt, "Secure input required") {
		t.Error("buildTTYPrompt missing security header in screen reader mode")
	}
}

func TestBuildTTYPrompt_NormalMode(t *testing.T) {
	// Ensure screen reader mode is off
	t.Setenv("SYMVAULT_SCREEN_READER", "0")

	req := PromptRequest{Path: "github", Field: "token", Description: "for CI"}
	prompt := buildTTYPrompt(req)

	// Should use box drawing
	if !strings.Contains(prompt, "╔") {
		t.Error("buildTTYPrompt should use box drawing in normal mode")
	}
	if !strings.Contains(prompt, "SECURE INPUT REQUIRED") {
		t.Error("buildTTYPrompt missing security header in normal mode")
	}
}

func TestBuildPlainTTYPrompt_LongPath(t *testing.T) {
	longPath := strings.Repeat("a", 200)
	req := PromptRequest{Path: longPath}
	prompt := buildPlainTTYPrompt(req)

	// Should contain the full path (no truncation in plain mode)
	if !strings.Contains(prompt, longPath) {
		t.Error("buildPlainTTYPrompt should contain full path")
	}
}

func TestBuildPlainTTYPrompt_SpecialCharacters(t *testing.T) {
	req := PromptRequest{
		Path:        "path/with spaces & special chars",
		Field:       "field-name_123",
		Description: "Description with <html> & \"quotes\"",
	}
	prompt := buildPlainTTYPrompt(req)

	if !strings.Contains(prompt, "path/with spaces & special chars") {
		t.Error("buildPlainTTYPrompt missing path with special chars")
	}
	if !strings.Contains(prompt, "field-name_123") {
		t.Error("buildPlainTTYPrompt missing field with special chars")
	}
}

func TestTruncateFunction(t *testing.T) {
	// Test the truncate function from backend_tty.go
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "short"},
		{strings.Repeat("a", 50), strings.Repeat("a", 50)},
		{strings.Repeat("b", 51), strings.Repeat("b", 47) + "..."},
		{"", ""},
	}

	for _, tt := range tests {
		got := truncate(tt.input)
		if got != tt.expected {
			t.Errorf("truncate(%q) = %q, want %q", tt.input[:min(20, len(tt.input))], got, tt.expected)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
