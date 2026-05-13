package render

import (
	"testing"

	"github.com/danieljustus/OpenPass/internal/vault/taint"
)

func TestForTerminal_StripsANSI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standalone escape",
			input: "\x1btest",
			want:  "test",
		},
		{
			name:  "bold text",
			input: "\x1b[1mbold\x1b[22m",
			want:  "bold",
		},
		{
			name:  "multiple sequences",
			input: "\x1b[1m\x1b[31mhello\x1b[0m",
			want:  "hello",
		},
		{
			name:  "cursor movement",
			input: "\x1b[2J\x1b[Hclear",
			want:  "clear",
		},
		{
			name:  "256 color",
			input: "\x1b[38;5;196mred\x1b[0m",
			want:  "red",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := taint.Wrap(tt.input, taint.Provenance{Source: "test"})
			got := ForTerminal(u)
			if got != tt.want {
				t.Fatalf("ForTerminal(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestForTerminal_StripsControlChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"null byte", "a\x00b", "ab"},
		{"bell", "bell\x07!", "bell!"},
		{"tab preserved", "a\tb", "a\tb"},
		{"newline preserved", "a\nb", "a\nb"},
		{"carriage return preserved", "a\rb", "a\rb"},
		{"delete", "abc\x7f", "abc"},
		{"escape", "\x1btest", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := taint.Wrap(tt.input, taint.Provenance{Source: "test"})
			got := ForTerminal(u)
			if got != tt.want {
				t.Fatalf("ForTerminal(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestForTerminal_StripsOSC8(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "osc8 link",
			input: "\x1b]8;;https://evil.com\x07click here\x1b]8;;\x07",
			want:  "click here",
		},
		{
			name:  "osc8 with ST terminator",
			input: "\x1b]8;;https://evil.com\x1b\\click here\x1b]8;;\x1b\\",
			want:  "click here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := taint.Wrap(tt.input, taint.Provenance{Source: "test"})
			got := ForTerminal(u)
			if got != tt.want {
				t.Fatalf("ForTerminal(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestForTerminal_CleanTextUnchanged(t *testing.T) {
	inputs := []string{
		"",
		"hello",
		"hello world",
		"path/to/entry",
		" note with spaces ",
		"UPPERCASE",
		"with.dots.and-dashes",
		"email@example.com",
		"https://example.com/path",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			u := taint.Wrap(input, taint.Provenance{Source: "test"})
			got := ForTerminal(u)
			if got != input {
				t.Fatalf("ForTerminal(%q) = %q, want %q", input, got, input)
			}
		})
	}
}

func TestQuoteForTerminal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"backslash", "a\\b", "a\\\\b"},
		{"double quote", `a"b`, `a\"b`},
		{"single quote", "a'b", "a\\'b"},
		{"newline", "a\nb", "a\\nb"},
		{"tab", "a\tb", "a\\tb"},
		{"control char", "a\x01b", "a\\x01b"},
		{"delete", "a\x7fb", "a\\x7fb"},
		{"plain text", "hello", "hello"},
		{"ansi stripped", "\x1b[31mhi", "hi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := taint.Wrap(tt.input, taint.Provenance{Source: "test"})
			got := QuoteForTerminal(u)
			if got != tt.want {
				t.Fatalf("QuoteForTerminal(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestForTerminalLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		max   int
		want  string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact fit", "hello", 5, "hello"},
		{"truncated", "hello world", 8, "hello..."},
		{"very short max", "hello world", 3, "..."},
		{"ansi stripped truncated", "\x1b[31mhello world\x1b[0m", 8, "hello..."},
		{"empty", "", 10, ""},
		{"unicode truncated", "abcdefghij", 6, "abc..."},
		{"max less than 3", "hello", 1, "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := taint.Wrap(tt.input, taint.Provenance{Source: "test"})
			got := ForTerminalLine(u, tt.max)
			if got != tt.want {
				t.Fatalf("ForTerminalLine(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
			}
		})
	}
}

func TestForTerminalLine_UnicodeSafety(t *testing.T) {
	u := taint.Wrap("hello ☺ world", taint.Provenance{Source: "test"})
	got := ForTerminalLine(u, 7)
	if got != "hell..." {
		t.Fatalf("got %q, want %q", got, "hell...")
	}
}

func TestForTerminal_UnicodePreserved(t *testing.T) {
	inputs := []string{
		"hello ☺ world",
		"日本語",
		"emoji 🎉 test",
		"accentué",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			u := taint.Wrap(input, taint.Provenance{Source: "test"})
			got := ForTerminal(u)
			if got != input {
				t.Fatalf("ForTerminal(%q) = %q, want %q", input, got, input)
			}
		})
	}
}

func TestForTerminal_MultipleInjectedSequences(t *testing.T) {
	input := "normal\x1b[2Jpath\x1b[31m\x1b[K\x1b]8;;https://phishing.example.com\x07click\x1b]8;;\x07"
	u := taint.Wrap(input, taint.Provenance{Source: "test"})
	got := ForTerminal(u)
	want := "normalpathclick"
	if got != want {
		t.Fatalf("ForTerminal() = %q, want %q", got, want)
	}
}
