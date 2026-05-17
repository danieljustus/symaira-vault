package theme

import "testing"

func TestDetectColor(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want ColorMode
	}{
		{"no-color wins", map[string]string{"NO_COLOR": "1", "COLORTERM": "truecolor"}, ColorMono},
		{"dumb terminal", map[string]string{"TERM": "dumb"}, ColorMono},
		{"force_color=3 → truecolor", map[string]string{"FORCE_COLOR": "3", "TERM": "xterm"}, ColorTrue},
		{"force_color=truecolor", map[string]string{"FORCE_COLOR": "truecolor", "TERM": "xterm"}, ColorTrue},
		{"force_color=2 → 256", map[string]string{"FORCE_COLOR": "2", "TERM": "xterm"}, Color256},
		{"force_color=1 → 16", map[string]string{"FORCE_COLOR": "1", "TERM": "xterm"}, Color16},
		{"colorterm=truecolor", map[string]string{"COLORTERM": "truecolor", "TERM": "xterm-256color"}, ColorTrue},
		{"256color in TERM", map[string]string{"TERM": "xterm-256color"}, Color256},
		{"basic xterm", map[string]string{"TERM": "xterm"}, Color16},
		{"clicolor_force", map[string]string{"CLICOLOR_FORCE": "1", "TERM": "xterm"}, Color256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"NO_COLOR", "FORCE_COLOR", "COLORTERM", "CLICOLOR_FORCE", "TERM"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := detectColor(); got != tc.want {
				t.Errorf("detectColor() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectASCIIOnly(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"openpass_ascii=1", map[string]string{"OPENPASS_ASCII": "1"}, true},
		{"lang=C", map[string]string{"LANG": "C"}, true},
		{"lang=POSIX", map[string]string{"LANG": "POSIX"}, true},
		{"lang=de_DE.UTF-8", map[string]string{"LANG": "de_DE.UTF-8"}, false},
		{"lc_all overrides lang", map[string]string{"LC_ALL": "C", "LANG": "de_DE.UTF-8"}, true},
		{"no env set", map[string]string{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"OPENPASS_ASCII", "LANG", "LC_ALL", "LC_CTYPE"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := detectASCIIOnly(); got != tc.want {
				t.Errorf("detectASCIIOnly() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplySymbols_ASCIIFallback(t *testing.T) {
	defer Reset()

	applySymbols(Capabilities{ASCIIOnly: true})
	if SymbolSuccess != asciiSuccess {
		t.Errorf("SymbolSuccess = %q, want %q in ASCII mode", SymbolSuccess, asciiSuccess)
	}
	if SymbolWarning != asciiWarning {
		t.Errorf("SymbolWarning = %q, want %q in ASCII mode", SymbolWarning, asciiWarning)
	}

	applySymbols(Capabilities{ASCIIOnly: false})
	if SymbolSuccess != "✓" {
		t.Errorf("SymbolSuccess = %q, want ✓ in unicode mode", SymbolSuccess)
	}
}

func TestColorModeString(t *testing.T) {
	cases := map[ColorMode]string{
		ColorMono: "mono",
		Color16:   "16",
		Color256:  "256",
		ColorTrue: "truecolor",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("ColorMode(%d).String() = %q, want %q", m, got, want)
		}
	}
}
