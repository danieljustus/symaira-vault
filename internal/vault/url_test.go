package vault

import (
	"testing"
)

func TestValidateURL(t *testing.T) {
	valid := []string{
		"https://github.com",
		"http://github.com",
		"github.com",
		"github.com/login",
		"https://sub.domain.example.com/path?foo=bar#frag",
		"http://localhost:3000",
		"http://localhost:80",
		"https://localhost:443",
		"127.0.0.1",
		"http://127.0.0.1:8080",
		"[::1]",
		"http://[::1]:8080",
		"https://[::1]:443",
		"user:pass@github.com:443/repo",
		"ssh://git@github.com:22/user/repo",
		"ftp://files.example.com:21/pub",
		"ws://socket.example.com:80/stream",
		"wss://secure.example.com:443/stream",
	}

	for _, u := range valid {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) unexpected error: %v", u, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"http://",
		"https://",
		"https:///",
		"http://[invalid-ipv6",
		"github.com:99999",
		"github.com:abc",
		"github.com:0",
		"https://bad host name.com",
		"http://example.com/bad\x00char",
		"http://example.com/bad\nnewline",
	}

	for _, u := range invalid {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) expected error, got nil", u)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"github.com", "https://github.com"},
		{"github.com/login", "https://github.com/login"},
		{"//github.com/path", "https://github.com/path"},
		{"HTTPS://GITHUB.COM/login", "https://github.com/login"},
		{"HTTP://GITHUB.COM:80/login", "http://github.com/login"},
		{"https://github.com:443/login", "https://github.com/login"},
		{"http://localhost:3000/app", "http://localhost:3000/app"},
		{"https://sub.domain.co.uk:8443/api?key=val#tag", "https://sub.domain.co.uk:8443/api?key=val#tag"},
		{"http://127.0.0.1:80", "http://127.0.0.1"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://[::1]:80", "http://[::1]"},
		{"http://[::1]:8080", "http://[::1]:8080"},
	}

	for _, tc := range tests {
		got, err := NormalizeURL(tc.input)
		if err != nil {
			t.Errorf("NormalizeURL(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://github.com/login", "github.com"},
		{"http://github.com:80/path", "github.com"},
		{"https://github.com:443", "github.com"},
		{"github.com", "github.com"},
		{"GITHUB.COM", "github.com"},
		{"github.com:443", "github.com"},
		{"github.com:80", "github.com"},
		{"github.com:8080", "github.com:8080"},
		{"https://github.com:8080/test", "github.com:8080"},
		{"http://localhost:3000", "localhost:3000"},
		{"http://localhost:80", "localhost"},
		{"localhost", "localhost"},
		{"user:pass@github.com:443/repo", "github.com"},
		{"https://SUB.DOMAIN.CO.UK/foo?bar=1#frag", "sub.domain.co.uk"},
		{"127.0.0.1:8000", "127.0.0.1:8000"},
		{"http://127.0.0.1:80", "127.0.0.1"},
		{"127.0.0.1", "127.0.0.1"},
		{"http://[::1]:8080", "[::1]:8080"},
		{"https://[::1]:443", "[::1]"},
		{"[::1]", "[::1]"},
	}

	for _, tc := range tests {
		got, err := NormalizeHost(tc.input)
		if err != nil {
			t.Errorf("NormalizeHost(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSameHost(t *testing.T) {
	matches := [][2]string{
		{"http://github.com", "https://github.com"},
		{"http://github.com:80", "https://github.com:443"},
		{"github.com", "GITHUB.COM"},
		{"https://github.com/login", "github.com/profile"},
		{"https://github.com:443", "github.com"},
		{"http://localhost:3000/a", "http://localhost:3000/b"},
		{"[::1]:8080", "http://[::1]:8080"},
		{"127.0.0.1", "http://127.0.0.1:80"},
	}

	for _, pair := range matches {
		if !SameHost(pair[0], pair[1]) {
			t.Errorf("SameHost(%q, %q) = false, want true", pair[0], pair[1])
		}
	}

	nonMatches := [][2]string{
		{"github.com", "gitlab.com"},
		{"localhost:3000", "localhost:8080"},
		{"sub.example.com", "example.com"},
		{"127.0.0.1:80", "127.0.0.1:8080"},
		{"invalid::url", "github.com"},
	}

	for _, pair := range nonMatches {
		if SameHost(pair[0], pair[1]) {
			t.Errorf("SameHost(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}

func TestExtractHostsFromData(t *testing.T) {
	t.Run("nil or empty data", func(t *testing.T) {
		if got := ExtractHostsFromData(nil); got != nil {
			t.Errorf("ExtractHostsFromData(nil) = %v, want nil", got)
		}
		if got := ExtractHostsFromData(map[string]any{}); got != nil {
			t.Errorf("ExtractHostsFromData(empty) = %v, want nil", got)
		}
	})

	t.Run("single string url", func(t *testing.T) {
		data := map[string]any{
			"url":      "https://github.com/login",
			"username": "alice",
		}
		got := ExtractHostsFromData(data)
		if len(got) != 1 || got[0] != "github.com" {
			t.Fatalf("ExtractHostsFromData = %v, want [github.com]", got)
		}
	})

	t.Run("slice of urls", func(t *testing.T) {
		data := map[string]any{
			"url": []any{
				"https://github.com/login",
				"http://gitlab.com:8080/auth",
				"GITHUB.COM:443",
			},
		}
		got := ExtractHostsFromData(data)
		if len(got) != 2 {
			t.Fatalf("ExtractHostsFromData len = %d, want 2 (%v)", len(got), got)
		}
		if got[0] != "github.com" || got[1] != "gitlab.com:8080" {
			t.Errorf("ExtractHostsFromData = %v, want [github.com, gitlab.com:8080]", got)
		}
	})

	t.Run("slice of strings", func(t *testing.T) {
		data := map[string]any{
			"url": []string{
				"https://apple.com",
				"https://icloud.com",
			},
		}
		got := ExtractHostsFromData(data)
		if len(got) != 2 || got[0] != "apple.com" || got[1] != "icloud.com" {
			t.Errorf("ExtractHostsFromData = %v, want [apple.com, icloud.com]", got)
		}
	})
}
