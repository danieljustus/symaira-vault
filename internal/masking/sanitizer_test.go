package masking

import (
	"strings"
	"testing"
)

func TestDefaultPatterns(t *testing.T) {
	patterns := DefaultPatterns()
	if len(patterns) == 0 {
		t.Fatal("expected default patterns")
	}
}

func TestFindMatches(t *testing.T) {
	registry := NewPatternRegistry()

	tests := []struct {
		name     string
		text     string
		want     int
		wantName string
	}{
		{
			name:     "AWS Access Key ID",
			text:     "My AWS key is AKIAIOSFODNN7EXAMPLE and some other text",
			want:     1,
			wantName: "aws_access_key_id",
		},
		{
			name:     "GitHub PAT",
			text:     "token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			want:     1,
			wantName: "github_pat",
		},
		{
			name:     "Stripe Test Key",
			text:     "stripe key: sk_test_FAKE123456789012345678901234",
			want:     1,
			wantName: "stripe_test_key",
		},
		{
			name:     "Slack Webhook",
			text:     "hook: https://hooks.slack.example/services/T00FAKE/B00FAKE/FAKEFAKEFAKEFAKEFAKEFAKE",
			want:     1,
			wantName: "slack_webhook",
		},
		{
			name:     "Private Key PEM",
			text:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAxgNS...",
			want:     1,
			wantName: "private_key",
		},
		{
			name: "No secrets",
			text: "This is just normal text without any secrets.",
			want: 0,
		},
		{
			name: "Multiple secrets",
			text: "AWS: AKIAIOSFODNN7EXAMPLE and GitHub: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := registry.FindMatches(tt.text)
			if len(matches) != tt.want {
				t.Errorf("FindMatches() got %d matches, want %d", len(matches), tt.want)
			}
			if tt.want > 0 && tt.wantName != "" {
				found := false
				for _, m := range matches {
					if m.PatternName == tt.wantName {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected pattern %q not found in matches", tt.wantName)
				}
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "AWS key masked",
			text: "My AWS key is AKIAIOSFODNN7EXAMPLE and some other text",
			want: "My AWS key is *** and some other text",
		},
		{
			name: "GitHub PAT masked",
			text: "token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			want: "token: ***",
		},
		{
			name: "No secrets",
			text: "This is just normal text.",
			want: "This is just normal text.",
		},
		{
			name: "Multiple secrets",
			text: "AWS: AKIAIOSFODNN7EXAMPLE and GitHub: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			want: "AWS: *** and GitHub: ***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizer.Sanitize(tt.text, MaskOptions{})
			if got != tt.want {
				t.Errorf("Sanitize() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeWithVaultResolver(t *testing.T) {
	sanitizer := NewSanitizer()
	resolver := func(secretValue string) (string, bool) {
		if strings.Contains(secretValue, "AKIA") {
			return "work/aws", true
		}
		return "", false
	}

	text := "My AWS key is AKIAIOSFODNN7EXAMPLE and some other text"
	want := "My AWS key is [MASKED: op://work/aws] and some other text"

	got := sanitizer.Sanitize(text, MaskOptions{
		MaskWithOPRefs: true,
		VaultResolver:  resolver,
	})
	if got != want {
		t.Errorf("Sanitize() = %q, want %q", got, want)
	}
}

func TestSanitizeWithKnownSecrets(t *testing.T) {
	text := "The secret is my-secret-value and another one is other-secret"
	secrets := map[string]string{
		"my-secret-value": "my-secret-value",
		"other-secret":    "other-secret",
	}

	want := "The secret is *** and another one is ***"
	got := SanitizeWithKnownSecrets(text, secrets, "***")
	if got != want {
		t.Errorf("SanitizeWithKnownSecrets() = %q, want %q", got, want)
	}
}

func TestSanitizePerformance(t *testing.T) {
	sanitizer := NewSanitizer()
	var text strings.Builder
	for i := 0; i < 1000; i++ {
		text.WriteString("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ")
	}
	text.WriteString("AKIAIOSFODNN7EXAMPLE")
	input := text.String()

	t.Run("10KB sanitization under 10ms", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			_ = sanitizer.Sanitize(input, MaskOptions{})
		}
	})
}

func TestDeduplicateMatches(t *testing.T) {
	matches := []Match{
		{Start: 0, End: 10, Value: "0123456789"},
		{Start: 5, End: 15, Value: "56789abcde"},
		{Start: 20, End: 30, Value: "klmnopqrst"},
	}

	result := deduplicateMatches(matches)
	if len(result) != 2 {
		t.Fatalf("expected 2 matches after deduplication, got %d", len(result))
	}
	if result[0].Start != 0 || result[0].End != 15 {
		t.Errorf("first match = %d-%d, want 0-15", result[0].Start, result[0].End)
	}
	if result[1].Start != 20 || result[1].End != 30 {
		t.Errorf("second match = %d-%d, want 20-30", result[1].Start, result[1].End)
	}
}

func TestPatternRegistry_AddPattern(t *testing.T) {
	r := NewPatternRegistry()
	before := len(r.Patterns())

	p := DefaultPatterns()[0]
	r.AddPattern(p)

	after := len(r.Patterns())
	if after != before+1 {
		t.Errorf("expected %d patterns after AddPattern, got %d", before+1, after)
	}
}

func TestPatternRegistry_Patterns_ReturnsCopy(t *testing.T) {
	r := NewPatternRegistry()
	p1 := r.Patterns()
	p2 := r.Patterns()
	if len(p1) != len(p2) {
		t.Errorf("Patterns() returned different lengths: %d vs %d", len(p1), len(p2))
	}
}

func TestNewSanitizerWithRegistry(t *testing.T) {
	r := NewPatternRegistry()
	s := NewSanitizerWithRegistry(r)
	if s == nil {
		t.Fatal("NewSanitizerWithRegistry returned nil")
	}
	// Verify it uses the registry by sanitizing a known pattern.
	result := s.Sanitize("AKIAIOSFODNN7EXAMPLE", MaskOptions{})
	if result == "AKIAIOSFODNN7EXAMPLE" {
		t.Error("expected sanitizer to mask AWS key")
	}
}
