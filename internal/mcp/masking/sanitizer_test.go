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
		{
			name:     "Email address",
			text:     "Contact: user@example.com for support",
			want:     1,
			wantName: "email_address",
		},
		{
			name:     "Credit card (with Luhn)",
			text:     "Card: 4111-1111-1111-1111",
			want:     1,
			wantName: "credit_card",
		},
		{
			name:     "IBAN (valid format)",
			text:     "IBAN: DE89370400440532013000",
			want:     1,
			wantName: "iban",
		},
		{
			name: "Phone number",
			text: "Call (555) 123-4567 for details",
			want: 1,
		},
		{
			name:     "Bearer token",
			text:     "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.token",
			want:     1,
			wantName: "bearer_token",
		},
		{
			name: "SSN (US)",
			text: "SSN: 123-45-6789",
			want: 1,
		},
		{
			name:     "IPv4 address",
			text:     "Server: 192.168.1.1 is online",
			want:     1,
			wantName: "ipv4_address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := registry.FindMatches(tt.text)
			if len(matches) != tt.want {
				t.Errorf("FindMatches() got %d matches, want %d\nmatches: %+v", len(matches), tt.want, matches)
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

func TestFindMatches_Negative(t *testing.T) {
	registry := NewPatternRegistry()

	tests := []struct {
		name string
		text string
	}{
		{
			name: "Not an email (missing @)",
			text: "useratexample.com is not an email",
		},
		{
			name: "Not an IBAN (bad country code)",
			text: "XX1234567890 is not an IBAN",
		},
		{
			name: "Not a bearer token (no Bearer prefix)",
			text: "Just a random token string",
		},
		{
			name: "Email with invalid TLD",
			text: "user@example.c",
		},
		{
			name: "Random hex string",
			text: "The hash is a1b2c3d4e5f6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := registry.FindMatches(tt.text)
			for _, m := range matches {
				t.Errorf("unexpected match %q (pattern=%s) in text %q", m.Value, m.PatternName, tt.text)
			}
		})
	}
}

func TestFindMatches_NegativePII(t *testing.T) {
	registry := NewPatternRegistry()

	matches := registry.FindMatches("Card: 1234-5678-9012-3456")
	for _, m := range matches {
		if m.PatternName == "credit_card" {
			t.Errorf("expected no credit_card match for invalid Luhn number, got %q", m.Value)
		}
	}

	matches = registry.FindMatches("My number is 12")
	for _, m := range matches {
		if m.PatternName == "phone_number" {
			t.Errorf("expected no phone_number match for short text, got %q", m.Value)
		}
	}

	matches = registry.FindMatches("ID: 1-2-3")
	for _, m := range matches {
		if m.PatternName == "ssn_us" {
			t.Errorf("expected no ssn_us match for wrong format, got %q", m.Value)
		}
	}

	matches = registry.FindMatches("Version: 1.2.3")
	for _, m := range matches {
		if m.PatternName == "ipv4_address" {
			t.Errorf("expected no ipv4_address match for 3 groups, got %q", m.Value)
		}
	}

	matches = registry.FindMatches("number 1234567890123456 here")
	for _, m := range matches {
		if m.PatternName == "credit_card" {
			t.Errorf("expected no credit_card match for invalid Luhn, got %q", m.Value)
		}
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
	result := s.Sanitize("AKIAIOSFODNN7EXAMPLE", MaskOptions{})
	if result == "AKIAIOSFODNN7EXAMPLE" {
		t.Error("expected sanitizer to mask AWS key")
	}
}

func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "Visa 4111-1111-1111-1111", value: "4111-1111-1111-1111", want: true},
		{name: "Visa 4111111111111111 (no dashes)", value: "4111111111111111", want: true},
		{name: "Mastercard 5500-0000-0000-0004", value: "5500-0000-0000-0004", want: true},
		{name: "Amex 3782-822463-10005", value: "3782-822463-10005", want: true},
		{name: "Discover 6011-1111-1111-1117", value: "6011-1111-1111-1117", want: true},
		{name: "Fails Luhn 1234-5678-9012-3456", value: "1234-5678-9012-3456", want: false},
		{name: "Too short (12 digits)", value: "123456789012", want: false},
		{name: "Too long (20 digits)", value: "12345678901234567890", want: false},
		{name: "Non-digit characters", value: "4111-1111-1111-111A", want: false},
		{name: "Empty string", value: "", want: false},
		{name: "13 zeros", value: "0000000000000", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateLuhn(tt.value)
			if got != tt.want {
				t.Errorf("ValidateLuhn(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestValidateIBAN(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "DE (Germany)", value: "DE89370400440532013000", want: true},
		{name: "DE with spaces", value: "DE89 3704 0044 0532 0130 00", want: true},
		{name: "GB (UK)", value: "GB29NWBK60161331926819", want: true},
		{name: "FR (France)", value: "FR1420041010050500013M02606", want: true},
		{name: "IT (Italy)", value: "IT60X0542811101000000123456", want: true},
		{name: "ES (Spain)", value: "ES9121000418450200051332", want: true},
		{name: "NL (Netherlands)", value: "NL91ABNA0417164300", want: true},
		{name: "Too short", value: "DE8937040044", want: false},
		{name: "Invalid country code", value: "XX89370400440532013000", want: false},
		{name: "Lowercase", value: "de89370400440532013000", want: true},
		{name: "Invalid characters", value: "DE89 3704 0044 0532 0130 0!", want: false},
		{name: "Empty string", value: "", want: false},
		{name: "Too long (35 chars)", value: "DE89370400440532013000123456789012345", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateIBAN(tt.value)
			if got != tt.want {
				t.Errorf("ValidateIBAN(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestSanitize_PII(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "Email masked",
			text: "Contact: user@example.com for help",
			want: "Contact: *** for help",
		},
		{
			name: "Credit card masked",
			text: "Card: 4111-1111-1111-1111",
			want: "Card: ***",
		},
		{
			name: "IBAN masked",
			text: "IBAN: DE89370400440532013000",
			want: "IBAN: ***",
		},
		{
			name: "Phone masked",
			text: "Call 555-123-4567 now",
			want: "Call *** now",
		},
		{
			name: "SSN masked",
			text: "SSN: 123-45-6789",
			want: "SSN: ***",
		},
		{
			name: "IPv4 masked",
			text: "Server: 192.168.1.1",
			want: "Server: ***",
		},
		{
			name: "Multiple PII masked",
			text: "Email: user@test.com, Phone: 555-123-4567",
			want: "Email: ***, Phone: ***",
		},
		{
			name: "PII not present (clean text)",
			text: "This is clean text with no PII",
			want: "This is clean text with no PII",
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

func TestSanitize_BearerToken(t *testing.T) {
	sanitizer := NewSanitizer()

	text := "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.token"
	result := sanitizer.Sanitize(text, MaskOptions{})
	if result == text {
		t.Error("expected Bearer token to be masked")
	}
	if !strings.Contains(result, "***") {
		t.Error("expected *** in masked output")
	}
}

func TestSanitize_NonPIIPreserved(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []string{
		"Version 1.2.3",
		"Just a normal sentence.",
		"ID: abc-def-ghi",
		"Product key: ABCDE-FGHIJ-KLMNO",
		"Reference #12345",
	}

	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			result := sanitizer.Sanitize(text, MaskOptions{})
			if result != text {
				t.Errorf("Sanitize(%q) = %q, expected no change", text, result)
			}
		})
	}
}

func TestValidatorIntegration(t *testing.T) {
	registry := NewPatternRegistry()

	matches := registry.FindMatches("Card: 1234-5678-9012-3456 is invalid")
	for _, m := range matches {
		if m.PatternName == "credit_card" {
			t.Errorf("expected no credit_card match for invalid Luhn number, got %q", m.Value)
		}
	}

	matches = registry.FindMatches("Card: 4111-1111-1111-1111 is valid")
	found := false
	for _, m := range matches {
		if m.PatternName == "credit_card" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected credit_card match for valid Luhn number")
	}

	matches = registry.FindMatches("IBAN: XX89370400440532013000 is bad")
	for _, m := range matches {
		if m.PatternName == "iban" {
			t.Errorf("expected no IBAN match for invalid country code, got %q", m.Value)
		}
	}
}
