// Package masking provides secret pattern detection and output sanitization
// to prevent accidental leakage of sensitive data in LLM chat contexts.
package masking

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// SecretPattern defines a detectable secret pattern with its regex and metadata.
type SecretPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Description string
	Severity    string // "high", "medium", "low"
	// Validator is an optional callback for post-regex validation (e.g., Luhn
	// check for credit cards, MOD-97 for IBANs). Returning false excludes the
	// match from results.
	Validator func(value string) bool
}

// DefaultPatterns returns the built-in secret detection patterns.
// These are lightweight, gitleaks-inspired regexes for common secret formats.
func DefaultPatterns() []SecretPattern {
	return []SecretPattern{
		{
			Name:        "aws_access_key_id",
			Regex:       regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			Description: "AWS Access Key ID",
			Severity:    "high",
		},
		{
			Name:        "aws_secret_access_key",
			Regex:       regexp.MustCompile(`\b([A-Za-z0-9/+=]{40})\b`),
			Description: "AWS Secret Access Key (base64-like 40 chars)",
			Severity:    "high",
		},
		{
			Name:        "github_pat",
			Regex:       regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36,251})\b`),
			Description: "GitHub Personal Access Token",
			Severity:    "high",
		},
		{
			Name:        "github_oauth",
			Regex:       regexp.MustCompile(`\b(gho_[a-zA-Z0-9]{36,251})\b`),
			Description: "GitHub OAuth Token",
			Severity:    "high",
		},
		{
			Name:        "github_app_token",
			Regex:       regexp.MustCompile(`\b(ghs_[a-zA-Z0-9]{36,251})\b`),
			Description: "GitHub App Token",
			Severity:    "high",
		},
		{
			Name:        "stripe_key",
			Regex:       regexp.MustCompile(`\b(sk_live_[a-zA-Z0-9]{24,})\b`),
			Description: "Stripe Live Secret Key",
			Severity:    "high",
		},
		{
			Name:        "stripe_test_key",
			Regex:       regexp.MustCompile(`\b(sk_test_[a-zA-Z0-9]{24,})\b`),
			Description: "Stripe Test Secret Key",
			Severity:    "medium",
		},
		{
			Name:        "slack_token",
			Regex:       regexp.MustCompile(`\b(xox[baprs]-[a-zA-Z0-9\-]+)\b`),
			Description: "Slack Bot/User Token",
			Severity:    "high",
		},
		{
			Name:        "slack_webhook",
			Regex:       regexp.MustCompile(`\b(https://hooks\.slack\.[a-z]+/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)\b`),
			Description: "Slack Webhook URL",
			Severity:    "high",
		},
		{
			Name:        "openai_api_key",
			Regex:       regexp.MustCompile(`\b(sk-[a-zA-Z0-9]{20,}-[a-zA-Z0-9]{10,})\b`),
			Description: "OpenAI API Key",
			Severity:    "high",
		},
		{
			Name:        "generic_api_key",
			Regex:       regexp.MustCompile(`\b(api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_-]{16,}['"]?)\b`),
			Description: "Generic API Key assignment",
			Severity:    "medium",
		},
		{
			Name:        "generic_secret",
			Regex:       regexp.MustCompile(`\b(secret[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_-]{16,}['"]?)\b`),
			Description: "Generic Secret Key assignment",
			Severity:    "medium",
		},
		{
			Name:        "password_in_url",
			Regex:       regexp.MustCompile(`\b([a-zA-Z]+://[^:]+:[^@]+@[^\s]+)\b`),
			Description: "URL with embedded password",
			Severity:    "high",
		},
		{
			Name:        "private_key",
			Regex:       regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Description: "PEM/DER Private Key",
			Severity:    "high",
		},
		{
			Name:        "ssh_private_key",
			Regex:       regexp.MustCompile(`\b(ssh-rsa\s+[A-Za-z0-9+/=]{100,})\b`),
			Description: "SSH Public Key (long base64)",
			Severity:    "low",
		},
		{
			Name:        "jwt_token",
			Regex:       regexp.MustCompile(`\b(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)\b`),
			Description: "JSON Web Token",
			Severity:    "medium",
		},
		{
			Name:        "email_address",
			Regex:       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
			Description: "Email Address",
			Severity:    "medium",
		},
		{
			Name:        "credit_card",
			Regex:       regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),
			Description: "Credit Card Number (Luhn validated)",
			Severity:    "high",
			Validator:   ValidateLuhn,
		},
		{
			Name:        "iban",
			Regex:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b`),
			Description: "IBAN (International Bank Account Number)",
			Severity:    "high",
			Validator:   ValidateIBAN,
		},
		{
			Name:        "phone_number",
			Regex:       regexp.MustCompile(`\b(?:\+?\d{1,3}[-. ]?)?\(?\d{2,4}\)?[-. ]?\d{2,4}[-. ]?\d{4,9}\b`),
			Description: "Phone Number",
			Severity:    "low",
		},
		{
			Name:        "bearer_token",
			Regex:       regexp.MustCompile(`\bBearer\s+[A-Za-z0-9\-._~+/]+={0,2}\b`),
			Description: "Bearer Authentication Token",
			Severity:    "high",
		},
		{
			Name:        "aws_sts_session_token",
			Regex:       regexp.MustCompile(`\bFQoGZXIvYXdzE[\w/+=]{100,}\b`),
			Description: "AWS STS Session Token",
			Severity:    "high",
		},
		{
			Name:        "ssn_us",
			Regex:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Description: "US Social Security Number",
			Severity:    "high",
		},
		{
			Name:        "ipv4_address",
			Regex:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			Description: "IPv4 Address",
			Severity:    "low",
		},
	}
}

// PatternRegistry holds compiled patterns and provides thread-safe access.
type PatternRegistry struct {
	mu       sync.RWMutex
	patterns []SecretPattern
}

// NewPatternRegistry creates a registry with default patterns.
func NewPatternRegistry() *PatternRegistry {
	return &PatternRegistry{
		patterns: DefaultPatterns(),
	}
}

// AddPattern adds a custom pattern to the registry.
func (r *PatternRegistry) AddPattern(p SecretPattern) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.patterns = append(r.patterns, p)
}

// Patterns returns a copy of all patterns.
func (r *PatternRegistry) Patterns() []SecretPattern {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]SecretPattern, len(r.patterns))
	copy(result, r.patterns)
	return result
}

// Match represents a detected secret in text.
type Match struct {
	PatternName string
	Value       string
	Start       int
	End         int
	Severity    string
}

// FindMatches scans text for all registered patterns and returns matches.
// Matches are sorted by position and do not overlap.
func (r *PatternRegistry) FindMatches(text string) []Match {
	r.mu.RLock()
	patterns := make([]SecretPattern, len(r.patterns))
	copy(patterns, r.patterns)
	r.mu.RUnlock()

	var allMatches []Match
	for _, p := range patterns {
		matches := p.Regex.FindAllStringIndex(text, -1)
		for _, m := range matches {
			value := text[m[0]:m[1]]
			if p.Validator != nil && !p.Validator(value) {
				continue
			}
			allMatches = append(allMatches, Match{
				PatternName: p.Name,
				Value:       value,
				Start:       m[0],
				End:         m[1],
				Severity:    p.Severity,
			})
		}
	}

	for i := 0; i < len(allMatches); i++ {
		for j := i + 1; j < len(allMatches); j++ {
			if allMatches[j].Start < allMatches[i].Start {
				allMatches[i], allMatches[j] = allMatches[j], allMatches[i]
			}
		}
	}

	return deduplicateMatches(allMatches)
}

func deduplicateMatches(matches []Match) []Match {
	if len(matches) == 0 {
		return nil
	}
	result := make([]Match, 0, len(matches))
	result = append(result, matches[0])
	for i := 1; i < len(matches); i++ {
		last := &result[len(result)-1]
		if matches[i].Start < last.End {
			if matches[i].End > last.End {
				last.End = matches[i].End
			}
			continue
		}
		result = append(result, matches[i])
	}
	return result
}

// MaskOptions controls how secrets are replaced.
type MaskOptions struct {
	// MaskWithOPRefs replaces vault-known secrets with op:// references.
	MaskWithOPRefs bool
	// VaultResolver is called to check if a secret exists in the vault
	// and returns the op:// reference path if found.
	VaultResolver func(secretValue string) (vaultPath string, found bool)
	// CustomMask is used when MaskWithOPRefs is false or vault not found.
	// Defaults to "***" if empty.
	CustomMask string
}

// Sanitizer performs text sanitization by scanning for secrets and masking them.
type Sanitizer struct {
	registry *PatternRegistry
}

// NewSanitizer creates a sanitizer with default patterns.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		registry: NewPatternRegistry(),
	}
}

// NewSanitizerWithRegistry creates a sanitizer with a custom pattern registry.
func NewSanitizerWithRegistry(registry *PatternRegistry) *Sanitizer {
	return &Sanitizer{registry: registry}
}

// Sanitize scans text for secrets and replaces them with masked values.
func (s *Sanitizer) Sanitize(text string, opts MaskOptions) string {
	matches := s.registry.FindMatches(text)
	if len(matches) == 0 {
		return text
	}

	customMask := opts.CustomMask
	if customMask == "" {
		customMask = "***"
	}

	var b strings.Builder
	lastEnd := 0
	for _, m := range matches {
		b.WriteString(text[lastEnd:m.Start])

		mask := customMask
		if opts.MaskWithOPRefs && opts.VaultResolver != nil {
			if vaultPath, found := opts.VaultResolver(m.Value); found {
				mask = fmt.Sprintf("[MASKED: op://%s]", vaultPath)
			}
		}
		b.WriteString(mask)
		lastEnd = m.End
	}
	b.WriteString(text[lastEnd:])
	return b.String()
}

// SanitizeWithKnownSecrets replaces known secret values in text with masks.
// This is used when you already know the secret values (e.g., from resolved env vars).
func SanitizeWithKnownSecrets(text string, secrets map[string]string, mask string) string {
	if mask == "" {
		mask = "***"
	}
	result := text
	for _, value := range secrets {
		if value == "" {
			continue
		}
		result = strings.ReplaceAll(result, value, mask)
	}
	return result
}
