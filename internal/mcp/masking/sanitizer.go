// Package masking provides secret pattern detection and output sanitization
// to prevent accidental leakage of sensitive data in LLM chat contexts.
package masking

import (
	"fmt"
	"regexp"
	"sort"
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

// MaxKnownSecretValues bounds the number of distinct values retained for
// one exact-redaction operation. Overflow is fail-closed.
const MaxKnownSecretValues = 1024

// MaxKnownSecretSpans bounds the number of match spans retained for one
// exact-redaction operation. Overflow is fail-closed.
const MaxKnownSecretSpans = 4096

// MaxKnownSecretScanWork bounds exact matching by the number of byte
// comparisons performed for one operation. The 64 MiB budget keeps a normal
// 16 MiB output with a small number of values usable while preventing a large
// output multiplied by many non-matching values from consuming unbounded CPU.
const MaxKnownSecretScanWork int64 = 64 * 1024 * 1024

// knownSecretSpan is a byte range in the original input text.
type knownSecretSpan struct {
	start int
	end   int
}

// RedactKnownSecrets scans the original text for all non-empty literal values
// and replaces their merged spans with mask. Values are stably deduplicated
// and matched longest-first before replacement, so replacement order cannot
// expose an overlapping suffix.
//
// The returned count is the number of merged redacted spans. If the distinct
// value, retained-span, or byte-comparison budget is exceeded, the entire
// output is replaced by mask and the count is 1, denoting one withheld output
// rather than a span count. The bounds avoid retaining or allocating unbounded
// match state or spending unbounded CPU while preserving exact matches as
// short as one byte.
func RedactKnownSecrets(text string, values []string, mask string) (string, int) {
	return redactKnownSecretsWithBudget(text, values, mask, MaxKnownSecretScanWork)
}

func redactKnownSecretsWithBudget(text string, values []string, mask string, scanWork int64) (string, int) {
	if mask == "" {
		mask = "***"
	}
	if text == "" {
		return text, 0
	}
	if scanWork < 0 {
		return mask, 1
	}

	seen := make(map[string]struct{}, minInt(len(values), MaxKnownSecretValues))
	unique := make([]string, 0, minInt(len(values), MaxKnownSecretValues))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		if len(unique) >= MaxKnownSecretValues {
			return mask, 1
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	// Match longer values first so Go and Rust consume the same deterministic
	// scan budget when overlapping values are supplied in different orders.
	sort.SliceStable(unique, func(i, j int) bool {
		return len(unique[i]) > len(unique[j])
	})

	spans := make([]knownSecretSpan, 0, minInt(len(unique), MaxKnownSecretSpans))
	for _, value := range unique {
		if len(value) > len(text) {
			continue
		}
		maxStart := len(text) - len(value)
		for searchStart := 0; searchStart <= maxStart; {
			matched := true
			for offset := 0; offset < len(value); offset++ {
				if scanWork <= 0 {
					return mask, 1
				}
				scanWork--
				if text[searchStart+offset] != value[offset] {
					matched = false
					break
				}
			}
			if matched {
				end := searchStart + len(value)
				if len(spans) >= MaxKnownSecretSpans {
					return mask, 1
				}
				spans = append(spans, knownSecretSpan{start: searchStart, end: end})
				searchStart = end
			} else {
				searchStart++
			}
		}
	}
	if len(spans) == 0 {
		return text, 0
	}

	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})
	merged := make([]knownSecretSpan, 0, len(spans))
	for _, candidate := range spans {
		if len(merged) == 0 || candidate.start >= merged[len(merged)-1].end {
			merged = append(merged, candidate)
			continue
		}
		if candidate.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = candidate.end
		}
	}

	var out strings.Builder
	lastEnd := 0
	for _, span := range merged {
		out.WriteString(text[lastEnd:span.start])
		out.WriteString(mask)
		lastEnd = span.end
	}
	out.WriteString(text[lastEnd:])
	return out.String(), len(merged)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SanitizeWithKnownSecrets replaces known secret values in text with masks.
// This is used when you already know the secret values (e.g., from resolved env vars).
func SanitizeWithKnownSecrets(text string, secrets map[string]string, mask string) string {
	keys := make([]string, 0, len(secrets))
	for key := range secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, secrets[key])
	}
	result, _ := RedactKnownSecrets(text, values, mask)
	return result
}
