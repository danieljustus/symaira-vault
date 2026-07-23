package redact

import (
	"github.com/danieljustus/symaira-vault/internal/mcp/masking"
)

// minExactValueLen is the shortest value the exact-value detector will
// treat as a secret. Values shorter than this are far too likely to
// produce false-positive matches against ordinary output (e.g. "ab") and
// carry little value as a secret in the first place.
const minExactValueLen = 4

// exactValueDetector matches literal occurrences of a fixed set of known
// values (e.g. currently-unlocked vault secret values) and replaces them
// with Marker. It never logs or returns the values themselves.
type exactValueDetector struct {
	values []string
}

// NewExactValueDetector returns a ConfidenceHigh Detector that redacts every
// literal occurrence of any value in values. Empty values and values
// shorter than minExactValueLen are ignored (never treated as matchable)
// to avoid mass false positives.
func NewExactValueDetector(values []string) Detector {
	filtered := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) >= minExactValueLen {
			filtered = append(filtered, v)
		}
	}
	return &exactValueDetector{values: filtered}
}

func (d *exactValueDetector) Name() string           { return "exact_value" }
func (d *exactValueDetector) Confidence() Confidence { return ConfidenceHigh }

func (d *exactValueDetector) Redact(text string) (string, int, error) {
	total := 0
	for _, v := range d.values {
		var n int
		text, n = replaceAllValue(text, v)
		total += n
	}
	return text, total, nil
}

// patternDetector matches explicit credential-shaped patterns (API key
// formats, tokens, private keys, ...) using the existing pattern registry
// from internal/mcp/masking, so this package composes with — rather than
// duplicates — that detection logic.
type patternDetector struct {
	registry *masking.PatternRegistry
}

// NewPatternDetector returns a ConfidenceHigh Detector for explicit
// variable-name/credential-shaped patterns (AWS keys, GitHub tokens,
// Slack tokens, private keys, etc.), backed by masking.DefaultPatterns.
func NewPatternDetector() Detector {
	return &patternDetector{registry: masking.NewPatternRegistry()}
}

// NewPatternDetectorWithRegistry allows callers to supply a custom pattern
// registry (e.g. with additional org-specific patterns registered).
func NewPatternDetectorWithRegistry(r *masking.PatternRegistry) Detector {
	return &patternDetector{registry: r}
}

func (d *patternDetector) Name() string           { return "credential_pattern" }
func (d *patternDetector) Confidence() Confidence { return ConfidenceHigh }

func (d *patternDetector) Redact(text string) (string, int, error) {
	matches := d.registry.FindMatches(text)
	if len(matches) == 0 {
		return text, 0, nil
	}

	var out []byte
	lastEnd := 0
	for _, m := range matches {
		out = append(out, text[lastEnd:m.Start]...)
		out = append(out, Marker...)
		lastEnd = m.End
	}
	out = append(out, text[lastEnd:]...)
	return string(out), len(matches), nil
}
