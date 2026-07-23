package redact

import (
	"math"
	"strings"
)

// Tuning constants for the entropy heuristic. These are deliberately
// conservative (see package doc and #697): false-positive resistance
// matters more than recall for this last-resort layer, so both the
// minimum token length and the entropy floor are set high enough that
// ordinary prose and short identifiers never match, at the cost of also
// missing some real secrets shorter than minTokenLen. This trade-off is
// intentional and documented, not a bug to "fix" by loosening the
// thresholds — see entropy_test.go's TestEntropyDetector_
// DocumentedFalsePositiveClasses for the classes this knowingly still
// misses or over-matches.
const (
	// minTokenLen is the shortest candidate token the detector considers.
	// Below this length, entropy measurements are too noisy to be
	// reliable, and short strings are unlikely to be secrets worth this
	// last-resort layer's attention (exact-value and pattern detectors
	// already cover the common short-secret formats).
	minTokenLen = 20
	// minEntropyBitsPerChar is the empirical Shannon-entropy floor a
	// candidate token's characters must clear to be flagged. Deliberately
	// set high (~4.85 bits/char): this is calibrated to sit above common
	// non-secret long tokens seen in real tool output — hex digests
	// (~3.7 bits/char, 16-symbol alphabet), alphanumeric identifiers such
	// as temp-dir names or generated test-run identifiers (~3.8-4.7
	// bits/char, verified against Go's own t.TempDir()/test-name shapes)
	// — while still catching mixed-case/digit/symbol secrets and
	// base64-encoded payloads (~5+ bits/char). The trade-off this buys is
	// fewer false positives at the cost of missing hex-only secrets and
	// some shorter random tokens; see entropy_test.go's
	// TestEntropyDetector_DocumentedFalsePositiveClasses.
	minEntropyBitsPerChar = 4.85
)

// entropyTokenChars is the set of characters treated as part of a
// candidate token. It intentionally excludes common separators — space,
// hyphen, colon, comma, and '/' — so that, e.g., a hyphen-delimited UUID
// is split into several short hex runs (each below minTokenLen) rather
// than analyzed as one long low-entropy string, and a filesystem path
// (e.g. a working directory echoed by a command) is split at each '/'
// instead of being treated as one long high-entropy token. '-' and '/'
// are excluded for the same reason even though both appear in some
// secret formats (base32, base64); this is a known, deliberate trade-off
// for a conservative last-resort detector — it costs some recall on
// slash- or hyphen-heavy encoded secrets in exchange for not flagging
// ordinary paths and identifiers.
func isEntropyTokenChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case strings.ContainsRune("+=_.~!@#$%^&*", r):
		return true
	default:
		return false
	}
}

// entropyDetector is the conservative, last-resort heuristic layer
// (#697): it flags long token-shaped substrings whose empirical character
// distribution is high enough in entropy to plausibly be a randomly
// generated secret, tagged at ConfidenceLow so strict-mode blocking
// (#696) treats it differently from exact-value/pattern matches.
type entropyDetector struct{}

// NewEntropyDetector returns a ConfidenceLow Detector implementing the
// conservative entropy/pattern heuristic described in #697. It is meant
// to run last in a Scanner's detector chain, after the ConfidenceHigh
// exact-value and pattern detectors.
func NewEntropyDetector() Detector {
	return entropyDetector{}
}

func (entropyDetector) Name() string           { return "entropy_heuristic" }
func (entropyDetector) Confidence() Confidence { return ConfidenceLow }

func (d entropyDetector) Redact(text string) (string, int, error) {
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return text, 0, nil
	}

	var out strings.Builder
	out.Grow(len(text))
	lastEnd := 0
	count := 0
	for _, tok := range tokens {
		if tok.end-tok.start < minTokenLen {
			continue
		}
		if shannonEntropy(text[tok.start:tok.end]) < minEntropyBitsPerChar {
			continue
		}
		out.WriteString(text[lastEnd:tok.start])
		out.WriteString(Marker)
		lastEnd = tok.end
		count++
	}
	out.WriteString(text[lastEnd:])

	if count == 0 {
		return text, 0, nil
	}
	return out.String(), count, nil
}

type tokenSpan struct{ start, end int }

// tokenize splits text into maximal runs of isEntropyTokenChar runes,
// returning their byte offsets.
func tokenize(text string) []tokenSpan {
	var spans []tokenSpan
	start := -1
	for i, r := range text {
		if isEntropyTokenChar(r) {
			if start == -1 {
				start = i
			}
			continue
		}
		if start != -1 {
			spans = append(spans, tokenSpan{start, i})
			start = -1
		}
	}
	if start != -1 {
		spans = append(spans, tokenSpan{start, len(text)})
	}
	return spans
}

// shannonEntropy returns the empirical Shannon entropy, in bits per
// character, of s's byte distribution.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
