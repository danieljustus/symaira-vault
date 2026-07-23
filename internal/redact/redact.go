// Package redact provides the output-scanning redaction core: a small set of
// composable detectors (exact known-value matches, credential-shaped
// patterns, and — see entropy.go — a conservative entropy heuristic) plus a
// Scanner that runs them over captured command output and MCP/tool response
// payloads before that content leaves the process boundary.
//
// Design principles (see #695/#696/#697):
//   - Redaction markers are a fixed, stable string. They never contain any
//     substring, prefix, length hint, or hash of the matched value.
//   - Detectors operate on plain strings and replace matched spans in place,
//     so callers can run the scanner over JSON payloads: only the substrings
//     inside string values are rewritten, and surrounding structural
//     characters (quotes, braces, commas) are left untouched.
//   - Fail-closed: if any detector errors, the Scanner does not return the
//     original (possibly-secret-bearing) text. It reports the failure via
//     Result.Blocked and a non-nil error, and Result.Text is always safe to
//     display.
package redact

import (
	"fmt"
	"strings"
)

// Marker is the stable, non-reversible string substituted for every
// detected secret. It intentionally carries no information about the
// original value (no prefix, no length hint, no hash).
const Marker = "[REDACTED]"

// blockedText is returned in place of the original text whenever the
// Scanner cannot guarantee the text is safe (detector failure, or a
// strict-mode block). It is a fixed marker, never derived from the input.
const blockedText = "[REDACTED: output withheld]"

// Confidence classifies how certain a detector is about its matches.
// Downstream consumers (e.g. strict-mode blocking in #696) use this to
// decide whether a match is trusted enough to block delivery outright.
type Confidence int

const (
	// ConfidenceHigh identifies detectors with very low false-positive
	// rates: exact known-value matches and explicit credential-shaped
	// patterns (e.g. "ghp_...", "AKIA...").
	ConfidenceHigh Confidence = iota
	// ConfidenceLow identifies last-resort heuristics (e.g. entropy-based
	// detection, see #697) that trade recall for precision and are more
	// prone to false positives.
	ConfidenceLow
)

// String returns a human-readable label for the confidence level.
func (c Confidence) String() string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceLow:
		return "low"
	default:
		return "unknown"
	}
}

// Detector scans text for one class of secret and redacts matches in place.
// Implementations must never return the matched value, a prefix of it, a
// hash of it, or any other information that could reconstruct it — Redact's
// returned string is the only thing callers are allowed to surface.
type Detector interface {
	// Name identifies the detector for audit/metadata purposes.
	Name() string
	// Confidence reports this detector's confidence tier.
	Confidence() Confidence
	// Redact returns text with every match replaced by Marker, the number
	// of matches found, and an error if scanning failed. On error the
	// returned string MUST NOT be used by the caller (see Scanner, which
	// fails closed).
	Redact(text string) (redacted string, count int, err error)
}

// Finding summarizes one detector's contribution to a Scan call. It
// carries metadata only — never the matched value or any excerpt of it —
// so it is safe to log or emit as an audit event.
type Finding struct {
	Detector   string
	Confidence Confidence
	Count      int
}

// ScanOptions configures a single Scan call.
type ScanOptions struct {
	// Strict, when true, causes the Scanner to block (withhold) the text
	// entirely instead of redacting it in place, whenever a
	// ConfidenceHigh detector reports at least one match. Lower-confidence
	// findings are still redacted (not blocked) even in strict mode; see
	// #696/#697 for the rationale.
	Strict bool
	// CorrelationID, if set, is echoed back on emitted AuditEvents so a
	// caller can tie a block/redaction back to the call that produced it.
	CorrelationID string
}

// Result is the outcome of a Scan call.
type Result struct {
	// Text is always safe to display: either the original text (no
	// findings), the redacted text, or a fixed block marker. It never
	// contains a matched secret value.
	Text string
	// Findings lists metadata about what was detected, in detector order.
	Findings []Finding
	// Blocked is true when Text was withheld/replaced entirely rather than
	// redacted in place — either because strict mode fired on a
	// high-confidence match, or because a detector failed (fail-closed).
	Blocked bool
}

// AuditFunc receives one AuditEvent per Scan call that produced at least one
// finding (whether redacted or blocked). Implementations must not derive
// secret material from the event; the event type itself carries metadata
// only, so any correctly-typed AuditFunc is safe.
type AuditFunc func(AuditEvent)

// AuditEvent is a metadata-only record of a detection. It never contains
// the matched value, a prefix of it, or a hash of it.
type AuditEvent struct {
	Detector      string
	Channel       string
	Confidence    Confidence
	RedactedCount int
	Blocked       bool
	CorrelationID string
}

// Scanner runs a fixed set of detectors over text.
type Scanner struct {
	detectors []Detector
	// Channel labels emitted audit events (e.g. "run_command.stdout").
	// Optional; defaults to "" if unset.
	Channel string
	// Audit, if set, is invoked once per detector that produced a finding
	// during a Scan call.
	Audit AuditFunc
}

// NewScanner builds a Scanner from the given detectors, applied in order.
func NewScanner(detectors ...Detector) *Scanner {
	return &Scanner{detectors: detectors}
}

// Scan runs every configured detector over text and returns a Result that
// is always safe to surface to a caller, per the fail-closed contract
// described on Result.Text.
func (s *Scanner) Scan(text string, opts ScanOptions) (Result, error) {
	if len(s.detectors) == 0 {
		return Result{Text: text}, nil
	}

	current := text
	var findings []Finding
	highConfidenceHit := false

	for _, d := range s.detectors {
		redacted, count, err := d.Redact(current)
		if err != nil {
			// Fail closed: never return text derived from a run where a
			// detector errored, even partially redacted text from prior
			// detectors in this loop.
			s.emitAudit(AuditEvent{
				Detector:      d.Name(),
				Channel:       s.Channel,
				Confidence:    d.Confidence(),
				Blocked:       true,
				CorrelationID: opts.CorrelationID,
			})
			return Result{Text: blockedText, Blocked: true}, fmt.Errorf("redact: detector %q failed: %w", d.Name(), err)
		}
		if count > 0 {
			findings = append(findings, Finding{Detector: d.Name(), Confidence: d.Confidence(), Count: count})
			if d.Confidence() == ConfidenceHigh {
				highConfidenceHit = true
			}
		}
		current = redacted
	}

	blocked := opts.Strict && highConfidenceHit
	for _, f := range findings {
		s.emitAudit(AuditEvent{
			Detector:      f.Detector,
			Channel:       s.Channel,
			Confidence:    f.Confidence,
			RedactedCount: f.Count,
			Blocked:       blocked,
			CorrelationID: opts.CorrelationID,
		})
	}

	if blocked {
		return Result{Text: blockedText, Findings: findings, Blocked: true}, nil
	}
	return Result{Text: current, Findings: findings}, nil
}

func (s *Scanner) emitAudit(e AuditEvent) {
	if s.Audit != nil {
		s.Audit(e)
	}
}

// replaceAllValue replaces every non-overlapping occurrence of value in text
// with Marker and returns the result plus the number of replacements. It is
// a thin wrapper over strings.Count/Replace kept here so every detector in
// this package redacts consistently.
func replaceAllValue(text, value string) (string, int) {
	if value == "" {
		return text, 0
	}
	n := strings.Count(text, value)
	if n == 0 {
		return text, 0
	}
	return strings.ReplaceAll(text, value, Marker), n
}
