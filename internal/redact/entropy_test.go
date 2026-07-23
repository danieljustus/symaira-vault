package redact

import (
	"strings"
	"testing"
)

func TestEntropyDetector_ConfidenceIsLow(t *testing.T) {
	d := NewEntropyDetector()
	if d.Confidence() != ConfidenceLow {
		t.Fatalf("entropy detector must be ConfidenceLow, got %v", d.Confidence())
	}
}

func TestEntropyDetector_FlagsHighEntropyToken(t *testing.T) {
	d := NewEntropyDetector()
	// Synthetic, obviously-fake high-entropy token (mixed case, digits,
	// symbols, no real-world credential format) — not a real secret.
	secret := "kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~"
	text := "config value: " + secret + " end"

	got, n, err := d.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected the high-entropy token to be flagged")
	}
	if strings.Contains(got, secret) {
		t.Fatalf("high-entropy secret leaked into output: %q", got)
	}
}

func TestEntropyDetector_IgnoresOrdinaryProse(t *testing.T) {
	d := NewEntropyDetector()
	text := "This is a perfectly ordinary sentence about deploying the release pipeline on Friday afternoon."
	got, n, err := d.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected no matches on ordinary prose, got %d: %q", n, got)
	}
}

func TestEntropyDetector_IgnoresShortTokens(t *testing.T) {
	d := NewEntropyDetector()
	got, n, err := d.Redact("short=aB3$kZ9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected short tokens below the length floor to be ignored, got %d: %q", n, got)
	}
}

// TestEntropyDetector_DocumentedFalsePositiveClasses measures — and pins
// via this test, rather than "fixing" by silently weakening the detector
// — the detector's behavior on shapes that are known to sometimes look
// like high-entropy secrets: UUIDs, hex hashes, base64-encoded non-secret
// payloads, and long opaque identifiers. False-positive resistance matters
// more than recall for this last-resort layer (#697), so several of these
// are expected to NOT match; where one does match, that is a documented,
// accepted limitation of a conservative last-resort heuristic, not a bug.
func TestEntropyDetector_DocumentedFalsePositiveClasses(t *testing.T) {
	d := NewEntropyDetector()

	cases := []struct {
		name        string
		text        string
		wantMatched bool
		note        string
	}{
		{
			name:        "uuid_v4",
			text:        "request_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			wantMatched: false,
			note:        "hyphenated hex runs are short between separators and low-entropy per byte (hex alphabet); the tokenizer's separator set treats '-' as a boundary",
		},
		{
			name:        "sha256_hash_of_content",
			text:        "checksum=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantMatched: false,
			note:        "hex digests use only a 16-symbol alphabet, so their empirical entropy (~3.7 bits/char) stays under the floor tuned to avoid flagging ordinary long identifiers; documented as a known miss (false negative), not a false positive, for this heuristic",
		},
		{
			name:        "base64_non_secret_payload",
			text:        "payload=" + "VGhpcyBpcyBqdXN0IGEgcGxhaW4gRW5nbGlzaCBzZW50ZW5jZSBlbmNvZGVkIGFzIGJhc2U2NA==",
			wantMatched: true,
			note:        "known limitation: base64-encoded text (even of non-secret content) is high-entropy by construction and is a documented false-positive class for this heuristic",
		},
		{
			name:        "long_numeric_identifier",
			text:        "order_id=12345678901234567890123456789012",
			wantMatched: false,
			note:        "digits-only runs have low charset diversity (10 symbols) and stay well under the entropy floor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, n, err := d.Redact(tc.text)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			matched := n > 0
			if matched != tc.wantMatched {
				t.Fatalf("%s: matched=%v, want=%v (%s)", tc.name, matched, tc.wantMatched, tc.note)
			}
		})
	}
}

func TestEntropyDetector_ComposesAsLowerConfidenceLayerInScanner(t *testing.T) {
	sc := NewScanner(NewPatternDetector(), NewEntropyDetector())
	secret := "kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~"

	res, err := sc.Scan("value: "+secret, ScanOptions{Strict: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only ConfidenceLow findings occurred, so strict mode must NOT block —
	// strict blocking is reserved for ConfidenceHigh matches (#696).
	if res.Blocked {
		t.Fatalf("strict mode should not block on a ConfidenceLow-only finding")
	}
	if strings.Contains(res.Text, secret) {
		t.Fatalf("secret leaked: %q", res.Text)
	}
	found := false
	for _, f := range res.Findings {
		if f.Detector == NewEntropyDetector().Name() && f.Confidence == ConfidenceLow {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a ConfidenceLow entropy finding, got %+v", res.Findings)
	}
}
