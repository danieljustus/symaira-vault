package redact

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExactValueDetector_RedactsKnownSecret(t *testing.T) {
	d := NewExactValueDetector([]string{"sup3r-s3cret-value-xyz"})
	got, n, err := d.Redact("the password is sup3r-s3cret-value-xyz and that's it")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 match, got %d", n)
	}
	if strings.Contains(got, "sup3r-s3cret-value-xyz") {
		t.Fatalf("secret leaked into output: %q", got)
	}
	if !strings.Contains(got, Marker) {
		t.Fatalf("expected marker in output: %q", got)
	}
}

func TestExactValueDetector_NoPartialLeak(t *testing.T) {
	d := NewExactValueDetector([]string{"abcdefghijklmnop"})
	got, _, _ := d.Redact("value=abcdefghijklmnop end")
	// Marker must not contain any substring (len >= 3) of the secret.
	secret := "abcdefghijklmnop"
	for i := 0; i+3 <= len(secret); i++ {
		sub := secret[i : i+3]
		if strings.Contains(got, sub) {
			t.Fatalf("output contains secret substring %q: %q", sub, got)
		}
	}
}

func TestExactValueDetector_IgnoresEmptyAndShortValues(t *testing.T) {
	d := NewExactValueDetector([]string{"", "ab"})
	got, n, err := d.Redact("ab is short and empty is nothing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected no matches for empty/too-short values, got %d", n)
	}
	if got != "ab is short and empty is nothing" {
		t.Fatalf("text should be unchanged, got %q", got)
	}
}

func TestExactValueDetector_OverlapSemantics(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		input  string
		want   string
		count  int
	}{
		{name: "equal_partial_short_first", values: []string{"abcd", "bcde"}, input: "abcde", want: Marker, count: 1},
		{name: "equal_partial_long_first", values: []string{"bcde", "abcd"}, input: "abcde", want: Marker, count: 1},
		{name: "unequal_partial", values: []string{"abcdef", "defgh"}, input: "abcdefgh", want: Marker, count: 1},
		{name: "containment", values: []string{"secret-value", "cret-val"}, input: "prefix secret-value suffix", want: "prefix " + Marker + " suffix", count: 1},
		{name: "adjacent_nonoverlap", values: []string{"abcd", "efgh"}, input: "abcdefgh", want: Marker + Marker, count: 2},
		{name: "repeated_occurrences", values: []string{"abcd"}, input: "abcd--abcd", want: Marker + "--" + Marker, count: 2},
		{name: "duplicates", values: []string{"abcd", "abcd", "bcde"}, input: "abcde abcd", want: Marker + " " + Marker, count: 2},
		{name: "utf8_surrounding_text", values: []string{"sëcret", "ëcret"}, input: "🔐sëcret🚀", want: "🔐" + Marker + "🚀", count: 1},
		{name: "self_overlap", values: []string{"abab"}, input: "ababab", want: Marker + "ab", count: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, count, err := NewExactValueDetector(tc.values).Redact(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want || count != tc.count {
				t.Fatalf("got (%q, %d), want (%q, %d)", got, count, tc.want, tc.count)
			}
		})
	}
}

func TestPatternDetector_DetectsCredentialShapedValues(t *testing.T) {
	d := NewPatternDetector()
	// Synthetic, obviously-fake GitHub-PAT-shaped token (not a real credential).
	text := "token=ghp_" + strings.Repeat("A", 36)
	got, n, err := d.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected pattern match, got none")
	}
	if strings.Contains(got, strings.Repeat("A", 36)) {
		t.Fatalf("pattern-matched secret leaked: %q", got)
	}
}

func TestPatternDetector_FalsePositiveResistance(t *testing.T) {
	d := NewPatternDetector()
	got, n, err := d.Redact("just a normal sentence about deployment pipelines and version 1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected no matches on benign text, got %d: %q", n, got)
	}
}

func TestScanner_JSONStructurePreserved(t *testing.T) {
	sc := NewScanner(NewExactValueDetector([]string{"topsecretvalue1"}))
	payload := `{"stdout":"login ok, token=topsecretvalue1","exit_code":0}`
	res, err := sc.Scan(payload, ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(res.Text, "topsecretvalue1") {
		t.Fatalf("secret leaked in JSON output: %q", res.Text)
	}
	if !strings.HasPrefix(res.Text, `{"stdout":"login ok, token=`) {
		t.Fatalf("JSON structure was corrupted: %q", res.Text)
	}
	if !strings.HasSuffix(res.Text, `,"exit_code":0}`) {
		t.Fatalf("JSON structure was corrupted: %q", res.Text)
	}
}

func TestScanner_MultilineAndTruncatedOutput(t *testing.T) {
	sc := NewScanner(NewExactValueDetector([]string{"multilinesecretval"}))
	text := "line one\nline two multilinesecretval\nline three (truncat"
	res, err := sc.Scan(text, ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(res.Text, "multilinesecretval") {
		t.Fatalf("secret leaked: %q", res.Text)
	}
	if !strings.HasPrefix(res.Text, "line one\nline two ") {
		t.Fatalf("multiline structure corrupted: %q", res.Text)
	}
	if !strings.HasSuffix(res.Text, "line three (truncat") {
		t.Fatalf("truncated tail corrupted: %q", res.Text)
	}
}

func TestExactValueDetector_OverlappingValuesPreferLongest(t *testing.T) {
	short := "short"
	long := "short-with-sensitive-suffix"
	input := "overlap=" + long + " standalone=" + short
	want := "overlap=" + Marker + " standalone=" + Marker

	for _, values := range [][]string{{short, long}, {long, short}} {
		d := NewExactValueDetector(values)
		got, n, err := d.Redact(input)
		if err != nil {
			t.Fatalf("values %v: unexpected error: %v", values, err)
		}
		if n != 2 {
			t.Fatalf("values %v: want 2 replacements, got %d", values, n)
		}
		if got != want {
			t.Fatalf("values %v: got %q, want %q", values, got, want)
		}
	}
}

// Replacement counts are non-overlapping matches after stable de-duplication;
// duplicate configured values do not increase the count.
func TestExactValueDetector_DeduplicatesReplacementCounts(t *testing.T) {
	d := NewExactValueDetector([]string{"short", "short", "short-with-sensitive-suffix"})
	got, n, err := d.Redact("short-with-sensitive-suffix short")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 replacements, got %d", n)
	}
	if got != Marker+" "+Marker {
		t.Fatalf("got %q, want %q", got, Marker+" "+Marker)
	}
}

type erroringDetector struct{}

func (erroringDetector) Name() string           { return "erroring" }
func (erroringDetector) Confidence() Confidence { return ConfidenceHigh }
func (erroringDetector) Redact(string) (string, int, error) {
	return "", 0, errors.New("boom")
}

func TestScanner_FailClosedOnDetectorError(t *testing.T) {
	sc := NewScanner(erroringDetector{})
	res, err := sc.Scan("some very sensitive output that must never leak", ScanOptions{})
	if err == nil {
		t.Fatalf("expected error to be surfaced")
	}
	if strings.Contains(res.Text, "sensitive output") {
		t.Fatalf("fail-closed violated: original text leaked through: %q", res.Text)
	}
	if !res.Blocked {
		t.Fatalf("expected Blocked=true on detector failure")
	}
}

func TestScanner_NoDetectors_ReturnsTextUnchanged(t *testing.T) {
	sc := NewScanner()
	res, err := sc.Scan("hello world", ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Text != "hello world" {
		t.Fatalf("expected unchanged text, got %q", res.Text)
	}
	if res.Blocked {
		t.Fatalf("should not be blocked")
	}
}

func TestExactValueDetector_ValueOverflowFailsClosed(t *testing.T) {
	values := make([]string, MaxExactValueCount+1)
	for i := range values {
		values[i] = fmt.Sprintf("secret-%04d", i)
	}

	got, count, err := NewExactValueDetector(values).Redact("ordinary output")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != Marker || count != 1 {
		t.Fatalf("overflow result = (%q, %d), want (%q, 1)", got, count, Marker)
	}
	if strings.Contains(got, "secret-") {
		t.Fatalf("overflow result leaked a retained value: %q", got)
	}
}
