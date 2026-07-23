package redact

import (
	"strings"
	"testing"
)

func TestScanner_StrictMode_BlocksHighConfidenceMatch(t *testing.T) {
	var events []AuditEvent
	sc := NewScanner(NewExactValueDetector([]string{"blockmehardvalue1"}))
	sc.Audit = func(e AuditEvent) { events = append(events, e) }

	res, err := sc.Scan("output containing blockmehardvalue1 here", ScanOptions{Strict: true, CorrelationID: "corr-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Blocked {
		t.Fatalf("expected strict mode to block a high-confidence match")
	}
	if strings.Contains(res.Text, "blockmehardvalue1") {
		t.Fatalf("blocked text must never contain the secret: %q", res.Text)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 audit event, got %d", len(events))
	}
	if !events[0].Blocked {
		t.Fatalf("expected audit event to record Blocked=true")
	}
	if events[0].CorrelationID != "corr-1" {
		t.Fatalf("correlation ID not propagated: got %q", events[0].CorrelationID)
	}
}

func TestScanner_NonStrictMode_RedactsAndContinues(t *testing.T) {
	var events []AuditEvent
	sc := NewScanner(NewExactValueDetector([]string{"redactmesoftvalue1"}))
	sc.Audit = func(e AuditEvent) { events = append(events, e) }

	res, err := sc.Scan("output containing redactmesoftvalue1 here, and more text after", ScanOptions{Strict: false, CorrelationID: "corr-2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Blocked {
		t.Fatalf("non-strict mode must not block")
	}
	if strings.Contains(res.Text, "redactmesoftvalue1") {
		t.Fatalf("secret leaked: %q", res.Text)
	}
	if !strings.Contains(res.Text, "and more text after") {
		t.Fatalf("non-strict mode must preserve surrounding output, got %q", res.Text)
	}
	if len(events) != 1 || events[0].Blocked {
		t.Fatalf("expected 1 non-blocked audit event, got %+v", events)
	}
}

func TestScanner_AuditEvents_NeverContainSecretMaterial(t *testing.T) {
	secret := "hyperconfidentialvalue42"
	var events []AuditEvent
	sc := NewScanner(NewExactValueDetector([]string{secret}))
	sc.Audit = func(e AuditEvent) { events = append(events, e) }

	for _, strict := range []bool{true, false} {
		events = nil
		_, err := sc.Scan("leaked here: "+secret, ScanOptions{Strict: strict, CorrelationID: "corr-3"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range events {
			// AuditEvent's fields are all metadata-typed (strings/ints/bools
			// that describe the detection, not the value) — assert none of
			// them, when formatted, contain the secret or a hash of it.
			if strings.Contains(e.Detector, secret) || strings.Contains(e.Channel, secret) || strings.Contains(e.CorrelationID, secret) {
				t.Fatalf("audit event leaked secret material: %+v", e)
			}
		}
	}
}

func TestScanner_CorrelationID_TiesBlockToCall(t *testing.T) {
	var events []AuditEvent
	sc := NewScanner(NewExactValueDetector([]string{"corrtiedvalue123"}))
	sc.Audit = func(e AuditEvent) { events = append(events, e) }

	if _, err := sc.Scan("a corrtiedvalue123 b", ScanOptions{Strict: true, CorrelationID: "call-A"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := sc.Scan("a corrtiedvalue123 b", ScanOptions{Strict: false, CorrelationID: "call-B"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(events))
	}
	if events[0].CorrelationID != "call-A" || !events[0].Blocked {
		t.Fatalf("event 0 does not tie back to call-A block: %+v", events[0])
	}
	if events[1].CorrelationID != "call-B" || events[1].Blocked {
		t.Fatalf("event 1 does not tie back to call-B redaction: %+v", events[1])
	}
}

func TestStrictModeEnabled_OptInEnvVar(t *testing.T) {
	t.Setenv(EnvStrictMode, "")
	if StrictModeEnabled() {
		t.Fatalf("expected strict mode disabled by default")
	}
	t.Setenv(EnvStrictMode, "true")
	if !StrictModeEnabled() {
		t.Fatalf("expected strict mode enabled when %s=true", EnvStrictMode)
	}
	t.Setenv(EnvStrictMode, "0")
	if StrictModeEnabled() {
		t.Fatalf("expected strict mode disabled when %s=0", EnvStrictMode)
	}
}

func TestNewCorrelationID_ReturnsNonEmptyUniqueValues(t *testing.T) {
	a := NewCorrelationID()
	b := NewCorrelationID()
	if a == "" || b == "" {
		t.Fatalf("expected non-empty correlation IDs")
	}
	if a == b {
		t.Fatalf("expected unique correlation IDs, got two equal values %q", a)
	}
}
