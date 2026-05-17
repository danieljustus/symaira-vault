package anomaly

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCanaryAccessDetection(t *testing.T) {
	d := New()
	event := ToolCallEvent{
		Timestamp: time.Now(),
		Agent:     "test-agent",
		Tool:      "get_entry_value",
		Path:      ".canary/aws-root-key",
		IsCanary:  true,
		RequestID: "req-1",
	}
	alert := d.Check(context.Background(), event)
	if alert == nil {
		t.Fatal("expected canary alert, got nil")
	}
	if alert.Type != AlertCanaryAccess {
		t.Fatalf("expected AlertCanaryAccess, got %s", alert.Type)
	}
	if alert.Severity != SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", alert.Severity)
	}
	if alert.Path != ".canary/aws-root-key" {
		t.Fatalf("expected path .canary/aws-root-key, got %s", alert.Path)
	}
	if alert.Agent != "test-agent" {
		t.Fatalf("expected agent test-agent, got %s", alert.Agent)
	}
}

func TestNonCanaryAccessNoAlert(t *testing.T) {
	d := New()
	event := ToolCallEvent{
		Timestamp: time.Now(),
		Agent:     "test-agent",
		Tool:      "get_entry_value",
		Path:      "normal/entry",
		IsCanary:  false,
		RequestID: "req-1",
	}
	alert := d.Check(context.Background(), event)
	if alert != nil {
		t.Fatalf("expected nil for non-canary access, got %v", alert)
	}
}

func TestOffHoursDetection(t *testing.T) {
	d := New(
		WithOffHoursStart(22), // 10 PM
		WithOffHoursEnd(6),    // 6 AM
	)

	// Simulate 3 AM (off-hours)
	offHours := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	event := ToolCallEvent{
		Timestamp: offHours,
		Agent:     "test-agent",
		Tool:      "get_entry",
		Path:      "some/entry",
		RequestID: "req-1",
	}
	alert := d.Check(context.Background(), event)
	if alert == nil {
		t.Fatal("expected off-hours alert, got nil")
	}
	if alert.Type != AlertOffHours {
		t.Fatalf("expected AlertOffHours, got %s", alert.Type)
	}
	if alert.Severity != SeverityLow {
		t.Fatalf("expected SeverityLow, got %v", alert.Severity)
	}
}

func TestOffHoursNoAlertDuringBusiness(t *testing.T) {
	d := New(
		WithOffHoursStart(22),
		WithOffHoursEnd(6),
	)

	// Simulate 2 PM (business hours)
	bizHours := time.Date(2026, 5, 16, 14, 0, 0, 0, time.UTC)
	event := ToolCallEvent{
		Timestamp: bizHours,
		Agent:     "test-agent",
		Tool:      "get_entry",
		Path:      "some/entry",
		RequestID: "req-1",
	}
	alert := d.Check(context.Background(), event)
	if alert != nil {
		t.Fatalf("expected nil during business hours, got %v", alert)
	}
}

func TestOffHoursWrapAround(t *testing.T) {
	d := New(
		WithOffHoursStart(20), // 8 PM
		WithOffHoursEnd(8),    // 8 AM
	)

	// 11 PM should be off-hours
	late := time.Date(2026, 5, 16, 23, 0, 0, 0, time.UTC)
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: late,
		Path:      "some/entry",
	})
	if alert == nil {
		t.Fatal("expected off-hours alert for 11 PM")
	}

	// 5 AM should be off-hours (wrap-around)
	early := time.Date(2026, 5, 16, 5, 0, 0, 0, time.UTC)
	alert2 := d.Check(context.Background(), ToolCallEvent{
		Timestamp: early,
		Path:      "some/entry",
	})
	if alert2 == nil {
		t.Fatal("expected off-hours alert for 5 AM")
	}

	// 10 AM should NOT be off-hours
	day := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	alert3 := d.Check(context.Background(), ToolCallEvent{
		Timestamp: day,
		Path:      "some/entry",
	})
	if alert3 != nil {
		t.Fatal("unexpected off-hours alert for 10 AM")
	}
}

func TestSweepDetection(t *testing.T) {
	d := New(
		WithSweepThreshold(3),
		WithSweepWindow(time.Minute),
	)

	now := time.Now()

	// Add 2 different paths - should not trigger
	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Path:      "alpha",
	})
	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Path:      "beta",
	})

	// 3rd unique path within window should trigger
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Agent:     "test-agent",
		Path:      "gamma",
		Tool:      "get_entry",
		RequestID: "req-1",
	})
	if alert == nil {
		t.Fatal("expected sweep alert, got nil")
	}
	if alert.Type != AlertSweep {
		t.Fatalf("expected AlertSweep, got %s", alert.Type)
	}
	if alert.Severity != SeverityMedium {
		t.Fatalf("expected SeverityMedium, got %v", alert.Severity)
	}
}

func TestSweepSamePathDoesNotTrigger(t *testing.T) {
	d := New(
		WithSweepThreshold(3),
		WithSweepWindow(time.Minute),
	)

	now := time.Now()

	// Same path accessed many times - should NOT trigger sweep
	for i := 0; i < 5; i++ {
		alert := d.Check(context.Background(), ToolCallEvent{
			Timestamp: now,
			Path:      "same/path",
		})
		if alert != nil {
			t.Fatalf("unexpected sweep alert for same path access: %v", alert)
		}
	}
}

func TestSweepOldEventsIgnored(t *testing.T) {
	d := New(
		WithSweepThreshold(2),
		WithSweepWindow(10*time.Millisecond), // very short window
	)

	now := time.Now()

	// These are within the window
	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Path:      "alpha",
	})
	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Path:      "beta",
	})

	// Wait for window to pass
	time.Sleep(15 * time.Millisecond)

	// New path with old window - should NOT trigger since old events expired
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: time.Now(),
		Agent:     "test-agent",
		Path:      "gamma",
	})
	if alert != nil {
		t.Fatal("expected no sweep alert with expired window")
	}
}

func TestRateAnomalyDetection(t *testing.T) {
	d := New(
		WithRateLimit(5),
		WithRateWindow(time.Minute),
	)

	now := time.Now()

	// 5 events below the limit
	for i := 0; i < 5; i++ {
		alert := d.Check(context.Background(), ToolCallEvent{
			Timestamp: now,
			Agent:     "test-agent",
			Path:      "entry",
		})
		if alert != nil {
			t.Fatalf("unexpected rate alert at event %d: %v", i+1, alert)
		}
	}

	// 6th event should trigger rate anomaly
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Agent:     "test-agent",
		Tool:      "get_entry",
		Path:      "entry",
		RequestID: "req-1",
	})
	if alert == nil {
		t.Fatal("expected rate anomaly alert, got nil")
	}
	if alert.Type != AlertRateAnomaly {
		t.Fatalf("expected AlertRateAnomaly, got %s", alert.Type)
	}
	if alert.Severity != SeverityMedium {
		t.Fatalf("expected SeverityMedium, got %v", alert.Severity)
	}
}

func TestRateAnomalyPerAgent(t *testing.T) {
	d := New(
		WithRateLimit(3),
		WithRateWindow(time.Minute),
	)

	now := time.Now()

	// Agent A makes 4 requests
	for i := 0; i < 4; i++ {
		d.Check(context.Background(), ToolCallEvent{
			Timestamp: now,
			Agent:     "agent-a",
			Path:      "entry",
		})
	}
	// Agent B makes 4 requests - should also trigger
	for i := 0; i < 4; i++ {
		d.Check(context.Background(), ToolCallEvent{
			Timestamp: now,
			Agent:     "agent-b",
			Path:      "entry",
		})
	}
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Agent:     "agent-b",
		Tool:      "get_entry",
		Path:      "entry",
		RequestID: "req-1",
	})
	if alert == nil {
		t.Fatal("expected rate anomaly for agent-b")
	}
}

func TestWindowSizeLimit(t *testing.T) {
	d := New(WithWindowSize(10))

	// Add 20 events
	for i := 0; i < 20; i++ {
		d.Check(context.Background(), ToolCallEvent{
			Timestamp: time.Now(),
			Path:      "entry",
		})
	}

	if d.WindowLen() > 10 {
		t.Fatalf("window size exceeded: got %d, want <= 10", d.WindowLen())
	}
}

func TestAlertHook(t *testing.T) {
	var called atomic.Int64
	d := New(
		WithAlertHook(func(a AnomalyAlert) {
			called.Add(1)
		}),
	)

	// Trigger a canary alert
	d.Check(context.Background(), ToolCallEvent{
		Timestamp: time.Now(),
		Path:      ".canary/test",
		IsCanary:  true,
	})

	if called.Load() != 1 {
		t.Fatalf("expected hook called 1 time, got %d", called.Load())
	}
}

func TestMultipleAlertHooks(t *testing.T) {
	var c1, c2 atomic.Int64
	d := New(
		WithAlertHook(func(a AnomalyAlert) { c1.Add(1) }),
		WithAlertHook(func(a AnomalyAlert) { c2.Add(1) }),
	)

	d.Check(context.Background(), ToolCallEvent{
		Timestamp: time.Now(),
		Path:      ".canary/test",
		IsCanary:  true,
	})

	if c1.Load() != 1 || c2.Load() != 1 {
		t.Fatalf("expected both hooks called 1 time, got c1=%d c2=%d", c1.Load(), c2.Load())
	}
}

func TestCombinedAnomalies(t *testing.T) {
	d := New(
		WithSweepThreshold(3),
		WithSweepWindow(time.Minute),
		WithRateLimit(5),
		WithRateWindow(time.Minute),
		WithOffHoursStart(22),
		WithOffHoursEnd(6),
	)

	now := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)

	// First 3 events with different paths + off-hours + one canary
	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Agent:     "test-agent",
		Path:      "entry-1",
	})
	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Agent:     "test-agent",
		Path:      "entry-2",
	})

	// Third event: different path + off-hours + canary
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: now,
		Agent:     "test-agent",
		Tool:      "get_entry_value",
		Path:      ".canary/prod-db",
		RequestID: "req-1",
		IsCanary:  true,
	})
	if alert == nil {
		t.Fatal("expected alert from combined conditions")
	}
	// Canary detection is checked first in evaluate()
	if alert.Type != AlertCanaryAccess {
		t.Fatalf("expected canary alert, got %s", alert.Type)
	}
}

func TestEmptyPathNoDetection(t *testing.T) {
	d := New()

	// Events with empty paths should not trigger detection
	for i := 0; i < 20; i++ {
		alert := d.Check(context.Background(), ToolCallEvent{
			Timestamp: time.Now(),
			Agent:     "test-agent",
			Tool:      "list_entries",
			Path:      "",
		})
		if alert != nil {
			t.Fatalf("unexpected alert for empty path: %v", alert)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	d := New(WithWindowSize(100))

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			d.Check(context.Background(), ToolCallEvent{
				Timestamp: time.Now(),
				Agent:     "agent-a",
				Path:      "entry",
			})
		}
		done <- struct{}{}
	}()

	go func() {
		for i := 0; i < 50; i++ {
			d.Check(context.Background(), ToolCallEvent{
				Timestamp: time.Now(),
				Agent:     "agent-b",
				Path:      "entry",
			})
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	if d.WindowLen() == 0 {
		t.Fatal("expected events after concurrent access")
	}
}

func TestDetectToolChain_FiresOnNotesRunCommand(t *testing.T) {
	d := New(WithToolChainWindow(30*time.Second), WithToolChainFieldThreshold(500))
	now := time.Now()
	agentName := "claude"

	e1 := ToolCallEvent{
		Timestamp:   now,
		Agent:       agentName,
		Tool:        "get_entry_value",
		Path:        "prod/db",
		FieldLength: 600,
		OK:          true,
	}
	if alert := d.Check(context.Background(), e1); alert != nil {
		t.Errorf("unexpected alert on read event: %v", alert)
	}

	e2 := ToolCallEvent{
		Timestamp: now.Add(5 * time.Second),
		Agent:     agentName,
		Tool:      "run_command",
		OK:        true,
	}
	alert := d.Check(context.Background(), e2)
	if alert == nil {
		t.Fatal("expected tool-chain alert, got nil")
	}
	if alert.Type != AlertToolChain {
		t.Errorf("alert type = %q, want %q", alert.Type, AlertToolChain)
	}
	if alert.Severity != SeverityHigh {
		t.Errorf("severity = %v, want High", alert.Severity)
	}
}

func TestDetectToolChain_NoFireBelowThreshold(t *testing.T) {
	d := New(WithToolChainWindow(30*time.Second), WithToolChainFieldThreshold(500))
	now := time.Now()

	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now, Agent: "agent", Tool: "get_entry_value", FieldLength: 200, OK: true,
	})
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: now.Add(2 * time.Second), Agent: "agent", Tool: "run_command", OK: true,
	})
	if alert != nil && alert.Type == AlertToolChain {
		t.Error("should not alert when FieldLength < threshold")
	}
}

func TestDetectToolChain_NoFireOutsideWindow(t *testing.T) {
	d := New(WithToolChainWindow(30*time.Second), WithToolChainFieldThreshold(500))
	now := time.Now()

	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now, Agent: "agent", Tool: "get_entry_value", FieldLength: 800, OK: true,
	})
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: now.Add(60 * time.Second), Agent: "agent", Tool: "run_command", OK: true,
	})
	if alert != nil && alert.Type == AlertToolChain {
		t.Error("should not alert when read is outside tool-chain window")
	}
}

func TestDetectToolChain_DifferentAgents(t *testing.T) {
	d := New(WithToolChainWindow(30*time.Second), WithToolChainFieldThreshold(500))
	now := time.Now()

	d.Check(context.Background(), ToolCallEvent{
		Timestamp: now, Agent: "agentA", Tool: "get_entry_value", FieldLength: 800, OK: true,
	})
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: now.Add(2 * time.Second), Agent: "agentB", Tool: "run_command", OK: true,
	})
	if alert != nil && alert.Type == AlertToolChain {
		t.Error("should not alert for different agents")
	}
}

func TestStaleAccessRuleNotYetImplemented(t *testing.T) {
	// Stale access detection requires entry metadata (created/updated timestamps).
	// The detector currently uses ToolCallEvent which doesn't carry this info.
	// This test documents the known gap. When stale detection is implemented,
	// the test should verify that accessing entries not modified in >90 days
	// triggers an alert.
	d := New()
	alert := d.Check(context.Background(), ToolCallEvent{
		Timestamp: time.Now(),
		Agent:     "test",
		Path:      "old/entry",
	})
	if alert != nil {
		t.Log("stale access detection hit (future implementation)")
	}
}
