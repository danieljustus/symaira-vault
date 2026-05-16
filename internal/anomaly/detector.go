// Package anomaly provides cross-tool anomaly detection for OpenPass MCP servers.
//
// The detector maintains a sliding window of recent tool calls and applies
// multiple detection rules to identify suspicious behavior: sweep detection,
// rate anomalies, off-hours access, and honeytoken/canary access.
//
// All anomaly detection runs asynchronously and MUST NOT block tool execution.
package anomaly

import (
	"context"
	"sync"
	"time"
)

// Severity represents the severity level of an anomaly alert.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// AlertType classifies the kind of anomaly detected.
type AlertType string

const (
	AlertSweep        AlertType = "sweep"
	AlertStaleAccess  AlertType = "stale_access"
	AlertRateAnomaly  AlertType = "rate_anomaly"
	AlertOffHours     AlertType = "off_hours"
	AlertCanaryAccess AlertType = "canary_access"
)

// AnomalyAlert represents a single anomaly detection event.
type AnomalyAlert struct {
	Type        AlertType `json:"type"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Agent       string    `json:"agent"`
	Path        string    `json:"path,omitempty"`
	Tool        string    `json:"tool,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
}

// ToolCallEvent represents a single tool call to be analyzed by the detector.
type ToolCallEvent struct {
	Timestamp time.Time
	Agent     string
	Tool      string
	Path      string
	Duration  time.Duration
	OK        bool
	IsCanary  bool
	RequestID string
}

// Option configures an AnomalyDetector.
type Option func(*AnomalyDetector)

// WithWindowSize sets the maximum number of events in the sliding window.
func WithWindowSize(n int) Option {
	return func(d *AnomalyDetector) {
		d.maxEvents = n
	}
}

// WithSweepThreshold sets the number of unique paths within the sweep window
// that triggers a sweep alert.
func WithSweepThreshold(n int) Option {
	return func(d *AnomalyDetector) {
		d.sweepThreshold = n
	}
}

// WithSweepWindow sets the time window for sweep detection.
func WithSweepWindow(dur time.Duration) Option {
	return func(d *AnomalyDetector) {
		d.sweepWindow = dur
	}
}

// WithRateLimit sets the maximum requests per minute before a rate alert fires.
func WithRateLimit(n int) Option {
	return func(d *AnomalyDetector) {
		d.rateLimit = n
	}
}

// WithRateWindow sets the time window for rate detection.
func WithRateWindow(dur time.Duration) Option {
	return func(d *AnomalyDetector) {
		d.rateWindow = dur
	}
}

// WithOffHoursStart sets the start of off-hours (inclusive). 0 = midnight.
func WithOffHoursStart(hour int) Option {
	return func(d *AnomalyDetector) {
		d.offHoursStart = hour
	}
}

// WithOffHoursEnd sets the end of off-hours (exclusive). 6 = 6 AM.
func WithOffHoursEnd(hour int) Option {
	return func(d *AnomalyDetector) {
		d.offHoursEnd = hour
	}
}

// WithStaleThreshold sets the age in days after which an entry is considered stale.
func WithStaleThreshold(days int) Option {
	return func(d *AnomalyDetector) {
		d.staleDays = days
	}
}

// WithAlertHook registers a callback invoked for every detected anomaly.
// The hook receives a copy of the alert and runs in the same goroutine as Check.
// Hooks must not block; they are called synchronously during Check.
func WithAlertHook(hook func(AnomalyAlert)) Option {
	return func(d *AnomalyDetector) {
		d.alertHooks = append(d.alertHooks, hook)
	}
}

// Default configuration values.
const (
	defaultMaxEvents     = 1000
	defaultSweepWindow   = 60 * time.Second
	defaultSweepThresh   = 10
	defaultRateWindow    = 60 * time.Second
	defaultRateLimit     = 30
	defaultOffHoursStart = 22 // 10 PM
	defaultOffHoursEnd   = 6  // 6 AM
	defaultStaleDays     = 90
)

// AnomalyDetector maintains a sliding window of tool call events and applies
// detection rules. All methods are safe for concurrent use.
type AnomalyDetector struct {
	mu        sync.Mutex
	events    []ToolCallEvent
	maxEvents int

	sweepWindow    time.Duration
	sweepThreshold int
	rateWindow     time.Duration
	rateLimit      int
	offHoursStart  int
	offHoursEnd    int
	staleDays      int
	alertHooks     []func(AnomalyAlert)
}

// New creates a new AnomalyDetector with the given options.
func New(opts ...Option) *AnomalyDetector {
	d := &AnomalyDetector{
		maxEvents:      defaultMaxEvents,
		sweepWindow:    defaultSweepWindow,
		sweepThreshold: defaultSweepThresh,
		rateWindow:     defaultRateWindow,
		rateLimit:      defaultRateLimit,
		offHoursStart:  defaultOffHoursStart,
		offHoursEnd:    defaultOffHoursEnd,
		staleDays:      defaultStaleDays,
	}
	for _, opt := range opts {
		opt(d)
	}
	d.events = make([]ToolCallEvent, 0, d.maxEvents)
	return d
}

// Check evaluates a tool call event against all detection rules and returns
// an anomaly alert if any pattern is matched. It records the event in the
// sliding window for future analysis. Returns nil when no anomaly is detected.
//
// Check is safe for concurrent use and designed to be called asynchronously
// (non-blocking). It should be called AFTER tool execution completes.
func (d *AnomalyDetector) Check(_ context.Context, event ToolCallEvent) *AnomalyAlert {
	d.mu.Lock()
	d.addEvent(event)
	alerts := d.evaluate(event)
	d.mu.Unlock()

	for _, alert := range alerts {
		for _, hook := range d.alertHooks {
			hook(alert)
		}
	}

	if len(alerts) == 0 {
		return nil
	}
	alert := alerts[0]
	return &alert
}

// addEvent appends an event to the sliding window and trims old events.
// Must be called with d.mu held.
func (d *AnomalyDetector) addEvent(event ToolCallEvent) {
	if len(d.events) >= d.maxEvents {
		copy(d.events, d.events[1:])
		d.events[len(d.events)-1] = event
	} else {
		d.events = append(d.events, event)
	}
}

// evaluate runs all detection rules against the given event.
// Must be called with d.mu held.
func (d *AnomalyDetector) evaluate(event ToolCallEvent) []AnomalyAlert {
	var alerts []AnomalyAlert

	if alert := d.detectCanaryAccess(event); alert != nil {
		alerts = append(alerts, *alert)
	}
	if alert := d.detectOffHours(event); alert != nil {
		alerts = append(alerts, *alert)
	}
	if alert := d.detectSweep(event); alert != nil {
		alerts = append(alerts, *alert)
	}
	if alert := d.detectRateAnomaly(event); alert != nil {
		alerts = append(alerts, *alert)
	}

	return alerts
}

// WindowLen returns the current number of events in the sliding window.
func (d *AnomalyDetector) WindowLen() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.events)
}
