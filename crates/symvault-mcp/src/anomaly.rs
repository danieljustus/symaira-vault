//! PLATFORM-002 / ADR 0034 item 29: the MCP anomaly detector.
//!
//! Ports `internal/anomaly` (`detector.go`, `rules.go`) at the ordered Go
//! reference `mcp-anomaly-ordered-v1` (`24acdb08`, ADR 0016) together with the
//! logging half of `detectAnomalyAsync` in `internal/mcp/server/server_dispatch.go`.
//! The audit rows and the approval-cache invalidation are applied by
//! `StoreReadOnlyRuntime`, which owns the audit logger and the cache.
//!
//! Every rule is a pure function of the sliding window and the event, so the
//! detector is deterministic once the clock is injected ([`AnomalyClock`]).
//! Desktop notifications are not ported (ADR 0034 item 28: absent, fail closed).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::{OffsetDateTime, UtcOffset};

/// Go `anomaly.Severity`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Go `anomaly.AlertType`. `StaleAccess` has no rule in Go either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertType {
    Sweep,
    StaleAccess,
    RateAnomaly,
    OffHours,
    CanaryAccess,
    ToolChain,
}

impl AlertType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sweep => "sweep",
            Self::StaleAccess => "stale_access",
            Self::RateAnomaly => "rate_anomaly",
            Self::OffHours => "off_hours",
            Self::CanaryAccess => "canary_access",
            Self::ToolChain => "tool_chain",
        }
    }
}

/// Go `anomaly.AnomalyAlert`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnomalyAlert {
    pub alert_type: AlertType,
    pub severity: Severity,
    pub description: String,
    pub timestamp: OffsetDateTime,
    pub agent: String,
    pub path: String,
    pub tool: String,
    pub request_id: String,
}

/// Go `anomaly.ToolCallEvent`.
#[derive(Clone, Debug)]
pub struct ToolCallEvent {
    pub timestamp: OffsetDateTime,
    pub agent: String,
    pub tool: String,
    pub path: String,
    pub duration: Duration,
    pub ok: bool,
    pub is_canary: bool,
    pub request_id: String,
    /// Byte length of the raw value before redaction; 0 for non-read tools.
    pub field_length: usize,
}

/// Go `anomaly.New` options. [`Default`] is Go's default configuration.
#[derive(Clone, Debug)]
pub struct DetectorConfig {
    pub max_events: usize,
    pub sweep_window: Duration,
    pub sweep_threshold: usize,
    pub rate_window: Duration,
    pub rate_limit: usize,
    /// Inclusive start hour of the off-hours window (local time).
    pub off_hours_start: u8,
    /// Exclusive end hour of the off-hours window (local time).
    pub off_hours_end: u8,
    pub tool_chain_window: Duration,
    pub tool_chain_threshold: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            max_events: 1000,
            sweep_window: Duration::from_secs(60),
            sweep_threshold: 10,
            rate_window: Duration::from_secs(60),
            rate_limit: 30,
            off_hours_start: 22,
            off_hours_end: 6,
            tool_chain_window: Duration::from_secs(30),
            tool_chain_threshold: 500,
        }
    }
}

/// Go `anomaly.AnomalyDetector`: a sliding window plus the five rules.
#[derive(Debug)]
pub struct AnomalyDetector {
    events: VecDeque<ToolCallEvent>,
    config: DetectorConfig,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new(DetectorConfig::default())
    }
}

impl AnomalyDetector {
    #[must_use]
    pub fn new(mut config: DetectorConfig) -> Self {
        // Go indexes `events[len-1]` after the trim and would panic on a zero
        // window; a window of one is the smallest meaningful value.
        config.max_events = config.max_events.max(1);
        Self {
            events: VecDeque::with_capacity(config.max_events.min(1024)),
            config,
        }
    }

    /// Go `WindowLen`.
    #[must_use]
    pub fn window_len(&self) -> usize {
        self.events.len()
    }

    /// Go `Check`, returning every alert in rule order (canary, off-hours,
    /// sweep, rate, tool chain). Go's `Check` hands the first one to its
    /// caller and every one to the alert hooks.
    pub fn check(&mut self, event: ToolCallEvent) -> Vec<AnomalyAlert> {
        if self.events.len() >= self.config.max_events {
            self.events.pop_front();
        }
        self.events.push_back(event.clone());
        let mut alerts = Vec::new();
        alerts.extend(self.detect_canary_access(&event));
        alerts.extend(self.detect_off_hours(&event));
        alerts.extend(self.detect_sweep(&event));
        alerts.extend(self.detect_rate_anomaly(&event));
        alerts.extend(self.detect_tool_chain(&event));
        alerts
    }

    fn alert(
        event: &ToolCallEvent,
        alert_type: AlertType,
        severity: Severity,
        description: String,
        with_path: bool,
    ) -> AnomalyAlert {
        AnomalyAlert {
            alert_type,
            severity,
            description,
            timestamp: event.timestamp,
            agent: event.agent.clone(),
            path: if with_path {
                event.path.clone()
            } else {
                String::new()
            },
            tool: event.tool.clone(),
            request_id: event.request_id.clone(),
        }
    }

    /// Go `detectCanaryAccess`: any canary/honeytoken access, critical.
    fn detect_canary_access(&self, event: &ToolCallEvent) -> Option<AnomalyAlert> {
        if !event.is_canary || event.path.is_empty() {
            return None;
        }
        Some(Self::alert(
            event,
            AlertType::CanaryAccess,
            Severity::Critical,
            format!("Honeytoken/canary entry accessed by agent {}", event.agent),
            true,
        ))
    }

    /// Go `detectOffHours`: access with a path during the off-hours window.
    fn detect_off_hours(&self, event: &ToolCallEvent) -> Option<AnomalyAlert> {
        if event.path.is_empty() {
            return None;
        }
        let hour = event.timestamp.hour();
        let (start, end) = (self.config.off_hours_start, self.config.off_hours_end);
        let off_hours = if start <= end {
            hour >= start && hour < end
        } else {
            hour >= start || hour < end
        };
        if !off_hours {
            return None;
        }
        Some(Self::alert(
            event,
            AlertType::OffHours,
            Severity::Low,
            format!("Entry access during off-hours by agent {}", event.agent),
            true,
        ))
    }

    /// Go `detectSweep`: many distinct paths inside the sweep window, over all
    /// agents (Go does not filter by agent here).
    fn detect_sweep(&self, event: &ToolCallEvent) -> Option<AnomalyAlert> {
        if event.path.is_empty() {
            return None;
        }
        let cutoff = event.timestamp - self.config.sweep_window;
        let mut seen = std::collections::HashSet::new();
        for stored in &self.events {
            if stored.timestamp < cutoff {
                continue;
            }
            if !stored.path.is_empty() {
                seen.insert(stored.path.as_str());
            }
        }
        if seen.len() < self.config.sweep_threshold {
            return None;
        }
        Some(Self::alert(
            event,
            AlertType::Sweep,
            Severity::Medium,
            format!(
                "Sweep access detected: {} accessed {} unique paths",
                event.agent,
                seen.len()
            ),
            true,
        ))
    }

    /// Go `detectRateAnomaly`: more than `rate_limit` calls by the same agent
    /// inside the rate window (the current call included).
    fn detect_rate_anomaly(&self, event: &ToolCallEvent) -> Option<AnomalyAlert> {
        let cutoff = event.timestamp - self.config.rate_window;
        let count = self
            .events
            .iter()
            .filter(|stored| stored.timestamp >= cutoff && stored.agent == event.agent)
            .count();
        if count <= self.config.rate_limit {
            return None;
        }
        Some(Self::alert(
            event,
            AlertType::RateAnomaly,
            Severity::Medium,
            format!("Rate anomaly: {} made {count} requests", event.agent),
            false,
        ))
    }

    /// Go `detectToolChain`: a large `get_entry*` read followed by a command
    /// tool from the same agent inside the chain window.
    fn detect_tool_chain(&self, event: &ToolCallEvent) -> Option<AnomalyAlert> {
        if event.tool != "run_command" && event.tool != "execute_with_secret" {
            return None;
        }
        let cutoff = event.timestamp - self.config.tool_chain_window;
        for stored in self.events.iter().rev() {
            if stored.timestamp < cutoff {
                break;
            }
            if stored.agent != event.agent {
                continue;
            }
            if (stored.tool == "get_entry" || stored.tool == "get_entry_value")
                && stored.field_length >= self.config.tool_chain_threshold
            {
                return Some(Self::alert(
                    event,
                    AlertType::ToolChain,
                    Severity::High,
                    format!(
                        "Tool-chain: agent {} read a large field ({} bytes) then invoked {}",
                        event.agent, stored.field_length, event.tool
                    ),
                    true,
                ));
            }
        }
        None
    }
}

/// The clock the monitor stamps events and log lines with. Injected so tests
/// are deterministic; Go uses `time.Now()` (local zone, which decides
/// off-hours).
pub trait AnomalyClock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

/// A clock frozen at one instant. Replay and contract tests that are not about
/// the detector pin it to midday so a run at night does not raise off-hours
/// alerts (which, like Go's, invalidate the approval cache and add audit rows).
#[derive(Clone, Copy, Debug)]
pub struct FixedAnomalyClock(pub OffsetDateTime);

impl FixedAnomalyClock {
    /// 2026-11-03 12:00:00 UTC, well outside the default off-hours window.
    #[must_use]
    pub fn midday() -> Self {
        Self(OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_793_707_200))
    }
}

impl AnomalyClock for FixedAnomalyClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// Wall clock in the host's local zone, like Go's `time.Now()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAnomalyClock;

impl AnomalyClock for SystemAnomalyClock {
    fn now(&self) -> OffsetDateTime {
        let utc = OffsetDateTime::now_utc();
        utc.to_offset(local_offset_at(utc))
    }
}

/// UTC offset the host zone (`TZ`, then the system zone) applies at `moment`.
/// The `time` crate refuses to read it once the process has a second thread,
/// so ask libc directly. Windows falls back to UTC (declared difference).
#[cfg(unix)]
#[allow(unsafe_code)] // One localtime_r(3) call on a stack-allocated `tm`.
fn local_offset_at(moment: OffsetDateTime) -> UtcOffset {
    let seconds: libc::time_t = moment.unix_timestamp();
    // SAFETY: `seconds` and `local` are valid for the call; localtime_r is the
    // reentrant variant and does not retain either pointer.
    let local = unsafe {
        let mut local: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&seconds, &mut local).is_null() {
            return UtcOffset::UTC;
        }
        local
    };
    i32::try_from(local.tm_gmtoff)
        .ok()
        .and_then(|offset| UtcOffset::from_whole_seconds(offset).ok())
        .unwrap_or(UtcOffset::UTC)
}

#[cfg(not(unix))]
fn local_offset_at(_moment: OffsetDateTime) -> UtcOffset {
    UtcOffset::UTC
}

/// Receives each rendered warning line (Go: `slog.Default().Warn`, which the
/// standard logger writes to stderr).
pub type WarnSink = Arc<dyn Fn(&str) + Send + Sync>;

pub(crate) fn stderr_sink() -> WarnSink {
    Arc::new(|line| write_warning_line(&mut std::io::stderr().lock(), line))
}

/// Writes one warning line and ignores every I/O error. `eprintln!` panics
/// when stderr is closed or broken (EPIPE), and the release profile aborts on
/// panic: a diagnostics channel must never take the MCP server down.
pub(crate) fn write_warning_line(writer: &mut impl std::io::Write, line: &str) {
    let _ = writeln!(writer, "{line}");
}

/// Detector, clock and warning sink of one MCP session.
pub(crate) struct AnomalyMonitor {
    detector: Mutex<AnomalyDetector>,
    clock: Arc<dyn AnomalyClock>,
    sink: WarnSink,
}

impl AnomalyMonitor {
    pub(crate) fn new() -> Self {
        Self {
            detector: Mutex::new(AnomalyDetector::default()),
            clock: Arc::new(SystemAnomalyClock),
            sink: stderr_sink(),
        }
    }

    pub(crate) fn with_clock(mut self, clock: Arc<dyn AnomalyClock>) -> Self {
        self.clock = clock;
        self
    }

    pub(crate) fn with_sink(mut self, sink: WarnSink) -> Self {
        self.sink = sink;
        self
    }

    pub(crate) fn with_config(self, config: DetectorConfig) -> Self {
        Self {
            detector: Mutex::new(AnomalyDetector::new(config)),
            ..self
        }
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// A poisoned lock only means another thread panicked mid-update; the
    /// event window is still a valid list, so detection keeps working instead
    /// of silently dropping every later alert.
    fn detector(&self) -> std::sync::MutexGuard<'_, AnomalyDetector> {
        self.detector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn window_len(&self) -> usize {
        self.detector().window_len()
    }

    /// Records `event` and returns the alerts. Nothing is written here: the
    /// caller persists the audit row and invalidates the approval cache first
    /// and only then calls [`Self::log_alerts`], so a stalled or broken log
    /// sink can never delay or suppress them.
    pub(crate) fn check(&self, event: ToolCallEvent) -> Vec<AnomalyAlert> {
        self.detector().check(event)
    }

    /// Go's `WithAlertHook` in `server.go` logs every alert (type, severity,
    /// agent, description); those lines are emitted here.
    pub(crate) fn log_alerts(&self, alerts: &[AnomalyAlert]) {
        for alert in alerts {
            self.warn(&[
                ("type", alert.alert_type.as_str()),
                ("severity", alert.severity.as_str()),
                ("agent", &alert.agent),
                ("description", &alert.description),
            ]);
        }
    }

    /// The `slog.Default().Warn("anomaly detected", ...)` of
    /// `detectAnomalyAsync`, which only the first alert reaches.
    pub(crate) fn warn_dispatched(&self, alert: &AnomalyAlert) {
        self.warn(&[
            ("type", alert.alert_type.as_str()),
            ("severity", alert.severity.as_str()),
            ("agent", &alert.agent),
            ("path", &alert.path),
            ("request_id", &alert.request_id),
            ("description", &alert.description),
        ]);
    }

    fn warn(&self, attrs: &[(&str, &str)]) {
        (self.sink)(&render_warning(self.clock.now(), "anomaly detected", attrs));
    }
}

/// The standard logger's `LstdFlags` prefix plus slog's text handler:
/// `2006/01/02 15:04:05 WARN msg key=value ...`.
pub(crate) fn render_warning(now: OffsetDateTime, message: &str, attrs: &[(&str, &str)]) -> String {
    let mut line = format!(
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02} WARN {}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        message,
    );
    for (key, value) in attrs {
        line.push(' ');
        line.push_str(key);
        line.push('=');
        line.push_str(&text_value(value));
    }
    line
}

/// slog `TextHandler` value quoting (`needsQuoting` + `strconv.Quote`).
fn text_value(value: &str) -> String {
    let needs_quoting = value.is_empty()
        || value.chars().any(|character| {
            if character.is_ascii() {
                character != '\\'
                    && (character == ' '
                        || character == '='
                        || character == '"'
                        || !(' '..='~').contains(&character))
            } else {
                character == '\u{FFFD}' || character.is_whitespace() || character.is_control()
            }
        });
    if needs_quoting {
        symvault_core::go_quote(value)
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(at: OffsetDateTime, agent: &str, tool: &str, path: &str) -> ToolCallEvent {
        ToolCallEvent {
            timestamp: at,
            agent: agent.into(),
            tool: tool.into(),
            path: path.into(),
            duration: Duration::ZERO,
            ok: true,
            is_canary: false,
            request_id: "req".into(),
            field_length: 0,
        }
    }

    /// 2026-11-03 12:00:00 +01:00.
    fn noon() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_793_703_600)
            .unwrap()
            .to_offset(UtcOffset::from_hms(1, 0, 0).unwrap())
    }

    #[test]
    fn off_hours_window_wraps_midnight_and_uses_the_event_offset() {
        let mut detector = AnomalyDetector::default();
        for (hour, expected) in [
            (21, false),
            (22, true),
            (23, true),
            (0, true),
            (5, true),
            (6, false),
        ] {
            let at = noon().replace_hour(hour).unwrap();
            let alerts = detector.check(event(at, "a", "get_entry", "p"));
            assert_eq!(
                alerts.iter().any(|a| a.alert_type == AlertType::OffHours),
                expected,
                "hour {hour}"
            );
        }
        // No path, no off-hours alert.
        let at = noon().replace_hour(3).unwrap();
        assert!(
            detector
                .check(event(at, "a", "list_entries", ""))
                .is_empty()
        );
    }

    #[test]
    fn rate_anomaly_needs_more_than_the_limit_in_the_window() {
        let mut detector = AnomalyDetector::default();
        let mut last = Vec::new();
        for i in 0..31 {
            last = detector.check(event(noon() + time::Duration::seconds(i), "a", "x", ""));
            assert!(i == 30 || last.is_empty(), "call {i}");
        }
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].alert_type, AlertType::RateAnomaly);
        assert_eq!(last[0].description, "Rate anomaly: a made 31 requests");
        assert_eq!(last[0].path, "");
        // Another agent is not counted.
        let other = detector.check(event(noon() + time::Duration::seconds(31), "b", "x", ""));
        assert!(other.is_empty());
        // The window is exclusive of events older than 60 s.
        let later = detector.check(event(noon() + time::Duration::seconds(300), "a", "x", ""));
        assert!(later.is_empty());
    }

    #[test]
    fn canary_is_critical_and_needs_a_path() {
        let mut detector = AnomalyDetector::default();
        let mut canary = event(noon(), "a", "get_entry", "honey/pot");
        canary.is_canary = true;
        let alerts = detector.check(canary);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(
            alerts[0].description,
            "Honeytoken/canary entry accessed by agent a"
        );
        let mut pathless = event(noon(), "a", "list_entries", "");
        pathless.is_canary = true;
        assert!(detector.check(pathless).is_empty());
    }

    #[test]
    fn alerts_are_returned_in_go_rule_order() {
        let mut detector = AnomalyDetector::default();
        let night = noon().replace_hour(2).unwrap();
        let mut canary = event(night, "a", "get_entry", "honey/pot");
        canary.is_canary = true;
        let alerts = detector.check(canary);
        let kinds: Vec<_> = alerts.iter().map(|a| a.alert_type).collect();
        assert_eq!(kinds, [AlertType::CanaryAccess, AlertType::OffHours]);
    }

    #[test]
    fn sweep_counts_unique_paths_over_all_agents() {
        let mut detector = AnomalyDetector::default();
        for i in 0..9 {
            let who = if i % 2 == 0 { "a" } else { "b" };
            let alerts = detector.check(event(
                noon() + time::Duration::seconds(i),
                who,
                "get_entry",
                &format!("p/{i}"),
            ));
            assert!(alerts.is_empty(), "path {i}");
        }
        // A repeated path does not count twice.
        assert!(
            detector
                .check(event(
                    noon() + time::Duration::seconds(9),
                    "a",
                    "get_entry",
                    "p/0"
                ))
                .is_empty()
        );
        let alerts = detector.check(event(
            noon() + time::Duration::seconds(10),
            "a",
            "get_entry",
            "p/9",
        ));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, AlertType::Sweep);
        assert_eq!(
            alerts[0].description,
            "Sweep access detected: a accessed 10 unique paths"
        );
        assert_eq!(alerts[0].path, "p/9");
    }

    #[test]
    fn tool_chain_needs_a_large_read_then_a_command_by_the_same_agent() {
        let mut detector = AnomalyDetector::default();
        let mut read = event(noon(), "a", "get_entry_value", "p");
        read.field_length = 554;
        assert!(detector.check(read).is_empty());
        // Other agent's command: no chain.
        assert!(
            detector
                .check(event(
                    noon() + time::Duration::seconds(1),
                    "b",
                    "run_command",
                    ""
                ))
                .is_empty()
        );
        let alerts = detector.check(event(
            noon() + time::Duration::seconds(2),
            "a",
            "execute_with_secret",
            "",
        ));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, AlertType::ToolChain);
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(
            alerts[0].description,
            "Tool-chain: agent a read a large field (554 bytes) then invoked execute_with_secret"
        );
        // Outside the 30 s window the read no longer counts.
        let late = detector.check(event(
            noon() + time::Duration::seconds(40),
            "a",
            "run_command",
            "",
        ));
        assert!(late.is_empty());
    }

    #[test]
    fn short_reads_and_command_before_read_are_not_chains() {
        let mut detector = AnomalyDetector::default();
        assert!(
            detector
                .check(event(noon(), "a", "run_command", ""))
                .is_empty()
        );
        let mut read = event(noon() + time::Duration::seconds(1), "a", "get_entry", "p");
        read.field_length = 554;
        assert!(detector.check(read).is_empty());
        let mut short = event(noon() + time::Duration::seconds(2), "a", "get_entry", "p");
        short.field_length = 499;
        assert!(detector.check(short).is_empty());
        assert!(
            detector
                .check(event(
                    noon() + time::Duration::seconds(3),
                    "a",
                    "run_command",
                    ""
                ))
                .iter()
                .all(|a| a.alert_type == AlertType::ToolChain)
        );
    }

    #[test]
    fn the_window_is_bounded_and_drops_the_oldest_event() {
        let mut detector = AnomalyDetector::new(DetectorConfig {
            max_events: 3,
            ..DetectorConfig::default()
        });
        for i in 0..5 {
            detector.check(event(noon() + time::Duration::seconds(i), "a", "x", ""));
        }
        assert_eq!(detector.window_len(), 3);
    }

    #[test]
    fn warning_lines_follow_the_go_standard_logger_and_slog_quoting() {
        let line = render_warning(
            // 2026-10-09 16:50:40 +02:00.
            OffsetDateTime::from_unix_timestamp(1_791_557_440)
                .unwrap()
                .to_offset(UtcOffset::from_hms(2, 0, 0).unwrap()),
            "anomaly detected",
            &[
                ("type", "tool_chain"),
                ("path", ""),
                ("agent", "a b"),
                ("description", "x=y \"q\" back\\slash"),
            ],
        );
        assert_eq!(
            line,
            "2026/10/09 16:50:40 WARN anomaly detected type=tool_chain path=\"\" agent=\"a b\" \
             description=\"x=y \\\"q\\\" back\\\\slash\""
        );
    }

    struct BrokenPipe;

    impl std::io::Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn a_broken_stderr_is_ignored_instead_of_panicking() {
        // eprintln! would panic here (and abort in release).
        write_warning_line(&mut BrokenPipe, "2026/11/03 03:00:00 WARN anomaly detected");
    }

    #[test]
    fn a_healthy_writer_gets_the_line_and_a_newline_negative_control() {
        let mut out = Vec::new();
        write_warning_line(&mut out, "line one");
        assert_eq!(out, b"line one\n");
    }

    #[test]
    fn a_poisoned_detector_lock_still_detects_and_counts() {
        let monitor = AnomalyMonitor::new().with_sink(Arc::new(|_| {}));
        let _ = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = monitor.detector.lock().unwrap();
                    panic!("poison the detector lock");
                })
                .join()
        });
        assert!(
            monitor.detector.is_poisoned(),
            "precondition: lock poisoned"
        );

        let alerts = monitor.check(event(
            noon().replace_hour(3).unwrap(),
            "a",
            "get_entry",
            "p",
        ));
        assert!(
            alerts.iter().any(|a| a.alert_type == AlertType::OffHours),
            "a poisoned lock must not drop alerts: {alerts:?}"
        );
        assert_eq!(monitor.window_len(), 1);
    }

    #[test]
    fn a_healthy_lock_detects_the_same_event_negative_control() {
        let monitor = AnomalyMonitor::new().with_sink(Arc::new(|_| {}));
        assert!(!monitor.detector.is_poisoned());
        let alerts = monitor.check(event(
            noon().replace_hour(3).unwrap(),
            "a",
            "get_entry",
            "p",
        ));
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn check_writes_nothing_until_log_alerts_is_called() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink_lines = lines.clone();
        let monitor = AnomalyMonitor::new().with_sink(Arc::new(move |line| {
            sink_lines.lock().unwrap().push(line.to_owned());
        }));
        let alerts = monitor.check(event(
            noon().replace_hour(3).unwrap(),
            "a",
            "get_entry",
            "p",
        ));
        assert!(lines.lock().unwrap().is_empty());
        monitor.log_alerts(&alerts);
        assert_eq!(lines.lock().unwrap().len(), 1);
    }
}
