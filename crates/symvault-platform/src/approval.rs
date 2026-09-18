//! Controlling-terminal human approval prompt.
//!
//! Ports `internal/mcp/server/approval.go` byte-for-byte where the Go
//! reference specifies behaviour (prompt layout, parsing, timeout and error
//! wording). Approval input is always read from the controlling terminal
//! (`/dev/tty`), never from MCP stdin/stdout, so a compromised or scripted
//! MCP client cannot answer its own approval prompt.

use std::time::{Duration, Instant};

/// Default approval timeout, mirroring Go's `defaultTimeout`.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Approval box width, mirroring Go's `boxWidth`.
const BOX_WIDTH: usize = 68;

/// Width of the value field within a prompt row (`boxWidth - 12`).
const VALUE_WIDTH: usize = BOX_WIDTH - 12;

/// Sensitivity level of a tool operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Human-readable label, mirroring Go's `RiskLevel.String()`.
    ///
    /// Go's zero-value `RiskLevel` renders `UNKNOWN` for out-of-range ints;
    /// Rust's enum has no such state, so `UNKNOWN` is unreachable here.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// Visual indicator, mirroring Go's `RiskLevel.Indicator()`.
    #[must_use]
    pub fn indicator(self) -> &'static str {
        match self {
            Self::Low => "🟢",
            Self::Medium => "🟡",
            Self::High => "🟠",
            Self::Critical => "🔴",
        }
    }

    /// Whether this risk level allows the "remember for session" option.
    #[must_use]
    pub fn can_remember(self) -> bool {
        self < Self::Critical
    }
}

/// A request for user approval of a sensitive operation.
#[derive(Debug, Clone, Default)]
pub struct ApprovalRequest {
    pub operation: String,
    pub details: String,
    pub timeout: Duration,
    pub agent_name: String,
    pub working_dir: String,
    pub git_branch: String,
    pub project_type: String,
    pub risk_level: RiskLevel,
    pub secrets_accessed: i64,
    pub can_remember: bool,
}

/// Distinguishable approval failure modes, mirroring the Go wrapped errors.
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalError {
    NoTty,
    RawMode(String),
    Write(String),
    Timeout(Duration),
    Read(String),
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTty => write!(
                f,
                "approval required but no TTY available (running non-interactively)"
            ),
            Self::RawMode(message) => write!(f, "failed to set terminal raw mode: {message}"),
            Self::Write(message) => write!(f, "failed to write to terminal: {message}"),
            Self::Timeout(duration) => write!(
                f,
                "approval timed out after {}",
                format_go_duration(*duration)
            ),
            Self::Read(message) => write!(f, "failed to read from terminal: {message}"),
        }
    }
}

impl std::error::Error for ApprovalError {}

/// Outcome of an approval request.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApprovalResult {
    pub approved: bool,
    pub remembered: bool,
    pub error: Option<ApprovalError>,
}

/// Checks whether a controlling terminal is available for reading and
/// writing. Unsupported platforms (anything non-unix, including Windows)
/// fail closed and always report no TTY.
///
/// ponytail: Windows has no controlling-terminal seam here, so approval
/// always fails closed there. Upgrade path: port `open_real_terminal` to the
/// Win32 console API (`CONIN$`/`CONOUT$` + `SetConsoleMode`) behind
/// `cfg(windows)`, mirroring Go's `go-tty` cross-platform behaviour.
#[must_use]
pub fn is_tty_present() -> bool {
    #[cfg(unix)]
    {
        open_real_terminal().is_some()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Prompts the user via the controlling terminal for approval of a sensitive
/// operation. Never reads from MCP stdin/stdout. See [`is_tty_present`] for
/// the platform support note.
#[must_use]
pub fn request_approval(req: &ApprovalRequest) -> ApprovalResult {
    #[cfg(unix)]
    {
        run_approval(req, open_real_terminal())
    }
    #[cfg(not(unix))]
    {
        let _ = req;
        ApprovalResult {
            approved: false,
            remembered: false,
            error: Some(ApprovalError::NoTty),
        }
    }
}

/// Seam abstracting a terminal so tests never touch a real TTY.
trait Terminal {
    fn set_raw_mode(&mut self) -> Result<(), String>;
    fn restore(&mut self);
    fn write_all(&mut self, buf: &[u8]) -> Result<(), String>;
    fn read_response(&mut self, deadline: Instant) -> Result<String, ReadFailure>;
}

enum ReadFailure {
    TimedOut,
    Io(String),
}

fn run_approval<T: Terminal>(req: &ApprovalRequest, terminal: Option<T>) -> ApprovalResult {
    let Some(mut terminal) = terminal else {
        return ApprovalResult {
            approved: false,
            remembered: false,
            error: Some(ApprovalError::NoTty),
        };
    };

    if let Err(message) = terminal.set_raw_mode() {
        return ApprovalResult {
            approved: false,
            remembered: false,
            error: Some(ApprovalError::RawMode(message)),
        };
    }

    let prompt = build_prompt(req);
    if let Err(message) = terminal.write_all(prompt.as_bytes()) {
        return ApprovalResult {
            approved: false,
            remembered: false,
            error: Some(ApprovalError::Write(message)),
        };
    }

    let timeout = if req.timeout.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        req.timeout
    };
    let deadline = Instant::now() + timeout;

    let response = match terminal.read_response(deadline) {
        Ok(response) => response,
        Err(ReadFailure::TimedOut) => {
            return ApprovalResult {
                approved: false,
                remembered: false,
                error: Some(ApprovalError::Timeout(timeout)),
            };
        }
        Err(ReadFailure::Io(message)) => {
            return ApprovalResult {
                approved: false,
                remembered: false,
                error: Some(ApprovalError::Read(message)),
            };
        }
    };

    let approved = parse_approval_response(&response);
    let remembered = req.can_remember && parse_remember_response(&response);
    // Go restores the cooked terminal before acknowledging the answer, so the
    // trailing newline is translated by the line discipline. Restoring here
    // (instead of only in `Drop` at return) keeps that byte-for-byte and keeps
    // the acknowledgement on its own line. `Drop` remains the safety net for
    // every early return above.
    terminal.restore();
    let ack: &[u8] = if approved || remembered {
        b"yes\n"
    } else {
        b"no\n"
    };
    let _ = terminal.write_all(ack);

    ApprovalResult {
        approved: approved || remembered,
        remembered,
        error: None,
    }
}

/// Builds the approval prompt string with full context display, mirroring
/// Go's `buildPrompt`.
fn build_prompt(req: &ApprovalRequest) -> String {
    let mut out = String::new();

    out.push('\n');
    out.push('╔');
    out.push_str(&"═".repeat(BOX_WIDTH));
    out.push_str("╗\n");
    out.push('║');
    out.push_str(&center_text("MCP OPERATION APPROVAL REQUIRED", BOX_WIDTH));
    out.push_str("║\n");
    out.push('╠');
    out.push_str(&"═".repeat(BOX_WIDTH));
    out.push_str("╣\n");

    if !req.agent_name.is_empty() {
        push_row(&mut out, "Agent:     ", &req.agent_name);
    }

    let risk_row = format!("{} {}", req.risk_level.indicator(), req.risk_level.label());
    push_row(&mut out, "Risk:      ", &risk_row);

    if !req.working_dir.is_empty() {
        push_row(&mut out, "Directory: ", &req.working_dir);
    }

    if !req.git_branch.is_empty() {
        push_row(&mut out, "Git:       ", &req.git_branch);
    }

    if !req.project_type.is_empty() {
        push_row(&mut out, "Project:   ", &req.project_type);
    }

    push_row(
        &mut out,
        "Secrets:   ",
        &format!("{} accessed this session", req.secrets_accessed),
    );

    out.push('║');
    out.push_str(&"─".repeat(BOX_WIDTH));
    out.push_str("║\n");

    if !req.operation.is_empty() {
        push_row(&mut out, "Operation: ", &req.operation);
    }

    if !req.details.is_empty() {
        push_row(&mut out, "Details:   ", &req.details);
    }

    out.push('╚');
    out.push_str(&"═".repeat(BOX_WIDTH));
    out.push_str("╝\n");

    if req.can_remember {
        out.push_str("\nApprove this operation? (y/n/r, r=remember for session): ");
    } else {
        out.push_str("\nApprove this operation? (y/n): ");
    }

    out
}

/// Appends one `║ <label><value padded to VALUE_WIDTH> ║\n` row. `label`
/// must already be exactly 11 columns, matching Go's hardcoded format
/// strings (e.g. `"Agent:     "`).
fn push_row(out: &mut String, label: &str, value: &str) {
    let value = truncate(value, VALUE_WIDTH);
    // Go's `%-*s` pads to the width in runes, and `centerText` pads by bytes —
    // mirror each one where it applies. Truncation above stays byte-based.
    let pad = VALUE_WIDTH.saturating_sub(value.chars().count());
    out.push_str("║ ");
    out.push_str(label);
    out.push_str(&value);
    out.push_str(&" ".repeat(pad));
    out.push_str(" ║\n");
}

/// Centers `text` within `width`, matching Go's byte-based `centerText`.
fn center_text(text: &str, width: usize) -> String {
    let bytes = text.as_bytes();
    if bytes.len() >= width {
        return String::from_utf8_lossy(&bytes[..width]).into_owned();
    }
    let padding = width - bytes.len();
    let left = padding / 2;
    let right = padding - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}

/// Truncates `s` to at most `max_len` bytes, matching Go's byte-based
/// `truncate`. Byte slicing never panics; if `max_len` lands inside a
/// multi-byte UTF-8 sequence, the invalid tail is replaced (never panics),
/// unlike Go's raw byte slice which may hold a partial rune.
fn truncate(s: &str, max_len: usize) -> String {
    let bytes = s.as_bytes();
    if bytes.len() <= max_len {
        return s.to_owned();
    }
    if max_len <= 3 {
        return String::from_utf8_lossy(&bytes[..max_len]).into_owned();
    }
    let mut out = String::from_utf8_lossy(&bytes[..max_len - 3]).into_owned();
    out.push_str("...");
    out
}

/// Determines if the user approved the operation. Accepts "y", "yes", "r",
/// "remember" (case-insensitive, trimmed).
fn parse_approval_response(response: &str) -> bool {
    let lower = response.trim().to_ascii_lowercase();
    lower == "y" || lower == "yes" || lower == "r" || lower == "remember"
}

/// Determines if the user opted to remember the approval for the session.
/// Accepts "r", "remember" (case-insensitive, trimmed).
fn parse_remember_response(response: &str) -> bool {
    let lower = response.trim().to_ascii_lowercase();
    lower == "r" || lower == "remember"
}

/// Renders a [`Duration`] the way Go's `time.Duration.String()` does
/// (`30s`, `1m30s`, `1h2m3.456s`, ...) rather than Rust's `Debug` form.
///
/// Public because callers that reproduce Go's `%s` on a `time.Duration` field
/// (for example the `share approve` prompt's TTL text) must render it the same
/// way this module renders its timeout error.
#[must_use]
pub fn format_go_duration(d: Duration) -> String {
    const MICROSECOND: u128 = 1_000;
    const MILLISECOND: u128 = 1_000_000;
    const SECOND: u128 = 1_000_000_000;

    let mut u = d.as_nanos();
    if u == 0 {
        return "0s".to_owned();
    }

    let mut buf = [0_u8; 32];
    let mut w = buf.len();

    if u < SECOND {
        let prec;
        w -= 1;
        buf[w] = b's';
        if u < MICROSECOND {
            prec = 0;
            w -= 1;
            buf[w] = b'n';
        } else if u < MILLISECOND {
            prec = 3;
            w -= 2;
            buf[w] = 0xC2;
            buf[w + 1] = 0xB5;
        } else {
            prec = 6;
            w -= 1;
            buf[w] = b'm';
        }
        let (new_w, new_u) = fmt_frac(&mut buf[..w], u, prec);
        w = new_w;
        u = new_u;
        w = fmt_int(&mut buf[..w], u);
    } else {
        w -= 1;
        buf[w] = b's';

        let (new_w, new_u) = fmt_frac(&mut buf[..w], u, 9);
        w = new_w;
        u = new_u;

        w = fmt_int(&mut buf[..w], u % 60);
        u /= 60;

        if u > 0 {
            w -= 1;
            buf[w] = b'm';
            w = fmt_int(&mut buf[..w], u % 60);
            u /= 60;

            if u > 0 {
                w -= 1;
                buf[w] = b'h';
                w = fmt_int(&mut buf[..w], u);
            }
        }
    }

    String::from_utf8(buf[w..].to_vec()).expect("go duration rendering is always valid UTF-8")
}

/// Port of Go's `fmtFrac`: formats the fraction of `v / 10**prec` into the
/// tail of `buf`, omitting trailing zeros (and the decimal point if the
/// fraction is zero). Returns the new write position and `v` with those
/// digits removed.
fn fmt_frac(buf: &mut [u8], mut v: u128, prec: u32) -> (usize, u128) {
    let mut w = buf.len();
    let mut print = false;
    for _ in 0..prec {
        let digit = (v % 10) as u8;
        print = print || digit != 0;
        if print {
            w -= 1;
            buf[w] = b'0' + digit;
        }
        v /= 10;
    }
    if print {
        w -= 1;
        buf[w] = b'.';
    }
    (w, v)
}

/// Port of Go's `fmtInt`: formats `v` into the tail of `buf`.
fn fmt_int(buf: &mut [u8], mut v: u128) -> usize {
    let mut w = buf.len();
    if v == 0 {
        w -= 1;
        buf[w] = b'0';
    } else {
        while v > 0 {
            w -= 1;
            buf[w] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    w
}

#[cfg(unix)]
struct RealTerminal {
    fd: rustix::fd::OwnedFd,
    original_termios: Option<rustix::termios::Termios>,
}

#[cfg(unix)]
fn open_real_terminal() -> Option<RealTerminal> {
    use rustix::fs::{Mode, OFlags, open};
    let fd = open("/dev/tty", OFlags::RDWR | OFlags::NOCTTY, Mode::empty()).ok()?;
    Some(RealTerminal {
        fd,
        original_termios: None,
    })
}

#[cfg(unix)]
impl Drop for RealTerminal {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(unix)]
impl RealTerminal {
    fn restore_now(&mut self) {
        if let Some(original) = self.original_termios.take() {
            let _ = rustix::termios::tcsetattr(
                &self.fd,
                rustix::termios::OptionalActions::Now,
                &original,
            );
        }
    }
}

#[cfg(unix)]
impl Terminal for RealTerminal {
    fn set_raw_mode(&mut self) -> Result<(), String> {
        let original = rustix::termios::tcgetattr(&self.fd).map_err(|error| error.to_string())?;
        let mut raw = original.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(&self.fd, rustix::termios::OptionalActions::Now, &raw)
            .map_err(|error| error.to_string())?;
        self.original_termios = Some(original);
        Ok(())
    }

    fn restore(&mut self) {
        self.restore_now();
    }

    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), String> {
        use rustix::io::Errno;
        while !buf.is_empty() {
            match rustix::io::write(&self.fd, buf) {
                Ok(0) => return Err("terminal write returned zero bytes".to_owned()),
                Ok(n) => buf = &buf[n..],
                Err(Errno::INTR) => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    fn read_response(&mut self, deadline: Instant) -> Result<String, ReadFailure> {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
        use rustix::io::Errno;

        // ponytail: macOS `poll`/`select` on /dev/tty is documented as
        // unreliable, and `select` requires unsafe code this crate denies.
        // A non-blocking-read + sleep poll loop sidesteps both, matching the
        // pattern already used for native helper pipes in macos.rs. Ceiling:
        // up to POLL_INTERVAL of added latency past the deadline; fine for a
        // human-facing prompt.
        const MAX_RESPONSE_BYTES: usize = 4096;
        const POLL_INTERVAL: Duration = Duration::from_millis(5);

        let original_flags =
            fcntl_getfl(&self.fd).map_err(|error| ReadFailure::Io(error.to_string()))?;
        fcntl_setfl(&self.fd, original_flags | OFlags::NONBLOCK)
            .map_err(|error| ReadFailure::Io(error.to_string()))?;

        let mut collected = Vec::new();
        let outcome = loop {
            let mut chunk = [0_u8; 256];
            match rustix::io::read(&self.fd, &mut chunk[..]) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    collected.extend_from_slice(&chunk[..n]);
                    if response_is_complete(&collected) || collected.len() >= MAX_RESPONSE_BYTES {
                        break Ok(());
                    }
                }
                Err(Errno::WOULDBLOCK) => {
                    if Instant::now() >= deadline {
                        break Err(ReadFailure::TimedOut);
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(Errno::INTR) => continue,
                Err(error) => break Err(ReadFailure::Io(error.to_string())),
            }
        };

        // Reset the deadline seam, mirroring Go's deferred
        // `SetReadDeadline(time.Time{})`.
        let _ = fcntl_setfl(&self.fd, original_flags);

        outcome.map(|()| String::from_utf8_lossy(&collected).into_owned())
    }
}

/// Whether the collected terminal bytes already hold a complete answer.
///
/// Go reads through `go-tty`, whose `ReadString` stops at either Enter byte, so
/// both `\r` and `\n` complete the answer. Raw mode clears `ICRNL`, which means
/// the Enter key arrives as `\r` only — waiting for `\n` alone would never see a
/// human keypress and would run into the timeout with the answer already typed.
fn response_is_complete(collected: &[u8]) -> bool {
    collected
        .iter()
        .any(|byte| *byte == b'\n' || *byte == b'\r')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeTerminal {
        raw_mode_result: Option<Result<(), String>>,
        write_result: Option<Result<(), String>>,
        read_result: Option<Result<String, ReadFailureKind>>,
        raw_mode_set: bool,
        restored: Arc<Mutex<bool>>,
        written: Vec<Vec<u8>>,
        /// Optional ordered marker log so a test can assert that the cooked
        /// terminal was restored before the acknowledgement was written.
        timeline: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    #[derive(Clone)]
    enum ReadFailureKind {
        TimedOut,
        Io(String),
    }

    impl FakeTerminal {
        fn tracking(restored: Arc<Mutex<bool>>) -> Self {
            Self {
                raw_mode_result: None,
                write_result: None,
                read_result: None,
                raw_mode_set: false,
                restored,
                written: Vec::new(),
                timeline: None,
            }
        }

        fn tracking_with_timeline(
            restored: Arc<Mutex<bool>>,
            timeline: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                raw_mode_result: None,
                write_result: None,
                read_result: None,
                raw_mode_set: false,
                restored,
                written: Vec::new(),
                timeline: Some(timeline),
            }
        }

        fn mark(&self, marker: &'static str) {
            if let Some(timeline) = &self.timeline {
                timeline.lock().unwrap().push(marker);
            }
        }
    }

    impl Drop for FakeTerminal {
        fn drop(&mut self) {
            if self.raw_mode_set {
                *self.restored.lock().unwrap() = true;
            }
        }
    }

    impl Terminal for FakeTerminal {
        fn set_raw_mode(&mut self) -> Result<(), String> {
            let result = self.raw_mode_result.clone().unwrap_or(Ok(()));
            if result.is_ok() {
                self.raw_mode_set = true;
            }
            result
        }

        fn restore(&mut self) {
            if self.raw_mode_set {
                *self.restored.lock().unwrap() = true;
            }
            self.mark("restore");
        }

        fn write_all(&mut self, buf: &[u8]) -> Result<(), String> {
            self.mark("write");
            self.written.push(buf.to_vec());
            self.write_result.clone().unwrap_or(Ok(()))
        }

        fn read_response(&mut self, _deadline: Instant) -> Result<String, ReadFailure> {
            match self.read_result.clone().unwrap_or(Ok(String::new())) {
                Ok(response) => Ok(response),
                Err(ReadFailureKind::TimedOut) => Err(ReadFailure::TimedOut),
                Err(ReadFailureKind::Io(message)) => Err(ReadFailure::Io(message)),
            }
        }
    }

    fn approved_request() -> ApprovalRequest {
        ApprovalRequest {
            can_remember: true,
            ..Default::default()
        }
    }

    #[test]
    fn risk_level_labels_indicators_and_can_remember_boundary() {
        assert_eq!(RiskLevel::Low.label(), "LOW");
        assert_eq!(RiskLevel::Medium.label(), "MEDIUM");
        assert_eq!(RiskLevel::High.label(), "HIGH");
        assert_eq!(RiskLevel::Critical.label(), "CRITICAL");
        assert_eq!(RiskLevel::Low.indicator(), "🟢");
        assert_eq!(RiskLevel::Medium.indicator(), "🟡");
        assert_eq!(RiskLevel::High.indicator(), "🟠");
        assert_eq!(RiskLevel::Critical.indicator(), "🔴");
        assert!(RiskLevel::Low.can_remember());
        assert!(RiskLevel::Medium.can_remember());
        assert!(RiskLevel::High.can_remember());
        assert!(!RiskLevel::Critical.can_remember());
    }

    #[test]
    fn parse_approval_response_accepts_y_yes_r_remember_case_and_whitespace_insensitive() {
        for accepted in [
            "y", "Y", " y ", "yes", "YES", "\tyes\n", "r", "R", "remember", "Remember",
        ] {
            assert!(
                parse_approval_response(accepted),
                "{accepted:?} should approve"
            );
        }
        for denied in ["n", "no", "", "garbage", "yesplease", " "] {
            assert!(!parse_approval_response(denied), "{denied:?} should deny");
        }
    }

    #[test]
    fn parse_remember_response_only_accepts_r_or_remember() {
        for accepted in ["r", "R", " remember ", "REMEMBER"] {
            assert!(parse_remember_response(accepted));
        }
        for denied in ["y", "yes", "n", "no", ""] {
            assert!(!parse_remember_response(denied));
        }
    }

    #[test]
    fn truncate_short_strings_are_unchanged() {
        assert_eq!(truncate("hi", 10), "hi");
        assert_eq!(truncate("exact", 5), "exact");
    }

    #[test]
    fn truncate_long_strings_get_ellipsis() {
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("hello world", 8).len(), 8);
    }

    #[test]
    fn truncate_max_len_at_or_below_three_hard_cuts() {
        assert_eq!(truncate("hello", 3), "hel");
        assert_eq!(truncate("hello", 0), "");
    }

    #[test]
    fn truncate_never_panics_on_multibyte_utf8_boundary() {
        // "café" is 5 bytes (é is 2 bytes); cutting at 4 bytes splits é.
        let value = "café";
        assert_eq!(value.len(), 5);
        let truncated = truncate(value, 4);
        assert!(!truncated.is_empty());
        // Never panics, and always yields valid UTF-8 (guaranteed by String).
        let _ = truncated.len();
    }

    #[test]
    fn center_text_pads_evenly_with_odd_padding_favoring_right() {
        assert_eq!(center_text("hi", 6), "  hi  ");
        assert_eq!(center_text("hi", 7), "  hi   ");
    }

    #[test]
    fn center_text_longer_than_width_is_cut_to_width() {
        assert_eq!(center_text("abcdef", 3), "abc");
    }

    #[test]
    fn center_text_never_panics_on_multibyte_utf8_boundary() {
        let value = "café résumé";
        let _ = center_text(value, 4);
    }

    #[test]
    fn go_duration_rendering_matches_go_examples() {
        assert_eq!(format_go_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_go_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_go_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_go_duration(Duration::from_secs(3661)), "1h1m1s");
        assert_eq!(format_go_duration(Duration::from_nanos(1)), "1ns");
        assert_eq!(format_go_duration(Duration::from_micros(1)), "1µs");
        assert_eq!(format_go_duration(Duration::from_millis(1)), "1ms");
        assert_eq!(format_go_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(format_go_duration(Duration::from_secs(60)), "1m0s");
        assert_eq!(format_go_duration(Duration::from_secs(3600)), "1h0m0s");
    }

    #[test]
    fn build_prompt_includes_rows_only_when_non_empty_and_default_timeout_footer() {
        let minimal = ApprovalRequest::default();
        let prompt = build_prompt(&minimal);
        assert!(prompt.contains("MCP OPERATION APPROVAL REQUIRED"));
        assert!(!prompt.contains("Agent:"));
        assert!(!prompt.contains("Directory:"));
        assert!(!prompt.contains("Git:"));
        assert!(!prompt.contains("Project:"));
        assert!(!prompt.contains("Operation:"));
        assert!(!prompt.contains("Details:"));
        assert!(prompt.contains("Secrets:   0 accessed this session"));
        assert!(prompt.contains("Risk:      🟢 LOW"));
        assert!(prompt.ends_with("\nApprove this operation? (y/n): "));
    }

    #[test]
    fn build_prompt_includes_every_populated_field_and_remember_footer() {
        let req = ApprovalRequest {
            operation: "approve_share".to_owned(),
            details: "share xyz with bob".to_owned(),
            agent_name: "claude".to_owned(),
            working_dir: "/tmp/project".to_owned(),
            git_branch: "main".to_owned(),
            project_type: "demo (Rust)".to_owned(),
            risk_level: RiskLevel::High,
            secrets_accessed: 3,
            can_remember: true,
            ..Default::default()
        };
        let prompt = build_prompt(&req);
        assert!(prompt.contains("Agent:     claude"));
        assert!(prompt.contains("Risk:      🟠 HIGH"));
        assert!(prompt.contains("Directory: /tmp/project"));
        assert!(prompt.contains("Git:       main"));
        assert!(prompt.contains("Project:   demo (Rust)"));
        assert!(prompt.contains("Secrets:   3 accessed this session"));
        assert!(prompt.contains("Operation: approve_share"));
        assert!(prompt.contains("Details:   share xyz with bob"));
        assert!(prompt.ends_with("\nApprove this operation? (y/n/r, r=remember for session): "));
    }

    #[test]
    fn build_prompt_truncates_long_values_to_56_bytes() {
        let req = ApprovalRequest {
            agent_name: "x".repeat(200),
            ..Default::default()
        };
        let prompt = build_prompt(&req);
        let row = prompt.lines().find(|l| l.starts_with("║ Agent:")).unwrap();
        // "║ Agent:     " prefix (13 bytes) + 56-byte value + " ║" suffix.
        let value_start = "║ Agent:     ".len();
        let value = &row.as_bytes()[value_start..value_start + 56];
        assert_eq!(value.len(), 56);
        assert!(row.ends_with(" ║"));
    }

    #[test]
    fn response_is_complete_accepts_both_enter_bytes() {
        // Raw mode clears ICRNL, so the Enter key arrives as CR. Go stops at
        // either byte; stopping only at LF would never end a real keypress.
        assert!(response_is_complete(b"y\r"));
        assert!(response_is_complete(b"y\n"));
        assert!(response_is_complete(b"\r\n"));
        assert!(!response_is_complete(b"yes"));
        assert!(!response_is_complete(b""));
    }

    #[test]
    fn push_row_pads_by_runes_like_go_printf_width() {
        let ascii = build_prompt(&ApprovalRequest {
            agent_name: "Muller".to_owned(),
            ..Default::default()
        });
        let umlaut = build_prompt(&ApprovalRequest {
            agent_name: "Müller".to_owned(),
            ..Default::default()
        });
        let agent_row = |prompt: &str| {
            prompt
                .lines()
                .find(|line| line.starts_with("║ Agent:"))
                .expect("agent row")
                .to_owned()
        };
        // Go's `%-*s` pads the 56-column value field by runes, so a multi-byte
        // value keeps the same row width as an ASCII value of the same rune
        // count. Byte padding would make the umlaut row one column narrower.
        assert_eq!(
            agent_row(&umlaut).chars().count(),
            agent_row(&ascii).chars().count()
        );
        assert!(agent_row(&umlaut).ends_with(" ║"));
        assert_eq!(agent_row(&umlaut).chars().count(), 71);
    }

    #[test]
    fn run_approval_restores_cooked_mode_before_acknowledging() {
        let restored = Arc::new(Mutex::new(false));
        let timeline = Arc::new(Mutex::new(Vec::new()));
        let mut terminal = FakeTerminal::tracking_with_timeline(restored.clone(), timeline.clone());
        terminal.read_result = Some(Ok("y\r".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert!(result.approved);
        assert!(*restored.lock().unwrap());
        let timeline = timeline.lock().unwrap().clone();
        assert_eq!(
            timeline,
            vec!["write", "restore", "write"],
            "prompt write, cooked-mode restore, then the acknowledgement"
        );
    }

    #[test]
    fn run_approval_approves_on_carriage_return_enter_byte() {
        let mut terminal = FakeTerminal::default();
        terminal.read_result = Some(Ok("yes\r".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert!(result.approved);
        assert!(!result.remembered);
    }

    #[test]
    fn run_approval_denies_when_no_terminal_available() {
        let result = run_approval::<FakeTerminal>(&approved_request(), None);
        assert!(!result.approved);
        assert_eq!(result.error, Some(ApprovalError::NoTty));
    }

    #[test]
    fn run_approval_surfaces_raw_mode_failure_without_marking_restored() {
        let restored = Arc::new(Mutex::new(false));
        let mut terminal = FakeTerminal::tracking(restored.clone());
        terminal.raw_mode_result = Some(Err("device busy".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert!(!result.approved);
        assert_eq!(
            result.error,
            Some(ApprovalError::RawMode("device busy".to_owned()))
        );
        // Raw mode was never confirmed set, so there is nothing to restore.
        assert!(!*restored.lock().unwrap());
    }

    #[test]
    fn run_approval_restores_raw_mode_on_write_failure() {
        let restored = Arc::new(Mutex::new(false));
        let mut terminal = FakeTerminal::tracking(restored.clone());
        terminal.write_result = Some(Err("broken pipe".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert!(!result.approved);
        assert_eq!(
            result.error,
            Some(ApprovalError::Write("broken pipe".to_owned()))
        );
        assert!(*restored.lock().unwrap());
    }

    #[test]
    fn run_approval_restores_raw_mode_on_timeout() {
        let restored = Arc::new(Mutex::new(false));
        let mut terminal = FakeTerminal::tracking(restored.clone());
        terminal.read_result = Some(Err(ReadFailureKind::TimedOut));
        let req = ApprovalRequest {
            timeout: Duration::from_secs(5),
            ..approved_request()
        };
        let result = run_approval(&req, Some(terminal));
        assert!(!result.approved);
        assert_eq!(
            result.error,
            Some(ApprovalError::Timeout(Duration::from_secs(5)))
        );
        assert!(*restored.lock().unwrap());
    }

    #[test]
    fn run_approval_zero_or_negative_timeout_reports_default_thirty_seconds() {
        let restored = Arc::new(Mutex::new(false));
        let mut terminal = FakeTerminal::tracking(restored);
        terminal.read_result = Some(Err(ReadFailureKind::TimedOut));
        let req = ApprovalRequest {
            timeout: Duration::ZERO,
            ..approved_request()
        };
        let result = run_approval(&req, Some(terminal));
        assert_eq!(
            result.error,
            Some(ApprovalError::Timeout(Duration::from_secs(30)))
        );
    }

    #[test]
    fn run_approval_restores_raw_mode_on_read_error() {
        let restored = Arc::new(Mutex::new(false));
        let mut terminal = FakeTerminal::tracking(restored.clone());
        terminal.read_result = Some(Err(ReadFailureKind::Io("device disconnected".to_owned())));
        let result = run_approval(&approved_request(), Some(terminal));
        assert!(!result.approved);
        assert_eq!(
            result.error,
            Some(ApprovalError::Read("device disconnected".to_owned()))
        );
        assert!(*restored.lock().unwrap());
    }

    #[test]
    fn run_approval_approves_on_yes_and_writes_ack() {
        let restored = Arc::new(Mutex::new(false));
        let mut terminal = FakeTerminal::tracking(restored.clone());
        terminal.read_result = Some(Ok("yes\n".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert_eq!(
            result,
            ApprovalResult {
                approved: true,
                remembered: false,
                error: None,
            }
        );
        assert!(*restored.lock().unwrap());
    }

    #[test]
    fn run_approval_denies_on_no_and_writes_ack() {
        let mut terminal = FakeTerminal::default();
        terminal.read_result = Some(Ok("no\n".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert_eq!(
            result,
            ApprovalResult {
                approved: false,
                remembered: false,
                error: None,
            }
        );
    }

    #[test]
    fn run_approval_remember_sets_both_flags_only_when_can_remember() {
        let mut terminal = FakeTerminal::default();
        terminal.read_result = Some(Ok("r\n".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert!(result.approved);
        assert!(result.remembered);

        let mut terminal = FakeTerminal::default();
        terminal.read_result = Some(Ok("r\n".to_owned()));
        let req = ApprovalRequest {
            can_remember: false,
            ..Default::default()
        };
        let result = run_approval(&req, Some(terminal));
        // "r" still parses as approval (parse_approval_response includes r),
        // but remembered stays false when the risk level forbids it.
        assert!(result.approved);
        assert!(!(result.remembered));
    }

    #[test]
    fn run_approval_writes_yes_ack_when_remembered_even_if_not_approved_text() {
        let mut terminal = FakeTerminal::default();
        terminal.read_result = Some(Ok("remember".to_owned()));
        let result = run_approval(&approved_request(), Some(terminal));
        assert!(result.approved);
        assert!(result.remembered);
    }
}
