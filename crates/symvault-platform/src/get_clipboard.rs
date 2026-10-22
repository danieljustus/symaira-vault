//! The clipboard path of `symvault get` (PLATFORM-001 slice 2, #1244).
//!
//! Go's `cmd/crud/get.go` copies a field to the clipboard when stdout is a
//! terminal, then (unless `clipboard.auto_clear_duration` is 0) shows a
//! countdown, clears the clipboard when the time is up or a termination signal
//! arrives, and finally calls `clipboard.VerifyCleared`. If a clipboard-history
//! manager restored the secret, the user gets a warning, not a failure.
//!
//! Everything observable is injectable: the clipboard ([`TextClipboard`]),
//! time and signals ([`Clock`]) and stderr (any [`Write`]). The Go oracle is
//! `testdata/port/platform/get_clipboard.json`, replayed by
//! `tests/get_clipboard_contract.rs`.
//!
//! Known, deliberate differences from Go:
//!
//! * Go runs the countdown on a goroutine; Rust runs one event loop. Output is
//!   identical except when the last tick and the timer fire at the same instant
//!   (Go's order is scheduler dependent). Rust prints the tick first.
//! * `--quiet` does not silence `[copied to clipboard]` or the failed-clear
//!   warning in the real Go binary, because `cliout` reads the quiet flag
//!   before cobra parses it. The fixture records that; this module therefore has
//!   no quiet input.
//! * Go styles the two `cliout` lines with lipgloss when stderr is a color
//!   terminal. This module always writes plain text.

use std::fmt;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Go `clipboard.ErrClipboardNotCleared`.
pub const NOT_CLEARED_MESSAGE: &str = "clipboard still contains the copied secret after clear; a clipboard-history manager may have restored it";

/// Default of `GetAutoClearDuration` when the config cannot supply a value.
pub const DEFAULT_AUTO_CLEAR_SECONDS: i64 = 30;

/// Result of [`verify_cleared`] when the clipboard could not be proven clear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Go `ErrClipboardNotCleared`.
    NotCleared,
    /// A read failure, passed through unchanged like Go.
    Read(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCleared => f.write_str(NOT_CLEARED_MESSAGE),
            Self::Read(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Go `clipboard.VerifyCleared`. One read, no retry and no delay. A missing
/// reader or an empty `expected_absent` skips the read and succeeds, because an
/// empty comparison cannot prove anything (some platforms keep an empty but
/// formatted pasteboard entry).
///
/// # Errors
/// [`VerifyError::NotCleared`] when the clipboard equals `expected_absent`;
/// [`VerifyError::Read`] when the read itself failed.
pub fn verify_cleared(
    expected_absent: &str,
    read: Option<&dyn Fn() -> Result<String, String>>,
) -> Result<(), VerifyError> {
    let Some(read) = read else {
        return Ok(());
    };
    if expected_absent.is_empty() {
        return Ok(());
    }
    let current = read().map_err(VerifyError::Read)?;
    if current == expected_absent {
        Err(VerifyError::NotCleared)
    } else {
        Ok(())
    }
}

/// Text clipboard with a read side, which [`crate::Clipboard`] lacks.
pub trait TextClipboard: Send + Sync {
    /// Go `Clipboard.Copy`.
    ///
    /// # Errors
    /// The backend's message.
    fn copy(&self, text: &str) -> Result<(), String>;
    /// Go `Clipboard.Read`.
    ///
    /// # Errors
    /// The backend's message.
    fn read(&self) -> Result<String, String>;
}

/// Cancellation shared between a waiter and the code that cancels it.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<(Mutex<bool>, Condvar)>);

impl CancelToken {
    pub fn cancel(&self) {
        let (flag, changed) = &*self.0;
        if let Ok(mut flag) = flag.lock() {
            *flag = true;
        }
        changed.notify_all();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.0.lock().map(|flag| *flag).unwrap_or(true)
    }

    /// Waits up to `limit` and reports whether cancelled.
    fn wait(&self, limit: Duration) -> bool {
        let (flag, changed) = &*self.0;
        let Ok(guard) = flag.lock() else {
            return true;
        };
        if *guard {
            return true;
        }
        match changed.wait_timeout(guard, limit) {
            Ok((guard, _)) => *guard,
            Err(_) => true,
        }
    }
}

/// Why a [`Clock::wait_until`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    Elapsed,
    Cancelled,
    /// A termination signal (SIGINT/SIGTERM/SIGHUP on Unix) arrived.
    Signal,
}

/// Time and signals, injectable so tests need no sleeping.
pub trait Clock: Send + Sync {
    /// Time since this clock started.
    fn elapsed(&self) -> Duration;
    /// Blocks until `elapsed() >= at`, `cancel` fires, or (when
    /// `watch_signals`) a termination signal arrives. Cancellation wins over an
    /// already elapsed target.
    fn wait_until(&self, at: Duration, cancel: &CancelToken, watch_signals: bool) -> Wake;
}

/// Wall-clock implementation. [`RealClock::with_termination_signals`] mirrors
/// Go `signal.Notify(os.Interrupt, SIGTERM, SIGHUP)` on Unix; on other targets
/// no signal is observed (Go also lists only Interrupt and SIGTERM on Windows;
/// the Windows console control handler is a documented residual).
pub struct RealClock {
    start: Instant,
    signaled: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(unix)]
    registrations: Vec<signal_hook::SigId>,
}

impl RealClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            signaled: Arc::default(),
            #[cfg(unix)]
            registrations: Vec::new(),
        }
    }

    /// # Errors
    /// Signal handler registration failed.
    pub fn with_termination_signals() -> std::io::Result<Self> {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut clock = Self::new();
        #[cfg(unix)]
        for signal in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ] {
            clock
                .registrations
                .push(signal_hook::flag::register(signal, clock.signaled.clone())?);
        }
        Ok(clock)
    }
}

impl Default for RealClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl Drop for RealClock {
    fn drop(&mut self) {
        for id in self.registrations.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

impl Clock for RealClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn wait_until(&self, at: Duration, cancel: &CancelToken, watch_signals: bool) -> Wake {
        loop {
            if cancel.is_cancelled() {
                return Wake::Cancelled;
            }
            if watch_signals && self.signaled.load(std::sync::atomic::Ordering::SeqCst) {
                return Wake::Signal;
            }
            let now = self.start.elapsed();
            if now >= at {
                return Wake::Elapsed;
            }
            // Signal handlers cannot wake a condvar, so poll in short slices.
            let slice = (at - now).min(Duration::from_millis(50));
            if cancel.wait(slice) {
                return Wake::Cancelled;
            }
        }
    }
}

/// Go `clipboard.Countdown`: the ticks shared by the library function and the
/// `get` flow.
struct Ticker {
    duration: i64,
    remaining: i64,
}

impl Ticker {
    /// Next tick time relative to the countdown start, or `None` when done.
    fn next_at(&self) -> Option<Duration> {
        if self.remaining <= 0 {
            return None;
        }
        let index = u64::try_from(self.duration - self.remaining + 1).ok()?;
        Some(Duration::from_secs(index))
    }

    fn tick(&mut self) -> i64 {
        self.remaining -= 1;
        self.remaining
    }
}

/// Go `clipboard.Countdown`: reports `duration`, then one value per second down
/// to zero, until cancelled. A non-positive duration or a missing callback
/// reports nothing. Cancellation is checked before each tick, so a token
/// cancelled up front still yields the first report, like Go.
pub fn countdown(
    duration: i64,
    update: Option<&mut dyn FnMut(i64)>,
    cancel: &CancelToken,
    clock: &dyn Clock,
) {
    let Some(update) = update else {
        return;
    };
    if duration <= 0 {
        return;
    }
    update(duration);
    let base = clock.elapsed();
    let mut ticker = Ticker {
        duration,
        remaining: duration,
    };
    while let Some(at) = ticker.next_at() {
        if clock.wait_until(base + at, cancel, false) == Wake::Cancelled {
            return;
        }
        update(ticker.tick());
    }
}

/// Failure of the copy itself: Go wraps it as `copy to clipboard: <cause>` with
/// exit code 1 (`ExitGeneralError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyError {
    pub cause: String,
}

impl CopyError {
    pub const EXIT_CODE: u8 = 1;
}

impl fmt::Display for CopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "copy to clipboard: {}", self.cause)
    }
}

impl std::error::Error for CopyError {}

/// Where `get` sends a field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetDestination {
    Clipboard,
    Stdout,
}

/// Go routing in `get.go`, after the `--length/--digest/--metadata` early
/// returns: structured output never touches the clipboard; `--print` or a
/// non-terminal stdout prints; otherwise an explicit `clipboard` config section
/// with `copyByDefault: false` prints. `copy_by_default` is `None` when the
/// config has no clipboard section.
#[must_use]
pub fn route_get_output(
    format: &str,
    print: bool,
    stdout_is_terminal: bool,
    copy_by_default: Option<bool>,
) -> GetDestination {
    if !format.is_empty() && format != "text" {
        return GetDestination::Stdout;
    }
    if print || !stdout_is_terminal || copy_by_default == Some(false) {
        return GetDestination::Stdout;
    }
    GetDestination::Clipboard
}

/// Go `GetAutoClearDuration`'s fallback chain once the config is known:
/// a missing section yields the default of 30 seconds.
#[must_use]
pub fn auto_clear_seconds(configured: Option<i64>) -> i64 {
    configured.unwrap_or(DEFAULT_AUTO_CLEAR_SECONDS)
}

/// Copies `secret`, then (when `auto_clear_seconds > 0`) counts down on stderr,
/// clears on timer or signal and verifies once. Mirrors the `!shouldPrint`
/// branch of `cmd/crud/get.go`. Warnings never change the result: Go returns
/// nil (exit 0) after a failed clear or a restored secret.
///
/// # Errors
/// [`CopyError`] when the initial copy fails; nothing else is written then.
pub fn copy_and_auto_clear(
    clipboard: &dyn TextClipboard,
    secret: &str,
    auto_clear_seconds: i64,
    clock: &dyn Clock,
    stderr: &mut dyn Write,
) -> Result<(), CopyError> {
    clipboard
        .copy(secret)
        .map_err(|cause| CopyError { cause })?;
    let _ = writeln!(stderr, "[copied to clipboard]");
    if auto_clear_seconds <= 0 {
        return Ok(());
    }

    let never = CancelToken::default();
    let base = clock.elapsed();
    let deadline = Duration::from_secs(u64::try_from(auto_clear_seconds).unwrap_or(0));
    let show = |stderr: &mut dyn Write, remaining: i64| {
        let _ = write!(stderr, "\r[clearing clipboard in {remaining}s] ");
        let _ = stderr.flush();
    };
    show(stderr, auto_clear_seconds);
    let mut ticker = Ticker {
        duration: auto_clear_seconds,
        remaining: auto_clear_seconds,
    };
    loop {
        match ticker.next_at() {
            // A tick due at the deadline goes first, so the countdown reaches 0.
            Some(at) if at <= deadline => {
                if clock.wait_until(base + at, &never, true) == Wake::Elapsed {
                    show(stderr, ticker.tick());
                } else {
                    break;
                }
            }
            _ => {
                let _ = clock.wait_until(base + deadline, &never, true);
                break;
            }
        }
    }

    if let Err(cause) = clipboard.copy("") {
        let _ = writeln!(stderr, "Warning: failed to clear clipboard: {cause}");
    }
    let read = || clipboard.read();
    match verify_cleared(secret, Some(&read)) {
        Err(error) => {
            let _ = writeln!(
                stderr,
                "\rWarning: {error} — consider disabling clipboard-history retention."
            );
        }
        Ok(()) => {
            let _ = writeln!(stderr, "\r[clipboard cleared]        ");
        }
    }
    let _ = stderr.flush();
    Ok(())
}

/// The OS clipboard for `get`: `pbcopy`/`pbpaste` on macOS, the atotto-style
/// tool selection from [`crate::desktop_commands`] on Linux, `arboard` on
/// Windows, unavailable elsewhere.
#[must_use]
pub fn native_get_clipboard() -> Arc<dyn TextClipboard> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacClipboard)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(CommandTextClipboard(
            crate::desktop_commands::CommandClipboard::new(Arc::new(
                crate::desktop_commands::SystemHost::new(),
            )),
        ))
    }
    #[cfg(windows)]
    {
        Arc::new(WindowsClipboard)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Arc::new(UnsupportedClipboard)
    }
}

#[cfg(target_os = "macos")]
struct MacClipboard;

#[cfg(target_os = "macos")]
impl TextClipboard for MacClipboard {
    fn copy(&self, text: &str) -> Result<(), String> {
        use crate::Clipboard;
        crate::MacOsPlatform
            .set(text.as_bytes())
            .map_err(|error| error.message)
    }

    fn read(&self) -> Result<String, String> {
        let output = std::process::Command::new("/usr/bin/pbpaste")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!("{}", output.status));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[cfg(target_os = "linux")]
struct CommandTextClipboard(crate::desktop_commands::CommandClipboard);

#[cfg(target_os = "linux")]
impl TextClipboard for CommandTextClipboard {
    fn copy(&self, text: &str) -> Result<(), String> {
        use crate::Clipboard;
        self.0.set(text.as_bytes()).map_err(|error| error.message)
    }

    fn read(&self) -> Result<String, String> {
        self.0
            .read()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .map_err(|error| error.message)
    }
}

#[cfg(windows)]
struct WindowsClipboard;

#[cfg(windows)]
impl TextClipboard for WindowsClipboard {
    fn copy(&self, text: &str) -> Result<(), String> {
        arboard::Clipboard::new()
            .and_then(|mut board| board.set_text(text))
            .map_err(|error| error.to_string())
    }

    fn read(&self) -> Result<String, String> {
        arboard::Clipboard::new()
            .and_then(|mut board| board.get_text())
            .map_err(|error| error.to_string())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
struct UnsupportedClipboard;

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
impl TextClipboard for UnsupportedClipboard {
    fn copy(&self, _text: &str) -> Result<(), String> {
        Err(crate::desktop_commands::MISSING_CLIPBOARD_COMMANDS.to_owned())
    }

    fn read(&self) -> Result<String, String> {
        Err(crate::desktop_commands::MISSING_CLIPBOARD_COMMANDS.to_owned())
    }
}
