//! Replays the Go-generated `get` clipboard fixture
//! (`testdata/port/platform/get_clipboard.json`, from
//! `cmd/get_clipboard_fixture_generator_test.go`) against
//! `symvault_platform::get_clipboard`.
//!
//! Go ran the production `get` command with an in-memory clipboard. Here the
//! clipboard, the clock and stderr are injected, so no desktop clipboard is
//! touched and no test sleeps: [`VirtualClock`] jumps to the requested instant.
//! One extra test uses the real clock for one second to check the production
//! timer path; that case is not oracle data and is labeled as such.
#![deny(unsafe_code)]

use serde::Deserialize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use symvault_platform::get_clipboard::{
    CancelToken, Clock, CopyError, GetDestination, InterruptSource, NOT_CLEARED_MESSAGE, RealClock,
    TextClipboard, VerifyError, Wake, copy_and_auto_clear, countdown, route_get_output,
    verify_cleared,
};

const FIXTURE: &str = include_str!("../../../testdata/port/platform/get_clipboard.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    commit: String,
    source_files: Vec<String>,
    source_hash: String,
    generator_hash: String,
    scenarios: Vec<Scenario>,
    colour_scenarios: Vec<Scenario>,
    verify_cleared: Vec<VerifyCase>,
    countdown: Vec<CountdownCase>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    secret: String,
    auto_clear_seconds: i64,
    stdout_terminal: bool,
    #[serde(default)]
    copy_by_default: Option<bool>,
    print: bool,
    json: bool,
    #[serde(default)]
    copy_error: String,
    #[serde(default)]
    clear_error: String,
    #[serde(default)]
    read_mode: String,
    #[serde(default)]
    read_error: String,
    #[serde(default)]
    timer_stub_ms: u64,
    #[serde(default)]
    signal_after_ms: u64,
    /// The CLIContext colour mode of a forced-colour scenario.
    #[serde(default)]
    color: String,
    /// A `--color` argv flag (read by Go after the colour decision).
    #[serde(default)]
    color_flag: String,
    stdout: String,
    stderr: String,
    exit_code: i32,
    clipboard_ops: Vec<String>,
    final_clipboard: String,
}

#[derive(Debug, Deserialize)]
struct VerifyCase {
    name: String,
    expected_absent: String,
    nil_read: bool,
    current: String,
    #[serde(default)]
    read_error: String,
    result: String,
    #[serde(default)]
    error_text: String,
    read_calls: usize,
}

#[derive(Debug, Deserialize)]
struct CountdownCase {
    name: String,
    duration: i64,
    nil_update: bool,
    #[serde(default)]
    cancel_after_ms: u64,
    #[serde(default)]
    pre_cancelled: bool,
    updates: Vec<i64>,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("get_clipboard.json parses")
}

/// Time that never sleeps. `wake_at` models an event that is not a tick: the
/// stubbed `StartAutoClear` timer or a SIGTERM in the Go scenarios.
struct VirtualClock {
    now: Mutex<Duration>,
    wake_at: Option<Duration>,
    cancel_at: Option<Duration>,
}

impl VirtualClock {
    fn new() -> Self {
        Self {
            now: Mutex::new(Duration::ZERO),
            wake_at: None,
            cancel_at: None,
        }
    }
}

impl Clock for VirtualClock {
    fn elapsed(&self) -> Duration {
        *self.now.lock().unwrap()
    }

    fn wait_until(&self, at: Duration, cancel: &CancelToken, watch_signals: bool) -> Wake {
        if cancel.is_cancelled() {
            return Wake::Cancelled;
        }
        let mut now = self.now.lock().unwrap();
        if let Some(cancel_at) = self.cancel_at.filter(|cancel_at| *cancel_at <= at) {
            *now = (*now).max(cancel_at);
            cancel.cancel();
            return Wake::Cancelled;
        }
        if watch_signals && let Some(wake) = self.wake_at.filter(|wake| *wake <= at) {
            *now = (*now).max(wake);
            return Wake::Signal;
        }
        *now = (*now).max(at);
        Wake::Elapsed
    }
}

struct FakeClipboard {
    secret: String,
    copy_error: String,
    clear_error: String,
    read_mode: String,
    read_error: String,
    state: Mutex<(String, Vec<String>)>,
}

impl FakeClipboard {
    fn new(s: &Scenario) -> Self {
        Self {
            secret: s.secret.clone(),
            copy_error: s.copy_error.clone(),
            clear_error: s.clear_error.clone(),
            read_mode: s.read_mode.clone(),
            read_error: s.read_error.clone(),
            state: Mutex::new((String::new(), Vec::new())),
        }
    }
}

impl TextClipboard for FakeClipboard {
    fn copy(&self, text: &str) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        state.1.push(format!("copy:{text}"));
        if !text.is_empty() && !self.copy_error.is_empty() {
            return Err(self.copy_error.clone());
        }
        if text.is_empty() && !self.clear_error.is_empty() {
            return Err(self.clear_error.clone());
        }
        state.0 = text.to_owned();
        Ok(())
    }

    fn read(&self) -> Result<String, String> {
        let mut state = self.state.lock().unwrap();
        state.1.push("read".to_owned());
        match self.read_mode.as_str() {
            "restore_secret" => Ok(self.secret.clone()),
            "other" => Ok("something the user copied later".to_owned()),
            "error" => Err(self.read_error.clone()),
            _ => Ok(state.0.clone()),
        }
    }
}

#[test]
fn fixture_is_bound_to_the_pinned_oracle() {
    let f = fixture();
    assert_eq!(f.commit, "861ad93813e3ee43c4ec989f45940d14b05b6eaf");
    assert!(
        f.source_files.contains(&"cmd/crud/get.go".to_owned())
            && f.source_files
                .contains(&"internal/clipboard/clipboard.go".to_owned())
    );
    assert_eq!(f.source_hash.len(), 64);
    assert_eq!(f.generator_hash.len(), 64);
    // The corpus must actually contain the interesting outcomes; a replay of
    // only happy paths would pass with a verify that never fails.
    let stderr: Vec<&str> = f.scenarios.iter().map(|s| s.stderr.as_str()).collect();
    assert!(stderr.iter().any(|s| s.contains(NOT_CLEARED_MESSAGE)));
    assert!(stderr.iter().any(|s| s.contains("[clipboard cleared]")));
    assert!(f.scenarios.iter().any(|s| s.exit_code == 1));
    assert!(f.scenarios.len() >= 16);
}

#[test]
fn verify_cleared_matches_go() {
    for case in fixture().verify_cleared {
        let calls = Mutex::new(0usize);
        let read = || {
            *calls.lock().unwrap() += 1;
            if case.read_error.is_empty() {
                Ok(case.current.clone())
            } else {
                Err(case.read_error.clone())
            }
        };
        let result = verify_cleared(
            &case.expected_absent,
            if case.nil_read { None } else { Some(&read) },
        );
        let (kind, text) = match &result {
            Ok(()) => ("ok", String::new()),
            Err(error @ VerifyError::NotCleared) => ("not_cleared", error.to_string()),
            Err(error @ VerifyError::Read(_)) => ("read_error", error.to_string()),
        };
        assert_eq!(kind, case.result, "{}", case.name);
        assert_eq!(text, case.error_text, "{} error text", case.name);
        assert_eq!(
            *calls.lock().unwrap(),
            case.read_calls,
            "{} reads",
            case.name
        );
    }
}

#[test]
fn countdown_matches_go() {
    for case in fixture().countdown {
        let mut clock = VirtualClock::new();
        if case.cancel_after_ms > 0 {
            clock.cancel_at = Some(Duration::from_millis(case.cancel_after_ms));
        }
        let cancel = CancelToken::default();
        if case.pre_cancelled {
            cancel.cancel();
        }
        let mut updates = Vec::new();
        let mut record = |remaining: i64| updates.push(remaining);
        let callback: Option<&mut dyn FnMut(i64)> = if case.nil_update {
            None
        } else {
            Some(&mut record)
        };
        countdown(case.duration, callback, &cancel, &clock);
        assert_eq!(updates, case.updates, "{}", case.name);
    }
}

#[test]
fn get_scenarios_match_go() {
    let mut clipboard_runs = 0;
    for s in fixture().scenarios {
        let format = if s.json { "json" } else { "text" };
        let destination = route_get_output(format, s.print, s.stdout_terminal, s.copy_by_default);
        let expected_destination = if s.clipboard_ops.is_empty() {
            GetDestination::Stdout
        } else {
            GetDestination::Clipboard
        };
        assert_eq!(destination, expected_destination, "{} routing", s.name);
        if destination == GetDestination::Stdout {
            // The value is printed (or masked) by the existing get writer; it
            // never reaches the clipboard.
            assert!(s.clipboard_ops.is_empty(), "{}", s.name);
            continue;
        }
        clipboard_runs += 1;

        let mut clock = VirtualClock::new();
        if s.timer_stub_ms > 0 {
            clock.wake_at = Some(Duration::from_millis(s.timer_stub_ms));
        }
        if s.signal_after_ms > 0 {
            clock.wake_at = Some(Duration::from_millis(s.signal_after_ms));
        }
        let clipboard = FakeClipboard::new(&s);
        let mut stderr = Vec::new();
        let result = copy_and_auto_clear(
            &clipboard,
            &s.secret,
            s.auto_clear_seconds,
            &clock,
            &mut stderr,
        );
        let mut stderr = String::from_utf8(stderr).expect("utf-8 stderr");
        let exit_code = match result {
            Ok(()) => 0,
            Err(error) => {
                // Go prints the command error once through cobra and once
                // through ExecuteRoot.
                stderr = format!("Error: {error}\nError: {error}\n");
                i32::from(CopyError::EXIT_CODE)
            }
        };
        assert_eq!(stderr, s.stderr, "{} stderr", s.name);
        assert_eq!(exit_code, s.exit_code, "{} exit", s.name);
        assert_eq!(s.stdout, "", "{} stdout", s.name);
        let state = clipboard.state.lock().unwrap();
        assert_eq!(state.1, s.clipboard_ops, "{} clipboard ops", s.name);
        assert_eq!(state.0, s.final_clipboard, "{} final clipboard", s.name);
    }
    assert!(
        clipboard_runs >= 10,
        "ran {clipboard_runs} clipboard scenarios"
    );
}

#[test]
fn routing_table_covers_every_branch() {
    use GetDestination::{Clipboard, Stdout};
    assert_eq!(route_get_output("text", false, true, None), Clipboard);
    assert_eq!(route_get_output("text", false, true, Some(true)), Clipboard);
    assert_eq!(route_get_output("text", false, true, Some(false)), Stdout);
    assert_eq!(route_get_output("text", true, true, None), Stdout);
    assert_eq!(route_get_output("text", false, false, None), Stdout);
    assert_eq!(route_get_output("json", false, true, None), Stdout);
    assert_eq!(route_get_output("yaml", true, true, None), Stdout);
    assert_eq!(route_get_output("", false, true, None), Clipboard);
}

/// Real clock, not oracle data: with `auto_clear_duration: 1` the tick due at
/// the deadline is printed before the clear (Go's order at that instant is
/// scheduler dependent, see the module docs).
#[test]
fn real_clock_counts_down_and_clears() {
    let clipboard = FakeClipboard::new(&Scenario {
        name: "real".into(),
        secret: "real-clock-secret".into(),
        auto_clear_seconds: 1,
        stdout_terminal: true,
        copy_by_default: None,
        print: false,
        json: false,
        copy_error: String::new(),
        clear_error: String::new(),
        read_mode: "honest".into(),
        read_error: String::new(),
        timer_stub_ms: 0,
        signal_after_ms: 0,
        stdout: String::new(),
        color: String::new(),
        color_flag: String::new(),
        stderr: String::new(),
        exit_code: 0,
        clipboard_ops: Vec::new(),
        final_clipboard: String::new(),
    });
    let clock = RealClock::new();
    let mut stderr = Vec::new();
    let started = std::time::Instant::now();
    copy_and_auto_clear(&clipboard, "real-clock-secret", 1, &clock, &mut stderr).unwrap();
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        "[copied to clipboard]\n\r[clearing clipboard in 1s] \r[clearing clipboard in 0s] \r[clipboard cleared]        \n"
    );
    assert_eq!(clipboard.state.lock().unwrap().0, "");
}

#[test]
fn real_clock_cancel_wins_over_elapsed_target() {
    let clock = RealClock::new();
    let cancel = CancelToken::default();
    cancel.cancel();
    assert_eq!(
        clock.wait_until(Duration::ZERO, &cancel, true),
        Wake::Cancelled
    );
}

#[cfg(unix)]
#[test]
fn real_clock_observes_sigterm_when_registered() {
    // signal-hook delivers to this process only. The handler is installed by
    // `arm_termination_signals`; its flag registration is removed when the
    // clock drops, but signal-hook leaves its own handler installed, so a later
    // SIGTERM is swallowed rather than terminating (fine: `get` exits). A
    // SIGTERM is raised from a helper thread after the wait begins.
    let clock = RealClock::with_termination_signals();
    clock.arm_termination_signals().expect("register");
    let cancel = CancelToken::default();
    let raiser = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        signal_hook::low_level::raise(signal_hook::consts::SIGTERM).expect("raise");
    });
    let outcome = clock.wait_until(Duration::from_secs(30), &cancel, true);
    raiser.join().unwrap();
    assert_eq!(outcome, Wake::Signal);
}

/// An [`InterruptSource`] the test fires by hand; it stands in for the Windows
/// console control handler (and for signal-hook), which cannot be raised
/// portably. `RealClock` and `copy_and_auto_clear` are the production code.
#[derive(Clone, Default)]
struct HandSource {
    flag: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    installs: Arc<AtomicUsize>,
    fail_with: Option<String>,
}

impl HandSource {
    fn failing(message: &str) -> Self {
        Self {
            fail_with: Some(message.to_owned()),
            ..Self::default()
        }
    }

    fn installed(&self) -> bool {
        self.flag.lock().unwrap().is_some()
    }

    /// Fires the interrupt once a handler is installed.
    fn fire(&self) {
        let flag = self.flag.lock().unwrap().clone().expect("installed");
        flag.store(true, Ordering::SeqCst);
    }
}

impl InterruptSource for HandSource {
    fn install(&self, flag: Arc<AtomicBool>) -> Result<(), String> {
        self.installs.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = &self.fail_with {
            return Err(message.clone());
        }
        *self.flag.lock().unwrap() = Some(flag);
        Ok(())
    }
}

/// Bounded, so a missing installation fails the test instead of hanging it.
fn wait_until_installed(source: &HandSource) {
    let started = std::time::Instant::now();
    while !source.installed() {
        assert!(
            // Setup bound, not the behavior under test: generous so load and coverage
            // instrumentation cannot win the race (#1564-#1567).
            started.elapsed() < Duration::from_secs(30),
            "the interrupt handler was never installed"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn scenario_clipboard(secret: &str) -> FakeClipboard {
    FakeClipboard {
        secret: secret.to_owned(),
        copy_error: String::new(),
        clear_error: String::new(),
        read_mode: "honest".to_owned(),
        read_error: String::new(),
        state: Mutex::new((String::new(), Vec::new())),
    }
}

#[test]
fn injected_interrupt_clears_and_verifies_long_before_the_deadline() {
    let source = HandSource::default();
    let clock = RealClock::with_interrupt_source(Some(Box::new(source.clone())));
    let clipboard = scenario_clipboard("interrupt-secret");
    let firing = source.clone();
    let interrupter = std::thread::spawn(move || {
        wait_until_installed(&firing);
        std::thread::sleep(Duration::from_millis(150));
        firing.fire();
    });
    let mut stderr = Vec::new();
    let started = std::time::Instant::now();
    copy_and_auto_clear(&clipboard, "interrupt-secret", 10, &clock, &mut stderr).unwrap();
    interrupter.join().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the interrupt must end the wait, took {:?}",
        started.elapsed()
    );
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("[clipboard cleared]"), "{stderr:?}");
    assert!(!stderr.contains("interrupt-secret"));
    let state = clipboard.state.lock().unwrap();
    assert_eq!(state.1, ["copy:interrupt-secret", "copy:", "read"]);
    assert_eq!(state.0, "");
}

#[test]
fn interrupt_handler_is_installed_before_the_secret_is_copied() {
    struct OrderClipboard {
        source: HandSource,
        installed_at_copy: Mutex<Vec<bool>>,
    }
    impl TextClipboard for OrderClipboard {
        fn copy(&self, _text: &str) -> Result<(), String> {
            self.installed_at_copy
                .lock()
                .unwrap()
                .push(self.source.installed());
            Ok(())
        }
        fn read(&self) -> Result<String, String> {
            Ok(String::new())
        }
    }
    let source = HandSource::default();
    let clipboard = OrderClipboard {
        source: source.clone(),
        installed_at_copy: Mutex::new(Vec::new()),
    };
    let clock = RealClock::with_interrupt_source(Some(Box::new(source.clone())));
    // Fire up front: the wait observes the already-set flag at once.
    let firing = source.clone();
    let armed = std::thread::spawn(move || {
        wait_until_installed(&firing);
        firing.fire();
    });
    copy_and_auto_clear(&clipboard, "s", 5, &clock, &mut Vec::new()).unwrap();
    armed.join().unwrap();
    // Both the secret and the empty clear happened with a handler in place.
    assert_eq!(*clipboard.installed_at_copy.lock().unwrap(), [true, true]);
}

#[test]
fn failed_handler_installation_refuses_to_copy_and_stays_silent() {
    let source = HandSource::failing("console handler refused");
    let clock = RealClock::with_interrupt_source(Some(Box::new(source.clone())));
    let clipboard = scenario_clipboard("never-copied");
    let mut stderr = Vec::new();
    let error: CopyError =
        copy_and_auto_clear(&clipboard, "never-copied", 30, &clock, &mut stderr).unwrap_err();
    assert_eq!(CopyError::EXIT_CODE, 1);
    let text = error.to_string();
    assert!(text.contains("console handler refused"), "{text}");
    assert!(text.contains("nothing was copied"), "{text}");
    assert!(!text.contains("never-copied"));
    assert!(stderr.is_empty(), "no hint or countdown after a refusal");
    let state = clipboard.state.lock().unwrap();
    assert!(state.1.is_empty(), "the clipboard must stay untouched");
}

#[test]
fn no_handler_is_installed_when_auto_clear_is_off() {
    let source = HandSource::default();
    let clock = RealClock::with_interrupt_source(Some(Box::new(source.clone())));
    let clipboard = scenario_clipboard("kept");
    let mut stderr = Vec::new();
    copy_and_auto_clear(&clipboard, "kept", 0, &clock, &mut stderr).unwrap();
    assert_eq!(source.installs.load(Ordering::SeqCst), 0);
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        "[copied to clipboard]\n"
    );
    assert_eq!(clipboard.state.lock().unwrap().0, "kept");
}

#[test]
fn arming_twice_installs_one_handler() {
    // ctrlc (Windows) allows a single handler per process.
    let source = HandSource::default();
    let clock = RealClock::with_interrupt_source(Some(Box::new(source.clone())));
    clock.arm_termination_signals().unwrap();
    clock.arm_termination_signals().unwrap();
    assert_eq!(source.installs.load(Ordering::SeqCst), 1);
}

#[test]
fn a_flag_set_without_watching_signals_is_ignored() {
    // The tick loop of `countdown` passes watch_signals = false.
    let source = HandSource::default();
    let clock = RealClock::with_interrupt_source(Some(Box::new(source.clone())));
    clock.arm_termination_signals().unwrap();
    source.fire();
    let cancel = CancelToken::default();
    assert_eq!(
        clock.wait_until(Duration::from_millis(20), &cancel, false),
        Wake::Elapsed
    );
    assert_eq!(
        clock.wait_until(Duration::from_secs(30), &cancel, true),
        Wake::Signal
    );
}

/// A stderr that blocks every write until released, like a pipe nobody reads.
/// Written bytes land in `written` only once the gate is open.
#[derive(Clone, Default)]
struct BlockedStderr {
    open: Arc<(Mutex<bool>, std::sync::Condvar)>,
    written: Arc<Mutex<Vec<u8>>>,
    entered: Arc<AtomicBool>,
}

impl BlockedStderr {
    fn release(&self) {
        let (open, changed) = &*self.open;
        *open.lock().unwrap() = true;
        changed.notify_all();
    }

    fn wait_for_first_write(&self) {
        let started = std::time::Instant::now();
        while !self.entered.load(Ordering::SeqCst) {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the writer was never reached"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn text(&self) -> String {
        String::from_utf8(self.written.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for BlockedStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.entered.store(true, Ordering::SeqCst);
        let (open, changed) = &*self.open;
        let mut open = open.lock().unwrap();
        while !*open {
            open = changed.wait(open).unwrap();
        }
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Polls until the fake clipboard is empty; returns how long that took.
fn wait_until_clipboard_clear(clipboard: &FakeClipboard, limit: Duration) -> Option<Duration> {
    let started = std::time::Instant::now();
    while started.elapsed() < limit {
        let state = clipboard.state.lock().unwrap();
        if state.1.iter().any(|op| op == "copy:") && state.0.is_empty() {
            return Some(started.elapsed());
        }
        drop(state);
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

/// Regression for the review finding: the countdown used to write and flush on
/// the thread that also owns the timer and the clear, so a stderr nobody reads
/// kept the secret on the clipboard past the timeout. Go keeps clearing
/// independent of the countdown output.
#[test]
fn blocked_stderr_does_not_delay_the_timer_clear() {
    let clipboard = scenario_clipboard("blocked-timer-secret");
    let clock = RealClock::new();
    let stderr = BlockedStderr::default();
    let mut writer = stderr.clone();
    std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            copy_and_auto_clear(&clipboard, "blocked-timer-secret", 1, &clock, &mut writer)
        });
        stderr.wait_for_first_write();
        // 1 s timeout plus generous scheduling margin.
        let cleared = wait_until_clipboard_clear(&clipboard, Duration::from_secs(15));
        let still_blocked = !run.is_finished();
        stderr.release();
        run.join().unwrap().unwrap();
        let cleared = cleared.expect("the secret stayed on the clipboard while stderr was blocked");
        assert!(
            cleared >= Duration::from_millis(900),
            "cleared early: {cleared:?}"
        );
        assert!(
            still_blocked,
            "the call must have been stuck on stderr at that point"
        );
    });
    // Nothing was lost: once the pipe drains, the Go-observed bytes appear.
    assert_eq!(
        stderr.text(),
        "[copied to clipboard]\n\r[clearing clipboard in 1s] \r[clearing clipboard in 0s] \r[clipboard cleared]        \n"
    );
    let state = clipboard.state.lock().unwrap();
    assert_eq!(state.1, ["copy:blocked-timer-secret", "copy:", "read"]);
}

#[test]
fn blocked_stderr_does_not_delay_the_signal_clear() {
    let source = HandSource::default();
    let clock = RealClock::with_interrupt_source(Some(Box::new(source.clone())));
    let clipboard = scenario_clipboard("blocked-signal-secret");
    let stderr = BlockedStderr::default();
    let mut writer = stderr.clone();
    std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            copy_and_auto_clear(&clipboard, "blocked-signal-secret", 30, &clock, &mut writer)
        });
        stderr.wait_for_first_write();
        wait_until_installed(&source);
        source.fire();
        let cleared = wait_until_clipboard_clear(&clipboard, Duration::from_secs(15));
        let still_blocked = !run.is_finished();
        stderr.release();
        run.join().unwrap().unwrap();
        assert!(
            cleared.is_some(),
            "a signal must clear the clipboard while stderr is blocked"
        );
        assert!(
            still_blocked,
            "the call must have been stuck on stderr at that point"
        );
    });
    let text = stderr.text();
    assert!(
        text.ends_with("\r[clipboard cleared]        \n"),
        "{text:?}"
    );
    assert!(!text.contains("blocked-signal-secret"));
}

/// Removes `ESC [ ... m` sequences (all lipgloss emits here).
fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The text of every `ESC[..m ... ESC[0m` run in `text`.
fn coloured_runs(text: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("\u{1b}[") {
        let after = &rest[start..];
        let open_end = after.find('m').expect("sgr start") + 1;
        let body = &after[open_end..];
        let close = body.find("\u{1b}[0m").expect("sgr reset");
        runs.push(body[..close].to_owned());
        rest = &body[close + 4..];
    }
    runs
}

/// ADR 0034 item 21 (ratified): Go styles the `cliout` lines of `get` with
/// lipgloss on a colour stderr; Rust writes plain text. The Go side is the
/// `colour_scenarios` of `get_clipboard.json` (colour decision forced on,
/// lipgloss pinned to true colour). The pin is exact: Rust's bytes equal Go's
/// bytes with the escape sequences removed, Go's coloured runs are precisely
/// the hint, the failed-clear warning and the final `Error:` line (not the
/// countdown, `[clipboard cleared]` or the not-cleared warning, which Go
/// prints plain), and Rust never emits an escape. Where Go itself is plain
/// (colour off, or only the `--color always` flag, which Go reads after it
/// has decided), the bytes must be identical, escapes or not.
#[test]
fn colour_is_the_only_difference_on_cliout_lines() {
    let fixture = fixture();
    assert_eq!(fixture.colour_scenarios.len(), 8);
    let (mut coloured, mut plain) = (0, 0);
    let mut runs_seen = std::collections::BTreeSet::new();
    for s in &fixture.colour_scenarios {
        let mut clock = VirtualClock::new();
        if s.timer_stub_ms > 0 {
            clock.wake_at = Some(Duration::from_millis(s.timer_stub_ms));
        }
        let clipboard = FakeClipboard::new(s);
        let mut stderr = Vec::new();
        let result = copy_and_auto_clear(
            &clipboard,
            &s.secret,
            s.auto_clear_seconds,
            &clock,
            &mut stderr,
        );
        let mut rust = String::from_utf8(stderr).expect("utf-8 stderr");
        let exit_code = match result {
            Ok(()) => 0,
            Err(error) => {
                rust = format!("Error: {error}\nError: {error}\n");
                i32::from(CopyError::EXIT_CODE)
            }
        };
        assert_eq!(exit_code, s.exit_code, "{} exit", s.name);
        assert_eq!(s.stdout, "", "{} stdout", s.name);
        assert_eq!(
            clipboard.state.lock().unwrap().1,
            s.clipboard_ops,
            "{} clipboard ops",
            s.name
        );
        assert!(!rust.contains('\u{1b}'), "{} Rust wrote an escape", s.name);
        assert_eq!(
            rust,
            strip_ansi(&s.stderr),
            "{} stderr modulo colour",
            s.name
        );
        if s.stderr.contains('\u{1b}') {
            coloured += 1;
            assert_eq!(s.color, "always", "{}", s.name);
            assert_ne!(
                rust, s.stderr,
                "{} must differ from Go only by colour",
                s.name
            );
            for run in coloured_runs(&s.stderr) {
                assert!(
                    run == "[copied to clipboard]"
                        || run.starts_with("Warning: failed to clear clipboard: ")
                        || run.starts_with("Error: copy to clipboard: "),
                    "{}: unexpected coloured run {run:?}",
                    s.name
                );
                runs_seen.insert(run.split(':').next().unwrap().to_owned());
            }
        } else {
            plain += 1;
            assert!(
                s.color == "never" || s.color_flag == "always",
                "{}: Go printed no colour although it was asked for",
                s.name
            );
            assert_eq!(rust, s.stderr, "{} plain controls are byte-equal", s.name);
        }
    }
    // Six coloured scenarios cover all three line kinds; two controls stay plain.
    assert_eq!((coloured, plain), (6, 2));
    assert_eq!(
        runs_seen.into_iter().collect::<Vec<_>>(),
        ["Error", "Warning", "[copied to clipboard]"]
    );
}

/// The pin's own helpers: the stripped Go line is what Rust must print, and
/// the coloured Go line must carry the escape Rust must not.
#[test]
fn colour_pin_helpers_tell_coloured_from_plain() {
    let fixture = fixture();
    let go = &fixture
        .colour_scenarios
        .iter()
        .find(|s| s.name == "colour_always_cleared")
        .unwrap()
        .stderr;
    assert!(go.starts_with("\u{1b}[38;5;82m[copied to clipboard]\u{1b}[0m\n"));
    let plain = strip_ansi(go);
    assert!(plain.starts_with("[copied to clipboard]\n"));
    assert_eq!(coloured_runs(go), ["[copied to clipboard]"]);
    assert_ne!(*go, plain);
    assert_eq!(strip_ansi("a\u{1b}[1;31mb\u{1b}[0mc"), "abc");
}
