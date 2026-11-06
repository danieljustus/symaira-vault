//! Go-compatible process shutdown for `symvault mcp`.
//!
//! Go's serve command subscribes SIGINT, SIGTERM and SIGQUIT, cancels its
//! context and returns success. The process therefore exits 0 with no output
//! (SIGQUIT first prints one warning) and removes the runtime port/TLS records
//! instead of dying from the signal. SIGHUP is not subscribed and keeps its
//! default action (HTTP: see below). These helpers exist only on Unix; Windows console events
//! use a different mechanism and are not covered here.
//!
//! HTTP (ADR 0009): the first SIGINT/SIGTERM/SIGQUIT stops accepting, cancels
//! the request context (a request that reaches the handler afterwards gets
//! Go's 403 `context canceled`), closes idle keep-alive transports and lets
//! in-flight requests finish for up to `MCP.shutdown_timeout` (5 s default).
//! Whatever is still open then is force-closed. The runtime port/TLS records
//! are cleared unconditionally afterwards and the process exits 0; a second
//! signal during the drain is swallowed.
//!
//! `mcp --stdio --allow-locked` installs the same shutdown (Go subscribes the
//! signals in `serve` before it branches on the vault; real-process observation
//! in `signal_process_contract.py`, cases `mcp-locked-*`).
//!
//! Armed clipboard auto-clear (real Go process): SIGINT/SIGTERM clear the
//! clipboard and then shut the server down (`serve` and the timer both
//! subscribe); SIGHUP is subscribed by the timer only, so it clears and the
//! server keeps serving. The router in `symvault-platform` `approval.rs`
//! requests this shutdown through the terminator installed here.
//!
//! SIGQUIT with an armed clipboard timer: Go's timer does not subscribe SIGQUIT,
//! so Go shuts down and leaves the copied secret on the clipboard. Rust clears it
//! before exiting 0 (declared Rust-safer difference, `clear_armed_stdio_clipboard`).
//!
//! HTTP armed clipboard (CLI007-LOW): Go's `Server.startClipboardAutoClear` is
//! transport-independent, so `copy_to_clipboard`/`generate_totp` over HTTP arm the
//! same `StartAutoClear` timer, which subscribes SIGINT/SIGTERM next to `serve`.
//! `install_http` therefore clears every armed HTTP timer at signal receipt and
//! again after the drain (SIGQUIT included, a declared Rust-safer addition).
//! Real Go process (`signal_process_contract.py`, cases `mcp-http-clipboard-*`):
//! with a copy armed, SIGINT/SIGTERM exit 0 but Go usually exits before its timer
//! has run the clear (13 of 14 runs left the secret; Rust always clears, a
//! declared Rust-safer difference). SIGHUP is subscribed by the timer only:
//! armed, it clears and the server keeps serving; the next SIGHUP finds no timer
//! and kills the process by the signal. Nothing armed, SIGHUP kills by the
//! signal (no runtime records are cleared), unless the process inherited
//! `SIG_IGN` for it: then an unarmed SIGHUP is ignored, an armed one overrides the
//! ignore (`Notify`) and clears, and the ignore is back in force afterwards.
//! `install_http` mirrors that: its SIGHUP listener clears and keeps serving
//! while a timer is armed and otherwise takes the default action (or ignores the
//! signal when it was inherited ignored, like `process_signals`).
//!
//! Shutdown-path clears run on a short-lived thread that is joined for a bounded
//! time (`CLIPBOARD_CLEAR_BOUND`): a hung clipboard backend can neither hold up
//! the drain and exit nor swallow later signals on the listener thread.
//!
//! Known residuals against Go (#1242):
//! - Go's SIGQUIT goroutine dump (ADR 0034 item 11) is a maintainer decision and
//!   is not reproduced here.
//!
//! Signal during an in-flight stdio prompt (#1472, Go oracle 0cc78062 under a
//! controlling PTY): the in-flight request is answered with Go's
//! context-canceled shape and the process then exits 0, like Go.
//! - secure input: JSON-RPC error -32603 `secure input failed: context
//!   canceled` (the `ContextCanceled` secure-input error). The typed value is
//!   never stored. Raw Ctrl-C (ETX) stays the user cancel `secure input
//!   canceled by user` and the server keeps serving.
//! - ordinary approval: `<tool> approval failed: failed to read from terminal:
//!   context canceled` through the tool's normal approval-failure mapping.
//! - Rust returns the response as soon as the prompt unwinds and the stdio loop
//!   sees the shutdown request, so it exits well inside Go's 0.5 s / 1 s;
//!   the exit code (0) and stdout are what is compared.

#[cfg(unix)]
mod unix {
    use std::{
        fs,
        io::Write,
        path::{Path, PathBuf},
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    // The numeric values are identical on Linux and macOS.
    const SIGINT: i32 = 2;
    const SIGQUIT: i32 = 3;
    const SIGTERM: i32 = 15;

    const SIGHUP: i32 = 1;

    /// Go's stdio bootstrap waits this long for the transport after cancel.
    const STDIO_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

    /// Longest a shutdown-path clipboard clear may hold up the signal thread
    /// that issued it. A clipboard tool that never returns is abandoned (the
    /// thread keeps running; the process is about to exit or keeps serving).
    const CLIPBOARD_CLEAR_BOUND: Duration = Duration::from_secs(2);

    static REQUESTED: AtomicBool = AtomicBool::new(false);
    static STDIO_FINISHED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

    /// True once a shutdown signal arrived. The stdio loop checks this between
    /// frames, like Go's transport checks its context.
    pub fn requested() -> bool {
        REQUESTED.load(Ordering::Acquire)
    }

    /// True when the process inherited `SIG_IGN` for `signal` (for example from
    /// `nohup`) and nothing has replaced it yet; same query as
    /// `process_signals`' (that module is not part of every build of this file).
    #[allow(unsafe_code)] // One read-only sigaction(2) query with a null new action.
    fn inherited_ignore(signal: i32) -> bool {
        // SAFETY: `current` is a zeroed, properly sized out-parameter, and a
        // null `act` makes sigaction(2) report the disposition without
        // changing it.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signal, std::ptr::null(), &mut current) == 0
                && current.sa_sigaction == libc::SIG_IGN
        }
    }

    /// Runs `work` on a short-lived thread and waits at most `bound` for its
    /// result. `None` means it did not finish in time (the thread is abandoned).
    /// If no thread can be started the work runs inline: clearing the secret
    /// matters more than the bound in a process that cannot start a thread.
    fn run_bounded<T: Send + 'static>(
        bound: Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let work = Arc::new(Mutex::new(Some(work)));
        let (sender, receiver) = std::sync::mpsc::channel();
        let for_thread = Arc::clone(&work);
        let spawned = std::thread::Builder::new()
            .name("symvault-clipboard-clear".to_owned())
            .spawn(move || {
                let taken = for_thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(work) = taken {
                    let _ = sender.send(work());
                }
            });
        if spawned.is_err() {
            let taken = work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            return taken.map(|work| work());
        }
        receiver.recv_timeout(bound).ok()
    }

    /// Takes every armed HTTP clipboard timer and clears its clipboard with a
    /// bounded wait. Returns how many timers were armed (the clear may still be
    /// running on the abandoned thread when the bound passed).
    fn clear_armed_http_clipboards(bound: Duration) -> usize {
        let armed = symvault_platform::approval::take_armed_process_clipboards();
        let count = armed.len();
        if count > 0 {
            let _ = run_bounded(bound, move || armed.clear_all());
        }
        count
    }

    /// Go's SIGHUP handling for HTTP `mcp`: only an armed `StartAutoClear` timer
    /// subscribes it. Armed: clear and keep serving. Not armed: the Go runtime
    /// default (death by SIGHUP, runtime records untouched), or nothing when the
    /// process inherited `SIG_IGN` for it.
    fn handle_http_hangup(inherited_ignore: bool, bound: Duration) {
        if clear_armed_http_clipboards(bound) > 0 || inherited_ignore {
            return;
        }
        if signal_hook::low_level::emulate_default_handler(SIGHUP).is_err() {
            std::process::abort();
        }
        std::process::exit(128 + SIGHUP);
    }

    fn warn_quit(signal: i32) {
        if signal == SIGQUIT {
            // A closed stderr must not stop the shutdown.
            let _ = writeln!(
                std::io::stderr(),
                "Received SIGQUIT, shutting down gracefully..."
            );
        }
    }

    /// Go clears both runtime records unconditionally after a signal-driven
    /// stdio shutdown, even though stdio mode never published them.
    fn clear_runtime_records(root: &Path) {
        let _ = fs::remove_file(root.join(".runtime-port"));
        let _ = fs::remove_file(root.join(".runtime-tls-cert"));
    }

    /// Routes SIGINT/SIGTERM (via the stdio signal router) and SIGQUIT (via its
    /// own listener) into the Go shutdown: stop reading after the in-flight
    /// frame (at most 2 seconds), clear the runtime records and exit 0.
    pub fn install_stdio(root: PathBuf) -> Result<(), String> {
        install_stdio_with_bound(root, CLIPBOARD_CLEAR_BOUND)
    }

    pub(super) fn install_stdio_with_bound(
        root: PathBuf,
        clear_bound: Duration,
    ) -> Result<(), String> {
        let root_for_fallback = root.clone();
        let shutdown = Arc::new(move |signal: i32| {
            REQUESTED.store(true, Ordering::Release);
            warn_quit(signal);
            if signal == SIGQUIT {
                // Go's clipboard timer does not subscribe SIGQUIT, so Go exits 0
                // with the copied secret still on the clipboard. Clear it first
                // (declared Rust-safer difference; SIGINT/SIGTERM were already
                // cleared by the signal router).
                let _ = run_bounded(
                    clear_bound,
                    symvault_platform::approval::clear_armed_stdio_clipboard,
                );
            }
            let (lock, changed) = &STDIO_FINISHED;
            let deadline = Instant::now() + STDIO_SHUTDOWN_GRACE;
            let mut finished = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*finished {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                finished = changed
                    .wait_timeout(finished, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
            drop(finished);
            clear_runtime_records(&root);
            std::process::exit(0);
        });
        let router = Arc::clone(&shutdown);
        let fallback_root = root_for_fallback;
        // The terminator runs on the thread that owns the in-flight request when
        // a prompt is canceled. It only records the request and hands the
        // grace-period wait and exit to a helper thread, so the request is
        // answered and flushed before the stdio loop sees the flag and returns.
        symvault_platform::approval::set_stdio_signal_terminator(move |signal| {
            REQUESTED.store(true, Ordering::Release);
            let router = Arc::clone(&router);
            if std::thread::Builder::new()
                .name("symvault-mcp-shutdown".to_owned())
                .spawn(move || router(signal))
                .is_err()
            {
                // No thread to wait on: exit now rather than keep serving.
                clear_runtime_records(&fallback_root);
                std::process::exit(0);
            }
        });
        symvault_platform::approval::spawn_signal_listener(&[SIGQUIT], move |signal| {
            shutdown(signal)
        })
    }

    /// Called by the stdio loop's owner once the transport returned.
    pub fn stdio_finished() {
        let (lock, changed) = &STDIO_FINISHED;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        changed.notify_all();
    }

    /// After a signal the shutdown thread owns cleanup and exit. Never let the
    /// main thread return first, or the records would survive.
    pub fn park_if_requested() {
        while requested() {
            std::thread::park();
        }
    }

    /// Subscribes the HTTP server to SIGINT/SIGTERM/SIGQUIT, like Go's
    /// `signal.Notify`: the first signal drains the server for at most
    /// `timeout` (stop accepting, close idle transports, let in-flight requests
    /// finish, then force-close), `cleanup` clears the runtime records and the
    /// process exits 0. The listener thread is busy until it exits, so a second
    /// signal is swallowed, as Go's buffered channel swallows it.
    ///
    /// SIGHUP gets its own listener (Go's armed clipboard timer is its only
    /// subscriber, see the module docs): it clears an armed copy and keeps
    /// serving, and otherwise behaves as if nothing were subscribed.
    pub fn install_http(
        drain: symvault_mcp::http::HttpShutdown,
        timeout: Duration,
        cleanup: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        install_http_with_bound(drain, timeout, cleanup, CLIPBOARD_CLEAR_BOUND)
    }

    pub(super) fn install_http_with_bound(
        drain: symvault_mcp::http::HttpShutdown,
        timeout: Duration,
        cleanup: Arc<dyn Fn() + Send + Sync>,
        clear_bound: Duration,
    ) -> Result<(), String> {
        // Asked before the listener below replaces the inherited disposition.
        let hangup_inherited_ignore = inherited_ignore(SIGHUP);
        symvault_platform::approval::spawn_signal_listener(
            &[SIGINT, SIGTERM, SIGQUIT],
            move |signal| {
                REQUESTED.store(true, Ordering::Release);
                warn_quit(signal);
                // Go's armed `StartAutoClear` timer receives the same signal and
                // clears at receipt (SIGQUIT is a declared Rust-safer addition);
                // do not wait for the drain. A request still in flight may copy
                // meanwhile, so clear again once the drain is over.
                clear_armed_http_clipboards(clear_bound);
                // Go ignores the drain error too: the process exits 0 either way.
                let _ = drain.drain(timeout);
                clear_armed_http_clipboards(clear_bound);
                cleanup();
                std::process::exit(0);
            },
        )?;
        symvault_platform::approval::spawn_signal_listener(&[SIGHUP], move |_| {
            handle_http_hangup(hangup_inherited_ignore, clear_bound);
        })
    }
}

#[cfg(unix)]
pub use unix::{install_http, install_stdio, park_if_requested, requested, stdio_finished};

#[cfg(not(unix))]
pub fn requested() -> bool {
    false
}

#[cfg(not(unix))]
pub fn stdio_finished() {}

#[cfg(not(unix))]
pub fn park_if_requested() {}

#[cfg(all(test, unix))]
mod tests {
    use std::{env, fs, io::Write, os::unix::process::ExitStatusExt, process::Command, sync::Arc};
    use symvault_core::platform::{Clipboard, PlatformError};

    struct EventClipboard(std::path::PathBuf);
    impl Clipboard for EventClipboard {
        fn set(&self, _: &[u8]) -> Result<(), PlatformError> {
            Ok(())
        }
        fn clear(&self) -> Result<(), PlatformError> {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.0)
                .unwrap();
            writeln!(file, "clear").unwrap();
            Ok(())
        }
    }

    /// stdio `mcp` with an armed clipboard timer. Go: SIGQUIT is not part of the
    /// timer's subscription, so Go shuts down (exit 0, warning) and leaves the
    /// secret on the clipboard. Rust clears first (declared Rust-safer
    /// difference). Control: without an armed timer nothing is cleared. The child
    /// owns the process-wide router and records clears in a file instead of
    /// touching the real pasteboard.
    #[test]
    fn sigquit_shutdown_clears_an_armed_clipboard() {
        if let Ok(spec) = env::var("SYMVAULT_MCP_QUIT_CHILD") {
            let events = std::path::PathBuf::from(env::var("SYMVAULT_MCP_QUIT_EVENTS").unwrap());
            let root = std::path::PathBuf::from(env::var("SYMVAULT_MCP_QUIT_ROOT").unwrap());
            symvault_platform::approval::install_stdio_clipboard_signal_router(Arc::new(
                EventClipboard(events),
            ))
            .unwrap();
            super::install_stdio(root).unwrap();
            let (cancel, _canceled) = std::sync::mpsc::channel();
            let _registration = (spec == "armed").then(|| {
                symvault_platform::approval::register_stdio_clipboard_auto_clear(
                    cancel,
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
                .expect("router installed")
            });
            signal_hook::low_level::raise(libc::SIGQUIT).unwrap();
            // The shutdown thread exits 0; reaching the end would be a failure.
            std::thread::sleep(std::time::Duration::from_secs(30));
            std::process::exit(99);
        }
        for (spec, clears) in [("armed", "clear\n"), ("idle", "")] {
            let dir = tempfile::tempdir().unwrap();
            let events = dir.path().join("events");
            fs::write(dir.path().join(".runtime-port"), "1").unwrap();
            let output = Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mcp_commands::mcp_shutdown::tests::sigquit_shutdown_clears_an_armed_clipboard",
                ])
                .env("SYMVAULT_MCP_QUIT_CHILD", spec)
                .env("SYMVAULT_MCP_QUIT_EVENTS", &events)
                .env("SYMVAULT_MCP_QUIT_ROOT", dir.path())
                .output()
                .expect("run SIGQUIT child");
            assert_eq!(output.status.code(), Some(0), "{spec}: {output:?}");
            assert_eq!(output.status.signal(), None, "{spec}: {output:?}");
            assert_eq!(
                fs::read_to_string(&events).unwrap_or_default(),
                clears,
                "{spec}"
            );
            assert!(
                !dir.path().join(".runtime-port").exists(),
                "{spec}: records cleared"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("Received SIGQUIT, shutting down gracefully..."),
                "{spec}: {output:?}"
            );
        }
    }

    /// HTTP `mcp` with a clipboard timer armed by `copy_to_clipboard` (Go arms
    /// `StartAutoClear` per Server, HTTP included, and its signal subscription
    /// clears at receipt). SIGINT/SIGTERM clear like Go; SIGQUIT is the declared
    /// Rust-safer addition. The child records clears in a file instead of
    /// touching the real pasteboard. Control: nothing armed, nothing cleared.
    #[test]
    fn http_signal_shutdown_clears_an_armed_clipboard() {
        if let Ok(spec) = env::var("SYMVAULT_MCP_HTTP_CHILD") {
            let (state, signal) = spec.split_once(':').unwrap();
            let events = std::path::PathBuf::from(env::var("SYMVAULT_MCP_HTTP_EVENTS").unwrap());
            let signal = match signal {
                "SIGINT" => libc::SIGINT,
                "SIGQUIT" => libc::SIGQUIT,
                _ => libc::SIGTERM,
            };
            let (cancel, _canceled) = std::sync::mpsc::channel();
            let _registration = (state == "armed").then(|| {
                symvault_platform::approval::register_process_clipboard_auto_clear(
                    cancel,
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    Arc::new(EventClipboard(events)),
                )
            });
            super::install_http(
                symvault_mcp::http::HttpShutdown::for_process(),
                std::time::Duration::from_millis(100),
                Arc::new(|| {}),
            )
            .unwrap();
            signal_hook::low_level::raise(signal).unwrap();
            // The listener thread exits 0; reaching the end would be a failure.
            std::thread::sleep(std::time::Duration::from_secs(30));
            std::process::exit(99);
        }
        for (spec, clears) in [
            ("armed:SIGINT", "clear\n"),
            ("armed:SIGTERM", "clear\n"),
            ("armed:SIGQUIT", "clear\n"),
            ("idle:SIGTERM", ""),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let events = dir.path().join("events");
            let output = Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mcp_commands::mcp_shutdown::tests::http_signal_shutdown_clears_an_armed_clipboard",
                ])
                .env("SYMVAULT_MCP_HTTP_CHILD", spec)
                .env("SYMVAULT_MCP_HTTP_EVENTS", &events)
                .output()
                .expect("run HTTP signal child");
            assert_eq!(output.status.code(), Some(0), "{spec}: {output:?}");
            assert_eq!(output.status.signal(), None, "{spec}: {output:?}");
            assert_eq!(
                fs::read_to_string(&events).unwrap_or_default(),
                clears,
                "{spec}: cleared exactly once, at receipt"
            );
        }
    }

    /// A backend that records the attempt and then never returns.
    struct HangClipboard(std::path::PathBuf);
    impl Clipboard for HangClipboard {
        fn set(&self, _: &[u8]) -> Result<(), PlatformError> {
            Ok(())
        }
        fn clear(&self) -> Result<(), PlatformError> {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.0)
                .unwrap();
            writeln!(file, "clear-started").unwrap();
            drop(file);
            std::thread::sleep(std::time::Duration::from_secs(60));
            Ok(())
        }
    }

    fn register_armed(
        clipboard: Arc<dyn Clipboard>,
    ) -> symvault_platform::approval::ProcessClipboardAutoClearRegistration {
        let (cancel, _canceled) = std::sync::mpsc::channel();
        symvault_platform::approval::register_process_clipboard_auto_clear(
            cancel,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            clipboard,
        )
    }

    fn wait_for_events(events: &std::path::Path, wanted: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !fs::read_to_string(events)
            .unwrap_or_default()
            .contains(wanted)
        {
            if std::time::Instant::now() > deadline {
                std::process::exit(98);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// HTTP `mcp` receives SIGHUP. Go (real process, `mcp-http-clipboard-*`
    /// records): only the armed `StartAutoClear` timer subscribes SIGHUP, so an
    /// armed copy is cleared and the server keeps serving, and the next SIGHUP
    /// (nothing armed) kills it by the signal; with nothing armed the first
    /// SIGHUP already kills it. A SIGHUP inherited as `SIG_IGN` is overridden by
    /// the armed subscription and ignored again afterwards. The child records
    /// clears in a file instead of touching the real pasteboard.
    #[test]
    fn http_sighup_follows_the_armed_clipboard_timer() {
        if let Ok(spec) = env::var("SYMVAULT_MCP_HUP_CHILD") {
            let events = std::path::PathBuf::from(env::var("SYMVAULT_MCP_HUP_EVENTS").unwrap());
            let _registration = spec
                .starts_with("armed")
                .then(|| register_armed(Arc::new(EventClipboard(events.clone()))));
            super::install_http(
                symvault_mcp::http::HttpShutdown::for_process(),
                std::time::Duration::from_millis(100),
                Arc::new(|| {}),
            )
            .unwrap();
            signal_hook::low_level::raise(libc::SIGHUP).unwrap();
            if spec.starts_with("armed") {
                wait_for_events(&events, "clear");
            }
            // An unarmed, not-ignored SIGHUP dies right here by the signal.
            std::thread::sleep(std::time::Duration::from_millis(500));
            println!("survived-first");
            signal_hook::low_level::raise(libc::SIGHUP).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(500));
            println!("survived-second");
            std::process::exit(0);
        }
        // (spec, inherit SIG_IGN, killed by SIGHUP at, clears)
        for (spec, ignored, dies, clears) in [
            ("armed", false, Some("second"), "clear\n"),
            ("idle", false, Some("first"), ""),
            ("armed-ignored", true, None, "clear\n"),
            ("idle-ignored", true, None, ""),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let events = dir.path().join("events");
            let exe = env::current_exe().unwrap();
            let mut command = if ignored {
                // SIG_IGN survives exec, like `nohup` or a supervisor parent.
                let mut command = Command::new("sh");
                command
                    .args(["-c", "trap '' HUP; exec \"$@\"", "sh"])
                    .arg(&exe);
                command
            } else {
                Command::new(&exe)
            };
            let output = command
                .args([
                    "--exact",
                    "mcp_commands::mcp_shutdown::tests::http_sighup_follows_the_armed_clipboard_timer",
                    "--nocapture",
                ])
                .env("SYMVAULT_MCP_HUP_CHILD", spec)
                .env("SYMVAULT_MCP_HUP_EVENTS", &events)
                .output()
                .expect("run SIGHUP child");
            let stdout = String::from_utf8_lossy(&output.stdout);
            match dies {
                Some(at) => {
                    assert_eq!(
                        output.status.signal(),
                        Some(libc::SIGHUP),
                        "{spec}: {output:?}"
                    );
                    assert_eq!(
                        stdout.contains("survived-first"),
                        at == "second",
                        "{spec}: dies at the {at} SIGHUP: {output:?}"
                    );
                    assert!(!stdout.contains("survived-second"), "{spec}: {output:?}");
                }
                None => {
                    assert_eq!(output.status.code(), Some(0), "{spec}: {output:?}");
                    assert!(stdout.contains("survived-second"), "{spec}: {output:?}");
                }
            }
            assert_eq!(
                fs::read_to_string(&events).unwrap_or_default(),
                clears,
                "{spec}: cleared once, by the first SIGHUP only"
            );
        }
    }

    /// A clipboard backend that never returns must not hold up the HTTP drain and
    /// exit (SIGTERM) nor swallow later signals (the SIGHUP that found it armed
    /// returns after the bound, so the next SIGHUP is handled). Without the
    /// bounded join both children run past the elapsed-time assertion.
    #[test]
    fn http_shutdown_bounds_a_hung_clipboard_backend() {
        if let Ok(spec) = env::var("SYMVAULT_MCP_HANG_CHILD") {
            let events = std::path::PathBuf::from(env::var("SYMVAULT_MCP_HANG_EVENTS").unwrap());
            let _registration = register_armed(Arc::new(HangClipboard(events.clone())));
            super::unix::install_http_with_bound(
                symvault_mcp::http::HttpShutdown::for_process(),
                std::time::Duration::from_millis(100),
                Arc::new(|| {}),
                std::time::Duration::from_millis(200),
            )
            .unwrap();
            if spec == "sigterm" {
                signal_hook::low_level::raise(libc::SIGTERM).unwrap();
            } else {
                signal_hook::low_level::raise(libc::SIGHUP).unwrap();
                wait_for_events(&events, "clear-started");
                std::thread::sleep(std::time::Duration::from_secs(1));
                // Nothing is armed any more: the default action must still run.
                signal_hook::low_level::raise(libc::SIGHUP).unwrap();
            }
            std::thread::sleep(std::time::Duration::from_secs(30));
            std::process::exit(99);
        }
        for (spec, code, signal) in [
            ("sigterm", Some(0), None),
            ("sighup", None, Some(libc::SIGHUP)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let events = dir.path().join("events");
            let started = std::time::Instant::now();
            let output = Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mcp_commands::mcp_shutdown::tests::http_shutdown_bounds_a_hung_clipboard_backend",
                ])
                .env("SYMVAULT_MCP_HANG_CHILD", spec)
                .env("SYMVAULT_MCP_HANG_EVENTS", &events)
                .output()
                .expect("run hung-clipboard child");
            assert_eq!(output.status.code(), code, "{spec}: {output:?}");
            assert_eq!(output.status.signal(), signal, "{spec}: {output:?}");
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "{spec}: waited on the hung clipboard: {:?}",
                started.elapsed()
            );
            assert_eq!(
                fs::read_to_string(&events).unwrap_or_default(),
                "clear-started\n",
                "{spec}: the clear was attempted exactly once"
            );
        }
    }

    /// stdio SIGQUIT clears an armed copy before exiting; a hung backend is
    /// abandoned after the bound, so the process still exits 0 and removes the
    /// runtime records.
    #[test]
    fn sigquit_shutdown_bounds_a_hung_clipboard_backend() {
        if env::var("SYMVAULT_MCP_QUIT_HANG_CHILD").is_ok() {
            let events =
                std::path::PathBuf::from(env::var("SYMVAULT_MCP_QUIT_HANG_EVENTS").unwrap());
            let root = std::path::PathBuf::from(env::var("SYMVAULT_MCP_QUIT_HANG_ROOT").unwrap());
            symvault_platform::approval::install_stdio_clipboard_signal_router(Arc::new(
                HangClipboard(events),
            ))
            .unwrap();
            super::unix::install_stdio_with_bound(root, std::time::Duration::from_millis(200))
                .unwrap();
            let (cancel, _canceled) = std::sync::mpsc::channel();
            let _registration = symvault_platform::approval::register_stdio_clipboard_auto_clear(
                cancel,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .expect("router installed");
            signal_hook::low_level::raise(libc::SIGQUIT).unwrap();
            std::thread::sleep(std::time::Duration::from_secs(30));
            std::process::exit(99);
        }
        let dir = tempfile::tempdir().unwrap();
        let events = dir.path().join("events");
        fs::write(dir.path().join(".runtime-port"), "1").unwrap();
        let started = std::time::Instant::now();
        let output = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "mcp_commands::mcp_shutdown::tests::sigquit_shutdown_bounds_a_hung_clipboard_backend",
            ])
            .env("SYMVAULT_MCP_QUIT_HANG_CHILD", "1")
            .env("SYMVAULT_MCP_QUIT_HANG_EVENTS", &events)
            .env("SYMVAULT_MCP_QUIT_HANG_ROOT", dir.path())
            .output()
            .expect("run hung SIGQUIT child");
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "waited on the hung clipboard: {:?}",
            started.elapsed()
        );
        assert_eq!(fs::read_to_string(&events).unwrap(), "clear-started\n");
        assert!(
            !dir.path().join(".runtime-port").exists(),
            "records cleared"
        );
    }
}
