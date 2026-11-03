//! Go-compatible process shutdown for `symvault mcp`.
//!
//! Go's serve command subscribes SIGINT, SIGTERM and SIGQUIT, cancels its
//! context and returns success. The process therefore exits 0 with no output
//! (SIGQUIT first prints one warning) and removes the runtime port/TLS records
//! instead of dying from the signal. SIGHUP is not subscribed and keeps its
//! default action. These helpers exist only on Unix; Windows console events
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
//! SIGHUP is not subscribed here, so an armed HTTP copy still dies with a SIGHUP
//! death (Go would clear it and keep serving).
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

    /// Go's stdio bootstrap waits this long for the transport after cancel.
    const STDIO_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

    static REQUESTED: AtomicBool = AtomicBool::new(false);
    static STDIO_FINISHED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

    /// True once a shutdown signal arrived. The stdio loop checks this between
    /// frames, like Go's transport checks its context.
    pub fn requested() -> bool {
        REQUESTED.load(Ordering::Acquire)
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
        let root_for_fallback = root.clone();
        let shutdown = Arc::new(move |signal: i32| {
            REQUESTED.store(true, Ordering::Release);
            warn_quit(signal);
            if signal == SIGQUIT {
                // Go's clipboard timer does not subscribe SIGQUIT, so Go exits 0
                // with the copied secret still on the clipboard. Clear it first
                // (declared Rust-safer difference; SIGINT/SIGTERM were already
                // cleared by the signal router).
                symvault_platform::approval::clear_armed_stdio_clipboard();
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
    pub fn install_http(
        drain: symvault_mcp::http::HttpShutdown,
        timeout: Duration,
        cleanup: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        symvault_platform::approval::spawn_signal_listener(
            &[SIGINT, SIGTERM, SIGQUIT],
            move |signal| {
                REQUESTED.store(true, Ordering::Release);
                warn_quit(signal);
                // Go's armed `StartAutoClear` timer receives the same signal and
                // clears at receipt (SIGQUIT is a declared Rust-safer addition);
                // do not wait for the drain. A request still in flight may copy
                // meanwhile, so clear again once the drain is over.
                symvault_platform::approval::clear_armed_process_clipboards();
                // Go ignores the drain error too: the process exits 0 either way.
                let _ = drain.drain(timeout);
                symvault_platform::approval::clear_armed_process_clipboards();
                cleanup();
                std::process::exit(0);
            },
        )
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
}
