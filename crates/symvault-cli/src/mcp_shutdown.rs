//! Go-compatible process shutdown for `symvault mcp`.
//!
//! Go's serve command subscribes SIGINT, SIGTERM and SIGQUIT, cancels its
//! context and returns success. The process therefore exits 0 with no output
//! (SIGQUIT first prints one warning) and removes the runtime port/TLS records
//! instead of dying from the signal. SIGHUP is not subscribed and keeps its
//! default action. These helpers exist only on Unix; Windows console events
//! use a different mechanism and are not covered here.

#[cfg(unix)]
mod unix {
    use std::{
        fs,
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
            eprintln!("Received SIGQUIT, shutting down gracefully...");
        }
    }

    /// Go clears both runtime records unconditionally after a signal-driven
    /// stdio shutdown, even though stdio mode never published them.
    fn clear_runtime_records(root: &Path) {
        let _ = fs::remove_file(root.join(".runtime-port"));
        let _ = fs::remove_file(root.join(".runtime-tls-cert"));
    }

    /// Routes SIGINT/SIGTERM from the stdio signal router into the Go
    /// shutdown: stop reading after the in-flight frame (at most 2 seconds),
    /// clear the runtime records and exit 0.
    pub fn install_stdio(root: PathBuf) {
        symvault_platform::approval::set_stdio_signal_terminator(move |signal| {
            REQUESTED.store(true, Ordering::Release);
            warn_quit(signal);
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

    /// Subscribes the HTTP server to SIGINT/SIGTERM/SIGQUIT. `cleanup` removes
    /// the server's own runtime records; the process then exits 0.
    pub fn install_http(cleanup: Arc<dyn Fn() + Send + Sync>) -> Result<(), String> {
        symvault_platform::approval::spawn_signal_listener(
            &[SIGINT, SIGTERM, SIGQUIT],
            move |signal| {
                REQUESTED.store(true, Ordering::Release);
                warn_quit(signal);
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
