//! Go-compatible signal handling for the long-running non-MCP commands
//! (`broker`, `run --broker`, `intake watch`), CLI-007 / #1242.
//!
//! Go subscribes exactly SIGINT and SIGTERM in these commands (`signal.Notify`
//! / `signal.NotifyContext`) and treats them as a clean stop that returns
//! success. Every other signal keeps the Go runtime default: SIGHUP kills the
//! process by that signal, SIGQUIT dumps goroutines and exits with status 2.
//! `run --broker` subscribes nothing, so SIGINT/SIGTERM also kill the process
//! by the signal and leave the child it started running.
//!
//! The previous implementation used `ctrlc` with its `termination` feature on
//! every platform, which additionally turned SIGHUP into a clean exit 0. On
//! Unix this module registers the four signals itself so that:
//!
//! - SIGINT/SIGTERM invoke the command's stop callback (clean exit);
//! - SIGHUP/SIGQUIT first remove the command's private temporary state, then
//!   end the process exactly like Go (death by SIGHUP, exit status 2).
//!
//! The cleanup matters because Rust, unlike Go, keeps the broker's public CA
//! certificate in a per-instance temporary directory instead of overwriting
//! `<vault>/broker-ca.pem`; a process ended by a signal must not leave it
//! behind. SIGKILL cannot be intercepted and still leaves it, as documented
//! in the broker contract.
//!
//! Windows keeps `ctrlc` (Ctrl-C and Ctrl-Break in a console) unchanged;
//! its native evidence lives in `egress_contract.py` and
//! `intake_watch_contract.py`.

use std::path::PathBuf;

/// Stop callback run for a graceful stop request (SIGINT/SIGTERM, or Ctrl-C /
/// Ctrl-Break on Windows).
pub(crate) type StopCallback = Box<dyn Fn() + Send + 'static>;

#[cfg(unix)]
mod unix {
    use super::{PathBuf, StopCallback};
    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM},
        iterator::Signals,
    };

    /// Go's runtime exits with status 2 after printing the goroutine dump.
    const GO_SIGQUIT_STATUS: i32 = 2;

    pub(crate) fn install(
        cleanup_dir: Option<PathBuf>,
        on_stop: Option<StopCallback>,
    ) -> Result<(), String> {
        let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])
            .map_err(|error| format!("register process signal listener: {error}"))?;
        std::thread::Builder::new()
            .name("symvault-command-signals".to_owned())
            .spawn(move || {
                for signal in signals.forever() {
                    if matches!(signal, SIGINT | SIGTERM)
                        && let Some(stop) = &on_stop
                    {
                        stop();
                        continue;
                    }
                    if let Some(directory) = &cleanup_dir {
                        // A missing directory means the owner already cleaned
                        // up; neither case may keep the process alive.
                        let _ = std::fs::remove_dir_all(directory);
                    }
                    if signal == SIGQUIT {
                        std::process::exit(GO_SIGQUIT_STATUS);
                    }
                    // Restore the default action and re-raise: the parent sees
                    // death by this signal, exactly like Go.
                    let _ = signal_hook::low_level::emulate_default_handler(signal);
                    std::process::exit(128 + signal);
                }
            })
            .map(drop)
            .map_err(|error| format!("start process signal listener: {error}"))
    }
}

/// Subscribes the Go signal set. `cleanup_dir` is removed before the process
/// dies from a signal that Go does not treat as a clean stop. `on_stop` is the
/// clean-stop request; without it SIGINT/SIGTERM also end the process (as in
/// Go's `run --broker`).
#[cfg(unix)]
pub(crate) fn install(
    cleanup_dir: Option<PathBuf>,
    on_stop: Option<StopCallback>,
) -> Result<(), String> {
    unix::install(cleanup_dir, on_stop)
}

#[cfg(not(unix))]
pub(crate) fn install(
    _cleanup_dir: Option<PathBuf>,
    on_stop: Option<StopCallback>,
) -> Result<(), String> {
    match on_stop {
        Some(stop) => ctrlc::set_handler(move || stop()).map_err(|error| error.to_string()),
        None => Ok(()),
    }
}
