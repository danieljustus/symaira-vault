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
//! Inherited `SIG_IGN` dispositions (Go 1.26 `runtime/signal_unix.go`):
//! `sigInstallGoHandler` keeps an inherited-ignored disposition for SIGHUP and
//! SIGINT only, so those two stay ignored unless the program calls
//! `signal.Notify` for them (which installs a handler and overrides the
//! ignore). SIGQUIT and SIGTERM always get the Go handler, so an inherited
//! ignore does not protect them. Mirrored per signal:
//!
//! | signal  | inherited `SIG_IGN`, no stop callback | inherited `SIG_IGN`, stop callback |
//! |---------|---------------------------------------|-------------------------------------|
//! | SIGHUP  | stays ignored (not registered)        | stays ignored (never `Notify`d)     |
//! | SIGINT  | stays ignored (not registered)        | registered (`Notify` overrides)     |
//! | SIGTERM | registered (dies by SIGTERM)          | registered (`Notify`)               |
//! | SIGQUIT | registered (status 2)                 | registered (status 2)               |
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

    /// True when the process inherited `SIG_IGN` for `signal` (for example from
    /// `nohup` or a parent that ignores it) and nothing has replaced it yet.
    #[allow(unsafe_code)] // One read-only sigaction(2) query with a null new action.
    fn ignored_at_startup(signal: i32) -> bool {
        // SAFETY: `current` is a zeroed, properly sized out-parameter, and a
        // null `act` makes sigaction(2) report the disposition without
        // changing it.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signal, std::ptr::null(), &mut current) == 0
                && current.sa_sigaction == libc::SIG_IGN
        }
    }

    /// The signals to register, mirroring Go's runtime (see the module docs):
    /// only SIGHUP and SIGINT respect an inherited `SIG_IGN`, and SIGINT is
    /// taken over again when the command subscribes it (`has_stop`).
    pub(super) fn registered_signals(has_stop: bool, ignored: impl Fn(i32) -> bool) -> Vec<i32> {
        [SIGINT, SIGTERM, SIGHUP, SIGQUIT]
            .into_iter()
            .filter(|&signal| match signal {
                SIGHUP => !ignored(signal),
                SIGINT => has_stop || !ignored(signal),
                _ => true,
            })
            .collect()
    }

    #[cfg(test)]
    pub(super) fn ignored_at_startup_for_tests(signal: i32) -> bool {
        ignored_at_startup(signal)
    }

    pub(crate) fn install(
        cleanup_dir: Option<PathBuf>,
        on_stop: Option<StopCallback>,
    ) -> Result<(), String> {
        let mut signals = Signals::new(registered_signals(on_stop.is_some(), ignored_at_startup))
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

#[cfg(all(test, unix))]
mod tests {
    use super::unix::registered_signals;
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};

    fn registered(has_stop: bool, ignored: &[i32]) -> Vec<i32> {
        registered_signals(has_stop, |signal| ignored.contains(&signal))
    }

    #[test]
    fn nothing_ignored_registers_every_signal() {
        for has_stop in [false, true] {
            assert_eq!(
                registered(has_stop, &[]),
                vec![SIGINT, SIGTERM, SIGHUP, SIGQUIT]
            );
        }
    }

    #[test]
    fn inherited_sighup_ignore_is_always_kept() {
        for has_stop in [false, true] {
            assert!(!registered(has_stop, &[SIGHUP]).contains(&SIGHUP));
        }
    }

    #[test]
    fn inherited_sigint_ignore_is_kept_unless_the_command_subscribes() {
        assert!(!registered(false, &[SIGINT]).contains(&SIGINT));
        assert!(registered(true, &[SIGINT]).contains(&SIGINT));
    }

    #[test]
    fn sigterm_and_sigquit_ignore_never_protects_like_go() {
        for has_stop in [false, true] {
            let signals = registered(has_stop, &[SIGTERM, SIGQUIT]);
            assert!(signals.contains(&SIGTERM) && signals.contains(&SIGQUIT));
        }
    }

    #[test]
    fn everything_ignored_without_stop_keeps_only_sigterm_and_sigquit() {
        assert_eq!(
            registered(false, &[SIGINT, SIGTERM, SIGHUP, SIGQUIT]),
            vec![SIGTERM, SIGQUIT]
        );
        assert_eq!(
            registered(true, &[SIGINT, SIGTERM, SIGHUP, SIGQUIT]),
            vec![SIGINT, SIGTERM, SIGQUIT]
        );
    }

    #[test]
    fn query_sees_the_real_disposition() {
        // The test harness does not ignore SIGUSR2 at startup.
        assert!(!super::unix::ignored_at_startup_for_tests(libc::SIGUSR2));
    }
}
