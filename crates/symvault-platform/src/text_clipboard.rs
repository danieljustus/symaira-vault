//! Owned native text clipboard, initialized only by an explicit UI caller.
use std::sync::Arc;
use symvault_core::platform::Clipboard;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use symvault_core::platform::UnavailablePlatform;

/// Go `clipboard.DefaultClipboard()` as every command-style consumer sees it:
/// `pbcopy` on macOS, the atotto tool selection (`wl-copy`, `xclip`, `xsel`,
/// Termux, `clip.exe`) from [`crate::desktop_commands::CommandClipboard`] on
/// Linux, fail-closed elsewhere. Tool selection happens once, when this is
/// called, like atotto's package `init()`. Used by the MCP runtime, the TUI and
/// (through its read-capable wrapper) `symvault get`.
#[must_use]
pub fn native_command_clipboard() -> Arc<dyn Clipboard> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(crate::MacOsPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(crate::desktop_commands::CommandClipboard::new(Arc::new(
            crate::desktop_commands::SystemHost::new(),
        )))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Arc::new(UnavailablePlatform)
    }
}

/// The clipboard for the interactive TUI: the command clipboard on macOS and
/// Linux (Go's TUI writes through atotto too), `arboard` on Windows.
pub fn native_text_clipboard() -> Arc<dyn Clipboard> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        native_command_clipboard()
    }
    #[cfg(target_os = "windows")]
    {
        match arboard::Clipboard::new() {
            Ok(backend) => Arc::new(NativeTextClipboard(std::sync::Mutex::new(backend))),
            Err(_) => Arc::new(symvault_core::platform::UnavailablePlatform),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        native_command_clipboard()
    }
}

#[cfg(target_os = "windows")]
struct NativeTextClipboard(std::sync::Mutex<arboard::Clipboard>);

#[cfg(target_os = "windows")]
impl Clipboard for NativeTextClipboard {
    fn set(&self, text: &[u8]) -> Result<(), symvault_core::platform::PlatformError> {
        let text = std::str::from_utf8(text).map_err(|_| clipboard_error())?;
        self.0
            .lock()
            .map_err(|_| clipboard_error())?
            .set_text(text)
            .map_err(|_| clipboard_error())
    }

    fn clear(&self) -> Result<(), symvault_core::platform::PlatformError> {
        self.0
            .lock()
            .map_err(|_| clipboard_error())?
            .clear()
            .map_err(|_| clipboard_error())
    }
}

#[cfg(target_os = "windows")]
fn clipboard_error() -> symvault_core::platform::PlatformError {
    symvault_core::platform::PlatformError {
        kind: symvault_core::platform::PlatformErrorKind::Failed,
        message: "native text clipboard operation failed".into(),
    }
}

/// One retained timer worker. Expiry continues while the caller's foreground
/// terminal is borrowed by an editor; scope exit stops and joins that worker.
pub struct OwnedTextClipboard {
    shared: Arc<(std::sync::Mutex<ClipboardState>, std::sync::Condvar)>,
    worker: Option<std::thread::JoinHandle<()>>,
}
struct ClipboardState {
    backend: Arc<dyn Clipboard>,
    active: bool,
    deadline: Option<std::time::Instant>,
    stopping: bool,
    cleared: Option<Result<(), symvault_core::platform::PlatformError>>,
}
impl OwnedTextClipboard {
    pub fn new(
        backend: Arc<dyn Clipboard>,
    ) -> Result<Self, symvault_core::platform::PlatformError> {
        let shared = Arc::new((
            std::sync::Mutex::new(ClipboardState {
                backend,
                active: false,
                deadline: None,
                stopping: false,
                cleared: None,
            }),
            std::sync::Condvar::new(),
        ));
        let owner = shared.clone();
        let worker = std::thread::Builder::new()
            .name("vault-ui-clipboard".into())
            .spawn(move || {
                let (lock, changed) = &*owner;
                let Ok(mut state) = lock.lock() else {
                    return;
                };
                loop {
                    if state.stopping {
                        // Last attempt before the worker ends; nobody polls
                        // `cleared` any more, so surface a failure here.
                        if let Err(error) = clear_owned(&mut state) {
                            report_clear_failure(&error);
                        }
                        return;
                    }
                    if let Some(deadline) = state.deadline {
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            let result = clear_owned(&mut state);
                            state.cleared = Some(result);
                            continue;
                        }
                        let Ok((next, _)) =
                            changed.wait_timeout(state, deadline.saturating_duration_since(now))
                        else {
                            return;
                        };
                        state = next;
                    } else {
                        let Ok(next) = changed.wait(state) else {
                            return;
                        };
                        state = next;
                    }
                }
            })
            .map_err(|_| ownership_error())?;
        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }
    pub fn copy(
        &self,
        text: &[u8],
        ttl: std::time::Duration,
    ) -> Result<(), symvault_core::platform::PlatformError> {
        let (lock, changed) = &*self.shared;
        let mut state = lock.lock().map_err(|_| ownership_error())?;
        if state.stopping {
            return Err(ownership_error());
        }
        // Serialize setting and expiry: an older timer cannot clear a new copy.
        state.backend.set(text)?;
        state.active = true;
        state.deadline = if ttl.is_zero() {
            None
        } else {
            std::time::Instant::now().checked_add(ttl)
        };
        state.cleared = None;
        changed.notify_all();
        Ok(())
    }
    pub fn clear(&self) -> Result<(), symvault_core::platform::PlatformError> {
        let (lock, changed) = &*self.shared;
        let mut state = lock.lock().map_err(|_| ownership_error())?;
        let result = clear_owned(&mut state);
        changed.notify_all();
        result
    }
    pub fn take_clear_result(&self) -> Option<Result<(), symvault_core::platform::PlatformError>> {
        self.shared.0.lock().ok()?.cleared.take()
    }
    /// A cloneable handle for a process signal thread. It shares the owner's
    /// state, so a signal cannot race an older timer or a newer copy.
    pub fn handle(&self) -> OwnedClipboardHandle {
        OwnedClipboardHandle {
            shared: self.shared.clone(),
        }
    }
}

/// Signal-side view of an [`OwnedTextClipboard`].
#[derive(Clone)]
pub struct OwnedClipboardHandle {
    shared: Arc<(std::sync::Mutex<ClipboardState>, std::sync::Condvar)>,
}
impl OwnedClipboardHandle {
    /// Go's `StartAutoClear` subscription is live exactly while a copy waits on
    /// its timer (a positive duration). Such a subscription clears on SIGHUP and
    /// the program keeps running. The result is reported like an expiry.
    pub fn clear_if_armed(&self) -> bool {
        let (lock, changed) = &*self.shared;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !(state.active && state.deadline.is_some()) {
            return false;
        }
        let result = clear_owned(&mut state);
        state.cleared = Some(result);
        changed.notify_all();
        true
    }
    /// Clears a still-held copy (armed or kept until quit) on a path that ends
    /// the process (SIGINT/SIGTERM stop, SIGHUP/SIGQUIT death). The owner is
    /// marked as stopping under the same lock, so a `copy` racing on another
    /// thread either finished before this clear or is refused afterwards: no
    /// new secret can land behind the clear. Never call this on a path that
    /// keeps running (the armed-SIGHUP clear uses [`Self::clear_if_armed`]).
    /// A failed clear is reported on stderr, as nobody polls the result.
    pub fn clear_before_exit(&self) {
        let (lock, changed) = &*self.shared;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.stopping = true;
        if let Err(error) = clear_owned(&mut state) {
            report_clear_failure(&error);
        }
        changed.notify_all();
    }
}

/// How long a failed clear waits before the worker retries it.
#[cfg(not(test))]
const CLEAR_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const CLEAR_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(30);

/// Clears the backend if a copy is held. A failing clear keeps the copy marked
/// as held and schedules a retry (the timer must not silently end with the
/// secret still on the clipboard); the caller gets the error to surface.
fn clear_owned(state: &mut ClipboardState) -> Result<(), symvault_core::platform::PlatformError> {
    if !state.active {
        state.deadline = None;
        return Ok(());
    }
    match state.backend.clear() {
        Ok(()) => {
            state.active = false;
            state.deadline = None;
            Ok(())
        }
        Err(error) => {
            state.deadline = std::time::Instant::now().checked_add(CLEAR_RETRY_INTERVAL);
            Err(error)
        }
    }
}

/// Paths without a UI left to show the result (worker shutdown, signal exit).
fn report_clear_failure(error: &symvault_core::platform::PlatformError) {
    use std::io::Write;
    // A closed stderr must not stop the shutdown.
    let _ = writeln!(
        std::io::stderr(),
        "warning: clipboard clear failed: {}",
        error.message
    );
}
impl Drop for OwnedTextClipboard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.0.lock() {
            state.stopping = true;
            self.shared.1.notify_all();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn ownership_error() -> symvault_core::platform::PlatformError {
    symvault_core::platform::PlatformError {
        kind: symvault_core::platform::PlatformErrorKind::Failed,
        message: "clipboard ownership unavailable".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Duration;
    use symvault_core::platform::{PlatformError, PlatformErrorKind};

    #[derive(Default)]
    struct Recording {
        /// "set:<text>" / "clear" in backend order.
        events: Mutex<Vec<String>>,
        fail_clears: AtomicUsize,
        clear_entered: Mutex<Option<mpsc::Sender<()>>>,
        clear_delay: Mutex<Duration>,
    }
    impl Recording {
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }
    impl Clipboard for Recording {
        fn set(&self, text: &[u8]) -> Result<(), PlatformError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("set:{}", String::from_utf8_lossy(text)));
            Ok(())
        }
        fn clear(&self) -> Result<(), PlatformError> {
            if let Some(entered) = self.clear_entered.lock().unwrap().as_ref() {
                let _ = entered.send(());
            }
            std::thread::sleep(*self.clear_delay.lock().unwrap());
            self.events.lock().unwrap().push("clear".into());
            if self
                .fail_clears
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(PlatformError {
                    kind: PlatformErrorKind::Failed,
                    message: "clear boom".into(),
                });
            }
            Ok(())
        }
    }

    fn wait_for(what: &str, condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A `copy` racing the death-path clear on another thread must not leave a
    /// new secret behind: it either lands before the clear (and is cleared) or
    /// is refused after it.
    #[test]
    fn clear_before_exit_refuses_a_racing_copy() {
        let backend = Arc::new(Recording::default());
        let (entered, clearing) = mpsc::channel();
        *backend.clear_entered.lock().unwrap() = Some(entered);
        *backend.clear_delay.lock().unwrap() = Duration::from_millis(200);
        let owner = OwnedTextClipboard::new(backend.clone()).unwrap();
        owner.copy(b"first", Duration::from_secs(60)).unwrap();
        let handle = owner.handle();
        let signal = std::thread::spawn(move || handle.clear_before_exit());
        // The clear holds the state lock; the racing copy queues behind it.
        clearing.recv_timeout(Duration::from_secs(10)).unwrap();
        let racing = owner.copy(b"second", Duration::from_secs(60));
        signal.join().unwrap();
        assert!(
            racing.is_err(),
            "a copy after the death-path clear is refused"
        );
        assert_eq!(backend.events(), ["set:first", "clear"]);
        assert!(owner.copy(b"third", Duration::ZERO).is_err());
        assert_eq!(
            backend.events(),
            ["set:first", "clear"],
            "no secret behind the clear"
        );
    }

    /// The armed-SIGHUP path keeps the program running, so it must not stop the
    /// owner: a later copy works and is armed again.
    #[test]
    fn clear_if_armed_keeps_the_owner_running() {
        let backend = Arc::new(Recording::default());
        let owner = OwnedTextClipboard::new(backend.clone()).unwrap();
        let handle = owner.handle();
        owner.copy(b"first", Duration::from_secs(60)).unwrap();
        assert!(handle.clear_if_armed());
        owner.copy(b"second", Duration::from_secs(60)).unwrap();
        assert!(handle.clear_if_armed());
        assert_eq!(
            backend.events(),
            ["set:first", "clear", "set:second", "clear"]
        );
    }

    /// A failed clear keeps the copy held and retries instead of dropping the
    /// deadline, and the failure is surfaced through the result channel.
    #[test]
    fn failed_expiry_clear_is_retried_and_surfaced() {
        let backend = Arc::new(Recording::default());
        backend.fail_clears.store(2, Ordering::SeqCst);
        let owner = OwnedTextClipboard::new(backend.clone()).unwrap();
        owner.copy(b"secret", Duration::from_millis(10)).unwrap();
        wait_for(
            "failure surfaced",
            || matches!(owner.take_clear_result(), Some(Err(e)) if e.message == "clear boom"),
        );
        // Two failures, then the third attempt succeeds without any new copy.
        wait_for("retried until cleared", || {
            backend.events().iter().filter(|e| *e == "clear").count() >= 3
        });
        wait_for("success surfaced", || {
            matches!(owner.take_clear_result(), Some(Ok(())))
        });
        assert!(!owner.handle().clear_if_armed(), "nothing left to clear");
        let clears = backend.events().iter().filter(|e| *e == "clear").count();
        std::thread::sleep(CLEAR_RETRY_INTERVAL * 3);
        assert_eq!(
            backend.events().iter().filter(|e| *e == "clear").count(),
            clears,
            "retries stop after the clear succeeded"
        );
    }

    #[test]
    fn failed_explicit_clear_keeps_the_copy_and_schedules_a_retry() {
        let backend = Arc::new(Recording::default());
        backend.fail_clears.store(1, Ordering::SeqCst);
        let owner = OwnedTextClipboard::new(backend.clone()).unwrap();
        // No timer at all: the retry deadline is the only thing that can save it.
        owner.copy(b"secret", Duration::ZERO).unwrap();
        assert_eq!(owner.clear().unwrap_err().message, "clear boom");
        wait_for("retry", || {
            backend.events().iter().filter(|e| *e == "clear").count() >= 2
        });
        wait_for("held copy released", || {
            !owner.shared.0.lock().unwrap().active
        });
    }

    #[test]
    fn stopping_flag_is_set_only_by_the_death_path() {
        let backend = Arc::new(Recording::default());
        let owner = OwnedTextClipboard::new(backend).unwrap();
        owner.handle().clear_before_exit();
        assert!(owner.shared.0.lock().unwrap().stopping);
    }
}
