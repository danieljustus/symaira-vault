//! Owned native text clipboard, initialized only by an explicit UI caller.
use std::sync::Arc;
use symvault_core::platform::Clipboard;
#[cfg(not(target_os = "macos"))]
use symvault_core::platform::UnavailablePlatform;

pub fn native_text_clipboard() -> Arc<dyn Clipboard> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(crate::MacOsPlatform)
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        match arboard::Clipboard::new() {
            Ok(backend) => Arc::new(NativeTextClipboard(std::sync::Mutex::new(backend))),
            Err(_) => Arc::new(UnavailablePlatform),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Arc::new(UnavailablePlatform)
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct NativeTextClipboard(std::sync::Mutex<arboard::Clipboard>);

#[cfg(any(target_os = "linux", target_os = "windows"))]
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

#[cfg(any(target_os = "linux", target_os = "windows"))]
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
                        let _ = clear_owned(&mut state);
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
}
fn clear_owned(state: &mut ClipboardState) -> Result<(), symvault_core::platform::PlatformError> {
    state.deadline = None;
    if !state.active {
        return Ok(());
    }
    state.backend.clear()?;
    state.active = false;
    Ok(())
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
