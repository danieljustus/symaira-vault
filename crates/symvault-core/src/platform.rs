//! Side-effecting platform contracts. Implementations are injected by callers;
//! the core crate never shells out, touches a clipboard, or shows UI itself.
use std::{error::Error, fmt, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformErrorKind {
    Unavailable,
    Canceled,
    TimedOut,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformError {
    pub kind: PlatformErrorKind,
    pub message: String,
}
impl PlatformError {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: PlatformErrorKind::Unavailable,
            message: message.into(),
        }
    }
}
impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl Error for PlatformError {}

/// Autotype is deliberately one operation: the adapter owns focus, timing,
/// cancellation, and any platform permission prompts.
pub trait Autotype: Send + Sync {
    fn type_text(&self, text: &str) -> Result<(), PlatformError>;
}
pub trait Clipboard: Send + Sync {
    fn set(&self, text: &[u8]) -> Result<(), PlatformError>;
    fn clear(&self) -> Result<(), PlatformError>;
}
pub trait Notifier: Send + Sync {
    fn notify(&self, title: &str, message: &str) -> Result<(), PlatformError>;
}
pub trait SecureUi: Send + Sync {
    fn prompt(
        &self,
        title: &str,
        hidden: bool,
        timeout: Duration,
    ) -> Result<Vec<u8>, PlatformError>;
    fn approve(&self, operation: &str, timeout: Duration) -> Result<bool, PlatformError>;
}
/// Biometric authentication is an authorization boundary. Implementations
/// return only the decision and never expose a passphrase or key material.
pub trait TouchId: Send + Sync {
    fn is_available(&self) -> bool;
    fn authenticate(&self, reason: &str, timeout: Duration) -> Result<(), PlatformError>;
}
pub trait Daemon: Send + Sync {
    fn install(&self) -> Result<(), PlatformError>;
    fn uninstall(&self) -> Result<(), PlatformError>;
    fn status(&self) -> Result<bool, PlatformError>;
}

/// Native slots are explicit and safe: until an OS adapter is linked, calls
/// fail closed rather than pretending that a side effect succeeded.
#[derive(Default)]
pub struct UnavailablePlatform;
impl Autotype for UnavailablePlatform {
    fn type_text(&self, _: &str) -> Result<(), PlatformError> {
        Err(PlatformError::unavailable("autotype backend unavailable"))
    }
}
impl Clipboard for UnavailablePlatform {
    fn set(&self, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::unavailable("clipboard backend unavailable"))
    }
    fn clear(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
impl Notifier for UnavailablePlatform {
    fn notify(&self, _: &str, _: &str) -> Result<(), PlatformError> {
        Err(PlatformError::unavailable(
            "notification backend unavailable",
        ))
    }
}
impl SecureUi for UnavailablePlatform {
    fn prompt(&self, _: &str, _: bool, _: Duration) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::unavailable("secure UI backend unavailable"))
    }
    fn approve(&self, _: &str, _: Duration) -> Result<bool, PlatformError> {
        Err(PlatformError::unavailable("secure UI backend unavailable"))
    }
}
impl TouchId for UnavailablePlatform {
    fn is_available(&self) -> bool {
        false
    }
    fn authenticate(&self, _: &str, _: Duration) -> Result<(), PlatformError> {
        Err(PlatformError::unavailable("touch id backend unavailable"))
    }
}
impl Daemon for UnavailablePlatform {
    fn install(&self) -> Result<(), PlatformError> {
        Err(PlatformError::unavailable("daemon backend unavailable"))
    }
    fn uninstall(&self) -> Result<(), PlatformError> {
        Err(PlatformError::unavailable("daemon backend unavailable"))
    }
    fn status(&self) -> Result<bool, PlatformError> {
        Err(PlatformError::unavailable("daemon backend unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_native_fails_closed() {
        let p = UnavailablePlatform;
        assert_eq!(
            p.type_text("secret").unwrap_err().kind,
            PlatformErrorKind::Unavailable
        );
        assert!(p.clear().is_ok());
        assert!(p.prompt("x", true, Duration::from_secs(1)).is_err());
    }
}
