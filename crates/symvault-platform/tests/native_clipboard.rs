#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

//! Opt-in clipboard round trip on an ephemeral CI runner.
use std::process::Command;
use symvault_core::platform::Clipboard;
use symvault_platform::MacOsPlatform;

struct ClearClipboard(MacOsPlatform);
impl Drop for ClearClipboard {
    fn drop(&mut self) {
        let _ = self.0.clear();
    }
}

#[test]
#[ignore = "requires explicit disposable-runner authorization; replaces runner clipboard contents"]
fn native_clipboard_set_read_clear() {
    assert_eq!(
        std::env::var("SYMVAULT_DISPOSABLE_NATIVE_RUNNER").as_deref(),
        Ok("1"),
        "never replace a real user's clipboard"
    );
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));

    let _cleanup = ClearClipboard(MacOsPlatform);
    let platform = MacOsPlatform;
    let payload = format!("symvault-native-clipboard-{}", std::process::id());
    platform.set(payload.as_bytes()).expect("pbcopy set");
    let readback = Command::new("/usr/bin/pbpaste")
        .output()
        .expect("pbpaste read");
    assert!(readback.status.success(), "pbpaste failed");
    assert_eq!(readback.stdout, payload.as_bytes());

    platform.clear().expect("pbcopy clear");
    let cleared = Command::new("/usr/bin/pbpaste")
        .output()
        .expect("pbpaste after clear");
    assert!(cleared.status.success(), "pbpaste after clear failed");
    assert!(cleared.stdout.is_empty(), "clipboard was not cleared");
}
