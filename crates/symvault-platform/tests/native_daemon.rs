#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

//! Opt-in launchd lifecycle on a disposable CI runner, never a user's domain.
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use symvault_core::platform::Daemon;
use symvault_platform::MacOsDaemon;

struct Cleanup {
    home: PathBuf,
    daemon: MacOsDaemon,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.daemon.plist_path().exists() {
            let _ = self.daemon.uninstall();
        }
        let _ = fs::remove_dir_all(&self.home);
    }
}

#[test]
#[ignore = "requires explicit disposable-runner authorization; changes launchd state"]
fn native_daemon_private_home_lifecycle_attempt() {
    assert_eq!(
        std::env::var("SYMVAULT_DISPOSABLE_NATIVE_RUNNER").as_deref(),
        Ok("1"),
        "never run this lifecycle in a real user launchd domain"
    );
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    let existing = Command::new("/bin/launchctl")
        .args(["list", "com.symvault.mcp"])
        .output()
        .expect("query launchd");
    assert!(
        !existing.status.success(),
        "refusing to replace an existing launch agent"
    );
    let home = std::env::temp_dir().join(format!(
        "symvault-native-daemon-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let vault = home.join("vault");
    fs::create_dir_all(&vault).unwrap();
    let cleanup = Cleanup {
        daemon: MacOsDaemon::with_home(&home, "/usr/bin/true", &vault, "127.0.0.1", 8787),
        home,
    };
    let daemon = &cleanup.daemon;
    assert!(!daemon.plist_path().exists());
    daemon
        .install()
        .expect("native launchd install must succeed");
    assert!(daemon.plist_path().is_file());
    assert!(daemon.status().expect("native launchd status"));
    daemon.uninstall().expect("native launchd uninstall");
    assert!(!daemon.plist_path().exists());
    assert!(!daemon.status().expect("native launchd removed status"));
}
