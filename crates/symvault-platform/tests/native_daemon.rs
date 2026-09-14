#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

//! Explicit native launchd attempt against a disposable home tree.
//! This test is ignored because `launchctl load` is an external user-session
//! side effect even though the plist and vault paths are temporary.
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use symvault_core::platform::Daemon;
use symvault_platform::MacOsDaemon;

struct TempHome(PathBuf);
impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "runs an explicit launchctl attempt using only temporary paths"]
fn native_daemon_private_home_lifecycle_attempt() {
    let home = std::env::temp_dir().join(format!(
        "symvault-native-daemon-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos()
    ));
    let _home = TempHome(home.clone());
    let vault = home.join("vault");
    fs::create_dir_all(&vault).expect("create disposable vault root");
    let daemon = MacOsDaemon::with_home(&home, "/usr/bin/true", &vault, "127.0.0.1", 8787);
    assert!(!daemon.plist_path().exists());

    let install = daemon.install();
    eprintln!("native launchd install outcome: {install:?}");
    if install.is_ok() {
        assert!(daemon.plist_path().is_file());
        let status = daemon.status().expect("query installed launch agent");
        eprintln!("native launchd status outcome: {status}");
    }

    // Cleanup is required for both an unavailable launchd session and a
    // successful registration. It never touches the user's LaunchAgents path.
    daemon.uninstall().expect("remove disposable launch agent");
    assert!(!daemon.plist_path().exists());
}
