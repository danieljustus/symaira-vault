//! Offline intake watch management commands.

use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

pub(crate) fn watch_disable(quiet: bool) -> Result<(), String> {
    let home = std::env::var_os("HOME").unwrap_or_default();
    let plist = PathBuf::from(home).join("Library/LaunchAgents/com.symaira.vault-intake.plist");
    if !plist.exists() {
        if !quiet {
            println!(
                "No intake LaunchAgent found at {} — nothing to disable.",
                plist.display()
            );
        }
        return Ok(());
    }
    if !cfg!(target_os = "macos") {
        return Err("LaunchAgent disable is only supported on macOS".to_owned());
    }

    let _ = Command::new("/bin/launchctl")
        .arg("unload")
        .arg(&plist)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    fs::remove_file(&plist).map_err(|error| format!("remove LaunchAgent plist: {error}"))?;
    if !quiet {
        println!("Removed intake LaunchAgent {}", plist.display());
    }
    Ok(())
}
