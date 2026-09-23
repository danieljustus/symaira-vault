//! Offline intake watch management commands.

use std::{
    fs, io,
    path::PathBuf,
    process::{Command, Stdio},
};

pub(crate) enum WatchDisableError {
    UnsupportedPlatform,
    Remove(io::Error),
}

impl std::fmt::Display for WatchDisableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                f.write_str("LaunchAgent disable is only supported on macOS")
            }
            Self::Remove(error) => write!(f, "remove LaunchAgent plist: {error}"),
        }
    }
}

pub(crate) fn watch_disable(quiet: bool) -> Result<(), WatchDisableError> {
    let home = std::env::var_os("HOME").unwrap_or_default();
    let plist = PathBuf::from(home).join("Library/LaunchAgents/com.symaira.vault-intake.plist");
    if matches!(
        fs::metadata(&plist),
        Err(ref error) if error.kind() == io::ErrorKind::NotFound
    ) {
        if !quiet {
            println!(
                "No intake LaunchAgent found at {} — nothing to disable.",
                plist.display()
            );
        }
        return Ok(());
    }
    if !cfg!(target_os = "macos") {
        return Err(WatchDisableError::UnsupportedPlatform);
    }

    let _ = Command::new("/bin/launchctl")
        .arg("unload")
        .arg(&plist)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    fs::remove_file(&plist).map_err(WatchDisableError::Remove)?;
    if !quiet {
        println!("Removed intake LaunchAgent {}", plist.display());
    }
    Ok(())
}
