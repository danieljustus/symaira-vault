//! Offline intake watch management commands.

use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
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
    let plist = launch_agent_plist_path(&home);
    let plist_display = if home.is_empty() {
        "/Library/LaunchAgents/com.symaira.vault-intake.plist".to_owned()
    } else {
        plist.display().to_string()
    };
    if matches!(
        fs::metadata(&plist),
        Err(ref error) if error.kind() == io::ErrorKind::NotFound
    ) {
        if !quiet {
            println!(
                "No intake LaunchAgent found at {} — nothing to disable.",
                plist_display
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
        println!("Removed intake LaunchAgent {plist_display}");
    }
    Ok(())
}

fn launch_agent_plist_path(home: &OsStr) -> PathBuf {
    if home.is_empty() {
        Path::new("/").join("Library/LaunchAgents/com.symaira.vault-intake.plist")
    } else {
        PathBuf::from(home).join("Library/LaunchAgents/com.symaira.vault-intake.plist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_home_does_not_resolve_launch_agent_under_working_directory() {
        let working_directory = tempfile::tempdir().expect("temporary working directory");
        let relative_plist = working_directory
            .path()
            .join("Library/LaunchAgents/com.symaira.vault-intake.plist");
        fs::create_dir_all(relative_plist.parent().expect("plist parent"))
            .expect("create relative LaunchAgents");
        fs::write(&relative_plist, b"untouched").expect("seed relative plist");

        let resolved = launch_agent_plist_path(OsStr::new(""));
        assert_eq!(
            resolved,
            Path::new("/Library/LaunchAgents/com.symaira.vault-intake.plist")
        );
        assert!(resolved.has_root());
        assert_eq!(
            fs::read(relative_plist).expect("relative plist remains"),
            b"untouched"
        );
    }
}
