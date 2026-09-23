//! Offline intake watch commands.

use std::io::Write as _;
use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use symvault_sync::intake::{Options, ScanResult, Spool, Watcher};

pub(crate) enum WatchOnceError {
    InvalidDirectory(String),
    Scan(symvault_sync::intake::IntakeError),
    BatchWriterUnavailable,
    Output(io::Error),
}

impl std::fmt::Display for WatchOnceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDirectory(message) => write!(f, "watch: {message}"),
            Self::Scan(error) => write!(f, "scan: {error}"),
            Self::BatchWriterUnavailable => {
                f.write_str("intake watch --once cannot write quarantined batches: vault-backed batch writer is unavailable")
            }
            Self::Output(error) => write!(f, "write scan output: {error}"),
        }
    }
}

pub(crate) fn watch_once(
    dir: &Path,
    interval: Duration,
    debounce: Duration,
    json: bool,
    quiet: bool,
) -> Result<(), WatchOnceError> {
    let _interval = interval; // Poll intervals do not affect a single scan.
    match fs::metadata(dir) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(WatchOnceError::InvalidDirectory(format!(
                "watch path is not a directory: {}",
                dir.display()
            )));
        }
        Ok(_) => {}
        Err(error) => {
            return Err(WatchOnceError::InvalidDirectory(format!(
                "stat watch directory: {error}"
            )));
        }
    }
    let mut options = Options::default();
    options.debounce = if debounce.is_zero() {
        Duration::from_secs(5)
    } else {
        debounce
    };
    let mut watcher = Watcher::new(dir, options).map_err(WatchOnceError::Scan)?;
    let spool = Spool::new(std::env::temp_dir()).map_err(WatchOnceError::Scan)?;
    let result = watcher.scan_result(&spool).map_err(WatchOnceError::Scan)?;
    if json {
        let mut stdout = io::stdout().lock();
        serde_json::to_writer(&mut stdout, &result)
            .map_err(|e| WatchOnceError::Output(io::Error::other(e)))?;
        writeln!(stdout).map_err(WatchOnceError::Output)?;
    } else if !quiet {
        print_scan_summary(&result)?;
    }
    if !result.staged_results.is_empty() {
        // The intake backend can stage files, but the CLI has no vault-backed
        // quarantine writer yet. Do not claim the batch was saved.
        return Err(WatchOnceError::BatchWriterUnavailable);
    }
    Ok(())
}

fn print_scan_summary(result: &ScanResult) -> Result<(), WatchOnceError> {
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "Scanned {} candidate(s), staged {}, skipped {}, errors {}",
        result.scanned,
        result.staged.as_ref().map_or(0, Vec::len),
        result.skipped.len(),
        result.errors.len()
    )
    .map_err(WatchOnceError::Output)?;
    for skipped in &result.skipped {
        writeln!(stdout, "  skip: {skipped}").map_err(WatchOnceError::Output)?;
    }
    for error in &result.errors {
        writeln!(stdout, "  error: {error}").map_err(WatchOnceError::Output)?;
    }
    Ok(())
}

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
