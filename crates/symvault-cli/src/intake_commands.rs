//! Offline intake watch commands.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{require_initialized, resolve_vault};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use symvault_crypto::Identity;
use symvault_store::{AttachmentInfo, Entry, Store};
use symvault_sync::{
    GoTime,
    intake::{FileResult, Options, Provenance, QuarantineSink, ScanResult, Spool, Watcher},
};

pub(crate) fn intake_files(
    paths: &[PathBuf],
    dry_run: bool,
    batch_limit: i64,
    max_files: i64,
    move_to_trash: bool,
    ocr_text: Option<&Path>,
    json: bool,
    quiet: bool,
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
) -> Result<(), (u8, String)> {
    if paths.is_empty() {
        return Err((9, "intake: no input files".into()));
    }
    if move_to_trash && !cfg!(target_os = "macos") {
        return Err((9, "--move-to-trash is only supported on macOS".into()));
    }
    if move_to_trash {
        return Err((
            9,
            "--move-to-trash is not supported by the Rust CLI yet".into(),
        ));
    }
    let spool = Spool::new(std::env::temp_dir()).map_err(|error| (1, error.to_string()))?;
    let options = Options {
        max_batch_size: if batch_limit <= 0 {
            32 << 20
        } else {
            batch_limit as u64
        },
        max_files: if max_files <= 0 {
            100
        } else {
            max_files as usize
        },
        ocr_text: ocr_text.map(Path::to_path_buf),
        ..Options::default()
    };
    let results = symvault_sync::intake::process_files(&spool, paths, &options)
        .map_err(|error| (9, format!("intake: {error}")))?;
    if dry_run {
        return render_parent_output(&results, "", true, json, quiet).map_err(|error| (1, error));
    }
    let staged = results
        .iter()
        .filter(|result| result.status == "ok")
        .cloned()
        .collect::<Vec<_>>();
    let scan = ScanResult {
        scanned: results.len(),
        staged: Some(
            staged
                .iter()
                .filter_map(|r| r.spool_path.as_ref().map(|p| p.display().to_string()))
                .collect(),
        ),
        staged_results: staged,
        ..ScanResult::default()
    };
    let vault = resolve_vault(explicit_vault, profile).map_err(|error| (1, error))?;
    require_initialized(&vault).map_err(|error| (1, error))?;
    let identity = crate::device::unlock_vault(&vault).map_err(|error| (1, error))?;
    let store = Store::open(&vault, &identity)
        .map_err(|error| (1, format!("cannot open vault: {error}")))?;
    let (import_id, _) =
        write_batch(&store, &identity, &scan).map_err(|error| (1, error.to_string()))?;
    render_parent_output(&results, &import_id, false, json, quiet).map_err(|error| (1, error))
}

fn render_parent_output(
    results: &[FileResult],
    import_id: &str,
    dry_run: bool,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    if json {
        let mut value = serde_json::Map::new();
        if !import_id.is_empty() {
            value.insert("import_id".into(), serde_json::json!(import_id));
        }
        value.insert(
            "results".into(),
            serde_json::to_value(results).map_err(|error| error.to_string())?,
        );
        serde_json::to_writer_pretty(io::stdout().lock(), &value)
            .map_err(|error| format!("encode intake output: {error}"))?;
        println!();
        return Ok(());
    }
    if quiet {
        return if !dry_run && !results.iter().any(|result| result.status == "ok") {
            Err("no files were accepted for intake".into())
        } else {
            Ok(())
        };
    }
    let mut ok = 0;
    for result in results {
        match result.status.as_str() {
            "ok" => {
                ok += 1;
                let provenance = result
                    .provenance
                    .as_ref()
                    .expect("successful intake provenance");
                println!(
                    "OK    {}  ({}, {} bytes, sha256 {})",
                    result.file,
                    source_type_name(provenance),
                    provenance.size,
                    &provenance.sha256[..provenance.sha256.len().min(12)]
                );
                for suggestion in &result.suggestions {
                    let label = if suggestion.attachment {
                        "attachment"
                    } else {
                        "field"
                    };
                    let warning = suggestion
                        .warning
                        .as_deref()
                        .map_or(String::new(), |message| format!("  [!] {message}"));
                    println!(
                        "      → {label}: {} (conf {:.2}){warning}",
                        suggestion.field, suggestion.confidence
                    );
                }
            }
            "skipped" => println!(
                "SKIP  {}  {}",
                result.file,
                result.reason.as_deref().unwrap_or_default()
            ),
            _ => println!(
                "ERROR {}  {}",
                result.file,
                result.reason.as_deref().unwrap_or_default()
            ),
        }
    }
    if dry_run {
        println!(
            "Dry run: {} file(s) processed, nothing written.",
            results.len()
        );
    } else if ok == 0 {
        return Err("no files were accepted for intake".into());
    } else {
        println!("Quarantine import ID: {import_id}");
        println!("Review and promote with: symvault import review promote {import_id}");
    }
    Ok(())
}

fn source_type_name(provenance: &Provenance) -> &'static str {
    match provenance.source_type {
        symvault_sync::intake::SourceType::Text => "text",
        symvault_sync::intake::SourceType::Env => "env",
        symvault_sync::intake::SourceType::Json => "json",
        symvault_sync::intake::SourceType::Certificate => "certificate",
        symvault_sync::intake::SourceType::Key => "key",
        symvault_sync::intake::SourceType::Image => "image",
        symvault_sync::intake::SourceType::Pdf => "pdf",
        symvault_sync::intake::SourceType::Archive => "archive",
        symvault_sync::intake::SourceType::Other => "other",
    }
}

pub(crate) enum WatchOnceError {
    InvalidDirectory(String),
    Scan(symvault_sync::intake::IntakeError),
    Vault(String),
    Batch(String),
    Signal(io::Error),
    Output(io::Error),
}

impl std::fmt::Display for WatchOnceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDirectory(message) => write!(f, "watch: {message}"),
            Self::Scan(error) => write!(f, "scan: {error}"),
            Self::Vault(error) => write!(f, "open vault for intake batch: {error}"),
            Self::Batch(error) => write!(f, "write intake batch: {error}"),
            Self::Signal(error) => write!(f, "watch signal handler: {error}"),
            Self::Output(error) => write!(f, "write scan output: {error}"),
        }
    }
}

fn make_watcher(dir: &Path, debounce: Duration) -> Result<(Watcher, Spool), WatchOnceError> {
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
    let options = Options {
        debounce: if debounce.is_zero() {
            Duration::from_secs(5)
        } else {
            debounce
        },
        ..Options::default()
    };
    let watcher = Watcher::new(dir, options).map_err(WatchOnceError::Scan)?;
    let spool = Spool::new(std::env::temp_dir()).map_err(WatchOnceError::Scan)?;
    Ok((watcher, spool))
}

pub(crate) fn watch_once(
    dir: &Path,
    interval: Duration,
    debounce: Duration,
    json: bool,
    quiet: bool,
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
) -> Result<(), WatchOnceError> {
    let _interval = interval; // Poll intervals do not affect a single scan.
    let (mut watcher, spool) = make_watcher(dir, debounce)?;
    let result = watcher.scan_result(&spool).map_err(WatchOnceError::Scan)?;
    let scan_output = scan_summary(&result, json, quiet)?;
    let batch_output = if result.staged_results.is_empty() {
        None
    } else {
        let vault = resolve_vault(explicit_vault, profile).map_err(WatchOnceError::Vault)?;
        require_initialized(&vault).map_err(WatchOnceError::Vault)?;
        let identity = crate::device::unlock_vault(&vault).map_err(WatchOnceError::Vault)?;
        let store = Store::open(&vault, &identity)
            .map_err(|error| WatchOnceError::Vault(format!("cannot open vault: {error}")))?;
        let (import_id, written) = write_batch(&store, &identity, &result)?;
        Some(render_batch_output(&import_id, &written, json, quiet)?)
    };

    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&scan_output)
        .map_err(WatchOnceError::Output)?;
    if let Some(output) = batch_output {
        stdout.write_all(&output).map_err(WatchOnceError::Output)?;
    }
    Ok(())
}

pub(crate) fn watch_continuous(
    dir: &Path,
    interval: Duration,
    debounce: Duration,
    json: bool,
    quiet: bool,
    explicit_vault: Option<&Path>,
    profile: Option<&str>,
) -> Result<(), WatchOnceError> {
    let (mut watcher, spool) = make_watcher(dir, debounce)?;
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))
        .map_err(WatchOnceError::Signal)?;
    #[cfg(unix)]
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))
        .map_err(WatchOnceError::Signal)?;

    if !quiet {
        let mut stdout = io::stdout().lock();
        writeln!(
            stdout,
            "Watching {} (interval {:?}, debounce {:?}). Ctrl-C to stop.",
            dir.display(),
            interval,
            debounce
        )
        .and_then(|()| stdout.flush())
        .map_err(WatchOnceError::Output)?;
    }

    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let result = watcher.scan_result(&spool).map_err(WatchOnceError::Scan)?;
        if !result.staged_results.is_empty() {
            let vault = resolve_vault(explicit_vault, profile).map_err(WatchOnceError::Vault)?;
            require_initialized(&vault).map_err(WatchOnceError::Vault)?;
            let identity = crate::device::unlock_vault(&vault).map_err(WatchOnceError::Vault)?;
            let store = Store::open(&vault, &identity)
                .map_err(|error| WatchOnceError::Vault(format!("cannot open vault: {error}")))?;
            let (import_id, written) = write_batch(&store, &identity, &result)?;
            let output = render_batch_output(&import_id, &written, json, quiet)?;
            let mut stdout = io::stdout().lock();
            stdout.write_all(&output).map_err(WatchOnceError::Output)?;
            stdout.flush().map_err(WatchOnceError::Output)?;
        }
        if wait_for_interval(&stop, interval) {
            break;
        }
    }
    Ok(())
}

fn wait_for_interval(stop: &AtomicBool, interval: Duration) -> bool {
    let started = Instant::now();
    loop {
        if stop.load(Ordering::Acquire) {
            return true;
        }
        let elapsed = started.elapsed();
        if elapsed >= interval {
            return false;
        }
        thread::sleep((interval - elapsed).min(Duration::from_millis(50)));
    }
}

fn scan_summary(result: &ScanResult, json: bool, quiet: bool) -> Result<Vec<u8>, WatchOnceError> {
    let mut output = Vec::new();
    if json {
        serde_json::to_writer(&mut output, result)
            .map_err(|error| WatchOnceError::Output(io::Error::other(error)))?;
        output.push(b'\n');
        return Ok(output);
    }
    if quiet {
        return Ok(output);
    }
    writeln!(
        output,
        "Scanned {} candidate(s), staged {}, skipped {}, errors {}",
        result.scanned,
        result.staged.as_ref().map_or(0, Vec::len),
        result.skipped.len(),
        result.errors.len()
    )
    .map_err(WatchOnceError::Output)?;
    for skipped in &result.skipped {
        writeln!(output, "  skip: {skipped}").map_err(WatchOnceError::Output)?;
    }
    for error in &result.errors {
        writeln!(output, "  error: {error}").map_err(WatchOnceError::Output)?;
    }
    Ok(output)
}

fn write_batch(
    store: &Store,
    identity: &Identity,
    result: &ScanResult,
) -> Result<(String, Vec<String>), WatchOnceError> {
    let existing_paths = store
        .list(identity)
        .map_err(|error| WatchOnceError::Batch(format!("list quarantine entries: {error}")))?;
    let mut staged = Vec::with_capacity(result.staged_results.len());
    for file in &result.staged_results {
        let spool_path = file
            .spool_path
            .as_deref()
            .ok_or_else(|| WatchOnceError::Batch("staged file has no spool path".into()))?;
        let bytes = fs::read(spool_path).map_err(|error| {
            WatchOnceError::Batch(format!("read staged copy for {:?}: {error}", file.file))
        })?;
        let expected_hash = file
            .provenance
            .as_ref()
            .map(|provenance| provenance.sha256.as_str())
            .ok_or_else(|| WatchOnceError::Batch("staged file has no provenance".into()))?;
        if sha256(&bytes) != expected_hash {
            return Err(WatchOnceError::Batch(format!(
                "staged copy hash mismatch for {:?} before write",
                file.file
            )));
        }
        staged.push((file.clone(), bytes));
    }

    let mut random = [0u8; 4];
    let random_id = if getrandom::fill(&mut random).is_ok() {
        format!("{:08x}", u32::from_be_bytes(random))
    } else {
        format!(
            "{:08x}",
            (time::OffsetDateTime::now_utc().unix_timestamp_nanos() as u64) as u32
        )
    };
    let date = time::OffsetDateTime::now_utc()
        .format(&time::format_description::parse("[year][month][day]").expect("fixed format"))
        .expect("format current date");
    let import_id = format!("intake-{date}-{random_id}");
    let mut sink = StoreQuarantineSink {
        store,
        identity,
        existing_paths: existing_paths
            .into_iter()
            .filter(|path| path.starts_with("quarantine/"))
            .collect(),
    };
    let written = symvault_sync::intake::quarantine(&mut sink, &staged, &import_id, false)
        .map_err(|error| WatchOnceError::Batch(error.to_string()))?;
    Ok((import_id, written))
}

struct StoreQuarantineSink<'a> {
    store: &'a Store,
    identity: &'a Identity,
    existing_paths: Vec<String>,
}

impl QuarantineSink for StoreQuarantineSink<'_> {
    fn write(
        &mut self,
        path: &str,
        fields: &BTreeMap<String, String>,
        attachment: &[u8],
        provenance: &Provenance,
    ) -> io::Result<()> {
        let mut entry = Entry::default();
        entry.data.extend(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone()))),
        );
        entry.data.insert(
            symvault_sync::intake::ATTACHMENT_FIELD.into(),
            serde_json::Value::String(STANDARD.encode(attachment)),
        );
        entry.secret_metadata.attachments.insert(
            symvault_sync::intake::ATTACHMENT_FIELD.into(),
            AttachmentInfo {
                filename: provenance.source_name.clone(),
                size: i64::try_from(provenance.size).map_err(io::Error::other)?,
                sha256: provenance.sha256.clone(),
            },
        );
        let created = GoTime::now().to_rfc3339_nano();
        entry.metadata.created = created.clone();
        entry.metadata.updated = created;
        entry.metadata.version = 1;
        let now = GoTime::now().to_rfc3339_nano();
        let entry = symvault_store::metadata::prepare_entry(
            &entry,
            &now,
            path,
            self.store.config().pseudonymize_paths,
            None,
        )
        .map_err(io::Error::other)?;
        self.store
            .write_new_entry(path, &entry, self.identity)
            .map_err(io::Error::other)?;
        if let Ok(stored_path) = self.store.configured_entry_path(path, self.identity)
            && let Ok(Some(ciphertext)) = symvault_sync::safeio::read(&stored_path)
        {
            let _ = self
                .store
                .update_manifest_entry(path, &ciphertext, self.identity);
        }
        crate::write_commands::auto_commit(self.store, self.identity, path, "Update");
        self.existing_paths.push(path.to_owned());
        Ok(())
    }

    fn contains_hash(&self, hash: &str) -> bool {
        self.existing_paths.iter().any(|path| {
            self.store
                .get(path, self.identity)
                .ok()
                .is_some_and(|entry| {
                    entry
                        .secret_metadata
                        .attachments
                        .values()
                        .any(|attachment| attachment.sha256 == hash)
                })
        })
    }

    fn contains_path(&self, path: &str) -> bool {
        self.existing_paths.iter().any(|existing| existing == path)
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn render_batch_output(
    import_id: &str,
    written: &[String],
    json: bool,
    quiet: bool,
) -> Result<Vec<u8>, WatchOnceError> {
    let mut output = Vec::new();
    if json {
        let value = if written.is_empty() {
            serde_json::json!({"import_id": null, "written": 0})
        } else {
            serde_json::json!({"import_id": import_id, "written": written})
        };
        serde_json::to_writer(&mut output, &value)
            .map_err(|error| WatchOnceError::Output(io::Error::other(error)))?;
        output.push(b'\n');
    } else if !quiet {
        if written.is_empty() {
            writeln!(output, "No new files to stage.").map_err(WatchOnceError::Output)?;
        } else {
            writeln!(
                output,
                "Staged batch {import_id} ({} entries)",
                written.len()
            )
            .map_err(WatchOnceError::Output)?;
            writeln!(
                output,
                "Review with: symvault import review promote {import_id}"
            )
            .map_err(WatchOnceError::Output)?;
        }
    }
    Ok(output)
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
