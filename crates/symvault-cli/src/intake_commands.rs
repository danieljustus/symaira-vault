//! Polling intake CLI. Private spool ownership, encrypted quarantine and
//! process-local deduplication follow the production Go watcher.
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::mpsc,
    time::Duration,
};
use symvault_crypto::Identity;
use symvault_store::{AttachmentInfo, Entry, Store, StoreError};
use symvault_sync::{
    GoTime,
    intake::{self, FileResult, Options, Spool, Watcher},
};

type Error = (u8, String);
const PLIST: &str = "Library/LaunchAgents/com.symaira.vault-intake.plist";

pub fn finish(result: Result<(), Error>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            crate::print_error_like_go(&message);
            ExitCode::from(code)
        }
    }
}

pub fn disable(quiet: bool) -> Result<(), Error> {
    // Match Go's HOME-derived fixed path; no daemon is installed automatically.
    let path = PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(PLIST);
    if matches!(fs::metadata(&path), Err(e) if e.kind() == io::ErrorKind::NotFound) {
        if !quiet {
            println!(
                "No intake LaunchAgent found at {} — nothing to disable.",
                path.display()
            );
        }
        return Ok(());
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err((9, "LaunchAgent disable is only supported on macOS".into()))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/bin/launchctl")
            .arg("unload")
            .arg(&path)
            .output();
        fs::remove_file(&path).map_err(|e| (1, format!("remove LaunchAgent plist: {e}")))?;
        if !quiet {
            println!("Removed intake LaunchAgent {}", path.display());
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn watch(
    directory: Option<&Path>,
    interval: &str,
    debounce: &str,
    once: bool,
    json: bool,
    quiet: bool,
    mut unlock: impl FnMut() -> Result<(PathBuf, Identity), Error>,
) -> ExitCode {
    finish((|| {
        let directory = directory.ok_or_else(|| (1, "accepts 1 arg(s), received 0".into()))?;
        let interval_ns = symvault_core::config::parse_go_duration(interval).map_err(|e| {
            (
                9,
                format!("invalid argument {interval:?} for \"--interval\" flag: {e}"),
            )
        })?;
        let debounce_ns = symvault_core::config::parse_go_duration(debounce).map_err(|e| {
            (
                9,
                format!("invalid argument {debounce:?} for \"--debounce\" flag: {e}"),
            )
        })?;
        validate_directory(directory)?;
        let options = Options {
            interval: Duration::from_nanos(interval_ns.max(0) as u64),
            debounce: Duration::from_nanos(debounce_ns.max(0) as u64),
            ..Default::default()
        };
        let mut watcher =
            Watcher::new(directory, options).map_err(|e| (9, format!("watch: {e}")))?;
        let spool = Spool::new(std::env::temp_dir()).map_err(|e| (9, e.to_string()))?;
        if once {
            let scan = watcher
                .scan_result(&spool)
                .map_err(|e| (1, format!("scan: {e}")))?;
            // Go's --once --json reports staging only and does not open a vault.
            if json {
                serde_json::to_writer(io::stdout().lock(), &scan)
                    .map_err(|e| (1, e.to_string()))?;
                println!();
                return Ok(());
            }
            if !quiet {
                println!(
                    "Scanned {} candidate(s), staged {}, skipped {}, errors {}",
                    scan.scanned,
                    scan.staged.as_ref().map_or(0, Vec::len),
                    scan.skipped.len(),
                    scan.errors.len()
                );
                for s in scan.skipped {
                    println!("  skip: {s}");
                }
                for e in scan.errors {
                    println!("  error: {e}");
                }
            }
            if !scan.staged_results.is_empty() {
                let (root, identity) = unlock()?;
                stage_batch(&root, &identity, &scan.staged_results, json, quiet)?;
            }
            return Ok(());
        }
        let (sender, stop) = mpsc::channel();
        ctrlc::set_handler(move || {
            let _ = sender.send(());
        })
        .map_err(|e| (1, format!("register intake stop handler: {e}")))?;
        if !quiet {
            println!(
                "Watching {} (interval {}, debounce {}). Ctrl-C to stop.",
                directory.display(),
                signed_duration(interval_ns),
                signed_duration(debounce_ns)
            );
            io::stdout().flush().map_err(|e| (1, e.to_string()))?;
        }
        // Poll once even if the stop arrived before the first scan, like Go.
        loop {
            let scan = watcher
                .scan_result(&spool)
                .map_err(|e| (1, e.to_string()))?;
            if !scan.staged_results.is_empty() {
                let (root, identity) = unlock()?;
                stage_batch(&root, &identity, &scan.staged_results, json, quiet)?;
            }
            match stop.recv_timeout(watcher.options.interval) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    })())
}

fn validate_directory(path: &Path) -> Result<(), Error> {
    if path.as_os_str().is_empty() {
        return Err((9, "watch: watch directory is required".into()));
    }
    let meta = fs::metadata(path).map_err(|e| (9, format!("watch: stat watch directory: {e}")))?;
    if !meta.is_dir() {
        return Err((
            9,
            format!("watch: watch path is not a directory: {}", path.display()),
        ));
    }
    Ok(())
}

fn signed_duration(ns: i64) -> String {
    let rendered =
        symvault_platform::approval::format_go_duration(Duration::from_nanos(ns.unsigned_abs()));
    if ns < 0 {
        format!("-{rendered}")
    } else {
        rendered
    }
}

fn stage_batch(
    root: &Path,
    identity: &Identity,
    results: &[FileResult],
    json: bool,
    quiet: bool,
) -> Result<(), Error> {
    let store =
        Store::open_with_legacy_migration(root, identity).map_err(|e| (1, e.to_string()))?;
    let session = store.read_session(identity);
    let mut hashes = BTreeSet::new();
    for path in session
        .list()
        .map_err(|e| (1, e.to_string()))?
        .into_iter()
        .filter(|p| p.starts_with("quarantine/"))
    {
        match session.get(&path) {
            Ok(entry) => {
                for attachment in entry.secret_metadata.attachments.values() {
                    hashes.insert(attachment.sha256.clone());
                }
            }
            Err(e) if e.is_resource_failure() => return Err((1, e.to_string())),
            Err(_) => {} // Go skips unreadable existing entries for hash deduplication.
        }
    }
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).map_err(|e| (1, format!("generate intake batch id: {e}")))?;
    let day = time::OffsetDateTime::now_utc();
    let id = format!(
        "intake-{:04}{:02}{:02}-{}",
        day.year(),
        u8::from(day.month()),
        day.day(),
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let mut written = Vec::new();
    for result in results {
        if result.status != "ok" {
            continue;
        }
        let Some(provenance) = &result.provenance else {
            continue;
        };
        let Some(staged) = &result.spool_path else {
            continue;
        };
        let bytes = fs::read(staged)
            .map_err(|e| (1, format!("read staged copy for {:?}: {e}", result.file)))?;
        let hash = format!("{:x}", Sha256::digest(&bytes));
        if hash != provenance.sha256 {
            return Err((
                1,
                format!(
                    "staged copy hash mismatch for {:?} before write",
                    result.file
                ),
            ));
        }
        let path = format!(
            "quarantine/{id}/{}",
            intake::proposed_path(&provenance.source_name)
        );
        match session.get(&path) {
            Ok(_) => continue,
            Err(StoreError::EntryNotFound(_)) => {}
            Err(e) => return Err((1, e.to_string())),
        }
        if hashes.contains(&hash) {
            continue;
        }
        let mut entry = Entry::default();
        for (key, value) in result.quarantine_fields() {
            entry.data.insert(key, value.into());
        }
        entry.data.insert(
            intake::ATTACHMENT_FIELD.into(),
            STANDARD.encode(&bytes).into(),
        );
        entry.secret_metadata.attachments.insert(
            intake::ATTACHMENT_FIELD.into(),
            AttachmentInfo {
                filename: provenance.source_name.clone(),
                size: provenance.size as i64,
                sha256: hash.clone(),
            },
        );
        let now = GoTime::now().to_rfc3339_nano();
        entry.metadata.created = now.clone();
        entry.metadata.updated = now.clone();
        entry.metadata.version = 1;
        store
            .write_entry_with_recipients_at(&path, &entry, identity, &now, None)
            .map_err(|e| (1, format!("write quarantine entry {path:?}: {e}")))?;
        hashes.insert(hash);
        written.push(path);
    }
    if json {
        let out = if written.is_empty() {
            serde_json::json!({"import_id": null, "written": 0})
        } else {
            serde_json::json!({"import_id": id, "written": written})
        };
        serde_json::to_writer(io::stdout().lock(), &out).map_err(|e| (1, e.to_string()))?;
        println!();
    } else if !quiet {
        if written.is_empty() {
            println!("No new files to stage.");
        } else {
            println!("Staged batch {id} ({} entries)", written.len());
            println!("Review with: symvault import review promote {id}");
            notify_local(&id, written.len());
        }
    }
    Ok(())
}

fn notify_local(id: &str, count: usize) {
    #[cfg(target_os = "macos")]
    {
        let message = format!("Batch {id} bereit zur Prüfung ({count} Einträge)");
        let script =
            format!("display notification {message:?} with title \"Symaira Vault Intake\"");
        let _ = std::process::Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .output();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (id, count);
}
