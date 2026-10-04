//! Polling intake CLI. Private spool ownership, encrypted quarantine and
//! process-local deduplication follow the production Go watcher.
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
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

#[derive(Debug, clap::Args)]
#[command(args_override_self = true)]
pub struct IntakeOptions {
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true,
        default_missing_value = "true", default_value = "false", value_parser = parse_bool)]
    dry_run: bool,
    #[arg(long, default_value_t = intake::MAX_BATCH_SIZE as i64, allow_hyphen_values = true)]
    batch_limit: i64,
    #[arg(long, default_value_t = intake::MAX_FILES as i64, allow_hyphen_values = true)]
    max_files: i64,
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true,
        default_missing_value = "true", default_value = "false", value_parser = parse_bool)]
    move_to_trash: bool,
    #[arg(long)]
    ocr_text: Option<PathBuf>,
}

pub fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(format!(
            "strconv.ParseBool: parsing {value:?}: invalid syntax"
        )),
    }
}

pub fn files(
    options: &IntakeOptions,
    json: bool,
    quiet: bool,
    mut unlock: impl FnMut() -> Result<(PathBuf, Identity), Error>,
) -> ExitCode {
    finish((|| {
        if options.files.is_empty() {
            return Err((1, "requires at least 1 arg(s), only received 0".into()));
        }
        if options.move_to_trash && !cfg!(target_os = "macos") {
            return Err((9, "--move-to-trash is only supported on macOS".into()));
        }
        let max_files = if options.max_files <= 0 {
            intake::MAX_FILES
        } else {
            options.max_files as usize
        };
        let max_bytes = if options.batch_limit <= 0 {
            intake::MAX_BATCH_SIZE
        } else {
            options.batch_limit as u64
        };
        if options.files.len() > max_files {
            return Err((
                9,
                format!(
                    "intake: batch exceeds the {max_files} file limit ({} given)",
                    options.files.len()
                ),
            ));
        }
        let spool = Spool::new(std::env::temp_dir())
            .map_err(|e| (1, format!("create intake spool: {e}")))?;
        let mut results = Vec::new();
        let mut total = 0u64;
        for path in &options.files {
            let mut result = intake::process(&spool, path, &Options::default());
            if result.status == "ok"
                && result.provenance.as_ref().is_some_and(|p| {
                    matches!(
                        p.source_type,
                        intake::SourceType::Image | intake::SourceType::Pdf
                    )
                })
                && let Some(ocr) = &options.ocr_text
            {
                match fs::read(ocr) {
                    Ok(text) => {
                        result.suggestions = intake::suggestions(
                            &text,
                            intake::SourceType::Text,
                            &result
                                .provenance
                                .as_ref()
                                .expect("checked source provenance")
                                .source_name,
                        );
                    }
                    Err(e) => {
                        result.status = "error".into();
                        result.reason = Some(format!("read OCR text: {e}"));
                        result.suggestions.clear();
                    }
                }
            }
            if let Some(provenance) = &result.provenance {
                total = total.saturating_add(provenance.size);
                if total > max_bytes {
                    result.status = "skipped".into();
                    result.reason = Some(format!("batch exceeds the {max_bytes} byte total limit"));
                    result.provenance = None;
                    result.suggestions.clear();
                }
            }
            results.push(result);
        }
        let batch = if options.dry_run {
            None
        } else {
            let (root, identity) = unlock()?;
            Some(write_batch(&root, &identity, &mut results)?)
        };
        if json {
            let mut out = serde_json::Map::new();
            if let Some(batch) = &batch {
                out.insert("import_id".into(), batch.id.clone().into());
            }
            out.insert(
                "results".into(),
                results
                    .iter()
                    .map(public_result)
                    .collect::<Result<Vec<_>, _>>()?
                    .into(),
            );
            // The IO-003 contract is semantic JSON; object ordering is not a
            // byte contract. Keep all secret suggestion values out of output.
            let encoded = symvault_gojson::to_string(&out).map_err(|e| (1, e.to_string()))?;
            let value: serde_json::Value =
                serde_json::from_str(&encoded).map_err(|e| (1, e.to_string()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|e| (1, e.to_string()))?
            );
        } else {
            let mut accepted = 0;
            for result in &results {
                if result.status == "ok" {
                    accepted += 1;
                }
                if quiet {
                    continue;
                }
                match result.status.as_str() {
                    "ok" => {
                        if let Some(p) = &result.provenance {
                            println!(
                                "OK    {}  ({}, {} bytes, sha256 {})",
                                result.file,
                                source_type(p.source_type),
                                p.size,
                                &p.sha256[..12.min(p.sha256.len())]
                            );
                            for s in &result.suggestions {
                                let label = if s.attachment { "attachment" } else { "field" };
                                let warning = s
                                    .warning
                                    .as_ref()
                                    .map_or(String::new(), |w| format!("  [!] {w}"));
                                println!(
                                    "      → {label}: {} (conf {:.2}){warning}",
                                    s.field, s.confidence
                                );
                            }
                        }
                    }
                    "skipped" => println!(
                        "SKIP  {}  {}",
                        result.file,
                        result.reason.as_deref().unwrap_or_default()
                    ),
                    "error" => println!(
                        "ERROR {}  {}",
                        result.file,
                        result.reason.as_deref().unwrap_or_default()
                    ),
                    _ => {}
                }
            }
            if options.dry_run {
                if !quiet {
                    println!(
                        "Dry run: {} file(s) processed, nothing written.",
                        results.len()
                    );
                }
            } else {
                if accepted == 0 {
                    return Err((1, "no files were accepted for intake".into()));
                }
                if !quiet {
                    let id = &batch.as_ref().expect("ordinary intake wrote batch").id;
                    println!("Quarantine import ID: {id}");
                    println!("Review and promote with: symvault import review promote {id}");
                }
            }
        }
        #[cfg(target_os = "macos")]
        if options.move_to_trash && !options.dry_run {
            for result in results.iter().filter(|r| r.status == "ok") {
                let script = format!(
                    "tell application \"Finder\" to delete POSIX file {:?}",
                    result.file
                );
                let output = std::process::Command::new("/usr/bin/osascript")
                    .args(["-e", &script])
                    .output();
                if !matches!(output, Ok(ref out) if out.status.success()) && !quiet {
                    println!("Warning: source cleanup incomplete: {}", result.file);
                }
            }
        }
        Ok(())
    })())
}

fn source_type(kind: intake::SourceType) -> &'static str {
    match kind {
        intake::SourceType::Text => "text",
        intake::SourceType::Env => "env",
        intake::SourceType::Json => "json",
        intake::SourceType::Certificate => "certificate",
        intake::SourceType::Key => "key",
        intake::SourceType::Image => "image",
        intake::SourceType::Pdf => "pdf",
        intake::SourceType::Archive => "archive",
        intake::SourceType::Other => "other",
    }
}

fn public_result(result: &FileResult) -> Result<serde_json::Value, Error> {
    let mut out = serde_json::Map::new();
    out.insert("file".into(), result.file.clone().into());
    out.insert("status".into(), result.status.clone().into());
    if let Some(reason) = &result.reason {
        out.insert("reason".into(), reason.clone().into());
    }
    if let Some(p) = &result.provenance {
        let stamp = time::OffsetDateTime::from_unix_timestamp_nanos(p.mtime_unix_nanoseconds)
            .map_err(|e| (1, format!("encode intake output: {e}")))?;
        out.insert("provenance".into(), serde_json::json!({"source_path":p.source_path,"source_name":p.source_name,
            "source_type":source_type(p.source_type),"size":p.size,"sha256":p.sha256,"mtime":GoTime::from_offset_datetime(stamp).to_rfc3339_nano()}));
    }
    if !result.suggestions.is_empty() {
        out.insert(
            "suggestions".into(),
            result
                .suggestions
                .iter()
                .map(|s| {
                    let mut v = serde_json::Map::new();
                    v.insert("path".into(), s.path.clone().into());
                    v.insert("field".into(), s.field.clone().into());
                    v.insert("confidence".into(), s.confidence.into());
                    if let Some(w) = &s.warning
                        && !w.is_empty()
                    {
                        v.insert("warning".into(), w.clone().into());
                    }
                    if s.attachment {
                        v.insert("attachment".into(), true.into());
                    }
                    v
                })
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !result.duplicate_paths.is_empty() {
        out.insert("duplicates".into(), result.duplicate_paths.clone().into());
    }
    Ok(out.into())
}

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
                1,
                format!("invalid argument {interval:?} for \"--interval\" flag: {e}"),
            )
        })?;
        let debounce_ns = symvault_core::config::parse_go_duration(debounce).map_err(|e| {
            (
                1,
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
    let batch = write_batch(root, identity, &mut results.to_vec())?;
    let id = batch.id;
    let written = batch.written;
    print_batch(&id, &written, json, quiet)
}

struct Batch {
    id: String,
    written: Vec<String>,
}

fn write_batch(
    root: &Path,
    identity: &Identity,
    results: &mut [FileResult],
) -> Result<Batch, Error> {
    let store =
        Store::open_with_legacy_migration(root, identity).map_err(|e| (1, e.to_string()))?;
    let session = store.read_session(identity);
    let mut hashes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in session
        .list()
        .map_err(|e| (1, e.to_string()))?
        .into_iter()
        .filter(|p| p.starts_with("quarantine/"))
    {
        match session.get(&path) {
            Ok(entry) => {
                for attachment in entry.secret_metadata.attachments.values() {
                    hashes
                        .entry(attachment.sha256.clone())
                        .or_default()
                        .push(path.clone());
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
            Ok(_) => {
                result.status = "skipped".into();
                result.reason = Some(format!("quarantine entry already exists: {path}"));
                continue;
            }
            Err(StoreError::EntryNotFound(_)) => {}
            Err(e) => return Err((1, e.to_string())),
        }
        if hashes.contains_key(&hash) {
            result.status = "skipped".into();
            result.reason = Some("duplicate source hash already quarantined".into());
            result.duplicate_paths = hashes.get(&hash).expect("checked duplicate hash").clone();
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
        // A source may be moved to Trash only after the encrypted attachment
        // has actually been read back. Keep verification within this batch's
        // resource admission rather than starting an unbounded fresh session.
        let persisted = session
            .get(&path)
            .map_err(|e| (1, format!("verify quarantine entry {path:?}: {e}")))?;
        if persisted.data.get(intake::ATTACHMENT_FIELD) != entry.data.get(intake::ATTACHMENT_FIELD)
            || persisted.secret_metadata.attachments != entry.secret_metadata.attachments
        {
            return Err((
                1,
                format!("quarantine attachment verification failed for {path:?}"),
            ));
        }
        hashes.entry(hash).or_default().push(path.clone());
        written.push(path);
    }
    Ok(Batch { id, written })
}

fn print_batch(id: &str, written: &[String], json: bool, quiet: bool) -> Result<(), Error> {
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
            notify_local(id, written.len());
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
