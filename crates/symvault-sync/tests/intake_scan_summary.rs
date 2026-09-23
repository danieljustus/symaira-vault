use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

use symvault_sync::intake::{Options, Spool, Watcher};
use tempfile::tempdir;

fn older_than_debounce(path: &Path) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(3600))
        .unwrap();
}

#[test]
fn watcher_scan_summary_matches_go_public_shape_and_private_staging() {
    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let spool = Spool::new(home.path().join("spool")).unwrap();
    let good = inbox.join("good.env");
    let large = inbox.join("oversize.env");
    let hidden = inbox.join(".hidden.env");
    for (path, bytes) in [
        (&good, b"A=1\n".as_slice()),
        (&large, b"B=123456789\n".as_slice()),
        (&hidden, b"C=2\n".as_slice()),
    ] {
        fs::write(path, bytes).unwrap();
        older_than_debounce(path);
    }
    let mut watcher = Watcher::new(
        &inbox,
        Options {
            max_file_size: 8,
            debounce: Duration::from_nanos(1),
            ..Options::default()
        },
    )
    .unwrap();

    let first = watcher.scan_result_at(SystemTime::now(), &spool).unwrap();
    assert_eq!(first.scanned, 2);
    assert_eq!(first.staged.as_ref().unwrap().len(), 1);
    assert_eq!(first.staged_results.len(), 1);
    assert_eq!(first.skipped.len(), 1);
    assert!(first.skipped[0].starts_with("oversize.env: "));
    assert!(first.errors.is_empty());
    let staged_path = Path::new(&first.staged.as_ref().unwrap()[0]);
    assert!(staged_path.starts_with(spool.root()));
    assert_eq!(fs::read(staged_path).unwrap(), b"A=1\n");
    assert_eq!(fs::read(&good).unwrap(), b"A=1\n");
    let json = serde_json::to_value(&first).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert_eq!(json["scanned"], 2);
    assert_eq!(json["staged"].as_array().unwrap().len(), 1);
    assert_eq!(json["skipped"].as_array().unwrap().len(), 1);
    assert!(json.get("errors").is_none());
    assert!(json.get("staged_results").is_none());

    let second = watcher.scan_result_at(SystemTime::now(), &spool).unwrap();
    assert_eq!(second.scanned, 1);
    assert!(second.staged.is_none());
    assert!(second.staged_results.is_empty());
    assert_eq!(second.skipped.len(), 1);
    assert!(second.errors.is_empty());
    let json = serde_json::to_value(&second).unwrap();
    assert_eq!(json["staged"], serde_json::Value::Null);
    assert_eq!(json.as_object().unwrap().len(), 3);
    fs::remove_file(staged_path).unwrap();
    assert_eq!(fs::read(&good).unwrap(), b"A=1\n");
}

#[test]
fn watcher_scan_summary_reports_staging_errors_separately_from_skips() {
    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let source = inbox.join("good.env");
    fs::write(&source, b"A=1\n").unwrap();
    older_than_debounce(&source);
    let spool = Spool::new(home.path().join("spool")).unwrap();
    fs::remove_dir_all(spool.root()).unwrap();
    let mut watcher = Watcher::new(&inbox, Options::default()).unwrap();
    let result = watcher.scan_result_at(SystemTime::now(), &spool).unwrap();
    assert_eq!(result.scanned, 1);
    assert!(result.staged.is_none());
    assert!(result.staged_results.is_empty());
    assert!(result.skipped.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].starts_with("good.env: "));
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["staged"], serde_json::Value::Null);
    assert_eq!(json.as_object().unwrap().len(), 3);
    assert!(json.get("skipped").is_none());
    assert_eq!(json["errors"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(&source).unwrap(), b"A=1\n");
}

#[cfg(unix)]
#[test]
fn watcher_metadata_failure_is_reported_without_silencing_legacy_scan() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let source = inbox.join("good.env");
    fs::write(&source, b"A=1\n").unwrap();
    older_than_debounce(&source);
    let spool = Spool::new(home.path().join("spool")).unwrap();
    let options = Options::default();
    let mut legacy = Watcher::new(&inbox, options.clone()).unwrap();
    let mut summary_watcher = Watcher::new(&inbox, options).unwrap();
    let original = fs::metadata(&inbox).unwrap().permissions();
    fs::set_permissions(&inbox, fs::Permissions::from_mode(0o400)).unwrap();
    let legacy_result = legacy.scan_at(SystemTime::now(), &spool);
    let summary_result = summary_watcher.scan_result_at(SystemTime::now(), &spool);
    fs::set_permissions(&inbox, original).unwrap();

    assert!(
        legacy_result.is_err(),
        "legacy API must not hide metadata failures"
    );
    let summary = summary_result.unwrap();
    assert_eq!(summary.scanned, 0);
    assert_eq!(summary.errors.len(), 1);
    assert!(summary.errors[0].starts_with("good.env: "));
    assert!(summary.staged.is_none());
    assert!(summary.skipped.is_empty());
}
