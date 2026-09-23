use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

use symvault_sync::intake::{Options, Spool, Watcher};
use tempfile::tempdir;

fn set_mtime(path: &Path, when: SystemTime) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

#[test]
fn watcher_matches_go_polling_debounce_ledger_and_skip_contract() {
    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let spool = Spool::new(home.path().join("spool")).unwrap();
    let source = inbox.join("sample.env");
    let first = b"A=1\n";
    let second = b"A=2\n";
    fs::write(&source, first).unwrap();
    // A clock ahead of creation makes dotfiles and new symlinks old enough
    // that debounce cannot hide a broken candidate filter.
    let now = SystemTime::now() + Duration::from_secs(3600);
    set_mtime(&source, now + Duration::from_secs(3600));
    fs::write(inbox.join(".hidden.env"), first).unwrap();
    fs::create_dir(inbox.join("subdir")).unwrap();
    #[cfg(unix)]
    {
        let link_target = home.path().join("link-target.env");
        fs::write(&link_target, b"L=1\n").unwrap();
        set_mtime(&link_target, now - Duration::from_secs(3600));
        std::os::unix::fs::symlink(&link_target, inbox.join("source-link.env")).unwrap();
    }

    let options = Options {
        debounce: Duration::ZERO, // Go normalizes zero to five seconds.
        max_file_size: 8,
        ..Default::default()
    };
    let mut watcher = Watcher::new(&inbox, options).unwrap();
    assert_eq!(watcher.options.debounce, Duration::from_secs(5));
    assert!(watcher.scan_at(now, &spool).unwrap().is_empty());
    assert_eq!(fs::read_dir(spool.root()).unwrap().count(), 0);

    set_mtime(&source, now - Duration::from_secs(3600));
    let first_scan = watcher.scan_at(now, &spool).unwrap();
    assert_eq!(first_scan.len(), 1);
    assert_eq!(first_scan[0].status, "ok");
    let first_stage = fs::read_dir(spool.root())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(fs::read(&first_stage).unwrap(), first);
    assert!(watcher.scan_at(now, &spool).unwrap().is_empty());

    fs::write(&source, second).unwrap();
    set_mtime(&source, now - Duration::from_secs(7200));
    let second_scan = watcher.scan_at(now, &spool).unwrap();
    assert_eq!(second_scan.len(), 1);
    assert_eq!(second_scan[0].status, "ok");
    let staged = fs::read_dir(spool.root())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(staged.len(), 2);
    assert_eq!(fs::read(&first_stage).unwrap(), first);
    assert!(staged.iter().any(|path| fs::read(path).unwrap() == second));

    let oversize = inbox.join("oversize.env");
    fs::write(&oversize, b"B=123456789\n").unwrap();
    set_mtime(&oversize, now - Duration::from_secs(3600));
    for _ in 0..2 {
        let skipped = watcher.scan_at(now, &spool).unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].status, "skipped");
        assert!(skipped[0].provenance.is_none());
        assert_eq!(fs::read_dir(spool.root()).unwrap().count(), 2);
    }
    assert_eq!(fs::read(&source).unwrap(), second);
}
