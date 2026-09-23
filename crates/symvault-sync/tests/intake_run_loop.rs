use std::{
    fs, io,
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, SystemTime},
};

use symvault_sync::intake::{IntakeError, Options, Spool, Watcher};
use tempfile::tempdir;

fn make_stable(path: &Path) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(3600))
        .unwrap();
}

#[test]
fn closed_stop_still_scans_once_and_private_spool_is_removed() {
    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let source = inbox.join("sample.env");
    fs::write(&source, b"A=1\n").unwrap();
    make_stable(&source);
    let spool = Spool::new(home.path().join("spool")).unwrap();
    let spool_root = spool.root().to_owned();
    let options = Options {
        interval: Duration::ZERO,
        ..Default::default()
    };
    let mut watcher = Watcher::new(&inbox, options).unwrap();
    assert_eq!(watcher.options.interval, Duration::from_secs(10));

    let (sender, stop) = mpsc::channel();
    drop(sender);
    let mut callbacks = 0;
    watcher
        .run(Some(&stop), &spool, |results| {
            callbacks += 1;
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].status, "ok");
            assert_eq!(
                fs::read(results[0].spool_path.as_ref().unwrap()).unwrap(),
                b"A=1\n"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(callbacks, 1);
    assert_eq!(fs::read(&source).unwrap(), b"A=1\n");
    drop(spool);
    assert!(!spool_root.exists());
}

#[test]
fn skipped_only_poll_suppresses_callback_and_batch_and_scan_errors_propagate() {
    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let oversized = inbox.join("oversize.env");
    fs::write(&oversized, b"B=123456789\n").unwrap();
    make_stable(&oversized);
    let spool = Spool::new(home.path().join("spool")).unwrap();
    let options = Options {
        max_file_size: 8,
        ..Default::default()
    };
    let mut watcher = Watcher::new(&inbox, options).unwrap();
    let (sender, stop) = mpsc::channel();
    drop(sender);
    let mut callbacks = 0;
    watcher
        .run(Some(&stop), &spool, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(callbacks, 0);

    let source = inbox.join("sample.env");
    fs::write(&source, b"A=1\n").unwrap();
    make_stable(&source);
    let error = watcher.run(None, &spool, |results| {
        callbacks += 1;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "ok");
        Err(IntakeError::Io(io::Error::other("synthetic batch failure")))
    });
    assert!(matches!(error, Err(IntakeError::Io(_))));
    assert_eq!(callbacks, 1);
    fs::remove_dir_all(&inbox).unwrap();
    assert!(matches!(
        watcher.run(None, &spool, |_| {
            callbacks += 1;
            Ok(())
        }),
        Err(IntakeError::Io(_))
    ));
    assert_eq!(callbacks, 1);
}

#[test]
fn later_poll_stages_changed_source_as_a_distinct_batch() {
    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let source = inbox.join("sample.env");
    fs::write(&source, b"A=1\n").unwrap();
    make_stable(&source);
    let spool = Spool::new(home.path().join("spool")).unwrap();
    let options = Options {
        interval: Duration::from_millis(10),
        debounce: Duration::from_nanos(1),
        ..Default::default()
    };
    let mut watcher = Watcher::new(&inbox, options).unwrap();
    let (stop_sender, stop) = mpsc::channel();
    let rescue_sender = stop_sender.clone();
    let (done_sender, done) = mpsc::channel();
    let task = thread::spawn(move || {
        let mut staged = Vec::new();
        let result = watcher.run(Some(&stop), &spool, |results| {
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].status, "ok");
            let path = results[0].spool_path.clone().unwrap();
            staged.push((path.clone(), fs::read(path)?));
            if staged.len() == 1 {
                fs::write(&source, b"A=2\n")?;
                fs::OpenOptions::new()
                    .write(true)
                    .open(&source)?
                    .set_modified(SystemTime::now() - Duration::from_secs(3660))?;
            } else {
                stop_sender.send(()).unwrap();
            }
            Ok(())
        });
        done_sender.send((result, staged)).unwrap();
    });
    let (result, staged) = match done.recv_timeout(Duration::from_secs(10)) {
        Ok(outcome) => outcome,
        Err(error) => {
            rescue_sender.send(()).unwrap();
            panic!("changed source was not delivered on a later poll: {error}");
        }
    };
    assert!(result.is_ok());
    assert_eq!(staged.len(), 2);
    assert_ne!(staged[0].0, staged[1].0);
    assert_eq!(staged[0].1, b"A=1\n");
    assert_eq!(staged[1].1, b"A=2\n");
    task.join().unwrap();
}

#[test]
fn live_stop_wakes_a_waiting_watcher_without_another_poll() {
    let home = tempdir().unwrap();
    let inbox = home.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let source = inbox.join("sample.env");
    fs::write(&source, b"A=1\n").unwrap();
    make_stable(&source);
    let spool = Spool::new(home.path().join("spool")).unwrap();
    let options = Options {
        interval: Duration::from_secs(30),
        ..Default::default()
    };
    let mut watcher = Watcher::new(&inbox, options).unwrap();
    let (stop_sender, stop) = mpsc::channel();
    let (ready_sender, ready) = mpsc::channel();
    let (done_sender, done) = mpsc::channel();
    let task = thread::spawn(move || {
        let mut callbacks = 0;
        let result = watcher.run(Some(&stop), &spool, |results| {
            callbacks += 1;
            ready_sender.send(results.len()).unwrap();
            Ok(())
        });
        done_sender.send((result, callbacks)).unwrap();
    });
    assert_eq!(ready.recv_timeout(Duration::from_secs(10)).unwrap(), 1);
    stop_sender.send(()).unwrap();
    let (result, callbacks) = done.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(result.is_ok());
    assert_eq!(callbacks, 1);
    task.join().unwrap();
    assert_eq!(fs::read(&source).unwrap(), b"A=1\n");
}
