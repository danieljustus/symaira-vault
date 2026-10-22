//! IO-002 restore behaviours that have no Go-derived corpus case because they
//! are deliberate Rust differences (entry-count limit) or host-dependent
//! (raw non-UTF-8 member names). Both are recorded in the contract matrix.
use flate2::{Compression, write::GzEncoder};
use std::{fs, io::Write, path::Path};
use symvault_sync::{ArchiveError, restore};
use tar::{Builder, Header};

fn gzip_tar(build: impl FnOnce(&mut Builder<Vec<u8>>)) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    build(&mut builder);
    let tar = builder.into_inner().unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

fn empty_file(builder: &mut Builder<Vec<u8>>, name: &str) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, name, std::io::empty())
        .unwrap();
}

fn count_entries(root: &Path) -> usize {
    fs::read_dir(root).unwrap().count()
}

#[test]
fn over_limit_archive_is_rejected_before_any_member_is_written() {
    // Go has no member-count limit and restores all of these; Rust rejects
    // the archive up front (documented unapproved divergence).
    let archive = gzip_tar(|builder| {
        for index in 0..100_001 {
            empty_file(builder, &format!("f{index}"));
        }
    });
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.tar.gz");
    fs::write(&input, archive).unwrap();
    let dest = root.path().join("vault");
    let error = restore(&input, &dest, true).unwrap_err();
    assert!(matches!(error, ArchiveError::Limit), "{error}");
    assert_eq!(error.to_string(), "archive exceeds safety limits");
    assert_eq!(count_entries(&dest), 0, "no member may be written");
}

#[test]
fn small_archive_passes_the_entry_limit_pre_pass() {
    // Guards against the pre-pass rejecting (or consuming) a valid archive.
    let archive = gzip_tar(|builder| {
        for index in 0..3 {
            empty_file(builder, &format!("f{index}"));
        }
    });
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.tar.gz");
    fs::write(&input, archive).unwrap();
    let dest = root.path().join("vault");
    let restored = restore(&input, &dest, true).unwrap();
    assert_eq!(restored.len(), 3);
}

#[cfg(unix)]
#[test]
fn non_utf8_member_name_reaches_the_operating_system_unchanged() {
    let archive = gzip_tar(|builder| {
        let mut header = Header::new_gnu();
        let name = b"raw-\xff\xfe";
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(1);
        header.set_mode(0o600);
        header.set_cksum();
        builder.append(&header, &b"x"[..]).unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.tar.gz");
    fs::write(&input, archive).unwrap();
    let dest = root.path().join("vault");
    let outcome = restore(&input, &dest, true);
    if cfg!(target_os = "macos") {
        // Go on macOS: `create file: open <path>: illegal byte sequence`.
        let message = outcome.unwrap_err().to_string();
        assert!(
            message.starts_with("create file: open ")
                && message.ends_with(": illegal byte sequence"),
            "{message}"
        );
        assert_eq!(count_entries(&dest), 0, "no U+FFFD-named file may appear");
    } else {
        // Filesystems that accept arbitrary bytes get the exact bytes, not a
        // lossy U+FFFD rewrite.
        use std::os::unix::ffi::OsStrExt as _;
        outcome.unwrap();
        let names: Vec<Vec<u8>> = fs::read_dir(&dest)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().as_bytes().to_vec())
            .collect();
        assert_eq!(names, vec![b"raw-\xff\xfe".to_vec()]);
    }
}

#[test]
fn backslash_member_name_is_rejected_with_go_wording_on_every_os() {
    // Go's `cleanBackupMemberName` rejects `\` in a member name whatever the
    // host (a Go v0.22.1 Windows backup stores `filepath.Rel` text verbatim).
    // The check must run before any path handling, because Windows would
    // otherwise treat the backslash as a separator and accept the name.
    let archive = gzip_tar(|builder| {
        let mut header = Header::new_gnu();
        let name = b"entries\\nested.age";
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(1);
        header.set_mode(0o600);
        header.set_cksum();
        builder.append(&header, &b"x"[..]).unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.tar.gz");
    fs::write(&input, archive).unwrap();
    let dest = root.path().join("vault");
    let error = restore(&input, &dest, true).unwrap_err();
    assert!(matches!(error, ArchiveError::Restore(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "archive contains unsafe path: entries\\nested.age"
    );
    assert_eq!(count_entries(&dest), 0, "nothing may be written");
}
