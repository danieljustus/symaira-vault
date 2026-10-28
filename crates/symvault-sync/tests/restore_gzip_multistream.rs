//! IO-002 / #1499: restore limits hold when the tar stream is split across
//! gzip members. Go reads concatenated members as one stream, so the
//! entry-count pre-pass and the size checks must see every member, not just
//! the first. The Go-derived error/tree comparison lives in
//! `symvault-cli/tests/restore_gzip_multistream_contract.rs`.
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::{fs, io::Read, io::Write};
use symvault_sync::{ArchiveError, restore};
use tar::{Builder, Header};

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
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

/// Splits `tar` at `at` into two gzip members.
fn two_members(tar: &[u8], at: usize) -> Vec<u8> {
    let mut out = gzip(&tar[..at]);
    out.extend(gzip(&tar[at..]));
    out
}

#[test]
fn entry_limit_counts_members_after_the_first_gzip_member() {
    let mut builder = Builder::new(Vec::new());
    for index in 0..100_001 {
        empty_file(&mut builder, &format!("f{index}"));
    }
    let tar = builder.into_inner().unwrap();
    // The cut falls in the first dozen headers, so a single-member reader
    // would count a handful of entries and never reach the limit.
    let archive = two_members(&tar, 512 * 10 + 100);
    let mut seen = Vec::new();
    let _ = GzDecoder::new(archive.as_slice()).read_to_end(&mut seen);
    assert!(
        seen.len() < 512 * 12,
        "negative control: single-member decoding stops at the first member"
    );

    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.tar.gz");
    fs::write(&input, archive).unwrap();
    let dest = root.path().join("vault");
    let error = restore(&input, &dest, true).unwrap_err();
    assert!(matches!(error, ArchiveError::Limit), "{error}");
    assert_eq!(
        fs::read_dir(&dest).unwrap().count(),
        0,
        "no member may be written"
    );
}

#[test]
fn oversize_member_header_in_a_later_gzip_member_is_rejected() {
    let mut builder = Builder::new(Vec::new());
    empty_file(&mut builder, "identity.age");
    let mut header = Header::new_gnu();
    header.set_size((1u64 << 30) + 1);
    header.set_mode(0o600);
    header.set_path("entries/huge").unwrap();
    header.set_cksum();
    // The header promises more data than follows; only the header is added.
    // `get_ref` copies the bytes written so far without the end marker that
    // `into_inner` would append.
    let mut tar = builder.get_ref().clone();
    tar.extend_from_slice(header.as_bytes());
    let archive = two_members(&tar, 512 + 100);

    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.tar.gz");
    fs::write(&input, archive).unwrap();
    let dest = root.path().join("vault");
    let error = restore(&input, &dest, true).unwrap_err();
    assert_eq!(
        error.to_string(),
        "archive entry entries/huge exceeds maximum file size of 1073741824 bytes"
    );
}

#[test]
fn split_archive_restores_every_member() {
    let mut builder = Builder::new(Vec::new());
    for name in ["identity.age", "config.yaml", "entries/a", "entries/b"] {
        let mut header = Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o600);
        header.set_cksum();
        builder
            .append_data(&mut header, name, b"data".as_slice())
            .unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let archive = two_members(&tar, 512 * 5 + 17);
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.tar.gz");
    fs::write(&input, archive).unwrap();
    let dest = root.path().join("vault");
    let restored = restore(&input, &dest, true).unwrap();
    let names: Vec<_> = restored.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(
        names,
        ["config.yaml", "entries/a", "entries/b", "identity.age"]
    );
    assert_eq!(fs::read(dest.join("entries/b")).unwrap(), b"data");
}
