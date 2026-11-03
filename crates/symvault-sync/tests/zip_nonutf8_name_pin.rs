//! IO-001 / ADR 0034 item 27 (Rust-only pin, no Go oracle).
//!
//! Go prints the raw bytes of a non-UTF-8 zip member name in the
//! `open <name>:` / `read <name>:` diagnostics of the CXF importer; Rust
//! prints U+FFFD for each invalid byte. The text is diagnostic only, the
//! importers select and read the same member. The divergence is ratified, so
//! it is pinned here instead of in `zip-errors.json` (which records Go).
//! `GODEBUG=zipinsecurepath` is not modelled and has no pin.

use symvault_sync::importer::parse_cxf;

fn le16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn le32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// One-member archive: general-purpose flag 0 (so the name is not declared
/// UTF-8), the given compression method, and a deliberately wrong CRC-32.
fn archive(name: &[u8], method: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let crc = 0xdead_beef_u32;
    out.extend_from_slice(b"PK\x03\x04");
    le16(&mut out, 20);
    le16(&mut out, 0);
    le16(&mut out, method);
    le32(&mut out, 0);
    le32(&mut out, crc);
    le32(&mut out, data.len() as u32);
    le32(&mut out, data.len() as u32);
    le16(&mut out, name.len() as u16);
    le16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(data);

    let directory_offset = out.len();
    out.extend_from_slice(b"PK\x01\x02");
    le16(&mut out, 20);
    le16(&mut out, 20);
    le16(&mut out, 0);
    le16(&mut out, method);
    le32(&mut out, 0);
    le32(&mut out, crc);
    le32(&mut out, data.len() as u32);
    le32(&mut out, data.len() as u32);
    le16(&mut out, name.len() as u16);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le32(&mut out, 0);
    le32(&mut out, 0);
    out.extend_from_slice(name);
    let directory_len = out.len() - directory_offset;

    out.extend_from_slice(b"PK\x05\x06");
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, 1);
    le16(&mut out, 1);
    le32(&mut out, directory_len as u32);
    le32(&mut out, directory_offset as u32);
    le16(&mut out, 0);
    out
}

fn error_text(archive: &[u8]) -> String {
    parse_cxf(archive)
        .expect_err("fixture archive must be rejected")
        .to_string()
}

/// `a\xff.json`: the importer selects it (ASCII `.json` suffix) and fails to
/// open it; the diagnostic carries U+FFFD where Go prints the byte `0xff`.
#[test]
fn non_utf8_member_name_prints_replacement_character_on_open_error() {
    let text = error_text(&archive(b"a\xff.json", 99, b"{}"));
    assert_eq!(
        text,
        "open a\u{fffd}.json: zip: unsupported compression algorithm"
    );
    assert!(!text.as_bytes().contains(&0xff));
}

/// Same replacement on the `read <name>:` path (stored member, bad CRC).
#[test]
fn non_utf8_member_name_prints_replacement_character_on_read_error() {
    let text = error_text(&archive(b"dir/\xc3\x28\xff.json", 0, b"{}"));
    assert_eq!(text, "read dir/\u{fffd}(\u{fffd}.json: zip: checksum error");
}

/// Control: the same archive with a valid UTF-8 name keeps the name verbatim,
/// so the pin tests the lossy conversion and not a changed error shape.
#[test]
fn utf8_member_name_is_printed_verbatim() {
    let text = error_text(&archive("a\u{e9}.json".as_bytes(), 99, b"{}"));
    assert_eq!(
        text,
        "open a\u{e9}.json: zip: unsupported compression algorithm"
    );
}
