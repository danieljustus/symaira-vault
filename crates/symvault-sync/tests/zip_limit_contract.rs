//! IO-001: the 100 MiB member limit of the 1PUX and CXF importers.
//!
//! Go reads a member through `io.ReadAll(io.LimitReader(rc, limit))` and stops
//! at exactly `limit` bytes, so a member of exactly that length never reaches
//! its end of stream: its checksum, declared size and data descriptor are not
//! looked at, and the importer reports `zip entry exceeds maximum size`. One
//! byte less, the stream end arrives with the last bytes and the checksum is
//! verified. `testdata/port/import/zip-limit.json` is produced by
//! `scripts/rust-port/cmd/zipgen` (`limit.go`): single-member deflate-zeros
//! archives at limit-1, limit and limit+1 with damaged CRC / declared sizes /
//! data descriptors, run through the REAL Go importers.
//!
//! The fixture stores a small spec per case. This test rebuilds the archive
//! from it and checks the SHA-256 recorded by Go, so the input is the one Go
//! saw even though 100 MiB archives are not stored.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use symvault_sync::importer::{ImportedEntry, parse_1pux, parse_cxf};

#[derive(Debug, Deserialize)]
struct Fixture {
    limit: usize,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    importer: String,
    zeros: usize,
    variant: String,
    archive_sha256: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    #[serde(default)]
    entries: Option<Vec<ImportedEntry>>,
    error: Option<String>,
}

const LIMIT: usize = 100 * 1024 * 1024;
const CASES: usize = 48;

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../../../testdata/port/import/zip-limit.json"))
        .expect("valid generated zip-limit fixture")
}

/// `bitWriter` of the generator: little-endian bit order, Huffman codes
/// written most significant bit first.
#[derive(Default)]
struct BitWriter {
    buf: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitWriter {
    fn bits(&mut self, value: u32, count: u32) {
        for i in 0..count {
            self.acc |= ((value >> i) & 1) << self.n;
            self.n += 1;
            if self.n == 8 {
                self.buf.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }

    fn code(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.bits((value >> i) & 1, 1);
        }
    }

    fn fixed_sym(&mut self, sym: u32) {
        match sym {
            0..=143 => self.code(0x30 + sym, 8),
            144..=255 => self.code(0x190 + sym - 144, 9),
            256..=279 => self.code(sym - 256, 7),
            _ => self.code(0xc0 + sym - 280, 8),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.buf.push(self.acc as u8);
        }
        self.buf
    }
}

/// `zerosDeflate`: one final fixed-Huffman block, a literal zero, matches of
/// length 258 at distance 1, the remainder as literals, end of block.
fn zeros_deflate(total: usize) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.bits(1, 1); // final block
    w.bits(1, 2); // fixed Huffman
    w.fixed_sym(0);
    let rest = total - 1;
    for _ in 0..rest / 258 {
        w.fixed_sym(285);
        w.code(0, 5);
    }
    for _ in 0..rest % 258 {
        w.fixed_sym(0);
    }
    w.fixed_sym(256);
    w.finish()
}

fn le16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn le32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// What the generator derives once per size.
struct Zeros {
    deflated: Vec<u8>,
    crc: u32,
}

fn zeros(total: usize) -> Zeros {
    let mut crc = flate2::Crc::new();
    let chunk = vec![0u8; 1 << 20];
    let mut left = total;
    while left > 0 {
        let take = left.min(chunk.len());
        crc.update(&chunk[..take]);
        left -= take;
    }
    Zeros {
        deflated: zeros_deflate(total),
        crc: crc.sum(),
    }
}

/// `zerosArchive`: a single deflate member, the headers damaged per variant.
fn archive(importer: &str, total: usize, variant: &str, zeros: &Zeros) -> Vec<u8> {
    let name: &[u8] = if importer == "cxf" {
        b"cxf.json"
    } else {
        b"export.json"
    };
    let csize = zeros.deflated.len() as u32;
    let mut crc = zeros.crc;
    let mut usize_field = total as u32;
    let mut flags = 0u16;
    let mut trailer = Vec::new();
    match variant {
        "good" => {}
        "bad-crc" => crc ^= 1,
        "crc-zero" => crc = 0,
        "size-minus1" => usize_field -= 1,
        "size-plus1" => usize_field += 1,
        "size-zero" => usize_field = 0,
        "dd-good" | "dd-bad-crc" => {
            flags = 8;
            let descriptor_crc = if variant == "dd-bad-crc" {
                crc ^ 1
            } else {
                crc
            };
            le32(&mut trailer, 0x0807_4b50);
            le32(&mut trailer, descriptor_crc);
            le32(&mut trailer, csize);
            le32(&mut trailer, usize_field);
        }
        other => panic!("unknown variant {other}"),
    }

    let mut out = Vec::new();
    le32(&mut out, 0x0403_4b50);
    le16(&mut out, 20);
    le16(&mut out, flags);
    le16(&mut out, 8);
    le16(&mut out, 0);
    le16(&mut out, 0x21);
    le32(&mut out, crc);
    le32(&mut out, csize);
    le32(&mut out, usize_field);
    le16(&mut out, name.len() as u16);
    le16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(&zeros.deflated);
    out.extend_from_slice(&trailer);

    let cd_start = out.len();
    le32(&mut out, 0x0201_4b50);
    le16(&mut out, 20);
    le16(&mut out, 20);
    le16(&mut out, flags);
    le16(&mut out, 8);
    le16(&mut out, 0);
    le16(&mut out, 0x21);
    le32(&mut out, crc);
    le32(&mut out, csize);
    le32(&mut out, usize_field);
    le16(&mut out, name.len() as u16);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, 0);
    le32(&mut out, 0);
    le32(&mut out, 0);
    out.extend_from_slice(name);
    let cd_size = (out.len() - cd_start) as u32;
    out.extend_from_slice(b"PK\x05\x06");
    le16(&mut out, 0);
    le16(&mut out, 0);
    le16(&mut out, 1);
    le16(&mut out, 1);
    le32(&mut out, cd_size);
    le32(&mut out, cd_start as u32);
    le16(&mut out, 0);
    out
}

fn run(importer: &str, input: &[u8]) -> (Option<String>, Option<Vec<ImportedEntry>>) {
    let result = match importer {
        "1pux" => parse_1pux(input),
        "cxf" => parse_cxf(input),
        other => panic!("unknown importer {other}"),
    };
    match result {
        Ok(entries) => (None, Some(entries)),
        Err(error) => (Some(error.to_string()), None),
    }
}

/// `None` when the outcome is Go's recorded one.
fn difference(
    case: &Case,
    error: Option<&str>,
    entries: Option<&[ImportedEntry]>,
) -> Option<String> {
    let id = &case.id;
    match (&case.expected.error, &case.expected.entries) {
        (Some(go), _) => match error {
            Some(text) if text == go => None,
            Some(text) => Some(format!("{id}: error differs\n  go:   {go}\n  rust: {text}")),
            None => Some(format!(
                "{id}: rust accepted {} entries, go: {go}",
                entries.map_or(0, <[ImportedEntry]>::len)
            )),
        },
        (None, expected) => {
            let expected = expected.clone().unwrap_or_default();
            match (error, entries) {
                (Some(text), _) => Some(format!("{id}: rust error {text}")),
                (None, Some(got)) if got == expected.as_slice() => None,
                (None, got) => Some(format!("{id}: entries differ: {got:?}")),
            }
        }
    }
}

/// Rebuilds and runs one case; `Some` is a difference from Go.
fn check_case(case: &Case, zeros: &Zeros) -> Option<String> {
    let input = archive(&case.importer, case.zeros, &case.variant, zeros);
    let sha = Sha256::digest(&input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        sha, case.archive_sha256,
        "{}: rebuilt archive differs from the one Go saw",
        case.id
    );
    let (error, entries) = run(&case.importer, &input);
    difference(case, error.as_deref(), entries.as_deref())
}

#[test]
fn limit_boundary_matches_the_go_importers() {
    let fixture = fixture();
    assert_eq!(fixture.limit, LIMIT);
    assert_eq!(fixture.cases.len(), CASES, "fixture cardinality is a gate");
    let sizes: Vec<usize> = fixture
        .cases
        .iter()
        .map(|case| case.zeros)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    // Each case inflates up to 100 MiB; the cases are independent, so they run
    // on a few threads to keep the debug build quick.
    let cache: BTreeMap<usize, Zeros> = std::thread::scope(|scope| {
        let handles: Vec<_> = sizes
            .iter()
            .map(|size| scope.spawn(move || (*size, zeros(*size))))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("zeros thread"))
            .collect()
    });
    assert_eq!(cache.len(), 3, "limit-1, limit and limit+1");
    let threads = 4;
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|worker| {
                let (cases, cache) = (&fixture.cases, &cache);
                scope.spawn(move || {
                    cases
                        .iter()
                        .skip(worker)
                        .step_by(threads)
                        .filter_map(|case| check_case(case, &cache[&case.zeros]))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("case thread"))
            .collect()
    });
    assert!(
        failures.is_empty(),
        "{} of {} limit cases differ from Go:\n{}",
        failures.len(),
        fixture.cases.len(),
        failures.join("\n")
    );
}

/// The corpus is not vacuous: the cases that separate "stream end observed"
/// from "stopped at the limit" exist and have the texts the analysis expects.
#[test]
fn corpus_separates_the_limit_from_its_neighbours() {
    let fixture = fixture();
    let error = |importer: &str, total: usize, variant: &str| -> String {
        fixture
            .cases
            .iter()
            .find(|case| {
                case.importer == importer && case.zeros == total && case.variant == variant
            })
            .and_then(|case| case.expected.error.clone())
            .unwrap_or_else(|| panic!("no error case {importer} {total} {variant}"))
    };
    let exceeds = format!("zip entry exceeds maximum size of {LIMIT} bytes");
    for importer in ["1pux", "cxf"] {
        // At the limit the checksum, a short declaration and a descriptor are
        // never looked at; a declaration smaller than the bytes read still is.
        for variant in [
            "good",
            "bad-crc",
            "crc-zero",
            "size-plus1",
            "dd-good",
            "dd-bad-crc",
        ] {
            assert_eq!(
                error(importer, LIMIT, variant),
                exceeds,
                "{importer} {variant}"
            );
        }
        assert!(error(importer, LIMIT, "size-minus1").ends_with("zip: not a valid zip file"));
        // One byte less the end arrives with the data.
        assert!(error(importer, LIMIT - 1, "bad-crc").ends_with("zip: checksum error"));
        assert!(error(importer, LIMIT - 1, "dd-bad-crc").ends_with("zip: checksum error"));
        assert!(error(importer, LIMIT - 1, "size-plus1").ends_with("unexpected EOF"));
        // One byte more is over the limit whatever the headers say.
        assert_eq!(error(importer, LIMIT + 1, "bad-crc"), exceeds);
    }
}
