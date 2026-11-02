//! A port of the part of Go's `archive/zip` reader (Go 1.26, `reader.go`) that
//! the 1PUX and CXF importers use: `zip.NewReader` over a byte slice, the
//! `File` records, `File.Open` and the checksum-verifying reader behind it.
//!
//! Go reports every structural problem with one of a handful of texts
//! (`zip: not a valid zip file`, `unexpected EOF`, `EOF`, `zip: checksum
//! error`, ...) chosen by exactly where in the central directory, local header
//! or data the reader gives up, so the checks and their order follow the Go
//! source rather than any other zip library. Names stay raw bytes, as in Go.

use crate::goflate::{FlateEnd, inflate};
use flate2::Crc;
use std::fmt;

const FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const DIRECTORY_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const DIRECTORY_END_SIGNATURE: [u8; 4] = [b'P', b'K', 0x05, 0x06];
const DIRECTORY64_LOC_SIGNATURE: u32 = 0x0706_4b50;
const DIRECTORY64_END_SIGNATURE: u32 = 0x0606_4b50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const FILE_HEADER_LEN: usize = 30;
const DIRECTORY_HEADER_LEN: usize = 46;
const DIRECTORY_END_LEN: usize = 22;
const DATA_DESCRIPTOR_LEN: usize = 16;
const DIRECTORY64_LOC_LEN: usize = 20;
const DIRECTORY64_END_LEN: usize = 56;
const ZIP64_EXTRA_ID: u16 = 0x0001;

const CREATOR_FAT: u16 = 0;
const CREATOR_UNIX: u16 = 3;
const CREATOR_NTFS: u16 = 11;
const CREATOR_VFAT: u16 = 14;
const CREATOR_MACOSX: u16 = 19;

const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// The error values Go's zip reader (and the layers it reads through) return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ZipError {
    /// `zip.ErrFormat`.
    Format,
    /// `io.ErrUnexpectedEOF`.
    UnexpectedEof,
    /// `io.EOF`.
    Eof,
    /// `zip.ErrAlgorithm`.
    Algorithm,
    /// `zip.ErrChecksum`.
    Checksum,
    /// `flate.CorruptInputError`.
    Corrupt(i64),
    /// Any other error text.
    Message(&'static str),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format => f.write_str("zip: not a valid zip file"),
            Self::UnexpectedEof => f.write_str("unexpected EOF"),
            Self::Eof => f.write_str("EOF"),
            Self::Algorithm => f.write_str("zip: unsupported compression algorithm"),
            Self::Checksum => f.write_str("zip: checksum error"),
            Self::Corrupt(offset) => {
                write!(f, "flate: corrupt input before offset {offset}")
            }
            Self::Message(text) => f.write_str(text),
        }
    }
}

const NEGATIVE_OFFSET: ZipError = ZipError::Message("bytes.Reader.ReadAt: negative offset");

/// Where a failed member read went wrong, so the importer can prefix the text
/// the way Go does (`open <name>:` versus `read <name>:`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EntryError {
    Open(ZipError),
    Read(ZipError),
}

/// A central-directory record (`zip.File`).
#[derive(Clone, Debug)]
pub(crate) struct GoZipFile {
    pub name: Vec<u8>,
    flags: u16,
    method: u16,
    creator_version: u16,
    external_attrs: u32,
    crc32: u32,
    pub uncompressed_size: u64,
    compressed_size: u64,
    header_offset: i64,
}

impl GoZipFile {
    /// `file.FileInfo().IsDir()`: the mode's directory bit, set by a trailing
    /// slash or by the creator-specific attribute bits.
    pub fn is_dir(&self) -> bool {
        if self.name.last() == Some(&b'/') {
            return true;
        }
        match self.creator_version >> 8 {
            CREATOR_UNIX | CREATOR_MACOSX => (self.external_attrs >> 16) & 0xf000 == 0x4000,
            CREATOR_NTFS | CREATOR_VFAT | CREATOR_FAT => self.external_attrs & 0x10 != 0,
            _ => false,
        }
    }

    fn has_data_descriptor(&self) -> bool {
        self.flags & 0x8 != 0
    }
}

struct DirectoryEnd {
    directory_records: u64,
    directory_size: u64,
    directory_offset: u64,
}

pub(crate) struct GoZip<'a> {
    data: &'a [u8],
    pub files: Vec<GoZipFile>,
}

/// `io.ReadFull` over the rest of the central directory.
struct Stream<'a> {
    rest: &'a [u8],
}

impl<'a> Stream<'a> {
    fn read_full(&mut self, n: usize) -> Result<&'a [u8], ZipError> {
        if n == 0 {
            return Ok(&[]);
        }
        if self.rest.is_empty() {
            return Err(ZipError::Eof);
        }
        if self.rest.len() < n {
            self.rest = &[];
            return Err(ZipError::UnexpectedEof);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(raw)
}

/// `bytes.Reader.ReadAt` for `len` bytes at `off`: a negative offset, an
/// offset at or past the end and a short read are all errors.
fn read_at(data: &[u8], off: i64, len: usize) -> Result<&[u8], ZipError> {
    if off < 0 {
        return Err(NEGATIVE_OFFSET);
    }
    let start = off as u64;
    if start >= data.len() as u64 {
        return Err(ZipError::Eof);
    }
    let start = start as usize;
    if data.len() - start < len {
        return Err(ZipError::Eof);
    }
    Ok(&data[start..start + len])
}

fn read_directory_header(r: &mut Stream<'_>) -> Result<GoZipFile, ZipError> {
    let buf = r.read_full(DIRECTORY_HEADER_LEN)?;
    if u32_at(buf, 0) != DIRECTORY_HEADER_SIGNATURE {
        return Err(ZipError::Format);
    }
    let creator_version = u16_at(buf, 4);
    let flags = u16_at(buf, 8);
    let method = u16_at(buf, 10);
    let crc32 = u32_at(buf, 16);
    let compressed_size = u32_at(buf, 20);
    let uncompressed_size = u32_at(buf, 24);
    let filename_len = usize::from(u16_at(buf, 28));
    let extra_len = usize::from(u16_at(buf, 30));
    let comment_len = usize::from(u16_at(buf, 32));
    let external_attrs = u32_at(buf, 38);
    let header_offset = u32_at(buf, 42);
    let d = r.read_full(filename_len + extra_len + comment_len)?;
    let name = d[..filename_len].to_vec();
    let extra = &d[filename_len..filename_len + extra_len];

    let mut file = GoZipFile {
        name,
        flags,
        method,
        creator_version,
        external_attrs,
        crc32,
        uncompressed_size: u64::from(uncompressed_size),
        compressed_size: u64::from(compressed_size),
        header_offset: i64::from(header_offset),
    };

    let mut need_usize = uncompressed_size == u32::MAX;
    let mut need_csize = compressed_size == u32::MAX;
    let mut need_header_offset = header_offset == u32::MAX;

    // Best effort, like Go: a malformed extra block ends the scan, only a
    // zip64 block that is too short for a field it must supply is an error.
    let mut extra = extra;
    while extra.len() >= 4 {
        let field_tag = u16_at(extra, 0);
        let field_size = usize::from(u16_at(extra, 2));
        extra = &extra[4..];
        if extra.len() < field_size {
            break;
        }
        let mut field = &extra[..field_size];
        extra = &extra[field_size..];
        if field_tag != ZIP64_EXTRA_ID {
            continue;
        }
        if need_usize {
            need_usize = false;
            if field.len() < 8 {
                return Err(ZipError::Format);
            }
            file.uncompressed_size = u64_at(field, 0);
            field = &field[8..];
        }
        if need_csize {
            need_csize = false;
            if field.len() < 8 {
                return Err(ZipError::Format);
            }
            file.compressed_size = u64_at(field, 0);
            field = &field[8..];
        }
        if need_header_offset {
            need_header_offset = false;
            if field.len() < 8 {
                return Err(ZipError::Format);
            }
            file.header_offset = u64_at(field, 0) as i64;
        }
    }
    // An uncompressed size of 2^32-1 without a zip64 block is accepted.
    if need_csize || need_header_offset {
        return Err(ZipError::Format);
    }
    Ok(file)
}

fn find_signature_in_block(b: &[u8]) -> Option<usize> {
    let mut i = b.len().checked_sub(DIRECTORY_END_LEN)?;
    loop {
        if b[i..i + 4] == DIRECTORY_END_SIGNATURE {
            let n = usize::from(u16_at(b, i + DIRECTORY_END_LEN - 2));
            if n + DIRECTORY_END_LEN + i > b.len() {
                // A truncated comment: Go treats the signature as not found.
                return None;
            }
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

fn find_directory64_end(data: &[u8], directory_end_offset: i64) -> Result<i64, ZipError> {
    let loc_offset = directory_end_offset - DIRECTORY64_LOC_LEN as i64;
    if loc_offset < 0 {
        return Ok(-1);
    }
    let buf = read_at(data, loc_offset, DIRECTORY64_LOC_LEN)?;
    if u32_at(buf, 0) != DIRECTORY64_LOC_SIGNATURE {
        return Ok(-1);
    }
    if u32_at(buf, 4) != 0 {
        return Ok(-1);
    }
    let p = u64_at(buf, 8);
    if u32_at(buf, 16) != 1 {
        return Ok(-1);
    }
    Ok(p as i64)
}

fn read_directory64_end(data: &[u8], offset: i64, d: &mut DirectoryEnd) -> Result<(), ZipError> {
    let buf = read_at(data, offset, DIRECTORY64_END_LEN)?;
    if u32_at(buf, 0) != DIRECTORY64_END_SIGNATURE {
        return Err(ZipError::Format);
    }
    // Skip size, versions, both disk numbers and the per-disk count.
    d.directory_records = u64_at(buf, 32);
    d.directory_size = u64_at(buf, 40);
    d.directory_offset = u64_at(buf, 48);
    Ok(())
}

fn read_directory_end(data: &[u8]) -> Result<(DirectoryEnd, i64), ZipError> {
    let size = data.len() as i64;
    let mut buf: &[u8] = &[];
    let mut directory_end_offset = 0i64;
    for (i, mut b_len) in [1024i64, 65 * 1024].into_iter().enumerate() {
        if b_len > size {
            b_len = size;
        }
        let window = &data[(size - b_len) as usize..];
        if let Some(p) = find_signature_in_block(window) {
            buf = &window[p..];
            directory_end_offset = size - b_len + p as i64;
            break;
        }
        if i == 1 || b_len == size {
            return Err(ZipError::Format);
        }
    }

    let mut d = DirectoryEnd {
        directory_records: u64::from(u16_at(buf, 10)),
        directory_size: u64::from(u32_at(buf, 12)),
        directory_offset: u64::from(u32_at(buf, 16)),
    };

    // These values mean that the file can be a zip64 file.
    if d.directory_records == 0xffff
        || d.directory_size == 0xffff
        || d.directory_offset == 0xffff_ffff
    {
        let p = find_directory64_end(data, directory_end_offset)?;
        if p >= 0 {
            directory_end_offset = p;
            read_directory64_end(data, p, &mut d)?;
        }
    }

    let max_int64 = i64::MAX as u64;
    if d.directory_size > max_int64 || d.directory_offset > max_int64 {
        return Err(ZipError::Format);
    }

    let mut base_offset = directory_end_offset
        .wrapping_sub(d.directory_size as i64)
        .wrapping_sub(d.directory_offset as i64);

    let o = base_offset.wrapping_add(d.directory_offset as i64);
    if o < 0 || o >= size {
        return Err(ZipError::Format);
    }

    // The directory end may name a wrong base offset; if a valid directory
    // entry sits at the bare directory offset, trust that instead.
    if base_offset > 0 {
        let off = d.directory_offset as i64;
        let rest = if off < size {
            &data[off as usize..]
        } else {
            &[][..]
        };
        if read_directory_header(&mut Stream { rest }).is_ok() {
            base_offset = 0;
        }
    }
    Ok((d, base_offset))
}

impl<'a> GoZip<'a> {
    /// `zip.NewReader(bytes.NewReader(data), len(data))`.
    pub fn new(data: &'a [u8]) -> Result<Self, ZipError> {
        let (end, base_offset) = read_directory_end(data)?;
        let start = base_offset.wrapping_add(end.directory_offset as i64);
        let mut stream = Stream {
            rest: &data[start as usize..],
        };

        // The record count is a uint16 in the directory end: read headers
        // until a bad one and compare the count modulo 65536 only.
        let mut files = Vec::new();
        let last = loop {
            match read_directory_header(&mut stream) {
                Ok(mut file) => {
                    file.header_offset = file.header_offset.wrapping_add(base_offset);
                    files.push(file);
                }
                Err(error @ (ZipError::Format | ZipError::UnexpectedEof)) => break error,
                Err(error) => return Err(error),
            }
        };
        if files.len() as u16 != end.directory_records as u16 {
            return Err(last);
        }
        Ok(Self { data, files })
    }

    /// `findBodyOffset`: the local header must be present and carry its
    /// signature; the body follows the header, name and extra field.
    fn find_body_offset(&self, file: &GoZipFile) -> Result<i64, ZipError> {
        let buf = read_at(self.data, file.header_offset, FILE_HEADER_LEN)?;
        if u32_at(buf, 0) != FILE_HEADER_SIGNATURE {
            return Err(ZipError::Format);
        }
        let filename_len = usize::from(u16_at(buf, 26));
        let extra_len = usize::from(u16_at(buf, 28));
        Ok((FILE_HEADER_LEN + filename_len + extra_len) as i64)
    }

    /// `io.NewSectionReader(data, off, n)` flattened to the bytes it can
    /// return, including Go's treatment of an overflowing or negative limit.
    fn section(&self, off: i64, n: i64) -> &'a [u8] {
        let limit = if off <= i64::MAX.wrapping_sub(n) {
            off.wrapping_add(n)
        } else {
            i64::MAX
        };
        if off < 0 || off >= limit || off as u64 >= self.data.len() as u64 {
            return &[];
        }
        let end = (limit as u64).min(self.data.len() as u64) as usize;
        &self.data[off as usize..end]
    }

    /// `io.ReadAll(io.LimitReader(file.Open(), limit))`.
    ///
    /// The result carries at most `limit` bytes; a member that reaches the
    /// limit is returned as is (the caller turns `len == limit` into Go's
    /// "exceeds maximum size" error), exactly as Go stops reading there
    /// without ever observing the member's checksum.
    pub fn read_limited(&self, file: &GoZipFile, limit: usize) -> Result<Vec<u8>, EntryError> {
        let body_offset = self.find_body_offset(file).map_err(EntryError::Open)?;
        if file.name.last() == Some(&b'/') {
            // `dirReader`: a directory with content is a format error on the
            // first read, an empty one reads as end of file.
            return if file.uncompressed_size != 0 {
                Err(EntryError::Read(ZipError::Format))
            } else {
                Ok(Vec::new())
            };
        }
        if file.method != METHOD_STORE && file.method != METHOD_DEFLATE {
            return Err(EntryError::Open(ZipError::Algorithm));
        }

        let size = file.compressed_size as i64;
        let body_start = file.header_offset.wrapping_add(body_offset);
        let region = self.section(body_start, size);

        // Everything the decompressor delivered, then how it ended.
        let (mut out, end) = if file.method == METHOD_STORE {
            let take = region.len().min(limit.saturating_add(1));
            (region[..take].to_vec(), FlateEnd::Eof)
        } else {
            inflate(region, limit)
        };

        // `checksumReader.Read`: more bytes than the header declares is a
        // format error even when the decompressor failed in the same read.
        let observed = out.len().min(limit);
        if observed as u64 > file.uncompressed_size {
            return Err(EntryError::Read(ZipError::Format));
        }
        // Go stops reading at the limit. A stored member's end of file is then
        // never observed; a deflate stream that ends exactly there still
        // delivers its end together with the last bytes.
        if out.len() > limit || (file.method == METHOD_STORE && out.len() >= limit) {
            out.truncate(limit);
            return Ok(out);
        }
        match end {
            FlateEnd::Capped => {
                out.truncate(limit);
                return Ok(out);
            }
            FlateEnd::Corrupt(offset) => {
                return Err(EntryError::Read(ZipError::Corrupt(offset)));
            }
            FlateEnd::UnexpectedEof => return Err(EntryError::Read(ZipError::UnexpectedEof)),
            FlateEnd::Eof => {}
        }

        if observed as u64 != file.uncompressed_size {
            return Err(EntryError::Read(ZipError::UnexpectedEof));
        }
        let mut crc = Crc::new();
        crc.update(&out);
        if file.has_data_descriptor() {
            let desc_start = body_start.wrapping_add(size);
            self.check_data_descriptor(desc_start, file)
                .map_err(EntryError::Read)?;
            if crc.sum() != file.crc32 {
                return Err(EntryError::Read(ZipError::Checksum));
            }
        } else if file.crc32 != 0 && crc.sum() != file.crc32 {
            return Err(EntryError::Read(ZipError::Checksum));
        }
        Ok(out)
    }

    /// `readDataDescriptor` over a 16-byte section reader. A missing
    /// descriptor is `unexpected EOF`; the optional signature shifts the CRC.
    fn check_data_descriptor(&self, start: i64, file: &GoZipFile) -> Result<(), ZipError> {
        if start < 0 {
            return Err(NEGATIVE_OFFSET);
        }
        let region = self.section(start, DATA_DESCRIPTOR_LEN as i64);
        let mut stream = Stream { rest: region };
        let eof = |error: ZipError| match error {
            ZipError::Eof => ZipError::UnexpectedEof,
            other => other,
        };
        let head = stream.read_full(4).map_err(eof)?;
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(head);
        let offset = if u32_at(&buf, 0) == DATA_DESCRIPTOR_SIGNATURE {
            0
        } else {
            4
        };
        let tail = stream.read_full(12 - offset).map_err(eof)?;
        buf[offset..12].copy_from_slice(tail);
        if u32_at(&buf, 0) != file.crc32 {
            return Err(ZipError::Checksum);
        }
        Ok(())
    }
}
