//! A port of Go's `archive/tar` reader (Go 1.26, `reader.go`, `format.go`,
//! `common.go`, `strconv.go`) for the restore path.
//!
//! `RestoreBackup` takes every member name, type, mode and size from
//! `tar.Reader.Next`, so what counts as a header error, which name wins when a
//! GNU long name, a PAX `path` and a USTAR/STAR prefix compete, and how
//! extension headers, PAX records and sparse maps are validated is decided by
//! that reader and by nothing else. The tar crate resolves several of those
//! differently (it reads STAR prefixes as USTAR, ignores extension header
//! fields, accepts malformed PAX records and rejects two consecutive long
//! names), so restore reads the stream with this port instead. Bodies are read
//! like Go's `regFileReader` and `sparseFileReader`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};

use crate::archive::{go_parse_numeric, go_parse_octal};

const BLOCK: usize = 512;
const MAX_SPECIAL_FILE_SIZE: usize = 1 << 20;
const MAX_SPARSE_FILE_ENTRIES: usize = 1 << 20;

const TYPE_REG: u8 = b'0';
const TYPE_REG_A: u8 = 0;
const TYPE_LINK: u8 = b'1';
const TYPE_SYMLINK: u8 = b'2';
const TYPE_CHAR: u8 = b'3';
const TYPE_BLOCK: u8 = b'4';
const TYPE_DIR: u8 = b'5';
const TYPE_FIFO: u8 = b'6';
const TYPE_XHEADER: u8 = b'x';
const TYPE_XGLOBAL: u8 = b'g';
const TYPE_GNU_SPARSE: u8 = b'S';
const TYPE_GNU_LONGNAME: u8 = b'L';
const TYPE_GNU_LONGLINK: u8 = b'K';

/// The errors `tar.Reader` returns, with Go's texts.
#[derive(Debug)]
pub(crate) enum TarError {
    /// `io.EOF`: a clean end of the stream.
    Eof,
    /// `io.ErrUnexpectedEOF`.
    UnexpectedEof,
    /// `tar.ErrHeader`.
    Header,
    /// `tar.ErrFieldTooLong`.
    FieldTooLong,
    /// `errSparseTooLong`.
    SparseTooLong,
    /// `errMissData`.
    MissData,
    /// `errUnrefData`.
    UnrefData,
    /// An error of the layer below (the gzip reader).
    Io(io::Error),
}

impl fmt::Display for TarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("EOF"),
            Self::UnexpectedEof => f.write_str("unexpected EOF"),
            Self::Header => f.write_str("archive/tar: invalid tar header"),
            Self::FieldTooLong => f.write_str("archive/tar: header field too long"),
            Self::SparseTooLong => f.write_str("archive/tar: sparse map too long"),
            Self::MissData => f.write_str("archive/tar: sparse file references non-existent data"),
            Self::UnrefData => f.write_str("archive/tar: sparse file contains unreferenced data"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TarError {}

impl TarError {
    /// The `io::Error` a body read reports: the lower layer's own error stays
    /// untouched, an unexpected end keeps its kind, every other tar error is
    /// carried as a [`TarError`] so the caller can print Go's text.
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Self::Io(error) => error,
            Self::UnexpectedEof | Self::Eof => io::Error::from(io::ErrorKind::UnexpectedEof),
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

/// What `tar.Reader.Next` returns for a member, after PAX and GNU overrides.
#[derive(Debug, Clone)]
pub(crate) struct GoTarHeader {
    pub name: Vec<u8>,
    pub typeflag: u8,
    pub size: i64,
    pub mode: i64,
}

enum Curr {
    /// `regFileReader`: remaining physical bytes.
    Reg(u64),
    /// `sparseFileReader` over a `regFileReader`.
    Sparse {
        physical: u64,
        holes: Vec<(i64, i64)>,
        pos: i64,
    },
}

pub(crate) struct GoTar<R: Read> {
    r: R,
    pad: u64,
    curr: Curr,
    blk: [u8; BLOCK],
    /// `Reader.err`: a body read error that arrived together with data (and so
    /// was not reported to the caller) is returned by the next `Next`.
    sticky: Option<TarError>,
}

type Pax = BTreeMap<Vec<u8>, Vec<u8>>;

/// The numeric fields and prefix that `readHeader` derives from one block.
struct RawHeader {
    name: Vec<u8>,
    typeflag: u8,
    size: i64,
    mode: i64,
}

fn parse_string(field: &[u8]) -> &[u8] {
    field
        .iter()
        .position(|byte| *byte == 0)
        .map_or(field, |nul| &field[..nul])
}

fn is_header_only_type(flag: u8) -> bool {
    matches!(
        flag,
        TYPE_LINK | TYPE_SYMLINK | TYPE_CHAR | TYPE_BLOCK | TYPE_DIR | TYPE_FIFO
    )
}

fn block_padding(n: u64) -> u64 {
    n.wrapping_neg() & (BLOCK as u64 - 1)
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Format {
    Unknown,
    V7,
    UstarPax,
    Star,
    Gnu,
}

/// `block.getFormat`: the checksum and the magic decide the format.
fn get_format(blk: &[u8; BLOCK]) -> Format {
    let Ok(value) = go_parse_octal(&blk[148..156]) else {
        return Format::Unknown;
    };
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (index, byte) in blk.iter().enumerate() {
        let byte = if (148..156).contains(&index) {
            b' '
        } else {
            *byte
        };
        unsigned += i64::from(byte);
        signed += i64::from(byte as i8);
    }
    if value != unsigned && value != signed {
        return Format::Unknown;
    }
    let magic = &blk[257..263];
    let version = &blk[263..265];
    let trailer = &blk[508..512];
    if magic == b"ustar\0" && trailer == b"tar\0" {
        Format::Star
    } else if magic == b"ustar\0" {
        Format::UstarPax
    } else if magic == b"ustar " && version == b" \0" {
        Format::Gnu
    } else {
        Format::V7
    }
}

/// `Reader.readHeader` after the zero-block handling: the checksum/format
/// check and the numeric fields of one header block.
fn read_header_fields(blk: &[u8; BLOCK]) -> Result<RawHeader, TarError> {
    let format = get_format(blk);
    if format == Format::Unknown {
        return Err(TarError::Header);
    }
    let numeric = |start: usize, len: usize| go_parse_numeric(&blk[start..start + len]);
    let mut failed = false;
    let mut num = |start: usize, len: usize| match numeric(start, len) {
        Ok(value) => value,
        Err(()) => {
            failed = true;
            0
        }
    };
    let typeflag = blk[156];
    let mut name = parse_string(&blk[0..100]).to_vec();
    let size = num(124, 12);
    let mode = num(100, 8);
    num(108, 8);
    num(116, 8);
    num(136, 12);

    if format != Format::V7 {
        num(329, 8);
        num(337, 8);
        let mut prefix: &[u8] = &[];
        match format {
            Format::UstarPax => prefix = parse_string(&blk[345..500]),
            Format::Star => {
                prefix = parse_string(&blk[345..476]);
                num(476, 12);
                num(488, 12);
            }
            Format::Gnu => {
                // A bad atime/ctime is not an error: the times are dropped and
                // the overlapping USTAR prefix is read when it is ASCII.
                let mut demoted = false;
                for start in [345usize, 357] {
                    if blk[start] != 0 && numeric(start, 12).is_err() {
                        demoted = true;
                    }
                }
                if demoted {
                    let candidate = parse_string(&blk[345..500]);
                    if candidate.is_ascii() {
                        prefix = candidate;
                    }
                }
            }
            Format::Unknown | Format::V7 => {}
        }
        if !prefix.is_empty() {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(&name);
            name = joined;
        }
    }
    if failed {
        return Err(TarError::Header);
    }
    Ok(RawHeader {
        name,
        typeflag,
        size,
        mode,
    })
}

fn parse_dec(value: &[u8]) -> Result<i64, TarError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse::<i64>().ok())
        .ok_or(TarError::Header)
}

/// `parsePAXTime`, validated only (the value itself is never used).
fn check_pax_time(value: &[u8]) -> Result<(), TarError> {
    let (secs, nanos) = match value.iter().position(|byte| *byte == b'.') {
        Some(dot) => (&value[..dot], &value[dot + 1..]),
        None => (value, &[][..]),
    };
    parse_dec(secs)?;
    if nanos.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(TarError::Header);
    }
    Ok(())
}

/// A PAX record split into key, value and the bytes after it.
type PaxRecord<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// `parsePAXRecord`: `<len> <key>=<value>\n`.
fn parse_pax_record(s: &[u8]) -> Result<PaxRecord<'_>, TarError> {
    let space = s
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(TarError::Header)?;
    let (n_str, rest) = (&s[..space], &s[space + 1..]);
    let n = parse_dec(n_str)?;
    if n < 5 || n > s.len() as i64 {
        return Err(TarError::Header);
    }
    let n = n - (n_str.len() as i64 + 1);
    if n <= 0 {
        return Err(TarError::Header);
    }
    let n = n as usize;
    let (record, newline, remainder) = (&rest[..n - 1], &rest[n - 1..n], &rest[n..]);
    if newline != b"\n" {
        return Err(TarError::Header);
    }
    let equals = record
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(TarError::Header)?;
    let (key, value) = (&record[..equals], &record[equals + 1..]);
    if key.is_empty() {
        return Err(TarError::Header);
    }
    let has_nul = |bytes: &[u8]| bytes.contains(&0);
    let valid = match key {
        b"path" | b"linkpath" | b"uname" | b"gname" => !has_nul(value),
        _ => !has_nul(key),
    };
    if !valid {
        return Err(TarError::Header);
    }
    Ok((key, value, remainder))
}

const SPARSE_OFFSET: &[u8] = b"GNU.sparse.offset";
const SPARSE_NUM_BYTES: &[u8] = b"GNU.sparse.numbytes";
const SPARSE_MAP: &[u8] = b"GNU.sparse.map";

/// `parsePAX` over the special file's bytes.
fn parse_pax(buf: &[u8]) -> Result<Pax, TarError> {
    let mut pax = Pax::new();
    let mut sparse_map: Vec<&[u8]> = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let (key, value, residual) = parse_pax_record(rest)?;
        rest = residual;
        if key == SPARSE_OFFSET || key == SPARSE_NUM_BYTES {
            let expected: &[u8] = if sparse_map.len().is_multiple_of(2) {
                SPARSE_OFFSET
            } else {
                SPARSE_NUM_BYTES
            };
            if key != expected || value.contains(&b',') {
                return Err(TarError::Header);
            }
            sparse_map.push(value);
        } else {
            pax.insert(key.to_vec(), value.to_vec());
        }
    }
    if !sparse_map.is_empty() {
        pax.insert(SPARSE_MAP.to_vec(), sparse_map.join(&b","[..]));
    }
    Ok(pax)
}

/// `mergePAX`: the records that change the header, validated like Go.
fn merge_pax(header: &mut GoTarHeader, pax: &Pax) -> Result<(), TarError> {
    for (key, value) in pax {
        if value.is_empty() {
            continue; // keep the original USTAR value
        }
        match key.as_slice() {
            b"path" => header.name = value.clone(),
            b"uid" | b"gid" => {
                parse_dec(value)?;
            }
            b"atime" | b"mtime" | b"ctime" => check_pax_time(value)?,
            b"size" => header.size = parse_dec(value)?,
            _ => {}
        }
    }
    Ok(())
}

type Sparse = Vec<(i64, i64)>;

/// The token buffer behind `readGNUSparseMap1x0`.
#[derive(Default)]
struct Map1x0 {
    buffer: Vec<u8>,
    consumed: usize,
    newlines: i64,
    total: usize,
}

impl Map1x0 {
    /// `nextToken`: one line without its newline (the rest when there is none).
    fn next_token(&mut self) -> Vec<u8> {
        self.newlines -= 1;
        let rest = &self.buffer[self.consumed..];
        match rest.iter().position(|byte| *byte == b'\n') {
            Some(end) => {
                let token = rest[..end].to_vec();
                self.consumed += end + 1;
                token
            }
            None => {
                let token = rest.to_vec();
                self.consumed = self.buffer.len();
                token
            }
        }
    }
}

fn append_sparse_entry(spd: &mut Sparse, entry: (i64, i64)) -> Result<(), TarError> {
    if spd.len() >= MAX_SPARSE_FILE_ENTRIES {
        return Err(TarError::SparseTooLong);
    }
    spd.push(entry);
    Ok(())
}

fn validate_sparse_entries(sp: &[(i64, i64)], size: i64) -> bool {
    if size < 0 {
        return false;
    }
    let mut pre_end = 0i64;
    for &(offset, length) in sp {
        if offset < 0 || length < 0 || offset > i64::MAX - length {
            return false;
        }
        let end = offset + length;
        if end > size || pre_end > offset {
            return false;
        }
        pre_end = end;
    }
    true
}

fn invert_sparse_entries(src: &[(i64, i64)], size: i64) -> Vec<(i64, i64)> {
    let mut dst = Vec::new();
    let mut pre = (0i64, 0i64);
    for &(offset, length) in src {
        if length == 0 {
            continue;
        }
        pre.1 = offset - pre.0;
        if pre.1 > 0 {
            dst.push(pre);
        }
        pre.0 = offset + length;
    }
    pre.1 = size - pre.0;
    dst.push(pre);
    dst
}

fn pax_value<'a>(pax: &'a Pax, key: &[u8]) -> &'a [u8] {
    pax.get(key).map_or(&[][..], Vec::as_slice)
}

impl<R: Read> GoTar<R> {
    pub(crate) fn new(r: R) -> Self {
        Self {
            r,
            pad: 0,
            curr: Curr::Reg(0),
            blk: [0; BLOCK],
            sticky: None,
        }
    }

    /// One read of the layer below; `Ok(0)` is its end of stream.
    fn raw_read(&mut self, buf: &mut [u8]) -> Result<usize, TarError> {
        loop {
            match self.r.read(buf) {
                Ok(n) => return Ok(n),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(TarError::Io(error)),
            }
        }
    }

    /// `tryReadFull` on the layer below: bytes read, then the error that
    /// stopped the read (`Eof` when the stream ended first).
    fn try_read_full(&mut self, buf: &mut [u8]) -> (usize, Option<TarError>) {
        let mut n = 0;
        while n < buf.len() {
            match self.raw_read(&mut buf[n..]) {
                Ok(0) => return (n, Some(TarError::Eof)),
                Ok(k) => n += k,
                Err(error) => return (n, Some(error)),
            }
        }
        (n, None)
    }

    /// `io.ReadFull`: nothing read is `Eof`, a partial read `UnexpectedEof`.
    fn read_full_blk(&mut self) -> Result<(), TarError> {
        let mut block = [0u8; BLOCK];
        let (n, error) = self.try_read_full(&mut block);
        self.blk = block;
        match error {
            None => Ok(()),
            Some(TarError::Eof) if n == 0 => Err(TarError::Eof),
            Some(TarError::Eof) => Err(TarError::UnexpectedEof),
            Some(other) => Err(other),
        }
    }

    /// `regFileReader.Read` over `nb` remaining physical bytes.
    fn reg_read(&mut self, nb: &mut u64, buf: &mut [u8]) -> (usize, Option<TarError>) {
        let want = (buf.len() as u64).min(*nb) as usize;
        let mut n = 0;
        let mut error = None;
        if want > 0 {
            match self.raw_read(&mut buf[..want]) {
                Ok(0) => error = Some(TarError::Eof),
                Ok(k) => n = k,
                Err(e) => error = Some(e),
            }
            *nb -= n as u64;
        }
        match error {
            Some(TarError::Eof) if *nb > 0 => (n, Some(TarError::UnexpectedEof)),
            None if *nb == 0 => (n, Some(TarError::Eof)),
            other => (n, other),
        }
    }

    /// `tryReadFull` over the current file reader.
    fn curr_try_read_full(&mut self, buf: &mut [u8]) -> (usize, Option<TarError>) {
        let mut n = 0;
        let mut error = None;
        while n < buf.len() && error.is_none() {
            let (k, e) = self.curr_read(&mut buf[n..]);
            n += k;
            error = e;
        }
        if n == buf.len() && matches!(error, Some(TarError::Eof)) {
            error = None;
        }
        (n, error)
    }

    fn must_read_full_curr(&mut self, buf: &mut [u8]) -> Result<(), TarError> {
        match self.curr_try_read_full(buf) {
            (_, None) => Ok(()),
            (_, Some(TarError::Eof)) => Err(TarError::UnexpectedEof),
            (_, Some(other)) => Err(other),
        }
    }

    /// `Reader.Read` / `curr.Read`: Go's `(n, err)` pair.
    fn curr_read(&mut self, buf: &mut [u8]) -> (usize, Option<TarError>) {
        match std::mem::replace(&mut self.curr, Curr::Reg(0)) {
            Curr::Reg(mut nb) => {
                let result = self.reg_read(&mut nb, buf);
                self.curr = Curr::Reg(nb);
                result
            }
            Curr::Sparse {
                mut physical,
                mut holes,
                mut pos,
            } => {
                let result = self.sparse_read(&mut physical, &mut holes, &mut pos, buf);
                self.curr = Curr::Sparse {
                    physical,
                    holes,
                    pos,
                };
                result
            }
        }
    }

    fn sparse_read(
        &mut self,
        physical: &mut u64,
        holes: &mut Vec<(i64, i64)>,
        pos: &mut i64,
        buf: &mut [u8],
    ) -> (usize, Option<TarError>) {
        let end_of_last = |holes: &[(i64, i64)]| {
            let (offset, length) = holes[holes.len() - 1];
            offset + length
        };
        let logical = end_of_last(holes) - *pos;
        let finished = buf.len() as i64 >= logical;
        let buf = if finished {
            &mut buf[..logical.max(0) as usize]
        } else {
            buf
        };
        let end_pos = *pos + buf.len() as i64;
        let mut done = 0usize;
        let mut error = None;
        while end_pos > *pos && error.is_none() {
            let (hole_start, hole_end) = (holes[0].0, holes[0].0 + holes[0].1);
            let remaining = buf.len() - done;
            let nf;
            if *pos < hole_start {
                let want = (remaining as i64).min(hole_start - *pos) as usize;
                let chunk = &mut buf[done..done + want];
                let mut n = 0;
                let mut e = None;
                while n < chunk.len() && e.is_none() {
                    let (k, err) = self.reg_read(physical, &mut chunk[n..]);
                    n += k;
                    e = err;
                }
                if n == chunk.len() && matches!(e, Some(TarError::Eof)) {
                    e = None;
                }
                nf = n;
                error = e;
            } else {
                let want = (remaining as i64).min(hole_end - *pos) as usize;
                buf[done..done + want].fill(0);
                nf = want;
            }
            done += nf;
            *pos += nf as i64;
            if *pos >= hole_end && holes.len() > 1 {
                holes.remove(0);
            }
        }
        let logical_after = end_of_last(holes) - *pos;
        match error {
            Some(TarError::Eof) => (done, Some(TarError::MissData)),
            Some(other) => (done, Some(other)),
            None if logical_after == 0 && *physical > 0 => (done, Some(TarError::UnrefData)),
            None if finished => (done, Some(TarError::Eof)),
            None => (done, None),
        }
    }

    fn physical_remaining(&self) -> u64 {
        match &self.curr {
            Curr::Reg(nb) => *nb,
            Curr::Sparse { physical, .. } => *physical,
        }
    }

    /// `discard(r, n)`: read and drop `n` bytes.
    fn discard(&mut self, mut n: u64) -> Result<(), TarError> {
        let mut scratch = [0u8; 4096];
        while n > 0 {
            let want = (n as usize).min(scratch.len());
            match self.raw_read(&mut scratch[..want])? {
                0 => return Err(TarError::UnexpectedEof),
                k => n -= k as u64,
            }
        }
        Ok(())
    }

    /// `readSpecialFile`: the whole current file, at most 1 MiB.
    fn read_special_file(&mut self) -> Result<Vec<u8>, TarError> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        while out.len() < MAX_SPECIAL_FILE_SIZE + 1 {
            let want = chunk.len().min(MAX_SPECIAL_FILE_SIZE + 1 - out.len());
            let (n, error) = self.curr_read(&mut chunk[..want]);
            out.extend_from_slice(&chunk[..n]);
            match error {
                None => {}
                Some(TarError::Eof) => break,
                Some(other) => {
                    if out.len() > MAX_SPECIAL_FILE_SIZE {
                        return Err(TarError::FieldTooLong);
                    }
                    return Err(other);
                }
            }
        }
        if out.len() > MAX_SPECIAL_FILE_SIZE {
            return Err(TarError::FieldTooLong);
        }
        Ok(out)
    }

    /// `handleRegularFile`.
    fn handle_regular_file(&mut self, header: &GoTarHeader) -> Result<(), TarError> {
        let nb = if is_header_only_type(header.typeflag) {
            0
        } else {
            header.size
        };
        if nb < 0 {
            return Err(TarError::Header);
        }
        self.pad = block_padding(nb as u64);
        self.curr = Curr::Reg(nb as u64);
        Ok(())
    }

    /// `readOldGNUSparseMap`; `raw` is the member's header block.
    fn read_old_gnu_sparse_map(
        &mut self,
        header: &mut GoTarHeader,
        raw: [u8; BLOCK],
    ) -> Result<Sparse, TarError> {
        if get_format(&raw) != Format::Gnu {
            return Err(TarError::Header);
        }
        header.size = go_parse_numeric(&raw[483..495]).map_err(|()| TarError::Header)?;
        let mut spd = Sparse::new();
        let mut block = raw;
        // The first array is 4 entries at 386 plus the extension flag at 482.
        let (mut start, mut entries, mut flag_at) = (386usize, 4usize, 482usize);
        let mut total = 97usize;
        while total < MAX_SPECIAL_FILE_SIZE {
            for i in 0..entries {
                let entry = &block[start + i * 24..start + i * 24 + 24];
                if entry[0] == 0 {
                    break;
                }
                let offset = go_parse_numeric(&entry[..12]).map_err(|()| TarError::Header)?;
                let length = go_parse_numeric(&entry[12..24]).map_err(|()| TarError::Header)?;
                append_sparse_entry(&mut spd, (offset, length))?;
            }
            if block[flag_at] > 0 {
                let mut next = [0u8; BLOCK];
                self.must_read_full_curr_raw(&mut next)?;
                block = next;
                (start, entries, flag_at) = (0, 21, 504);
                total += BLOCK;
                continue;
            }
            return Ok(spd);
        }
        Err(TarError::SparseTooLong)
    }

    /// `mustReadFull(tr.r, blk)`: a block straight from the stream.
    fn must_read_full_curr_raw(&mut self, block: &mut [u8; BLOCK]) -> Result<(), TarError> {
        match self.try_read_full(block) {
            (_, None) => Ok(()),
            (_, Some(TarError::Eof)) => Err(TarError::UnexpectedEof),
            (_, Some(other)) => Err(other),
        }
    }

    /// `feedTokens`: read whole blocks until `n` newlines are buffered.
    fn feed_tokens(&mut self, map: &mut Map1x0, n: i64) -> Result<(), TarError> {
        while map.newlines < n {
            map.total += BLOCK;
            if map.total > MAX_SPECIAL_FILE_SIZE {
                return Err(TarError::SparseTooLong);
            }
            let mut block = [0u8; BLOCK];
            self.must_read_full_curr(&mut block)?;
            map.buffer.extend_from_slice(&block);
            map.newlines += block.iter().filter(|byte| **byte == b'\n').count() as i64;
        }
        Ok(())
    }

    /// `readGNUSparseMap1x0`: the map is the first blocks of the file data.
    fn read_gnu_sparse_map_1x0(&mut self) -> Result<Sparse, TarError> {
        let mut map = Map1x0::default();
        self.feed_tokens(&mut map, 1)?;
        let num_entries = parse_dec(&map.next_token())?;
        if num_entries < 0 || num_entries.wrapping_mul(2) < num_entries {
            return Err(TarError::Header);
        }
        self.feed_tokens(&mut map, num_entries.wrapping_mul(2))?;
        let mut spd = Sparse::new();
        for _ in 0..num_entries {
            let offset = parse_dec(&map.next_token());
            let length = parse_dec(&map.next_token());
            let (Ok(offset), Ok(length)) = (offset, length) else {
                return Err(TarError::Header);
            };
            append_sparse_entry(&mut spd, (offset, length))?;
        }
        Ok(spd)
    }

    /// `readGNUSparseMap0x1`: the map comes from the PAX records.
    fn read_gnu_sparse_map_0x1(pax: &Pax) -> Result<Sparse, TarError> {
        let num_entries = parse_dec(pax_value(pax, b"GNU.sparse.numblocks"))?;
        if num_entries < 0 || num_entries.wrapping_mul(2) < num_entries {
            return Err(TarError::Header);
        }
        let joined = pax_value(pax, SPARSE_MAP);
        let mut parts: Vec<&[u8]> = joined.split(|byte| *byte == b',').collect();
        if parts.len() == 1 && parts[0].is_empty() {
            parts.clear();
        }
        if parts.len() as i64 != num_entries.wrapping_mul(2) {
            return Err(TarError::Header);
        }
        let mut spd = Sparse::new();
        for pair in parts.chunks(2) {
            let (Ok(offset), Ok(length)) = (parse_dec(pair[0]), parse_dec(pair[1])) else {
                return Err(TarError::Header);
            };
            append_sparse_entry(&mut spd, (offset, length))?;
        }
        Ok(spd)
    }

    /// `readGNUSparsePAXHeaders`.
    fn read_gnu_sparse_pax_headers(
        &mut self,
        header: &mut GoTarHeader,
        pax: &Pax,
    ) -> Result<Option<Sparse>, TarError> {
        let major = pax_value(pax, b"GNU.sparse.major");
        let minor = pax_value(pax, b"GNU.sparse.minor");
        let is_1x0 = if major == b"0" && (minor == b"0" || minor == b"1") {
            false
        } else if major == b"1" && minor == b"0" {
            true
        } else if !major.is_empty() || !minor.is_empty() {
            return Ok(None);
        } else if !pax_value(pax, SPARSE_MAP).is_empty() {
            false
        } else {
            return Ok(None);
        };
        let name = pax_value(pax, b"GNU.sparse.name");
        if !name.is_empty() {
            header.name = name.to_vec();
        }
        let mut size = pax_value(pax, b"GNU.sparse.size");
        if size.is_empty() {
            size = pax_value(pax, b"GNU.sparse.realsize");
        }
        if !size.is_empty() {
            header.size = parse_dec(size)?;
        }
        if is_1x0 {
            self.read_gnu_sparse_map_1x0().map(Some)
        } else {
            Self::read_gnu_sparse_map_0x1(pax).map(Some)
        }
    }

    /// `handleSparseFile`.
    fn handle_sparse_file(
        &mut self,
        header: &mut GoTarHeader,
        raw: [u8; BLOCK],
        pax: &Pax,
    ) -> Result<(), TarError> {
        let spd = if header.typeflag == TYPE_GNU_SPARSE {
            Some(self.read_old_gnu_sparse_map(header, raw)?)
        } else {
            self.read_gnu_sparse_pax_headers(header, pax)?
        };
        if let Some(spd) = spd {
            if is_header_only_type(header.typeflag) || !validate_sparse_entries(&spd, header.size) {
                return Err(TarError::Header);
            }
            let holes = invert_sparse_entries(&spd, header.size);
            let physical = self.physical_remaining();
            self.curr = Curr::Sparse {
                physical,
                holes,
                pos: 0,
            };
        }
        Ok(())
    }

    /// `Reader.readHeader`: the next header block, with Go's end-of-archive rules.
    fn read_header(&mut self) -> Result<(RawHeader, [u8; BLOCK]), TarError> {
        self.read_full_blk()?;
        if self.blk.iter().all(|byte| *byte == 0) {
            self.read_full_blk()?;
            if self.blk.iter().all(|byte| *byte == 0) {
                return Err(TarError::Eof);
            }
            return Err(TarError::Header);
        }
        let raw = self.blk;
        let fields = read_header_fields(&raw)?;
        Ok((fields, raw))
    }

    /// `Reader.Next`. `Ok(None)` is the clean end of the archive.
    pub(crate) fn next(&mut self) -> Result<Option<GoTarHeader>, TarError> {
        if let Some(error) = self.sticky.take() {
            return Err(error);
        }
        match self.next_inner() {
            Ok(header) => Ok(Some(header)),
            Err(TarError::Eof) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn next_inner(&mut self) -> Result<GoTarHeader, TarError> {
        let mut pax = Pax::new();
        let mut gnu_long_name: Vec<u8> = Vec::new();
        loop {
            // Discard the rest of the previous file and its padding.
            let remaining = self.physical_remaining();
            self.discard(remaining)?;
            self.curr = Curr::Reg(0);
            let pad = self.pad as usize;
            if pad > 0 {
                let mut padding = vec![0u8; pad];
                match self.try_read_full(&mut padding) {
                    (_, None) => {}
                    (_, Some(error)) => return Err(error),
                }
            }
            self.pad = 0;

            let (fields, raw) = self.read_header()?;
            let mut header = GoTarHeader {
                name: fields.name,
                typeflag: fields.typeflag,
                size: fields.size,
                mode: fields.mode,
            };
            self.handle_regular_file(&header)?;

            match header.typeflag {
                TYPE_XHEADER | TYPE_XGLOBAL => {
                    let buf = self.read_special_file()?;
                    pax = parse_pax(&buf)?;
                    if header.typeflag == TYPE_XGLOBAL {
                        merge_pax(&mut header, &pax)?;
                        return Ok(header);
                    }
                }
                TYPE_GNU_LONGNAME | TYPE_GNU_LONGLINK => {
                    let buf = self.read_special_file()?;
                    if header.typeflag == TYPE_GNU_LONGNAME {
                        gnu_long_name = parse_string(&buf).to_vec();
                    }
                }
                _ => {
                    merge_pax(&mut header, &pax)?;
                    if !gnu_long_name.is_empty() {
                        header.name = gnu_long_name;
                    }
                    if header.typeflag == TYPE_REG_A {
                        header.typeflag = if header.name.ends_with(b"/") {
                            TYPE_DIR
                        } else {
                            TYPE_REG
                        };
                    }
                    // The extended headers may have updated the size.
                    self.handle_regular_file(&header)?;
                    // Sparse formats read from the logical data section.
                    self.handle_sparse_file(&mut header, raw, &pax)?;
                    return Ok(header);
                }
            }
        }
    }
}

/// Reads the body of the member `next` returned, like `tar.Reader.Read`.
impl<R: Read> Read for GoTar<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (n, error) = self.curr_read(buf);
        if n > 0 {
            // Like `io.CopyN`, a caller that has all the bytes it asked for
            // never sees the error; `Next` reports it.
            if let Some(error) = error.filter(|error| !matches!(error, TarError::Eof)) {
                self.sticky = Some(error);
            }
            return Ok(n);
        }
        match error {
            None | Some(TarError::Eof) => Ok(0),
            Some(error) => Err(error.into_io()),
        }
    }
}
