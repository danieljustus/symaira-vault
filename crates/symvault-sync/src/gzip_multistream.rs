//! A gzip reader with the semantics of Go's `compress/gzip.Reader` in its
//! default multistream mode (IO-002, #1499).
//!
//! `flate2::read::GzDecoder` stops after the first member, so a tar stream
//! split across members, or bytes trailing a member, behave differently from
//! production Go. This reader walks the members itself, on top of
//! `flate2::bufread::DeflateDecoder`, so the observable results match Go:
//!
//! * members are concatenated into one stream; an empty member is fine;
//! * a clean end of input at a member boundary ends the stream; anything else
//!   there is parsed as the next header (`unexpected EOF` for fewer than ten
//!   bytes, `gzip: invalid header` for a wrong magic or method);
//! * every member's CRC-32 and length are verified when its data ends
//!   (`gzip: invalid checksum`), and a short trailer is `unexpected EOF`;
//! * the first failure is sticky.
//!
//! Like Go, the work for the end of a member happens on the read after its
//! last byte, so a consumer that stops reading earlier (a tar reader that
//! has seen its end-of-archive marker) never observes what follows.
use flate2::{Crc, bufread::DeflateDecoder};
use std::io::{self, BufRead, BufReader, Read};

/// Go's `gzip.Reader` buffer for header strings (`[512]byte`).
const MAX_HEADER_STRING: usize = 512;

const FLAG_HEADER_CRC: u8 = 1 << 1;
const FLAG_EXTRA: u8 = 1 << 2;
const FLAG_NAME: u8 = 1 << 3;
const FLAG_COMMENT: u8 = 1 << 4;

/// Failures of the gzip framing, worded like Go's.
#[derive(Debug)]
enum Fault {
    /// No byte at all where a header was expected.
    Eof,
    UnexpectedEof,
    Header,
    Checksum,
    Io(io::Error),
}

impl Fault {
    fn text(&self) -> String {
        match self {
            Self::Eof => "EOF".to_owned(),
            Self::UnexpectedEof => "unexpected EOF".to_owned(),
            Self::Header => "gzip: invalid header".to_owned(),
            Self::Checksum => "gzip: invalid checksum".to_owned(),
            Self::Io(error) => error.to_string(),
        }
    }

    fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Eof | Self::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            Self::Header | Self::Checksum => io::ErrorKind::InvalidData,
            Self::Io(error) => error.kind(),
        }
    }

    /// Go's `noEOF`: an end of input inside a header or trailer is never a
    /// clean end.
    fn no_eof(self) -> Self {
        match self {
            Self::Eof => Self::UnexpectedEof,
            other => other,
        }
    }
}

/// `io.ReadFull`: `Eof` when nothing was read, `UnexpectedEof` when the input
/// ended part-way.
fn read_full(input: &mut impl BufRead, buffer: &mut [u8]) -> Result<(), Fault> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) if filled == 0 => return Err(Fault::Eof),
            Ok(0) => return Err(Fault::UnexpectedEof),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Fault::Io(error)),
        }
    }
    Ok(())
}

/// A NUL-terminated header string; its bytes (and the NUL) go into `seen` for
/// the optional header checksum.
fn read_string(input: &mut impl BufRead, seen: &mut Vec<u8>) -> Result<(), Fault> {
    for index in 0.. {
        if index >= MAX_HEADER_STRING {
            return Err(Fault::Header);
        }
        let mut byte = [0u8; 1];
        read_full(input, &mut byte).map_err(Fault::no_eof)?;
        seen.push(byte[0]);
        if byte[0] == 0 {
            break;
        }
    }
    Ok(())
}

/// Go's `readHeader`. Only the framing matters here; the header fields are
/// not exposed.
fn read_header(input: &mut impl BufRead) -> Result<(), Fault> {
    let mut fixed = [0u8; 10];
    read_full(input, &mut fixed)?;
    if fixed[0] != 0x1f || fixed[1] != 0x8b || fixed[2] != 8 {
        return Err(Fault::Header);
    }
    let flags = fixed[3];
    let mut seen = fixed.to_vec();
    if flags & FLAG_EXTRA != 0 {
        let mut length = [0u8; 2];
        read_full(input, &mut length).map_err(Fault::no_eof)?;
        seen.extend_from_slice(&length);
        let mut extra = vec![0u8; usize::from(u16::from_le_bytes(length))];
        read_full(input, &mut extra).map_err(Fault::no_eof)?;
        seen.extend_from_slice(&extra);
    }
    if flags & FLAG_NAME != 0 {
        read_string(input, &mut seen)?;
    }
    if flags & FLAG_COMMENT != 0 {
        read_string(input, &mut seen)?;
    }
    if flags & FLAG_HEADER_CRC != 0 {
        let mut stored = [0u8; 2];
        read_full(input, &mut stored).map_err(Fault::no_eof)?;
        let mut crc = Crc::new();
        crc.update(&seen);
        if u16::from_le_bytes(stored) != (crc.sum() & 0xffff) as u16 {
            return Err(Fault::Header);
        }
    }
    Ok(())
}

enum State<R: Read> {
    /// Waiting for a member header; `first` marks the very first one.
    Header {
        input: BufReader<R>,
        first: bool,
    },
    Body(DeflateDecoder<BufReader<R>>),
    Done,
    Failed(io::ErrorKind, String),
}

/// Reads the concatenated members of a gzip file as one stream, like Go.
pub(crate) struct GoGzip<R: Read> {
    state: Option<State<R>>,
    crc: Crc,
}

impl<R: Read> GoGzip<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            state: Some(State::Header {
                input: BufReader::new(inner),
                first: true,
            }),
            crc: Crc::new(),
        }
    }

    /// Go's `gzip.NewReader` validates the first header eagerly. The error is
    /// Go's text (`EOF`, `unexpected EOF`, `gzip: invalid header`); it is
    /// sticky, so a later read repeats it.
    pub(crate) fn read_first_header(&mut self) -> Result<(), String> {
        let state = self.state.take().expect("state is always restored");
        let (state, outcome) = match state {
            State::Header { mut input, .. } => match read_header(&mut input) {
                Ok(()) => (State::Body(DeflateDecoder::new(input)), Ok(())),
                Err(fault) => {
                    let text = fault.text();
                    (State::Failed(fault.kind(), text.clone()), Err(text))
                }
            },
            other => (other, Ok(())),
        };
        self.state = Some(state);
        outcome
    }

    fn fail(&mut self, fault: Fault) -> io::Error {
        let text = fault.text();
        let kind = fault.kind();
        self.state = Some(State::Failed(kind, text.clone()));
        io::Error::new(kind, text)
    }
}

impl<R: Read> Read for GoGzip<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state.take().expect("state is always restored") {
                State::Failed(kind, text) => {
                    self.state = Some(State::Failed(kind, text.clone()));
                    return Err(io::Error::new(kind, text));
                }
                State::Done => {
                    self.state = Some(State::Done);
                    return Ok(0);
                }
                State::Header { mut input, first } => match read_header(&mut input) {
                    Ok(()) => self.state = Some(State::Body(DeflateDecoder::new(input))),
                    // A clean end of input between members ends the stream; a
                    // file with no member at all is an error, as in Go.
                    Err(Fault::Eof) if !first => self.state = Some(State::Done),
                    Err(fault) => return Err(self.fail(fault)),
                },
                State::Body(mut decoder) => match decoder.read(buffer) {
                    Ok(0) => {
                        let mut input = decoder.into_inner();
                        let mut trailer = [0u8; 8];
                        if let Err(fault) = read_full(&mut input, &mut trailer) {
                            return Err(self.fail(fault.no_eof()));
                        }
                        let digest =
                            u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
                        let size =
                            u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
                        if digest != self.crc.sum() || size != self.crc.amount() {
                            return Err(self.fail(Fault::Checksum));
                        }
                        self.crc.reset();
                        self.state = Some(State::Header {
                            input,
                            first: false,
                        });
                    }
                    Ok(count) => {
                        self.crc.update(&buffer[..count]);
                        self.state = Some(State::Body(decoder));
                        return Ok(count);
                    }
                    // The inflater reports input that ends inside the deflate
                    // stream as "incomplete deflate stream"; Go says
                    // `unexpected EOF`. Other inflate errors keep their own
                    // text (Go's `flate: corrupt input before offset N` has an
                    // offset flate2 does not expose).
                    Err(error)
                        if error.kind() == io::ErrorKind::UnexpectedEof
                            || error.to_string().contains("incomplete") =>
                    {
                        return Err(self.fail(Fault::UnexpectedEof));
                    }
                    Err(error) => {
                        let kind = error.kind();
                        let text = error.to_string();
                        self.state = Some(State::Failed(kind, text));
                        return Err(error);
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    fn member(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn read_all(bytes: &[u8]) -> (Vec<u8>, Option<String>) {
        let mut reader = GoGzip::new(bytes);
        let mut out = Vec::new();
        match reader.read_to_end(&mut out) {
            Ok(_) => (out, None),
            Err(error) => (out, Some(error.to_string())),
        }
    }

    #[test]
    fn concatenated_members_read_as_one_stream() {
        let mut bytes = member(b"hello ");
        bytes.extend(member(b""));
        bytes.extend(member(b"world"));
        assert_eq!(read_all(&bytes), (b"hello world".to_vec(), None));
    }

    #[test]
    fn short_or_wrong_bytes_after_a_member_are_header_errors() {
        for (tail, expected) in [
            (vec![0u8; 1], "unexpected EOF"),
            (vec![0u8; 9], "unexpected EOF"),
            (vec![0u8; 10], "gzip: invalid header"),
            (b"trailing garbage".to_vec(), "gzip: invalid header"),
            (
                vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff],
                "unexpected EOF",
            ),
        ] {
            let mut bytes = member(b"data");
            bytes.extend(&tail);
            let (out, error) = read_all(&bytes);
            assert_eq!(out, b"data", "data before the damage is delivered");
            assert_eq!(error.as_deref(), Some(expected), "tail {tail:?}");
        }
    }

    #[test]
    fn checksum_and_length_are_verified_per_member() {
        for offset in [8, 4] {
            let mut bytes = member(b"first");
            let at = bytes.len() - offset;
            bytes[at] ^= 0xff;
            bytes.extend(member(b"second"));
            let (_, error) = read_all(&bytes);
            assert_eq!(error.as_deref(), Some("gzip: invalid checksum"));
        }
    }

    #[test]
    fn truncated_member_and_trailer_are_unexpected_eof() {
        let packed = member(b"some payload that is long enough to need a body");
        let (_, error) = read_all(&packed[..packed.len() / 2]);
        assert_eq!(error.as_deref(), Some("unexpected EOF"));
        let (_, error) = read_all(&packed[..packed.len() - 3]);
        assert_eq!(error.as_deref(), Some("unexpected EOF"));
    }

    #[test]
    fn first_header_is_validated_eagerly_with_go_text() {
        for (bytes, expected) in [
            (Vec::new(), "EOF"),
            (vec![0x1f, 0x8b], "unexpected EOF"),
            (vec![0u8; 10], "gzip: invalid header"),
        ] {
            let mut reader = GoGzip::new(bytes.as_slice());
            assert_eq!(reader.read_first_header().unwrap_err(), expected);
        }
    }

    #[test]
    fn header_extra_name_comment_and_crc_are_framed_like_go() {
        // FEXTRA | FNAME | FCOMMENT | FHCRC around a stored empty body.
        let mut header = vec![0x1f, 0x8b, 8, 0x1e, 0, 0, 0, 0, 0, 0xff];
        header.extend([3, 0, b'a', b'b', b'c']);
        header.extend(b"name\0");
        header.extend(b"note\0");
        let mut crc = Crc::new();
        crc.update(&header);
        let mut good = header.clone();
        good.extend(((crc.sum() & 0xffff) as u16).to_le_bytes());
        good.extend([0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(read_all(&good), (Vec::new(), None));

        let mut bad = good.clone();
        let at = header.len();
        bad[at] ^= 0xff;
        assert_eq!(read_all(&bad).1.as_deref(), Some("gzip: invalid header"));

        let mut name_only = header[..10].to_vec();
        name_only[3] = 0x08;
        name_only.extend(vec![b'x'; MAX_HEADER_STRING]);
        assert_eq!(
            read_all(&name_only).1.as_deref(),
            Some("gzip: invalid header")
        );
        let mut short_name = header[..10].to_vec();
        short_name[3] = 0x08;
        short_name.extend(b"ab");
        assert_eq!(read_all(&short_name).1.as_deref(), Some("unexpected EOF"));
    }

    #[test]
    fn failures_are_sticky() {
        let mut bytes = member(b"data");
        bytes.extend([0u8; 10]);
        let mut reader = GoGzip::new(bytes.as_slice());
        let mut out = Vec::new();
        assert!(reader.read_to_end(&mut out).is_err());
        let mut more = [0u8; 4];
        assert_eq!(
            reader.read(&mut more).unwrap_err().to_string(),
            "gzip: invalid header"
        );
    }
}
