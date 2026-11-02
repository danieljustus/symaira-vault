//! A port of Go's `compress/flate` decompressor (`inflate.go`, Go 1.26).
//!
//! The 1PUX and CXF importers read zip members through Go's
//! `archive/zip`, which reports a damaged deflate stream as
//! `flate: corrupt input before offset N`, where `N` is the number of bytes the
//! decoder had consumed when it noticed. The offset depends on exactly how many
//! bytes Go's lazy bit reader had fetched, which no other inflater reproduces,
//! so the decoder, its Huffman tables and its byte accounting follow the Go
//! source step for step. Output is collected up to a caller supplied cap.

use std::fmt;
use std::sync::OnceLock;

const MAX_CODE_LEN: usize = 16;
const MAX_NUM_LIT: usize = 286;
const MAX_NUM_DIST: usize = 30;
const NUM_CODES: usize = 19;
const END_BLOCK_MARKER: usize = 256;
const HISTORY: usize = 32 * 1024;

const HUFFMAN_CHUNK_BITS: u32 = 9;
const HUFFMAN_NUM_CHUNKS: usize = 1 << HUFFMAN_CHUNK_BITS;
const HUFFMAN_COUNT_MASK: u32 = 15;
const HUFFMAN_VALUE_SHIFT: u32 = 4;

const CODE_ORDER: [usize; NUM_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// How Go's inflater ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FlateEnd {
    /// `io.EOF` after the final block.
    Eof,
    /// `io.ErrUnexpectedEOF`: the input ended inside the stream.
    UnexpectedEof,
    /// `flate.CorruptInputError(offset)`.
    Corrupt(i64),
    /// The output cap was reached before the stream ended.
    Capped,
}

impl fmt::Display for FlateEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("EOF"),
            Self::UnexpectedEof => f.write_str("unexpected EOF"),
            Self::Corrupt(offset) => write!(f, "flate: corrupt input before offset {offset}"),
            Self::Capped => f.write_str("output limit reached"),
        }
    }
}

#[derive(Default)]
struct Huffman {
    min: u32,
    chunks: Vec<u32>,
    links: Vec<Vec<u32>>,
    link_mask: u32,
}

impl Huffman {
    fn empty() -> Self {
        Self {
            min: 0,
            chunks: vec![0; HUFFMAN_NUM_CHUNKS],
            links: Vec::new(),
            link_mask: 0,
        }
    }

    /// Go's `huffmanDecoder.init`; `false` is an over- or under-subscribed code.
    fn init(&mut self, lengths: &[i32]) -> bool {
        *self = Self::empty();
        let mut count = [0usize; MAX_CODE_LEN];
        let (mut min, mut max) = (0usize, 0usize);
        for &n in lengths {
            if n == 0 {
                continue;
            }
            let n = n as usize;
            if min == 0 || n < min {
                min = n;
            }
            if n > max {
                max = n;
            }
            count[n] += 1;
        }
        if max == 0 {
            return true;
        }

        let mut code = 0usize;
        let mut nextcode = [0usize; MAX_CODE_LEN];
        for i in min..=max {
            code <<= 1;
            nextcode[i] = code;
            code += count[i];
        }
        if code != 1 << max && !(code == 1 && max == 1) {
            return false;
        }

        self.min = min as u32;
        if max > HUFFMAN_CHUNK_BITS as usize {
            let num_links = 1usize << (max - HUFFMAN_CHUNK_BITS as usize);
            self.link_mask = (num_links - 1) as u32;
            let link = nextcode[HUFFMAN_CHUNK_BITS as usize + 1] >> 1;
            self.links = vec![Vec::new(); HUFFMAN_NUM_CHUNKS - link];
            for j in link..HUFFMAN_NUM_CHUNKS {
                let reverse = ((j as u16).reverse_bits() >> (16 - HUFFMAN_CHUNK_BITS)) as usize;
                let off = j - link;
                self.chunks[reverse] =
                    ((off as u32) << HUFFMAN_VALUE_SHIFT) | (HUFFMAN_CHUNK_BITS + 1);
                self.links[off] = vec![0; num_links];
            }
        }

        for (i, &n) in lengths.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let n = n as usize;
            let code = nextcode[n];
            nextcode[n] += 1;
            let chunk = ((i as u32) << HUFFMAN_VALUE_SHIFT) | n as u32;
            let mut reverse = ((code as u16).reverse_bits() >> (16 - n)) as usize;
            if n <= HUFFMAN_CHUNK_BITS as usize {
                let mut off = reverse;
                while off < self.chunks.len() {
                    self.chunks[off] = chunk;
                    off += 1 << n;
                }
            } else {
                let j = reverse & (HUFFMAN_NUM_CHUNKS - 1);
                let value = (self.chunks[j] >> HUFFMAN_VALUE_SHIFT) as usize;
                reverse >>= HUFFMAN_CHUNK_BITS;
                let linktab = &mut self.links[value];
                let mut off = reverse;
                while off < linktab.len() {
                    linktab[off] = chunk;
                    off += 1 << (n - HUFFMAN_CHUNK_BITS as usize);
                }
            }
        }
        true
    }
}

fn fixed_decoder() -> &'static Huffman {
    static FIXED: OnceLock<Huffman> = OnceLock::new();
    FIXED.get_or_init(|| {
        let mut bits = [0i32; 288];
        for (i, slot) in bits.iter_mut().enumerate() {
            *slot = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let mut h = Huffman::empty();
        h.init(&bits);
        h
    })
}

struct Inflater<'a> {
    input: &'a [u8],
    /// Bytes consumed so far (`roffset` in Go).
    roffset: i64,
    b: u32,
    nb: u32,
    out: Vec<u8>,
    max_out: usize,
    h1: Huffman,
    h2: Huffman,
    bits: [i32; MAX_NUM_LIT + MAX_NUM_DIST],
    codebits: [i32; NUM_CODES],
}

/// Internal early exit: a terminal state that is not `Eof`.
type Stop = FlateEnd;

impl<'a> Inflater<'a> {
    fn read_byte(&mut self) -> Option<u8> {
        let byte = *self.input.get(self.roffset as usize)?;
        self.roffset += 1;
        Some(byte)
    }

    fn more_bits(&mut self) -> Result<(), Stop> {
        // Go's `moreBits`: a missing byte is `noEOF(io.EOF)`.
        let c = self.read_byte().ok_or(FlateEnd::UnexpectedEof)?;
        self.b |= u32::from(c) << (self.nb & 31);
        self.nb += 8;
        Ok(())
    }

    fn need(&mut self, bits: u32) -> Result<(), Stop> {
        while self.nb < bits {
            self.more_bits()?;
        }
        Ok(())
    }

    fn huff_sym(&mut self, h: &Huffman) -> Result<usize, Stop> {
        let mut n = h.min;
        let (mut nb, mut b) = (self.nb, self.b);
        loop {
            while nb < n {
                let Some(c) = self.read_byte() else {
                    self.b = b;
                    self.nb = nb;
                    return Err(FlateEnd::UnexpectedEof);
                };
                b |= u32::from(c) << (nb & 31);
                nb += 8;
            }
            let mut chunk = h.chunks[(b & (HUFFMAN_NUM_CHUNKS as u32 - 1)) as usize];
            n = chunk & HUFFMAN_COUNT_MASK;
            if n > HUFFMAN_CHUNK_BITS {
                chunk = h.links[(chunk >> HUFFMAN_VALUE_SHIFT) as usize]
                    [((b >> HUFFMAN_CHUNK_BITS) & h.link_mask) as usize];
                n = chunk & HUFFMAN_COUNT_MASK;
            }
            if n <= nb {
                if n == 0 {
                    self.b = b;
                    self.nb = nb;
                    return Err(FlateEnd::Corrupt(self.roffset));
                }
                self.b = b >> (n & 31);
                self.nb = nb - n;
                return Ok((chunk >> HUFFMAN_VALUE_SHIFT) as usize);
            }
        }
    }

    fn read_huffman(&mut self) -> Result<(), Stop> {
        self.need(5 + 5 + 4)?;
        let nlit = (self.b & 0x1F) as usize + 257;
        if nlit > MAX_NUM_LIT {
            return Err(FlateEnd::Corrupt(self.roffset));
        }
        self.b >>= 5;
        let ndist = (self.b & 0x1F) as usize + 1;
        if ndist > MAX_NUM_DIST {
            return Err(FlateEnd::Corrupt(self.roffset));
        }
        self.b >>= 5;
        let nclen = (self.b & 0xF) as usize + 4;
        self.b >>= 4;
        self.nb -= 5 + 5 + 4;

        for &slot in CODE_ORDER.iter().take(nclen) {
            self.need(3)?;
            self.codebits[slot] = (self.b & 0x7) as i32;
            self.b >>= 3;
            self.nb -= 3;
        }
        for &slot in CODE_ORDER.iter().skip(nclen) {
            self.codebits[slot] = 0;
        }
        let mut h1 = std::mem::take(&mut self.h1);
        let ok = h1.init(&self.codebits);
        self.h1 = h1;
        if !ok {
            return Err(FlateEnd::Corrupt(self.roffset));
        }

        let n = nlit + ndist;
        let mut i = 0;
        while i < n {
            let h1 = std::mem::take(&mut self.h1);
            let x = self.huff_sym(&h1);
            self.h1 = h1;
            let x = x?;
            if x < 16 {
                self.bits[i] = x as i32;
                i += 1;
                continue;
            }
            let (mut rep, nb, b): (usize, u32, i32);
            match x {
                16 => {
                    rep = 3;
                    nb = 2;
                    if i == 0 {
                        return Err(FlateEnd::Corrupt(self.roffset));
                    }
                    b = self.bits[i - 1];
                }
                17 => {
                    rep = 3;
                    nb = 3;
                    b = 0;
                }
                _ => {
                    rep = 11;
                    nb = 7;
                    b = 0;
                }
            }
            self.need(nb)?;
            rep += (self.b & ((1u32 << nb) - 1)) as usize;
            self.b >>= nb;
            self.nb -= nb;
            if i + rep > n {
                return Err(FlateEnd::Corrupt(self.roffset));
            }
            for _ in 0..rep {
                self.bits[i] = b;
                i += 1;
            }
        }

        let lit_ok = self.h1.init(&self.bits[..nlit]);
        let dist_ok = lit_ok && self.h2.init(&self.bits[nlit..nlit + ndist]);
        if !lit_ok || !dist_ok {
            return Err(FlateEnd::Corrupt(self.roffset));
        }
        let end_marker = self.bits[END_BLOCK_MARKER] as u32;
        if self.h1.min < end_marker {
            self.h1.min = end_marker;
        }
        Ok(())
    }

    /// Whether the output cap has been exceeded; the byte that crosses it is
    /// the proof the caller needs, so decoding stops one byte past the cap.
    fn full(&self) -> bool {
        self.out.len() > self.max_out
    }

    fn huffman_block(&mut self, fixed: bool) -> Result<(), Stop> {
        // `hl`/`hd` are taken out of `self` for the duration of the block.
        let hl = if fixed {
            None
        } else {
            Some(std::mem::take(&mut self.h1))
        };
        let hd = if fixed {
            None
        } else {
            Some(std::mem::take(&mut self.h2))
        };
        let result = self.huffman_block_inner(hl.as_ref(), hd.as_ref());
        if let Some(h) = hl {
            self.h1 = h;
        }
        if let Some(h) = hd {
            self.h2 = h;
        }
        result
    }

    fn huffman_block_inner(
        &mut self,
        hl: Option<&Huffman>,
        hd: Option<&Huffman>,
    ) -> Result<(), Stop> {
        let lit = hl.unwrap_or_else(|| fixed_decoder());
        loop {
            if self.full() {
                return Err(FlateEnd::Capped);
            }
            let v = self.huff_sym(lit)?;
            let (mut length, n): (usize, u32);
            match v {
                0..=255 => {
                    self.out.push(v as u8);
                    continue;
                }
                256 => return Ok(()),
                257..=264 => {
                    length = v - (257 - 3);
                    n = 0;
                }
                265..=268 => {
                    length = v * 2 - (265 * 2 - 11);
                    n = 1;
                }
                269..=272 => {
                    length = v * 4 - (269 * 4 - 19);
                    n = 2;
                }
                273..=276 => {
                    length = v * 8 - (273 * 8 - 35);
                    n = 3;
                }
                277..=280 => {
                    length = v * 16 - (277 * 16 - 67);
                    n = 4;
                }
                281..=284 => {
                    length = v * 32 - (281 * 32 - 131);
                    n = 5;
                }
                285 => {
                    length = 258;
                    n = 0;
                }
                _ => return Err(FlateEnd::Corrupt(self.roffset)),
            }
            if n > 0 {
                self.need(n)?;
                length += (self.b & ((1u32 << n) - 1)) as usize;
                self.b >>= n;
                self.nb -= n;
            }

            let mut dist: usize;
            match hd {
                None => {
                    self.need(5)?;
                    dist = usize::from((((self.b & 0x1F) << 3) as u8).reverse_bits());
                    self.b >>= 5;
                    self.nb -= 5;
                }
                Some(h) => dist = self.huff_sym(h)?,
            }

            if dist < 4 {
                dist += 1;
            } else if dist < MAX_NUM_DIST {
                let nb = ((dist - 2) >> 1) as u32;
                let mut extra = (dist & 1) << nb;
                self.need(nb)?;
                extra |= (self.b & ((1u32 << nb) - 1)) as usize;
                self.b >>= nb;
                self.nb -= nb;
                dist = (1usize << (nb + 1)) + 1 + extra;
            } else {
                return Err(FlateEnd::Corrupt(self.roffset));
            }

            if dist > self.out.len().min(HISTORY) {
                return Err(FlateEnd::Corrupt(self.roffset));
            }
            let start = self.out.len() - dist;
            for k in 0..length {
                let byte = self.out[start + k];
                self.out.push(byte);
            }
        }
    }

    /// Go's `dataBlock` (stored block).
    fn data_block(&mut self) -> Result<(), Stop> {
        self.nb = 0;
        self.b = 0;
        let available = self.input.len().saturating_sub(self.roffset as usize);
        let nr = available.min(4);
        let header = self.input[self.roffset as usize..self.roffset as usize + nr].to_vec();
        self.roffset += nr as i64;
        if nr < 4 {
            return Err(FlateEnd::UnexpectedEof);
        }
        let n = usize::from(header[0]) | usize::from(header[1]) << 8;
        let nn = usize::from(header[2]) | usize::from(header[3]) << 8;
        if nn as u16 != !(n as u16) {
            return Err(FlateEnd::Corrupt(self.roffset));
        }
        if n == 0 {
            return Ok(());
        }
        let available = self.input.len().saturating_sub(self.roffset as usize);
        let cnt = available.min(n);
        // Bytes read before a short read are still delivered by Go.
        let room = (self.max_out + 1).saturating_sub(self.out.len());
        let take = cnt.min(room);
        let start = self.roffset as usize;
        self.out.extend_from_slice(&self.input[start..start + take]);
        self.roffset += cnt as i64;
        if self.full() {
            return Err(FlateEnd::Capped);
        }
        if cnt < n {
            return Err(FlateEnd::UnexpectedEof);
        }
        Ok(())
    }

    fn run(&mut self) -> FlateEnd {
        loop {
            if self.full() {
                return FlateEnd::Capped;
            }
            if let Err(end) = self.need(1 + 2) {
                return end;
            }
            let final_block = self.b & 1 == 1;
            self.b >>= 1;
            let typ = self.b & 3;
            self.b >>= 2;
            self.nb -= 1 + 2;
            let result = match typ {
                0 => self.data_block(),
                1 => self.huffman_block(true),
                2 => self.read_huffman().and_then(|()| self.huffman_block(false)),
                _ => Err(FlateEnd::Corrupt(self.roffset)),
            };
            if let Err(end) = result {
                return end;
            }
            if final_block {
                return FlateEnd::Eof;
            }
        }
    }
}

/// Inflate `input` like Go's `flate.NewReader`, keeping at most `max_out + 1`
/// output bytes. The returned bytes are everything the decoder had produced
/// when it stopped, including the output that precedes an error.
pub(crate) fn inflate(input: &[u8], max_out: usize) -> (Vec<u8>, FlateEnd) {
    let mut inflater = Inflater {
        input,
        roffset: 0,
        b: 0,
        nb: 0,
        out: Vec::new(),
        max_out,
        h1: Huffman::empty(),
        h2: Huffman::empty(),
        bits: [0; MAX_NUM_LIT + MAX_NUM_DIST],
        codebits: [0; NUM_CODES],
    };
    let end = inflater.run();
    (inflater.out, end)
}
