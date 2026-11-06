//! Go string primitives: strings are byte slices, runes are decoded the way
//! `unicode/utf8` does, and case/class tables come from Go's `unicode` package.

use super::unicode_tables::{DIGIT, LETTER, TO_LOWER, TO_UPPER};

pub type Bytes = Vec<u8>;

pub const RUNE_ERROR: u32 = 0xFFFD;
pub const MAX_RUNE: u32 = 0x0010_FFFF;

/// `utf8.DecodeRune`: invalid encodings decode as `(RuneError, 1)`; empty
/// input is `(RuneError, 0)`.
pub fn decode_rune(s: &[u8]) -> (u32, usize) {
    let Some(&b0) = s.first() else {
        return (RUNE_ERROR, 0);
    };
    if b0 < 0x80 {
        return (u32::from(b0), 1);
    }
    let cont = |i: usize, lo: u8, hi: u8| -> Option<u32> {
        s.get(i)
            .copied()
            .filter(|b| (lo..=hi).contains(b))
            .map(|b| u32::from(b & 0x3F))
    };
    match b0 {
        0xC2..=0xDF => {
            if let Some(c1) = cont(1, 0x80, 0xBF) {
                return ((u32::from(b0 & 0x1F) << 6) | c1, 2);
            }
        }
        0xE0..=0xEF => {
            let (lo, hi) = match b0 {
                0xE0 => (0xA0, 0xBF),
                0xED => (0x80, 0x9F),
                _ => (0x80, 0xBF),
            };
            if let (Some(c1), Some(c2)) = (cont(1, lo, hi), cont(2, 0x80, 0xBF)) {
                return ((u32::from(b0 & 0x0F) << 12) | (c1 << 6) | c2, 3);
            }
        }
        0xF0..=0xF4 => {
            let (lo, hi) = match b0 {
                0xF0 => (0x90, 0xBF),
                0xF4 => (0x80, 0x8F),
                _ => (0x80, 0xBF),
            };
            if let (Some(c1), Some(c2), Some(c3)) =
                (cont(1, lo, hi), cont(2, 0x80, 0xBF), cont(3, 0x80, 0xBF))
            {
                return (
                    (u32::from(b0 & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3,
                    4,
                );
            }
        }
        _ => {}
    }
    (RUNE_ERROR, 1)
}

/// `utf8.DecodeLastRune`.
pub fn decode_last_rune(s: &[u8]) -> (u32, usize) {
    let Some(&last) = s.last() else {
        return (RUNE_ERROR, 0);
    };
    if last < 0x80 {
        return (u32::from(last), 1);
    }
    let lim = s.len().saturating_sub(4);
    let mut start = s.len() - 1;
    while start > lim && (s[start] & 0xC0) == 0x80 {
        start -= 1;
    }
    let (r, size) = decode_rune(&s[start..]);
    if start + size != s.len() {
        return (RUNE_ERROR, 1);
    }
    (r, size)
}

pub fn valid_utf8(s: &[u8]) -> bool {
    std::str::from_utf8(s).is_ok()
}

pub fn valid_rune(r: u32) -> bool {
    r < 0xD800 || (0xE000..=MAX_RUNE).contains(&r)
}

/// `utf8.AppendRune`: out-of-range or surrogate runes become U+FFFD.
pub fn append_rune(out: &mut Bytes, r: u32) {
    let r = if valid_rune(r) { r } else { RUNE_ERROR };
    // `valid_rune` guarantees a scalar value.
    let ch = char::from_u32(r).unwrap_or('\u{FFFD}');
    let mut buf = [0u8; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
}

pub fn rune_len(r: u32) -> usize {
    if !valid_rune(r) {
        return 3;
    }
    match r {
        0..=0x7F => 1,
        0x80..=0x7FF => 2,
        0x800..=0xFFFF => 3,
        _ => 4,
    }
}

/// `utf8.RuneCount`.
pub fn rune_count(s: &[u8]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < s.len() {
        let (_, w) = decode_rune(&s[i..]);
        i += w;
        n += 1;
    }
    n
}

pub fn contains(s: &[u8], needle: &[u8]) -> bool {
    index_of(s, needle).is_some()
}

pub fn index_of(s: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    s.windows(needle.len()).position(|w| w == needle)
}

pub fn last_index_of(s: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(s.len());
    }
    s.windows(needle.len()).rposition(|w| w == needle)
}

fn in_ranges(table: &[(u32, u32)], r: u32) -> bool {
    table
        .binary_search_by(|&(lo, hi)| {
            if r < lo {
                std::cmp::Ordering::Greater
            } else if r > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `unicode.IsLetter`.
pub fn is_letter(r: u32) -> bool {
    in_ranges(LETTER, r)
}

/// `unicode.IsDigit`.
pub fn is_digit(r: u32) -> bool {
    in_ranges(DIGIT, r)
}

fn map_rune(table: &[(u32, u32)], r: u32) -> u32 {
    table
        .binary_search_by_key(&r, |&(from, _)| from)
        .map_or(r, |i| table[i].1)
}

pub fn to_upper_rune(r: u32) -> u32 {
    map_rune(TO_UPPER, r)
}

pub fn to_lower_rune(r: u32) -> u32 {
    map_rune(TO_LOWER, r)
}

/// Go's `strings.Map` driven by a rune mapping: invalid bytes become U+FFFD.
fn map_string(s: &[u8], f: fn(u32) -> u32) -> Bytes {
    let mut out = Bytes::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let (r, w) = decode_rune(&s[i..]);
        append_rune(&mut out, f(r));
        i += w;
    }
    out
}

/// `strings.ToUpper`.
pub fn to_upper(s: &[u8]) -> Bytes {
    if s.is_ascii() {
        return s.to_ascii_uppercase();
    }
    map_string(s, to_upper_rune)
}

/// `strings.ToLower`.
pub fn to_lower(s: &[u8]) -> Bytes {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    map_string(s, to_lower_rune)
}

/// `bytes.TrimSpace` semantics for the emptiness test of a text node.
pub fn is_blank(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        let (r, w) = decode_rune(&s[i..]);
        if !is_space_rune(r) {
            return false;
        }
        i += w;
    }
    true
}

/// `unicode.IsSpace`.
pub fn is_space_rune(r: u32) -> bool {
    matches!(
        r,
        0x09..=0x0D
            | 0x20
            | 0x85
            | 0xA0
            | 0x1680
            | 0x2000..=0x200A
            | 0x2028
            | 0x2029
            | 0x202F
            | 0x205F
            | 0x3000
    )
}

pub fn b(s: &str) -> Bytes {
    s.as_bytes().to_vec()
}

/// Lossless-enough rendering for Rust-side errors and logs.
pub fn lossy(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}
