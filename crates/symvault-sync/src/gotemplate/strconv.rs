//! The slice of Go's `strconv` that `text/template` and `fmt` rely on:
//! quoting, unquoting, integer/float parsing and float formatting.

use super::gostr::{Bytes, RUNE_ERROR, append_rune, decode_rune, valid_rune, valid_utf8};

pub fn is_print(r: u32) -> bool {
    char::from_u32(r).is_some_and(symvault_core::go_is_print)
}

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut Bytes, mut v: u32, digits: usize) {
    let mut buf = [0u8; 8];
    for slot in buf.iter_mut().take(digits).rev() {
        *slot = LOWER_HEX[(v & 0xF) as usize];
        v >>= 4;
    }
    out.extend_from_slice(&buf[..digits]);
}

fn append_escaped_rune(out: &mut Bytes, r: u32, quote: u8, ascii_only: bool) {
    if r == u32::from(quote) || r == u32::from(b'\\') {
        out.push(b'\\');
        out.push(r as u8);
        return;
    }
    if ascii_only {
        if r < 0x80 && is_print(r) {
            out.push(r as u8);
            return;
        }
    } else if is_print(r) {
        append_rune(out, r);
        return;
    }
    match r {
        0x07 => out.extend_from_slice(b"\\a"),
        0x08 => out.extend_from_slice(b"\\b"),
        0x0C => out.extend_from_slice(b"\\f"),
        0x0A => out.extend_from_slice(b"\\n"),
        0x0D => out.extend_from_slice(b"\\r"),
        0x09 => out.extend_from_slice(b"\\t"),
        0x0B => out.extend_from_slice(b"\\v"),
        _ => {
            if r < 0x20 || r == 0x7F {
                out.extend_from_slice(b"\\x");
                push_hex(out, r, 2);
            } else {
                let r = if valid_rune(r) { r } else { RUNE_ERROR };
                if r < 0x10000 {
                    out.extend_from_slice(b"\\u");
                    push_hex(out, r, 4);
                } else {
                    out.extend_from_slice(b"\\U");
                    push_hex(out, r, 8);
                }
            }
        }
    }
}

fn quote_with(s: &[u8], quote: u8, ascii_only: bool) -> Bytes {
    let mut out = Bytes::with_capacity(s.len() + 2);
    out.push(quote);
    let mut i = 0;
    while i < s.len() {
        let (r, w) = decode_rune(&s[i..]);
        if w == 1 && r == RUNE_ERROR {
            out.extend_from_slice(b"\\x");
            push_hex(&mut out, u32::from(s[i]), 2);
            i += 1;
            continue;
        }
        append_escaped_rune(&mut out, r, quote, ascii_only);
        i += w;
    }
    out.push(quote);
    out
}

/// `strconv.Quote`.
pub fn quote(s: &[u8]) -> Bytes {
    quote_with(s, b'"', false)
}

/// `strconv.QuoteToASCII`.
pub fn quote_to_ascii(s: &[u8]) -> Bytes {
    quote_with(s, b'"', true)
}

/// `strconv.QuoteRune` / `QuoteRuneToASCII`.
pub fn quote_rune(r: u32, ascii_only: bool) -> Bytes {
    let r = if valid_rune(r) { r } else { RUNE_ERROR };
    let mut out = vec![b'\''];
    append_escaped_rune(&mut out, r, b'\'', ascii_only);
    out.push(b'\'');
    out
}

/// `strconv.CanBackquote`.
pub fn can_backquote(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        let (r, w) = decode_rune(&s[i..]);
        i += w;
        if w > 1 {
            if r == 0xFEFF {
                return false;
            }
            continue;
        }
        if r == RUNE_ERROR {
            return false;
        }
        if (r < 0x20 && r != 0x09) || r == u32::from(b'`') || r == 0x7F {
            return false;
        }
    }
    true
}

fn unhex(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some(u32::from(c - b'0')),
        b'a'..=b'f' => Some(u32::from(c - b'a') + 10),
        b'A'..=b'F' => Some(u32::from(c - b'A') + 10),
        _ => None,
    }
}

/// `strconv.UnquoteChar`: `(value, multibyte, tail)`; `Err(())` is ErrSyntax.
pub fn unquote_char(s: &[u8], quote: u8) -> Result<(u32, bool, &[u8]), ()> {
    let Some(&c) = s.first() else {
        return Err(());
    };
    if c == quote && (quote == b'\'' || quote == b'"') {
        return Err(());
    }
    if c >= 0x80 {
        let (r, size) = decode_rune(s);
        return Ok((r, true, &s[size..]));
    }
    if c != b'\\' {
        return Ok((u32::from(c), false, &s[1..]));
    }
    if s.len() <= 1 {
        return Err(());
    }
    let c = s[1];
    let rest = &s[2..];
    let mut multibyte = false;
    let (value, tail) = match c {
        b'a' => (0x07, rest),
        b'b' => (0x08, rest),
        b'f' => (0x0C, rest),
        b'n' => (0x0A, rest),
        b'r' => (0x0D, rest),
        b't' => (0x09, rest),
        b'v' => (0x0B, rest),
        b'x' | b'u' | b'U' => {
            let n = match c {
                b'x' => 2,
                b'u' => 4,
                _ => 8,
            };
            if rest.len() < n {
                return Err(());
            }
            let mut v: u32 = 0;
            for &d in &rest[..n] {
                v = v.checked_shl(4).ok_or(())? | unhex(d).ok_or(())?;
            }
            if c != b'x' {
                if !valid_rune(v) {
                    return Err(());
                }
                multibyte = true;
            }
            (v, &rest[n..])
        }
        b'0'..=b'7' => {
            let mut v = u32::from(c - b'0');
            if rest.len() < 2 {
                return Err(());
            }
            for &d in &rest[..2] {
                if !(b'0'..=b'7').contains(&d) {
                    return Err(());
                }
                v = (v << 3) | u32::from(d - b'0');
            }
            if v > 255 {
                return Err(());
            }
            (v, &rest[2..])
        }
        b'\\' => (u32::from(b'\\'), rest),
        b'\'' | b'"' => {
            if c != quote {
                return Err(());
            }
            (u32::from(c), rest)
        }
        _ => return Err(()),
    };
    Ok((value, multibyte, tail))
}

/// `strconv.Unquote`; `Err(())` is `strconv.ErrSyntax` ("invalid syntax").
pub fn unquote(input: &[u8]) -> Result<Bytes, ()> {
    if input.len() < 2 {
        return Err(());
    }
    let quote = input[0];
    let Some(end) = input[1..].iter().position(|&c| c == quote) else {
        return Err(());
    };
    let end = end + 2;
    let head = &input[..end];
    match quote {
        b'`' => {
            let body = &head[1..end - 1];
            let out: Bytes = body.iter().copied().filter(|&c| c != b'\r').collect();
            if end != input.len() {
                return Err(());
            }
            Ok(out)
        }
        b'"' | b'\'' => {
            if !head.contains(&b'\\') && !head.contains(&b'\n') {
                let body = &head[1..end - 1];
                let valid = if quote == b'"' {
                    valid_utf8(body)
                } else {
                    let (r, n) = decode_rune(body);
                    1 + n + 1 == end && (r != RUNE_ERROR || n != 1)
                };
                if valid {
                    if end != input.len() {
                        return Err(());
                    }
                    return Ok(body.to_vec());
                }
            }
            let mut rest = &input[1..];
            let mut buf = Bytes::new();
            while !rest.is_empty() && rest[0] != quote {
                let (r, multibyte, tail) = unquote_char(rest, quote)?;
                if rest[0] == b'\n' {
                    return Err(());
                }
                rest = tail;
                if r < 0x80 || !multibyte {
                    buf.push(r as u8);
                } else {
                    append_rune(&mut buf, r);
                }
                if quote == b'\'' {
                    break;
                }
            }
            if rest.first() != Some(&quote) {
                return Err(());
            }
            rest = &rest[1..];
            if !rest.is_empty() {
                return Err(());
            }
            Ok(buf)
        }
        _ => Err(()),
    }
}

// ---------------------------------------------------------------------------
// Integer and float parsing
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumErr {
    Syntax,
    Range,
}

fn lower(c: u8) -> u8 {
    c | 0x20
}

fn underscore_ok(s: &[u8]) -> bool {
    let mut saw = b'^';
    let mut i = 0;
    let mut s = s;
    if !s.is_empty() && (s[0] == b'-' || s[0] == b'+') {
        s = &s[1..];
    }
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(lower(s[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = lower(s[1]) == b'x';
    }
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(c))) {
            saw = b'0';
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

/// `strconv.ParseUint(s, 0, 64)`.
pub fn parse_uint(s: &[u8]) -> Result<u64, NumErr> {
    if s.is_empty() {
        return Err(NumErr::Syntax);
    }
    let s0 = s;
    let mut s = s;
    let mut base: u64 = 10;
    if s[0] == b'0' {
        if s.len() >= 3 && lower(s[1]) == b'b' {
            base = 2;
            s = &s[2..];
        } else if s.len() >= 3 && lower(s[1]) == b'o' {
            base = 8;
            s = &s[2..];
        } else if s.len() >= 3 && lower(s[1]) == b'x' {
            base = 16;
            s = &s[2..];
        } else {
            base = 8;
            s = &s[1..];
        }
    }
    let cutoff = u64::MAX / base + 1;
    let mut n: u64 = 0;
    let mut underscores = false;
    for &c in s {
        let d = match c {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => u64::from(c - b'0'),
            _ if lower(c).is_ascii_lowercase() => u64::from(lower(c) - b'a') + 10,
            _ => return Err(NumErr::Syntax),
        };
        if d >= base {
            return Err(NumErr::Syntax);
        }
        if n >= cutoff {
            return Err(NumErr::Range);
        }
        n *= base;
        let n1 = n.wrapping_add(d);
        if n1 < n {
            return Err(NumErr::Range);
        }
        n = n1;
    }
    if underscores && !underscore_ok(s0) {
        return Err(NumErr::Syntax);
    }
    Ok(n)
}

/// `strconv.ParseInt(s, 0, 64)`.
pub fn parse_int(s: &[u8]) -> Result<i64, NumErr> {
    if s.is_empty() {
        return Err(NumErr::Syntax);
    }
    let mut neg = false;
    let mut body = s;
    if s[0] == b'+' {
        body = &s[1..];
    } else if s[0] == b'-' {
        neg = true;
        body = &s[1..];
    }
    let un = parse_uint(body)?;
    let cutoff: u64 = 1 << 63;
    if !neg && un >= cutoff {
        return Err(NumErr::Range);
    }
    if neg && un > cutoff {
        return Err(NumErr::Range);
    }
    Ok(if neg {
        (un as i64).wrapping_neg()
    } else {
        un as i64
    })
}

/// `strconv.ParseFloat(s, 64)` for the number shapes the template lexer can
/// produce (no `inf`/`nan` spellings).
pub fn parse_float(s: &[u8]) -> Result<f64, NumErr> {
    let mut i = 0;
    let mut neg = false;
    if s.is_empty() {
        return Err(NumErr::Syntax);
    }
    match s[0] {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            neg = true;
        }
        _ => {}
    }
    let mut hex = false;
    if i + 2 < s.len() && s[i] == b'0' && lower(s[i + 1]) == b'x' {
        hex = true;
        i += 2;
    }
    let exp_char = if hex { b'p' } else { b'e' };
    let mut underscores = false;
    let mut saw_dot = false;
    let mut saw_digits = false;
    let mut mant_digits: Vec<u8> = Vec::new();
    let mut dp: i64 = 0;
    let mut nd: i64 = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            underscores = true;
        } else if c == b'.' {
            if saw_dot {
                break;
            }
            saw_dot = true;
            dp = nd;
        } else if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(c))) {
            saw_digits = true;
            nd += 1;
            mant_digits.push(c);
        } else {
            break;
        }
        i += 1;
    }
    if !saw_digits {
        return Err(NumErr::Syntax);
    }
    if !saw_dot {
        dp = nd;
    }
    let mut exp: i64 = 0;
    if i < s.len() && lower(s[i]) == exp_char {
        i += 1;
        if i >= s.len() {
            return Err(NumErr::Syntax);
        }
        let mut esign = 1;
        match s[i] {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        if i >= s.len() || !s[i].is_ascii_digit() {
            return Err(NumErr::Syntax);
        }
        let mut e: i64 = 0;
        while i < s.len() && (s[i].is_ascii_digit() || s[i] == b'_') {
            if s[i] == b'_' {
                underscores = true;
            } else if e < 10000 {
                e = e * 10 + i64::from(s[i] - b'0');
            }
            i += 1;
        }
        exp = e * esign;
    } else if hex {
        return Err(NumErr::Syntax);
    }
    if underscores && !underscore_ok(&s[..i]) {
        return Err(NumErr::Syntax);
    }
    if i != s.len() {
        return Err(NumErr::Syntax);
    }
    let value = if hex {
        let mut m: u64 = 0;
        let mut used = 0;
        for &c in &mant_digits {
            if used < 16 {
                let d = if c.is_ascii_digit() {
                    u64::from(c - b'0')
                } else {
                    u64::from(lower(c) - b'a') + 10
                };
                m = m * 16 + d;
                used += 1;
            }
        }
        // exponent = (digits before the point - digits kept) * 4 + p exponent
        let binary_exp = (dp - i64::from(used)) * 4 + exp;
        let mut f = m as f64;
        let mut e = binary_exp;
        while e > 0 && f.is_finite() {
            let step = e.min(1000);
            f *= 2f64.powi(step as i32);
            e -= step;
        }
        while e < 0 && f != 0.0 {
            let step = (-e).min(1000);
            f /= 2f64.powi(step as i32);
            e += step;
        }
        f
    } else {
        let cleaned: String = s[..i]
            .iter()
            .filter(|&&c| c != b'_')
            .map(|&c| c as char)
            .collect();
        let unsigned = cleaned.trim_start_matches(['+', '-']);
        unsigned.parse::<f64>().map_err(|_| NumErr::Syntax)?
    };
    if value.is_infinite() {
        return Err(NumErr::Range);
    }
    Ok(if neg { -value } else { value })
}

// ---------------------------------------------------------------------------
// Float formatting
// ---------------------------------------------------------------------------

struct Digits {
    d: Vec<u8>,
    dp: i64,
}

impl Digits {
    fn nd(&self) -> i64 {
        self.d.len() as i64
    }
}

fn digits_from_exp(s: &str) -> Digits {
    // "d.ddde<exp>" as produced by `{:e}`.
    let (mant, exp) = s.split_once('e').unwrap_or((s, "0"));
    let exp: i64 = exp.parse().unwrap_or(0);
    let mut d: Vec<u8> = mant.bytes().filter(u8::is_ascii_digit).collect();
    while d.last() == Some(&b'0') {
        d.pop();
    }
    if d.is_empty() {
        return Digits { d, dp: 0 };
    }
    Digits { d, dp: exp + 1 }
}

fn digits_from_fixed(s: &str) -> Digits {
    let dot = s.find('.').unwrap_or(s.len());
    let mut d: Vec<u8> = s.bytes().filter(u8::is_ascii_digit).collect();
    let mut dp = dot as i64;
    let lead = d.iter().take_while(|&&c| c == b'0').count();
    d.drain(..lead);
    dp -= lead as i64;
    while d.last() == Some(&b'0') {
        d.pop();
    }
    if d.is_empty() {
        return Digits { d, dp: 0 };
    }
    Digits { d, dp }
}

fn fmt_e(out: &mut Bytes, neg: bool, d: &Digits, prec: i64, fmt: u8) {
    if neg {
        out.push(b'-');
    }
    out.push(d.d.first().copied().unwrap_or(b'0'));
    if prec > 0 {
        out.push(b'.');
        let mut i: i64 = 1;
        let m = d.nd().min(prec + 1);
        if i < m {
            out.extend_from_slice(&d.d[i as usize..m as usize]);
            i = m;
        }
        while i <= prec {
            out.push(b'0');
            i += 1;
        }
    }
    out.push(fmt);
    let mut exp = d.dp - 1;
    if d.nd() == 0 {
        exp = 0;
    }
    if exp < 0 {
        out.push(b'-');
        exp = -exp;
    } else {
        out.push(b'+');
    }
    if exp < 10 {
        out.push(b'0');
        out.push(b'0' + exp as u8);
    } else if exp < 100 {
        out.push(b'0' + (exp / 10) as u8);
        out.push(b'0' + (exp % 10) as u8);
    } else {
        out.push(b'0' + (exp / 100) as u8);
        out.push(b'0' + ((exp / 10) % 10) as u8);
        out.push(b'0' + (exp % 10) as u8);
    }
}

fn fmt_f(out: &mut Bytes, neg: bool, d: &Digits, prec: i64) {
    if neg {
        out.push(b'-');
    }
    if d.dp > 0 {
        let m = d.nd().min(d.dp);
        out.extend_from_slice(&d.d[..m as usize]);
        for _ in m..d.dp {
            out.push(b'0');
        }
    } else {
        out.push(b'0');
    }
    if prec > 0 {
        out.push(b'.');
        for i in 0..prec {
            let j = d.dp + i;
            out.push(if 0 <= j && j < d.nd() {
                d.d[j as usize]
            } else {
                b'0'
            });
        }
    }
}

fn format_digits(out: &mut Bytes, shortest: bool, neg: bool, d: &Digits, prec: i64, fmt: u8) {
    match fmt {
        b'e' | b'E' => fmt_e(out, neg, d, prec, fmt),
        b'f' => fmt_f(out, neg, d, prec),
        b'g' | b'G' => {
            let mut prec = prec;
            let mut eprec = prec;
            if eprec > d.nd() && d.nd() >= d.dp {
                eprec = d.nd();
            }
            if shortest {
                eprec = 6;
            }
            let exp = d.dp - 1;
            if exp < -4 || exp >= eprec {
                if prec > d.nd() {
                    prec = d.nd();
                }
                fmt_e(out, neg, d, prec - 1, fmt + b'e' - b'g');
                return;
            }
            if prec > d.dp {
                prec = d.nd();
            }
            fmt_f(out, neg, d, (prec - d.dp).max(0));
        }
        _ => {
            out.push(b'%');
            out.push(fmt);
        }
    }
}

fn fmt_b(out: &mut Bytes, neg: bool, mant: u64, exp: i64) {
    if neg {
        out.push(b'-');
    }
    out.extend_from_slice(mant.to_string().as_bytes());
    out.push(b'p');
    let exp = exp - 52;
    if exp >= 0 {
        out.push(b'+');
    }
    out.extend_from_slice(exp.to_string().as_bytes());
}

fn fmt_x(out: &mut Bytes, prec: i64, fmt: u8, neg: bool, mant: u64, exp: i64) {
    let mut mant = mant;
    let mut exp = exp;
    if mant == 0 {
        exp = 0;
    }
    mant <<= 60 - 52;
    while mant != 0 && mant & (1 << 60) == 0 {
        mant <<= 1;
        exp -= 1;
    }
    if (0..15).contains(&prec) {
        let shift = (prec * 4) as u32;
        let extra = (mant << shift) & ((1 << 60) - 1);
        mant >>= 60 - shift;
        if extra | (mant & 1) > 1 << 59 {
            mant += 1;
        }
        mant <<= 60 - shift;
        if mant & (1 << 61) != 0 {
            mant >>= 1;
            exp += 1;
        }
    }
    let hex: &[u8; 16] = if fmt == b'X' {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    if neg {
        out.push(b'-');
    }
    out.push(b'0');
    out.push(fmt);
    out.push(b'0' + ((mant >> 60) & 1) as u8);
    mant <<= 4;
    if prec < 0 && mant != 0 {
        out.push(b'.');
        while mant != 0 {
            out.push(hex[((mant >> 60) & 15) as usize]);
            mant <<= 4;
        }
    } else if prec > 0 {
        out.push(b'.');
        for _ in 0..prec {
            out.push(hex[((mant >> 60) & 15) as usize]);
            mant <<= 4;
        }
    }
    out.push(if fmt == b'X' { b'P' } else { b'p' });
    if exp < 0 {
        out.push(b'-');
        exp = -exp;
    } else {
        out.push(b'+');
    }
    if exp < 100 {
        out.push(b'0' + (exp / 10) as u8);
        out.push(b'0' + (exp % 10) as u8);
    } else {
        out.extend_from_slice(exp.to_string().as_bytes());
    }
}

/// `strconv.FormatFloat(v, fmt, prec, 64)` for fmt in `b e E f g G x X`.
pub fn format_float(v: f64, fmt: u8, prec: i64) -> Bytes {
    let bits = v.to_bits();
    let neg = bits >> 63 != 0;
    let exp_bits = ((bits >> 52) & 0x7FF) as i64;
    let mant = bits & ((1u64 << 52) - 1);
    let mut out = Bytes::new();
    if exp_bits == 0x7FF {
        out.extend_from_slice(if mant != 0 {
            b"NaN"
        } else if neg {
            b"-Inf"
        } else {
            b"+Inf"
        });
        return out;
    }
    let (mut exp, mut m) = (exp_bits, mant);
    if exp == 0 {
        exp = 1;
    } else {
        m |= 1 << 52;
    }
    exp -= 1023;
    if fmt == b'b' {
        fmt_b(&mut out, neg, m, exp);
        return out;
    }
    if fmt == b'x' || fmt == b'X' {
        fmt_x(&mut out, prec, fmt, neg, m, exp);
        return out;
    }
    let shortest = prec < 0;
    let abs = v.abs();
    let mut prec = prec;
    let digs = if abs == 0.0 {
        Digits {
            d: Vec::new(),
            dp: 0,
        }
    } else if shortest {
        let digs = digits_from_exp(&format!("{abs:e}"));
        match fmt {
            b'e' | b'E' => prec = (digs.nd() - 1).max(0),
            b'f' => prec = (digs.nd() - digs.dp).max(0),
            _ => prec = digs.nd(),
        }
        digs
    } else {
        // Rust's formatter takes the precision as u16 and panics above 65535;
        // Go accepts up to 1e6. An f64 has at most 1074 fractional and 767
        // significant decimal digits, so digits past EXACT_DIGITS are zero and
        // fmt_e/fmt_f pad them.
        const EXACT_DIGITS: i64 = 1100;
        match fmt {
            b'e' | b'E' => {
                digits_from_exp(&format!("{:.*e}", prec.min(EXACT_DIGITS) as usize, abs))
            }
            b'f' => digits_from_fixed(&format!("{:.*}", prec.min(EXACT_DIGITS) as usize, abs)),
            _ => {
                if prec == 0 {
                    prec = 1;
                }
                digits_from_exp(&format!(
                    "{:.*e}",
                    (prec - 1).min(EXACT_DIGITS) as usize,
                    abs
                ))
            }
        }
    };
    format_digits(&mut out, shortest, neg, &digs, prec, fmt);
    out
}
