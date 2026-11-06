//! A port of Go's `fmt` printer for the value model in `value.rs`
//! (`Sprint`, `Sprintln`, `Sprintf`, `Errorf`).

use super::gostr::{Bytes, MAX_RUNE, RUNE_ERROR, append_rune, decode_rune, rune_count};
use super::strconv::{self, can_backquote, format_float, is_print, quote_rune, quote_to_ascii};
use super::value::Value;

const LDIGITS: &[u8; 17] = b"0123456789abcdefx";
const UDIGITS: &[u8; 17] = b"0123456789ABCDEFX";

#[derive(Default)]
pub struct Printer {
    pub buf: Bytes,
    wid: i64,
    prec: i64,
    wid_present: bool,
    prec_present: bool,
    minus: bool,
    plus: bool,
    sharp: bool,
    space: bool,
    zero: bool,
    plus_v: bool,
    sharp_v: bool,
    cur: Option<Value>,
    erroring: bool,
    wrap_errs: bool,
    reordered: bool,
    good_arg_num: bool,
}

pub fn sprint(args: &[Value]) -> Bytes {
    let mut p = Printer::default();
    p.do_print(args);
    p.buf
}

pub fn sprintln(args: &[Value]) -> Bytes {
    let mut p = Printer::default();
    p.do_println(args);
    p.buf
}

pub fn sprintf(format: &[u8], args: &[Value]) -> Bytes {
    let mut p = Printer::default();
    p.do_printf(format, args);
    p.buf
}

/// `fmt.Errorf` (with `%w` support); the result is the error text.
pub fn errorf(format: &[u8], args: &[Value]) -> Bytes {
    let mut p = Printer {
        wrap_errs: true,
        ..Printer::default()
    };
    p.do_printf(format, args);
    p.buf
}

fn too_large(x: i64) -> bool {
    const MAX: i64 = 1_000_000;
    !(-MAX..=MAX).contains(&x)
}

fn parsenum(s: &[u8], start: usize, end: usize) -> (i64, bool, usize) {
    if start >= end {
        return (0, false, end);
    }
    let mut num: i64 = 0;
    let mut isnum = false;
    let mut newi = start;
    while newi < end && s[newi].is_ascii_digit() {
        if too_large(num) {
            return (0, false, end);
        }
        num = num * 10 + i64::from(s[newi] - b'0');
        isnum = true;
        newi += 1;
    }
    (num, isnum, newi)
}

fn int_from_arg(a: &[Value], arg_num: usize) -> (i64, bool, usize) {
    let mut new_arg_num = arg_num;
    let mut num = 0;
    let mut is_int = false;
    if arg_num < a.len() {
        match &a[arg_num] {
            Value::Int(n) => {
                num = *n;
                is_int = true;
            }
            Value::Uint8(n) => {
                num = i64::from(*n);
                is_int = true;
            }
            _ => {}
        }
        new_arg_num = arg_num + 1;
        if too_large(num) {
            num = 0;
            is_int = false;
        }
    }
    (num, is_int, new_arg_num)
}

fn parse_arg_number(format: &[u8]) -> (i64, usize, bool) {
    if format.len() < 3 {
        return (0, 1, false);
    }
    for i in 1..format.len() {
        if format[i] == b']' {
            let (width, ok, newi) = parsenum(format, 1, i);
            if !ok || newi != i {
                return (0, i + 1, false);
            }
            return (width - 1, i + 1, true);
        }
    }
    (0, 1, false)
}

impl Printer {
    fn clear_flags(&mut self) {
        self.wid = 0;
        self.prec = 0;
        self.wid_present = false;
        self.prec_present = false;
        self.minus = false;
        self.plus = false;
        self.sharp = false;
        self.space = false;
        self.zero = false;
        self.plus_v = false;
        self.sharp_v = false;
    }

    // ---- fmt (format.go) ------------------------------------------------

    fn write_padding(&mut self, n: i64) {
        if n <= 0 {
            return;
        }
        let pad = if self.zero && !self.minus { b'0' } else { b' ' };
        self.buf.extend(std::iter::repeat_n(pad, n as usize));
    }

    fn pad(&mut self, b: &[u8]) {
        if !self.wid_present || self.wid == 0 {
            self.buf.extend_from_slice(b);
            return;
        }
        let width = self.wid - rune_count(b) as i64;
        if self.minus {
            self.buf.extend_from_slice(b);
            self.write_padding(width);
        } else {
            self.write_padding(width);
            self.buf.extend_from_slice(b);
        }
    }

    fn fmt_boolean(&mut self, v: bool) {
        self.pad(if v { b"true" } else { b"false" });
    }

    fn fmt_unicode(&mut self, mut u: u64) {
        let mut prec: i64 = 4;
        if self.prec_present && self.prec > 4 {
            prec = self.prec;
        }
        let mut rev: Bytes = Vec::new();
        // Build back to front, mirroring the Go buffer fill.
        let mut tail: Bytes = Vec::new();
        if self.sharp && u <= u64::from(MAX_RUNE) && is_print(u as u32) {
            tail.push(b' ');
            tail.push(b'\'');
            let mut enc = Vec::new();
            append_rune(&mut enc, u as u32);
            tail.extend_from_slice(&enc);
            tail.push(b'\'');
        }
        while u >= 16 {
            rev.push(UDIGITS[(u & 0xF) as usize]);
            prec -= 1;
            u >>= 4;
        }
        rev.push(UDIGITS[u as usize]);
        prec -= 1;
        while prec > 0 {
            rev.push(b'0');
            prec -= 1;
        }
        rev.push(b'+');
        rev.push(b'U');
        rev.reverse();
        let mut out = rev;
        out.extend_from_slice(&tail);
        let old_zero = self.zero;
        self.zero = false;
        self.pad(&out);
        self.zero = old_zero;
    }

    fn fmt_integer_base(&mut self, u: u64, base: u64, signed: bool, verb: u8, digits: &[u8; 17]) {
        let mut u = u;
        let negative = signed && (u as i64) < 0;
        if negative {
            u = u.wrapping_neg();
        }
        let mut prec: i64 = 0;
        if self.prec_present {
            prec = self.prec;
            if prec == 0 && u == 0 {
                let old_zero = self.zero;
                self.zero = false;
                self.write_padding(self.wid);
                self.zero = old_zero;
                return;
            }
        } else if self.zero && !self.minus && self.wid_present {
            prec = self.wid;
            if negative || self.plus || self.space {
                prec -= 1;
            }
        }
        let mut rev: Bytes = Vec::new();
        while u >= base {
            rev.push(digits[(u % base) as usize]);
            u /= base;
        }
        rev.push(digits[u as usize]);
        while (rev.len() as i64) < prec {
            rev.push(b'0');
        }
        if self.sharp {
            match base {
                2 => {
                    rev.push(b'b');
                    rev.push(b'0');
                }
                8 => {
                    if rev.last() != Some(&b'0') {
                        rev.push(b'0');
                    }
                }
                16 => {
                    rev.push(digits[16]);
                    rev.push(b'0');
                }
                _ => {}
            }
        }
        if verb == b'O' {
            rev.push(b'o');
            rev.push(b'0');
        }
        if negative {
            rev.push(b'-');
        } else if self.plus {
            rev.push(b'+');
        } else if self.space {
            rev.push(b' ');
        }
        rev.reverse();
        let old_zero = self.zero;
        self.zero = false;
        self.pad(&rev);
        self.zero = old_zero;
    }

    fn truncate_string<'a>(&self, s: &'a [u8]) -> &'a [u8] {
        if self.prec_present {
            let mut n = self.prec;
            let mut i = 0;
            while i < s.len() {
                n -= 1;
                if n < 0 {
                    return &s[..i];
                }
                let (_, w) = decode_rune(&s[i..]);
                i += w;
            }
        }
        s
    }

    fn fmt_s(&mut self, s: &[u8]) {
        let s = self.truncate_string(s).to_vec();
        self.pad(&s);
    }

    fn fmt_sx(&mut self, s: &[u8], digits: &[u8; 17]) {
        let mut length = s.len() as i64;
        if self.prec_present && self.prec < length {
            length = self.prec;
        }
        let mut width = 2 * length;
        if width > 0 {
            if self.space {
                if self.sharp {
                    width *= 2;
                }
                width += length - 1;
            } else if self.sharp {
                width += 2;
            }
        } else {
            if self.wid_present {
                self.write_padding(self.wid);
            }
            return;
        }
        if self.wid_present && self.wid > width && !self.minus {
            self.write_padding(self.wid - width);
        }
        if self.sharp {
            self.buf.push(b'0');
            self.buf.push(digits[16]);
        }
        for (i, &c) in s.iter().enumerate().take(length as usize) {
            if self.space && i > 0 {
                self.buf.push(b' ');
                if self.sharp {
                    self.buf.push(b'0');
                    self.buf.push(digits[16]);
                }
            }
            self.buf.push(digits[(c >> 4) as usize]);
            self.buf.push(digits[(c & 0xF) as usize]);
        }
        if self.wid_present && self.wid > width && self.minus {
            self.write_padding(self.wid - width);
        }
    }

    fn fmt_q(&mut self, s: &[u8]) {
        let s = self.truncate_string(s).to_vec();
        if self.sharp && can_backquote(&s) {
            let mut b = vec![b'`'];
            b.extend_from_slice(&s);
            b.push(b'`');
            self.pad(&b);
            return;
        }
        let q = if self.plus {
            quote_to_ascii(&s)
        } else {
            strconv::quote(&s)
        };
        self.pad(&q);
    }

    fn fmt_c(&mut self, c: u64) {
        let r = if c > u64::from(MAX_RUNE) {
            RUNE_ERROR
        } else {
            c as u32
        };
        let mut b = Vec::new();
        append_rune(&mut b, r);
        self.pad(&b);
    }

    fn fmt_qc(&mut self, c: u64) {
        let r = if c > u64::from(MAX_RUNE) {
            RUNE_ERROR
        } else {
            c as u32
        };
        let q = quote_rune(r, self.plus);
        self.pad(&q);
    }

    fn fmt_float_raw(&mut self, v: f64, verb: u8, prec: i64) {
        let prec = if self.prec_present { self.prec } else { prec };
        let mut num = vec![b'+'];
        num.extend_from_slice(&format_float(v, verb, prec));
        if num[1] == b'-' || num[1] == b'+' {
            num.remove(0);
        } else {
            num[0] = b'+';
        }
        if self.space && num[0] == b'+' && !self.plus {
            num[0] = b' ';
        }
        if num[1] == b'I' || num[1] == b'N' {
            let old_zero = self.zero;
            self.zero = false;
            if num[1] == b'N' && !self.space && !self.plus {
                num.remove(0);
            }
            self.pad(&num);
            self.zero = old_zero;
            return;
        }
        if self.sharp && verb != b'b' {
            let mut digits: i64 = 0;
            if matches!(verb, b'v' | b'g' | b'G' | b'x') {
                digits = prec;
                if digits == -1 {
                    digits = 6;
                }
            }
            let mut tail: Bytes = Vec::new();
            let mut has_decimal_point = false;
            let mut saw_nonzero_digit = false;
            let mut i = 1;
            while i < num.len() {
                match num[i] {
                    b'.' => has_decimal_point = true,
                    b'p' | b'P' => {
                        tail.extend_from_slice(&num[i..]);
                        num.truncate(i);
                    }
                    b'e' | b'E' if verb != b'x' && verb != b'X' => {
                        tail.extend_from_slice(&num[i..]);
                        num.truncate(i);
                    }
                    c => {
                        if c != b'0' {
                            saw_nonzero_digit = true;
                        }
                        if saw_nonzero_digit {
                            digits -= 1;
                        }
                    }
                }
                i += 1;
            }
            if !has_decimal_point {
                if num.len() == 2 && num[1] == b'0' {
                    digits -= 1;
                }
                num.push(b'.');
            }
            while digits > 0 {
                num.push(b'0');
                digits -= 1;
            }
            num.extend_from_slice(&tail);
        }
        if self.plus || num[0] != b'+' {
            if self.zero && !self.minus && self.wid_present && self.wid > num.len() as i64 {
                self.buf.push(num[0]);
                self.write_padding(self.wid - num.len() as i64);
                self.buf.extend_from_slice(&num[1..]);
                return;
            }
            self.pad(&num);
            return;
        }
        self.pad(&num[1..]);
    }

    // ---- print.go -------------------------------------------------------

    fn bad_verb(&mut self, verb: u32) {
        self.erroring = true;
        self.buf.extend_from_slice(b"%!");
        append_rune(&mut self.buf, verb);
        self.buf.push(b'(');
        match self.cur.clone() {
            Some(v) if v.is_valid() => {
                self.buf.extend_from_slice(v.type_name().as_bytes());
                self.buf.push(b'=');
                self.print_value(&v, u32::from(b'v'), 0);
            }
            _ => self.buf.extend_from_slice(b"<nil>"),
        }
        self.buf.push(b')');
        self.erroring = false;
    }

    fn fmt_bool(&mut self, v: bool, verb: u32) {
        match char::from_u32(verb) {
            Some('t' | 'v') => self.fmt_boolean(v),
            _ => self.bad_verb(verb),
        }
    }

    fn fmt_0x64(&mut self, v: u64, leading0x: bool) {
        let sharp = self.sharp;
        self.sharp = leading0x;
        self.fmt_integer_base(v, 16, false, b'v', LDIGITS);
        self.sharp = sharp;
    }

    fn fmt_integer(&mut self, v: u64, signed: bool, verb: u32) {
        let Some(c) = char::from_u32(verb) else {
            return self.bad_verb(verb);
        };
        match c {
            'v' => {
                if self.sharp_v && !signed {
                    self.fmt_0x64(v, true);
                } else {
                    self.fmt_integer_base(v, 10, signed, b'v', LDIGITS);
                }
            }
            'd' => self.fmt_integer_base(v, 10, signed, b'd', LDIGITS),
            'b' => self.fmt_integer_base(v, 2, signed, b'b', LDIGITS),
            'o' => self.fmt_integer_base(v, 8, signed, b'o', LDIGITS),
            'O' => self.fmt_integer_base(v, 8, signed, b'O', LDIGITS),
            'x' => self.fmt_integer_base(v, 16, signed, b'x', LDIGITS),
            'X' => self.fmt_integer_base(v, 16, signed, b'X', UDIGITS),
            'c' => self.fmt_c(v),
            'q' => self.fmt_qc(v),
            'U' => self.fmt_unicode(v),
            _ => self.bad_verb(verb),
        }
    }

    fn fmt_float(&mut self, v: f64, verb: u32) {
        let Some(c) = char::from_u32(verb) else {
            return self.bad_verb(verb);
        };
        match c {
            'v' => self.fmt_float_raw(v, b'g', -1),
            'b' | 'g' | 'G' | 'x' | 'X' => self.fmt_float_raw(v, c as u8, -1),
            'f' | 'e' | 'E' => self.fmt_float_raw(v, c as u8, 6),
            'F' => self.fmt_float_raw(v, b'f', 6),
            _ => self.bad_verb(verb),
        }
    }

    fn fmt_complex(&mut self, re: f64, im: f64, verb: u32) {
        match char::from_u32(verb) {
            Some('v' | 'b' | 'g' | 'G' | 'x' | 'X' | 'f' | 'F' | 'e' | 'E') => {
                let old_plus = self.plus;
                self.buf.push(b'(');
                self.fmt_float(re, verb);
                self.plus = true;
                self.fmt_float(im, verb);
                self.buf.extend_from_slice(b"i)");
                self.plus = old_plus;
            }
            _ => self.bad_verb(verb),
        }
    }

    fn fmt_string(&mut self, v: &[u8], verb: u32) {
        match char::from_u32(verb) {
            Some('v') => {
                if self.sharp_v {
                    self.fmt_q(v);
                } else {
                    self.fmt_s(v);
                }
            }
            Some('s') => self.fmt_s(v),
            Some('x') => self.fmt_sx(v, LDIGITS),
            Some('X') => self.fmt_sx(v, UDIGITS),
            Some('q') => self.fmt_q(v),
            _ => self.bad_verb(verb),
        }
    }

    fn handle_methods(&mut self, arg: &Value, verb: u32) -> bool {
        if self.erroring {
            return false;
        }
        let Value::Err(text) = arg else {
            if verb == u32::from(b'w') {
                self.bad_verb(verb);
                return true;
            }
            return false;
        };
        let mut verb = verb;
        if verb == u32::from(b'w') {
            if !self.wrap_errs {
                self.bad_verb(verb);
                return true;
            }
            verb = u32::from(b'v');
        }
        if self.sharp_v {
            return false;
        }
        if matches!(char::from_u32(verb), Some('v' | 's' | 'x' | 'X' | 'q')) {
            self.fmt_string(text, verb);
            return true;
        }
        false
    }

    fn print_arg(&mut self, arg: &Value, verb: u32) {
        self.cur = Some(arg.clone());
        if !arg.is_valid() {
            match char::from_u32(verb) {
                Some('T' | 'v') => self.pad(b"<nil>"),
                _ => self.bad_verb(verb),
            }
            return;
        }
        match char::from_u32(verb) {
            Some('T') => {
                self.fmt_s(arg.type_name().as_bytes());
                return;
            }
            Some('p') => {
                match arg {
                    Value::Map(_) => {
                        self.fmt_0x64(0x00c0_0000_0000, !self.sharp);
                    }
                    _ => self.bad_verb(verb),
                }
                return;
            }
            _ => {}
        }
        match arg {
            Value::Bool(b) => self.fmt_bool(*b, verb),
            Value::Float(f) => self.fmt_float(*f, verb),
            Value::Complex(re, im) => self.fmt_complex(*re, *im, verb),
            Value::Int(i) => self.fmt_integer(*i as u64, true, verb),
            Value::Uint8(u) => self.fmt_integer(u64::from(*u), false, verb),
            Value::Str(s) => self.fmt_string(s, verb),
            _ => {
                if !self.handle_methods(arg, verb) {
                    self.print_value(arg, verb, 0);
                }
            }
        }
    }

    fn print_value(&mut self, value: &Value, verb: u32, depth: usize) {
        if depth > 0 && value.is_valid() {
            self.cur = Some(value.clone());
            if self.handle_methods(value, verb) {
                return;
            }
        }
        self.cur = Some(value.clone());
        match value {
            Value::Invalid => {
                if depth == 0 {
                    self.buf.extend_from_slice(b"<invalid reflect.Value>");
                } else if verb == u32::from(b'v') {
                    self.buf.extend_from_slice(b"<nil>");
                } else {
                    self.bad_verb(verb);
                }
            }
            Value::Bool(b) => self.fmt_bool(*b, verb),
            Value::Int(i) => self.fmt_integer(*i as u64, true, verb),
            Value::Uint8(u) => self.fmt_integer(u64::from(*u), false, verb),
            Value::Float(f) => self.fmt_float(*f, verb),
            Value::Complex(re, im) => self.fmt_complex(*re, *im, verb),
            Value::Str(s) => self.fmt_string(s, verb),
            Value::Map(m) => {
                if self.sharp_v {
                    self.buf.extend_from_slice(b"map[string]string{");
                } else {
                    self.buf.extend_from_slice(b"map[");
                }
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        if self.sharp_v {
                            self.buf.extend_from_slice(b", ");
                        } else {
                            self.buf.push(b' ');
                        }
                    }
                    self.print_value(&Value::Str(k.clone()), verb, depth + 1);
                    self.buf.push(b':');
                    self.print_value(&Value::Str(v.clone()), verb, depth + 1);
                }
                self.buf.push(if self.sharp_v { b'}' } else { b']' });
            }
            Value::Data(d) => {
                if self.sharp_v {
                    self.buf.extend_from_slice(b"template.RenderData");
                }
                self.buf.push(b'{');
                let fields: [(&[u8], Value); 3] = [
                    (b"Name", Value::Str(d.name.clone())),
                    (b"Refs", Value::Map(d.refs.clone())),
                    (b"Values", Value::Map(d.values.clone())),
                ];
                for (i, (name, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        if self.sharp_v {
                            self.buf.extend_from_slice(b", ");
                        } else {
                            self.buf.push(b' ');
                        }
                    }
                    if self.plus_v || self.sharp_v {
                        self.buf.extend_from_slice(name);
                        self.buf.push(b':');
                    }
                    self.print_value(v, verb, depth + 1);
                }
                self.buf.push(b'}');
            }
            Value::Err(_) => {
                // A pointer to an unexported struct; only reachable with
                // verbs fmt does not special-case.
                self.bad_verb(verb);
            }
        }
    }

    fn arg_number(
        &mut self,
        arg_num: usize,
        format: &[u8],
        i: usize,
        num_args: usize,
    ) -> (usize, usize, bool) {
        if format.len() <= i || format[i] != b'[' {
            return (arg_num, i, false);
        }
        self.reordered = true;
        let (index, wid, ok) = parse_arg_number(&format[i..]);
        if ok && 0 <= index && (index as usize) < num_args {
            return (index as usize, i + wid, true);
        }
        self.good_arg_num = false;
        (arg_num, i + wid, ok)
    }

    #[allow(unused_assignments)]
    fn do_printf(&mut self, format: &[u8], a: &[Value]) {
        let end = format.len();
        let mut arg_num = 0usize;
        let mut after_index = false;
        self.reordered = false;
        let mut i = 0usize;
        'format_loop: while i < end {
            self.good_arg_num = true;
            let lasti = i;
            while i < end && format[i] != b'%' {
                i += 1;
            }
            if i > lasti {
                self.buf.extend_from_slice(&format[lasti..i]);
            }
            if i >= end {
                break;
            }
            i += 1;
            self.clear_flags();
            while i < end {
                let c = format[i];
                match c {
                    b'#' => self.sharp = true,
                    b'0' => self.zero = true,
                    b'+' => self.plus = true,
                    b'-' => self.minus = true,
                    b' ' => self.space = true,
                    _ => {
                        if c.is_ascii_lowercase() && arg_num < a.len() {
                            if c == b'v' || c == b'w' {
                                self.sharp_v = self.sharp;
                                self.sharp = false;
                                self.plus_v = self.plus;
                                self.plus = false;
                            }
                            self.print_arg(&a[arg_num], u32::from(c));
                            arg_num += 1;
                            i += 1;
                            continue 'format_loop;
                        }
                        break;
                    }
                }
                i += 1;
            }
            let (an, ni, ai) = self.arg_number(arg_num, format, i, a.len());
            arg_num = an;
            i = ni;
            after_index = ai;
            if i < end && format[i] == b'*' {
                i += 1;
                let (w, present, an) = int_from_arg(a, arg_num);
                self.wid = w;
                self.wid_present = present;
                arg_num = an;
                if !self.wid_present {
                    self.buf.extend_from_slice(b"%!(BADWIDTH)");
                }
                if self.wid < 0 {
                    self.wid = -self.wid;
                    self.minus = true;
                    self.zero = false;
                }
                after_index = false;
            } else {
                let (w, present, ni) = parsenum(format, i, end);
                self.wid = w;
                self.wid_present = present;
                i = ni;
                if after_index && self.wid_present {
                    self.good_arg_num = false;
                }
            }
            if i + 1 < end && format[i] == b'.' {
                i += 1;
                if after_index {
                    self.good_arg_num = false;
                }
                let (an, ni, ai) = self.arg_number(arg_num, format, i, a.len());
                arg_num = an;
                i = ni;
                after_index = ai;
                if i < end && format[i] == b'*' {
                    i += 1;
                    let (p, present, an) = int_from_arg(a, arg_num);
                    self.prec = p;
                    self.prec_present = present;
                    arg_num = an;
                    if self.prec < 0 {
                        self.prec = 0;
                        self.prec_present = false;
                    }
                    if !self.prec_present {
                        self.buf.extend_from_slice(b"%!(BADPREC)");
                    }
                    after_index = false;
                } else {
                    let (p, present, ni) = parsenum(format, i, end);
                    self.prec = p;
                    self.prec_present = present;
                    i = ni;
                    if !self.prec_present {
                        self.prec = 0;
                        self.prec_present = true;
                    }
                }
            }
            if !after_index {
                let (an, ni, ai) = self.arg_number(arg_num, format, i, a.len());
                arg_num = an;
                i = ni;
                after_index = ai;
            }
            if i >= end {
                self.buf.extend_from_slice(b"%!(NOVERB)");
                break;
            }
            let (verb, size) = decode_rune(&format[i..]);
            i += size;
            if verb == u32::from(b'%') {
                self.buf.push(b'%');
            } else if !self.good_arg_num {
                self.buf.extend_from_slice(b"%!");
                append_rune(&mut self.buf, verb);
                self.buf.extend_from_slice(b"(BADINDEX)");
            } else if arg_num >= a.len() {
                self.buf.extend_from_slice(b"%!");
                append_rune(&mut self.buf, verb);
                self.buf.extend_from_slice(b"(MISSING)");
            } else {
                if verb == u32::from(b'w') || verb == u32::from(b'v') {
                    self.sharp_v = self.sharp;
                    self.sharp = false;
                    self.plus_v = self.plus;
                    self.plus = false;
                }
                self.print_arg(&a[arg_num], verb);
                arg_num += 1;
            }
        }
        if !self.reordered && arg_num < a.len() {
            self.clear_flags();
            self.buf.extend_from_slice(b"%!(EXTRA ");
            for (i, arg) in a[arg_num..].iter().enumerate() {
                if i > 0 {
                    self.buf.extend_from_slice(b", ");
                }
                if arg.is_valid() {
                    self.buf.extend_from_slice(arg.type_name().as_bytes());
                    self.buf.push(b'=');
                    self.print_arg(arg, u32::from(b'v'));
                } else {
                    self.buf.extend_from_slice(b"<nil>");
                }
            }
            self.buf.push(b')');
        }
    }

    fn do_print(&mut self, a: &[Value]) {
        let mut prev_string = false;
        for (arg_num, arg) in a.iter().enumerate() {
            let is_string = matches!(arg, Value::Str(_));
            if arg_num > 0 && !is_string && !prev_string {
                self.buf.push(b' ');
            }
            self.print_arg(arg, u32::from(b'v'));
            prev_string = is_string;
        }
    }

    fn do_println(&mut self, a: &[Value]) {
        for (arg_num, arg) in a.iter().enumerate() {
            if arg_num > 0 {
                self.buf.push(b' ');
            }
            self.print_arg(arg, u32::from(b'v'));
        }
        self.buf.push(b'\n');
    }
}
