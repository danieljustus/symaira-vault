//! `gopkg.in/yaml.v3` scalar resolver (`resolve.go`): which tag a *plain*
//! scalar resolves to, and its value where the decoder needs one.
//!
//! The resolver is what `yaml.Marshal` consults to decide whether a string must
//! be quoted (a string that would resolve to anything but `!!str` is
//! double-quoted) and what `yaml.Unmarshal` consults to decide how a plain
//! scalar decodes into a typed field. It is a hint table plus a handful of
//! parsers, ported rule for rule, including the quirks (a leading-zero decimal
//! like `08` is a float, `<<` is a plain string here, `1e1000` is a string).

/// The result of resolving a plain scalar.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Resolved {
    Null,
    Bool(bool),
    /// `!!int` that fits `int64`.
    Int(i64),
    /// `!!int` above `int64::MAX` (Go's `uint64`).
    Uint(u64),
    Float(f64),
    Timestamp,
    Str,
}

impl Resolved {
    /// The short tag yaml.v3 prints in decode errors.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Null => "!!null",
            Self::Bool(_) => "!!bool",
            Self::Int(_) | Self::Uint(_) => "!!int",
            Self::Float(_) => "!!float",
            Self::Timestamp => "!!timestamp",
            Self::Str => "!!str",
        }
    }
}

/// `resolveTable`: `+`/`-` are signs, digits are digits, `yYnNtTfFoO~` are map
/// candidates, `.` is a potential float; every other first byte is a string.
fn hint(first: Option<u8>) -> u8 {
    match first {
        None => b'N',
        Some(b'+' | b'-') => b'S',
        Some(b'0'..=b'9') => b'D',
        Some(b'y' | b'Y' | b'n' | b'N' | b't' | b'T' | b'f' | b'F' | b'o' | b'O' | b'~') => b'M',
        Some(b'.') => b'.',
        Some(_) => 0,
    }
}

/// `resolve("", text)` for a plain scalar.
#[must_use]
pub fn resolve(text: &str) -> Resolved {
    let hint = hint(text.as_bytes().first().copied());
    if hint == 0 {
        return Resolved::Str;
    }
    match text {
        "true" | "True" | "TRUE" => return Resolved::Bool(true),
        "false" | "False" | "FALSE" => return Resolved::Bool(false),
        "" | "~" | "null" | "Null" | "NULL" => return Resolved::Null,
        ".nan" | ".NaN" | ".NAN" => return Resolved::Float(f64::NAN),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => {
            return Resolved::Float(f64::INFINITY);
        }
        "-.inf" | "-.Inf" | "-.INF" => return Resolved::Float(f64::NEG_INFINITY),
        _ => {}
    }
    match hint {
        b'.' => {
            if let Some(number) = go_parse_float(text) {
                return Resolved::Float(number);
            }
        }
        b'D' | b'S' => {
            if is_timestamp(text) {
                return Resolved::Timestamp;
            }
            let plain = text.replace('_', "");
            if let Some(int) = parse_int_base0(&plain) {
                return match int {
                    Parsed::Int(value) => Resolved::Int(value),
                    Parsed::Uint(value) => Resolved::Uint(value),
                };
            }
            if yaml_style_float(&plain)
                && let Some(number) = go_parse_float(&plain)
            {
                return Resolved::Float(number);
            }
            if let Some(int) = parse_prefixed_int(&plain) {
                return match int {
                    Parsed::Int(value) => Resolved::Int(value),
                    Parsed::Uint(value) => Resolved::Uint(value),
                };
            }
        }
        _ => {}
    }
    Resolved::Str
}

enum Parsed {
    Int(i64),
    Uint(u64),
}

/// `strconv.ParseInt(s, 0, 64)`, then `strconv.ParseUint(s, 0, 64)` for what
/// does not fit (underscores are already removed by the caller).
fn parse_int_base0(text: &str) -> Option<Parsed> {
    let (negative, unsigned) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if unsigned.is_empty() {
        return None;
    }
    let (radix, digits) = match unsigned.as_bytes() {
        [b'0', b'x' | b'X', ..] => (16, &unsigned[2..]),
        [b'0', b'b' | b'B', ..] => (2, &unsigned[2..]),
        [b'0', b'o' | b'O', ..] => (8, &unsigned[2..]),
        [b'0', _, ..] => (8, &unsigned[1..]),
        _ => (10, unsigned),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let magnitude = u64::from_str_radix(digits, radix).ok()?;
    if negative {
        // ParseInt only: ParseUint rejects a sign.
        if magnitude <= i64::MAX as u64 + 1 {
            return Some(Parsed::Int((magnitude as i64).wrapping_neg()));
        }
        return None;
    }
    if text.starts_with('+') {
        // ParseInt accepts `+`, ParseUint does not.
        return i64::try_from(magnitude).ok().map(Parsed::Int);
    }
    Some(match i64::try_from(magnitude) {
        Ok(value) => Parsed::Int(value),
        Err(_) => Parsed::Uint(magnitude),
    })
}

/// The `0b`/`-0b`/`0o`/`-0o` branches `resolve.go` tries after the float: the
/// prefix is cut off and the rest goes through `strconv.ParseInt(rest, radix,
/// 64)`, which accepts its own sign (`0b+1` and `0o-12` are ints) and then
/// `strconv.ParseUint(rest, radix, 64)`, which does not. Underscores are gone.
/// The prefix check is case sensitive: `0B+1` stays a string.
fn parse_prefixed_int(plain: &str) -> Option<Parsed> {
    for (prefix, radix) in [("0b", 2), ("0o", 8)] {
        if let Some(rest) = plain.strip_prefix(prefix) {
            return parse_radix_signed(rest, radix);
        }
    }
    for (prefix, radix) in [("-0b", 2), ("-0o", 8)] {
        if let Some(rest) = plain.strip_prefix(prefix) {
            // `ParseInt("-"+rest, radix, 64)` only: a second sign is a syntax error.
            return parse_radix_signed(&format!("-{rest}"), radix)
                .filter(|parsed| matches!(parsed, Parsed::Int(_)));
        }
    }
    None
}

/// `ParseInt(text, radix, 64)`, then `ParseUint(text, radix, 64)`.
fn parse_radix_signed(text: &str, radix: u32) -> Option<Parsed> {
    let (negative, positive, digits) = match text.as_bytes().first()? {
        b'-' => (true, false, &text[1..]),
        b'+' => (false, true, &text[1..]),
        _ => (false, false, text),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let magnitude = u64::from_str_radix(digits, radix).ok()?;
    if negative {
        return (magnitude <= i64::MAX as u64 + 1)
            .then(|| Parsed::Int((magnitude as i64).wrapping_neg()));
    }
    match i64::try_from(magnitude) {
        Ok(value) => Some(Parsed::Int(value)),
        // ParseUint rejects the `+`.
        Err(_) if positive => None,
        Err(_) => Some(Parsed::Uint(magnitude)),
    }
}

/// `yamlStyleFloat`: `^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`.
fn yaml_style_float(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = usize::from(matches!(bytes.first(), Some(b'-' | b'+')));
    let digits = |from: usize| {
        bytes[from..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count()
    };
    if bytes.get(index) == Some(&b'.') {
        let count = digits(index + 1);
        if count == 0 {
            return false;
        }
        index += 1 + count;
    } else {
        let count = digits(index);
        if count == 0 {
            return false;
        }
        index += count;
        if bytes.get(index) == Some(&b'.') {
            index += 1 + digits(index + 1);
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'-' | b'+')) {
            index += 1;
        }
        let count = digits(index);
        if count == 0 {
            return false;
        }
        index += count;
    }
    index == bytes.len()
}

/// `strconv.ParseFloat(text, 64)` for the shapes the resolver can reach
/// (decimal digits, `.`, an exponent, a sign): finite results only, a range
/// error (`1e1000`) is a failure like in Go.
fn go_parse_float(text: &str) -> Option<f64> {
    if !text
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | 'e' | 'E' | '_'))
    {
        return None;
    }
    // A leading-dot float skips the underscore removal of the int/float path
    // and goes to ParseFloat as is, which takes `_` between digits.
    let digits;
    let text = if text.contains('_') {
        if !underscore_ok(text) {
            return None;
        }
        digits = text.replace('_', "");
        digits.as_str()
    } else {
        text
    };
    let number: f64 = text.parse().ok()?;
    number.is_finite().then_some(number)
}

/// `strconv.underscoreOK` for a decimal literal: every `_` sits between two
/// digits.
fn underscore_ok(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = usize::from(matches!(bytes.first(), Some(b'-' | b'+')));
    let mut saw = b'^';
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_digit() {
            saw = b'0';
        } else if byte == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        index += 1;
    }
    saw != b'_'
}

/// `parseTimestamp`: a date, optionally followed by `T`/`t`/space and a time,
/// in one of the four layouts yaml.v3 allows
/// (`2006-1-2T15:4:5.999999999Z07:00`, the same with `t`, `2006-1-2
/// 15:4:5.999999999` and `2006-1-2`), with every field range-checked like
/// `time.Parse`.
#[must_use]
pub fn is_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let year_digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if year_digits != 4 || year_digits == bytes.len() || bytes[year_digits] != b'-' {
        return false;
    }
    let year: u32 = text[..4].parse().unwrap_or(0);
    let mut cursor = Cursor { text, pos: 5 };
    let Some(month) = cursor.number(1, 2) else {
        return false;
    };
    if !cursor.eat(b'-') {
        return false;
    }
    let Some(day) = cursor.number(1, 2) else {
        return false;
    };
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return false;
    }
    if cursor.done() {
        return true;
    }
    let with_zone = match cursor.peek() {
        Some(b'T' | b't') => true,
        Some(b' ') => false,
        _ => return false,
    };
    cursor.pos += 1;
    let Some(hour) = cursor.number(1, 2) else {
        return false;
    };
    if !cursor.eat(b':') {
        return false;
    }
    let Some(minute) = cursor.number(1, 2) else {
        return false;
    };
    if !cursor.eat(b':') {
        return false;
    }
    let Some(second) = cursor.number(1, 2) else {
        return false;
    };
    if hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    if cursor.peek() == Some(b'.') || cursor.peek() == Some(b',') {
        let start = cursor.pos + 1;
        let count = bytes[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if count == 0 || count > 9 {
            return false;
        }
        cursor.pos = start + count;
    }
    if cursor.done() {
        // Only the space layout has no zone; the `T` layouts require one.
        return !with_zone;
    }
    if !with_zone {
        return false;
    }
    if cursor.eat(b'Z') {
        return cursor.done();
    }
    let sign = cursor.peek();
    if !matches!(sign, Some(b'+' | b'-')) {
        return false;
    }
    cursor.pos += 1;
    let (Some(zone_hour), true, Some(zone_minute)) = (
        cursor.fixed_number(2),
        cursor.eat(b':'),
        cursor.fixed_number(2),
    ) else {
        return false;
    };
    zone_hour <= 24 && zone_minute <= 59 && cursor.done()
}

struct Cursor<'a> {
    text: &'a str,
    pos: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }
    fn done(&self) -> bool {
        self.pos == self.text.len()
    }
    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    /// One or two digits (`getnum(value, false)`).
    fn number(&mut self, min: usize, max: usize) -> Option<u32> {
        let rest = &self.text.as_bytes()[self.pos..];
        let count = rest
            .iter()
            .take(max)
            .take_while(|b| b.is_ascii_digit())
            .count();
        if count < min {
            return None;
        }
        let value = self.text[self.pos..self.pos + count].parse().ok()?;
        self.pos += count;
        Some(value)
    }
    fn fixed_number(&mut self, width: usize) -> Option<u32> {
        let rest = &self.text.as_bytes()[self.pos..];
        if rest.len() < width || !rest[..width].iter().all(u8::is_ascii_digit) {
            return None;
        }
        let value = self.text[self.pos..self.pos + width].parse().ok()?;
        self.pos += width;
        Some(value)
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        _ => 28,
    }
}

/// `isBase60Float`: `^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$` (the
/// encoder quotes these for YAML 1.1 readers).
#[must_use]
pub fn is_base60_float(text: &str) -> bool {
    let bytes = text.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if !(first == b'+' || first == b'-' || first.is_ascii_digit()) || !text.contains(':') {
        return false;
    }
    let mut index = usize::from(first == b'+' || first == b'-');
    if !bytes.get(index).is_some_and(u8::is_ascii_digit) {
        return false;
    }
    index += 1;
    while bytes
        .get(index)
        .is_some_and(|b| b.is_ascii_digit() || *b == b'_')
    {
        index += 1;
    }
    let mut groups = 0;
    while bytes.get(index) == Some(&b':') {
        let rest = &bytes[index + 1..];
        let take = match rest {
            [a, b, ..] if (b'0'..=b'5').contains(a) && b.is_ascii_digit() => 2,
            [a, ..] if a.is_ascii_digit() => 1,
            _ => return false,
        };
        index += 1 + take;
        groups += 1;
    }
    if groups == 0 {
        return false;
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        while bytes
            .get(index)
            .is_some_and(|b| b.is_ascii_digit() || *b == b'_')
        {
            index += 1;
        }
    }
    index == bytes.len()
}

/// `isOldBool`: the YAML 1.1 spellings the encoder keeps quoted.
#[must_use]
pub fn is_old_bool(text: &str) -> bool {
    matches!(
        text,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "on"
            | "On"
            | "ON"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "off"
            | "Off"
            | "OFF"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(text, tag)` pairs recorded from gopkg.in/yaml.v3 v3.0.1 (a `yaml.Node`
    /// parse of the plain scalar) by a throwaway Go probe.
    const GO_TAGS: &[(&str, &str)] = &[
        ("~", "!!null"),
        ("null", "!!null"),
        ("Null", "!!null"),
        ("NULL", "!!null"),
        ("NuLL", "!!str"),
        ("true", "!!bool"),
        ("True", "!!bool"),
        ("TRUE", "!!bool"),
        ("tRUE", "!!str"),
        ("false", "!!bool"),
        ("FALSE", "!!bool"),
        ("yes", "!!str"),
        ("no", "!!str"),
        ("on", "!!str"),
        ("off", "!!str"),
        ("y", "!!str"),
        ("n", "!!str"),
        ("Y", "!!str"),
        ("N", "!!str"),
        (".inf", "!!float"),
        (".Inf", "!!float"),
        (".INF", "!!float"),
        ("+.inf", "!!float"),
        ("-.inf", "!!float"),
        ("-.INF", "!!float"),
        (".nan", "!!float"),
        (".NaN", "!!float"),
        (".NAN", "!!float"),
        (".nAn", "!!str"),
        ("<", "!!str"),
        ("12", "!!int"),
        ("-12", "!!int"),
        ("+12", "!!int"),
        ("012", "!!int"),
        ("08", "!!float"),
        ("0x1f", "!!int"),
        ("0X1F", "!!int"),
        ("0o17", "!!int"),
        ("0O17", "!!int"),
        ("0b101", "!!int"),
        ("0B11", "!!int"),
        ("-0b11", "!!int"),
        ("1_000", "!!int"),
        ("_1", "!!str"),
        ("1__0", "!!int"),
        ("9223372036854775807", "!!int"),
        ("9223372036854775808", "!!int"),
        ("18446744073709551615", "!!int"),
        ("18446744073709551616", "!!float"),
        ("-9223372036854775808", "!!int"),
        ("-9223372036854775809", "!!float"),
        ("1.5", "!!float"),
        ("1.", "!!float"),
        (".5", "!!float"),
        ("-.5", "!!float"),
        ("+.5", "!!float"),
        ("1e3", "!!float"),
        ("1E3", "!!float"),
        ("1e+3", "!!float"),
        ("e3", "!!str"),
        ("1.5e", "!!str"),
        ("1_0.5", "!!float"),
        ("0.5_5", "!!float"),
        ("1:30", "!!str"),
        ("1:30:00", "!!str"),
        ("12:30:45", "!!str"),
        ("190:20:30.15", "!!str"),
        ("0x", "!!str"),
        ("0b", "!!str"),
        ("0o", "!!str"),
        ("0xg", "!!str"),
        ("+", "!!str"),
        (".", "!!str"),
        ("..", "!!str"),
        ("-0", "!!int"),
        ("+0", "!!int"),
        ("0", "!!int"),
        ("00", "!!int"),
        ("1 2", "!!str"),
        ("2026-10-31", "!!timestamp"),
        ("2026-1-2", "!!timestamp"),
        ("2026-13-01", "!!str"),
        ("2026-02-30", "!!str"),
        ("2026-10-31T10:00:00Z", "!!timestamp"),
        ("2026-10-31t10:00:00Z", "!!timestamp"),
        ("2026-10-31 10:00:00", "!!timestamp"),
        ("2026-10-31 10:00", "!!str"),
        ("2026-10-31T10:00:00", "!!str"),
        ("2026-10-31T10:00:00+02:00", "!!timestamp"),
        ("2026-10-31T10:00:00.123456789Z", "!!timestamp"),
        ("2026-10-31T25:00:00Z", "!!str"),
        ("2026-10-31T1:2:3Z", "!!timestamp"),
        ("2026-10-31 1:2:3", "!!timestamp"),
        ("2026-10-31 10:00:00 +0200", "!!str"),
        ("2026-10-31T10:00:00 Z", "!!str"),
        ("20261031", "!!int"),
        ("10000-01-01", "!!str"),
        ("0000-01-01", "!!timestamp"),
        ("2026-10-31x", "!!str"),
        ("a", "!!str"),
        ("abc", "!!str"),
        ("Yes", "!!str"),
        ("NO", "!!str"),
        ("tru", "!!str"),
        ("nul", "!!str"),
        ("0.1.2", "!!str"),
        ("1.2.3", "!!str"),
        ("0e", "!!str"),
        ("0e0", "!!float"),
        ("1e1000", "!!str"),
        ("-1e1000", "!!str"),
        ("0.0", "!!float"),
        ("-0.0", "!!float"),
        ("1.0", "!!float"),
        ("100", "!!int"),
        ("1e2", "!!float"),
        (".e2", "!!str"),
        ("+1e2", "!!float"),
        ("0xFFFFFFFFFFFFFFFF", "!!int"),
        ("0x7FFFFFFFFFFFFFFF", "!!int"),
        ("0x8000000000000000", "!!int"),
        ("-0x8000000000000000", "!!int"),
        ("0777", "!!int"),
        ("0888", "!!float"),
        ("-0777", "!!int"),
        ("0_7", "!!int"),
        ("0b_1", "!!int"),
        // Probed with the oracle's `sessionTimeout` decode error: the 0b/0o
        // prefix is cut off and ParseInt takes the sign behind it.
        ("0b+1", "!!int"),
        ("0b-1", "!!int"),
        ("0o-12", "!!int"),
        ("0o+12", "!!int"),
        ("0B+1", "!!str"),
        ("0O-12", "!!str"),
        ("0b--1", "!!str"),
        ("0b+", "!!str"),
        (".1_0", "!!float"),
        (".5_6", "!!float"),
        (".5e1_0", "!!float"),
        ("._5", "!!str"),
        (".5_", "!!str"),
        (".5__6", "!!str"),
        (".5_e3", "!!str"),
        ("0x_1f", "!!int"),
        ("-a", "!!str"),
        ("a#b", "!!str"),
        (" a", "!!str"),
        ("a ", "!!str"),
        ("", "!!null"),
    ];

    #[test]
    fn resolver_matches_recorded_yaml_v3_tags() {
        for (text, tag) in GO_TAGS {
            assert_eq!(resolve(text).tag(), *tag, "{text:?}");
        }
    }

    #[test]
    fn resolver_values_follow_go() {
        assert_eq!(resolve("0x1f"), Resolved::Int(31));
        assert_eq!(resolve("0777"), Resolved::Int(511));
        assert_eq!(resolve("1_000"), Resolved::Int(1000));
        assert_eq!(resolve("-0b11"), Resolved::Int(-3));
        assert_eq!(resolve("-9223372036854775808"), Resolved::Int(i64::MIN));
        assert_eq!(
            resolve("9223372036854775808"),
            Resolved::Uint(9_223_372_036_854_775_808)
        );
        assert_eq!(resolve("08"), Resolved::Float(8.0));
        assert_eq!(
            resolve("<<"),
            Resolved::Str,
            "the encoder sees << as a plain string"
        );
        assert!(is_base60_float("190:20:30.15"));
        assert!(!is_base60_float("1:60"));
        assert!(is_old_bool("Yes") && !is_old_bool("yEs"));
    }
}
