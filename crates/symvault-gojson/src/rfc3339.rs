//! `time.Time.UnmarshalText` (`time.Parse(time.RFC3339, s)`) error wording.
//!
//! yaml.v3 hands any scalar of a `time.Time` field that did not resolve to a
//! `!!timestamp` to `UnmarshalText`, and a failure aborts the whole decode
//! with the `*time.ParseError` text. Go parses RFC 3339 leniently (the strict
//! checks are disabled in `parseStrictRFC3339`), so this ports the layout
//! walk of `time.parse` for the one layout `2006-01-02T15:04:05Z07:00`:
//! every element, range check and error spelling, the fractional second that
//! the layout does not name, and `quote`'s `\x` escapes.

/// The `Error()` text `time.Parse(time.RFC3339, value)` returns, or `None`
/// when Go accepts `value`.
#[must_use]
pub fn parse_error(value: &str) -> Option<String> {
    match walk(value) {
        Ok(()) => None,
        Err(Failure::Element { element, seen }) => Some(format!(
            "parsing time {} as {}: cannot parse {} as {}",
            quote(value),
            quote(LAYOUT),
            quote(&seen),
            quote(element)
        )),
        Err(Failure::Message(message)) => Some(format!("parsing time {}{message}", quote(value))),
    }
}

const LAYOUT: &str = "2006-01-02T15:04:05Z07:00";

enum Failure {
    /// `cannot parse "<seen>" as "<element>"`.
    Element { element: &'static str, seen: String },
    /// A `ParseError` with a message: `parsing time "<value>"<message>`.
    Message(String),
}

/// `time.quote`: ASCII printable bytes verbatim (`"` and `\` escaped), every
/// byte of a non-ASCII or control character as `\xNN`.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        if u32::from(character) >= 0x80 || character < ' ' {
            let mut buffer = [0u8; 4];
            for byte in character.encode_utf8(&mut buffer).bytes() {
                out.push_str(&format!("\\x{byte:02x}"));
            }
        } else {
            if character == '"' || character == '\\' {
                out.push('\\');
            }
            out.push(character);
        }
    }
    out.push('"');
    out
}

fn is_digit(bytes: &[u8], index: usize) -> bool {
    bytes.get(index).is_some_and(u8::is_ascii_digit)
}

/// `getnum`: one or two digits (exactly two when `fixed`).
fn getnum(bytes: &[u8], fixed: bool) -> Option<(u32, &[u8])> {
    if !is_digit(bytes, 0) {
        return None;
    }
    if !is_digit(bytes, 1) {
        return if fixed {
            None
        } else {
            Some((u32::from(bytes[0] - b'0'), &bytes[1..]))
        };
    }
    Some((
        u32::from(bytes[0] - b'0') * 10 + u32::from(bytes[1] - b'0'),
        &bytes[2..],
    ))
}

fn days_in(month: u32, year: u32) -> u32 {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn walk(whole: &str) -> Result<(), Failure> {
    let mut value = whole.as_bytes();
    // The text from `at` on; every consumed byte is ASCII, so `at` is always a
    // character boundary of `whole`.
    let seen = |value: &[u8]| String::from_utf8_lossy(value).into_owned();
    let fail = |element: &'static str, at: &[u8]| Failure::Element {
        element,
        seen: seen(at),
    };
    let range = |what: &str| Failure::Message(format!(": {what} out of range"));

    // `skip(value, prefix)`: the literal between two elements.
    let skip = |value: &mut &[u8], prefix: &'static str| -> Result<(), Failure> {
        if value.first() != Some(&prefix.as_bytes()[0]) {
            return Err(Failure::Element {
                element: prefix,
                seen: seen(value),
            });
        }
        *value = &value[1..];
        Ok(())
    };

    // 2006
    let hold = value;
    if value.len() < 4 || !is_digit(value, 0) || !value[..4].iter().all(u8::is_ascii_digit) {
        return Err(fail("2006", hold));
    }
    let year: u32 = std::str::from_utf8(&value[..4])
        .ok()
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0);
    value = &value[4..];

    // -01
    skip(&mut value, "-")?;
    let hold = value;
    let Some((month, rest)) = getnum(value, true) else {
        return Err(fail("01", hold));
    };
    value = rest;
    if month == 0 || month > 12 {
        return Err(range("month"));
    }

    // -02 (any two-digit day here; the combination is validated at the end)
    skip(&mut value, "-")?;
    let hold = value;
    let Some((day, rest)) = getnum(value, true) else {
        return Err(fail("02", hold));
    };
    value = rest;

    // T15
    skip(&mut value, "T")?;
    let hold = value;
    let Some((hour, rest)) = getnum(value, false) else {
        return Err(fail("15", hold));
    };
    value = rest;
    if hour >= 24 {
        return Err(range("hour"));
    }

    // :04
    skip(&mut value, ":")?;
    let hold = value;
    let Some((minute, rest)) = getnum(value, true) else {
        return Err(fail("04", hold));
    };
    value = rest;
    if minute >= 60 {
        return Err(range("minute"));
    }

    // :05, then a fractional second the layout does not name
    skip(&mut value, ":")?;
    let hold = value;
    let Some((second, rest)) = getnum(value, true) else {
        return Err(fail("05", hold));
    };
    value = rest;
    if second >= 60 {
        return Err(range("second"));
    }
    if value.len() >= 2 && matches!(value[0], b'.' | b',') && is_digit(value, 1) {
        let mut digits = 2;
        while is_digit(value, digits) {
            digits += 1;
        }
        value = &value[digits..];
    }

    // Z07:00
    let hold = value;
    if value.first() == Some(&b'Z') {
        value = &value[1..];
    } else {
        if value.len() < 6 || value[3] != b':' {
            return Err(fail("Z07:00", hold));
        }
        let (sign, hour_digits, minute_digits) = (value[0], &value[1..3], &value[4..6]);
        value = &value[6..];
        let zone_hour = getnum(hour_digits, true).map(|(number, _)| number);
        let zone_minute = zone_hour.and_then(|_| getnum(minute_digits, true).map(|(n, _)| n));
        // The range tests use > rather than >=: offsets of 24 hours and 60
        // minutes are written by some people.
        if zone_hour.is_some_and(|hours| hours > 24) {
            return Err(range("time zone offset hour"));
        }
        if zone_minute.is_some_and(|minutes| minutes > 60) {
            return Err(range("time zone offset minute"));
        }
        if zone_hour.is_none() || zone_minute.is_none() || !matches!(sign, b'+' | b'-') {
            return Err(fail("Z07:00", hold));
        }
    }

    if !value.is_empty() {
        return Err(Failure::Message(format!(
            ": extra text: {}",
            quote(&seen(value))
        )));
    }
    if day < 1 || day > days_in(month, year) {
        return Err(Failure::Message(": day out of range".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_error;

    #[test]
    fn accepted_values_have_no_error() {
        for value in [
            "2026-10-31T10:00:00Z",
            "2026-10-31T10:00:00+02:00",
            "2026-10-31T10:00:00.123456789Z",
            "2026-10-31T10:00:00,5Z",
            "2026-10-31T1:04:05Z",
            "2026-10-31T10:00:00+24:60",
            "2026-02-29T00:00:00Z",
            "0000-01-01T00:00:00Z",
        ] {
            let result = parse_error(value);
            // 2026 is not a leap year: only that one is rejected.
            if value.starts_with("2026-02-29") {
                assert!(result.is_some(), "{value}");
            } else {
                assert_eq!(result, None, "{value}");
            }
        }
    }

    /// `(value, error)` pairs from the pinned Go CLI (`config set` on a file
    /// whose `vault.last_rotated` is the quoted value), the doubled cause cut
    /// to one copy.
    #[test]
    fn messages_match_the_ones_go_prints() {
        const LAYOUT: &str = "2006-01-02T15:04:05Z07:00";
        let element = |value: &str, seen: &str, layout: &str| {
            format!(
                "parsing time \"{value}\" as \"{LAYOUT}\": cannot parse \"{seen}\" as \"{layout}\""
            )
        };
        let range =
            |value: &str, what: &str| format!("parsing time \"{value}\": {what} out of range");
        for (value, want) in [
            ("12", element("12", "12", "2006")),
            (
                "20x6-10-31T10:00:00Z",
                element("20x6-10-31T10:00:00Z", "20x6-10-31T10:00:00Z", "2006"),
            ),
            ("2026-10-31", element("2026-10-31", "", "T")),
            ("2026-10-31x", element("2026-10-31x", "x", "T")),
            (
                "2026-10-31T10:00:00",
                element("2026-10-31T10:00:00", "", "Z07:00"),
            ),
            (
                "2026-10-31T10:0:00Z",
                element("2026-10-31T10:0:00Z", "0:00Z", "04"),
            ),
            (
                "2026-10-31T10:00:00+0200",
                element("2026-10-31T10:00:00+0200", "+0200", "Z07:00"),
            ),
            (
                "2026-10-31T10:00:00+aa:bb",
                element("2026-10-31T10:00:00+aa:bb", "+aa:bb", "Z07:00"),
            ),
            (
                "2026-13-01T00:00:00Z",
                range("2026-13-01T00:00:00Z", "month"),
            ),
            (
                "2026-10-31T24:00:00Z",
                range("2026-10-31T24:00:00Z", "hour"),
            ),
            (
                "2026-10-31T10:00:60Z",
                range("2026-10-31T10:00:60Z", "second"),
            ),
            (
                "2026-10-31T10:00:00+25:00",
                range("2026-10-31T10:00:00+25:00", "time zone offset hour"),
            ),
            (
                "2026-10-31T10:00:00+24:61",
                range("2026-10-31T10:00:00+24:61", "time zone offset minute"),
            ),
            (
                "2026-02-30T00:00:00Z",
                "parsing time \"2026-02-30T00:00:00Z\": day out of range".to_owned(),
            ),
            (
                "2026-10-31T10:00:00Zjunk",
                "parsing time \"2026-10-31T10:00:00Zjunk\": extra text: \"junk\"".to_owned(),
            ),
        ] {
            assert_eq!(parse_error(value), Some(want), "{value}");
        }
    }

    #[test]
    fn quoting_escapes_bytes_like_time_quote() {
        assert_eq!(
            parse_error("é\"\\\u{1}").as_deref(),
            Some(
                "parsing time \"\\xc3\\xa9\\\"\\\\\\x01\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"\\xc3\\xa9\\\"\\\\\\x01\" as \"2006\""
            )
        );
    }
}
