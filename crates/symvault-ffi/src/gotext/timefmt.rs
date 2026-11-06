//! Go `time` RFC 3339 behavior needed by the entry bridge: strict parsing with
//! Go's `time.ParseError` wording, and canonical `RFC3339Nano` output.

use super::quote;

const LAYOUT: &str = "2006-01-02T15:04:05Z07:00";

/// A parsed timestamp, kept in its own offset like Go's `time.Time`.
struct Stamp {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
    nano_digits: usize,
    offset_minutes: i32,
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

fn cannot(value: &str, rest: &str, element: &str) -> String {
    format!(
        "parsing time {} as {}: cannot parse {} as {}",
        quote(value),
        quote(LAYOUT),
        quote(rest),
        quote(element)
    )
}

fn range(value: &str, what: &str) -> String {
    format!("parsing time {}: {what} out of range", quote(value))
}

/// Takes exactly `width` ASCII digits, as Go's two/four-digit layout elements do.
fn digits(rest: &str, width: usize) -> Option<(u32, &str)> {
    let bytes = rest.as_bytes();
    if bytes.len() < width || !bytes[..width].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = rest[..width].parse().ok()?;
    Some((value, &rest[width..]))
}

fn parse_stamp(value: &str) -> Result<Stamp, String> {
    let mut rest = value;
    let (year, next) = digits(rest, 4).ok_or_else(|| cannot(value, rest, "2006"))?;
    rest = next;
    let expect = |rest: &mut &str, separator: char, element: &str| -> Result<(), String> {
        match rest.strip_prefix(separator) {
            Some(next) => {
                *rest = next;
                Ok(())
            }
            None => Err(cannot(value, rest, element)),
        }
    };
    expect(&mut rest, '-', "-")?;
    let (month, next) = digits(rest, 2).ok_or_else(|| cannot(value, rest, "01"))?;
    rest = next;
    if !(1..=12).contains(&month) {
        return Err(range(value, "month"));
    }
    expect(&mut rest, '-', "-")?;
    let (day, next) = digits(rest, 2).ok_or_else(|| cannot(value, rest, "02"))?;
    rest = next;
    expect(&mut rest, 'T', "T")?;
    let (hour, next) = digits(rest, 2).ok_or_else(|| cannot(value, rest, "15"))?;
    rest = next;
    if hour >= 24 {
        return Err(range(value, "hour"));
    }
    expect(&mut rest, ':', ":")?;
    let (minute, next) = digits(rest, 2).ok_or_else(|| cannot(value, rest, "04"))?;
    rest = next;
    if minute >= 60 {
        return Err(range(value, "minute"));
    }
    expect(&mut rest, ':', ":")?;
    let (second, next) = digits(rest, 2).ok_or_else(|| cannot(value, rest, "05"))?;
    rest = next;
    if second >= 60 {
        return Err(range(value, "second"));
    }
    if day == 0 || day > days_in_month(i64::from(year), month) {
        return Err(range(value, "day"));
    }
    let mut nanos = 0u32;
    let mut nano_digits = 0usize;
    if let Some(fraction) = rest.strip_prefix(['.', ',']) {
        let count = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if count == 0 {
            return Err(cannot(value, rest, "Z07:00"));
        }
        nano_digits = count.min(9);
        let mut padded = fraction[..nano_digits].to_owned();
        while padded.len() < 9 {
            padded.push('0');
        }
        nanos = padded.parse().unwrap_or(0);
        rest = &fraction[count..];
    }
    let offset_minutes = if let Some(next) = rest.strip_prefix('Z') {
        rest = next;
        0
    } else if let Some(sign) = rest.chars().next().filter(|c| matches!(c, '+' | '-')) {
        let after = &rest[1..];
        let (hours, after) = digits(after, 2).ok_or_else(|| cannot(value, rest, "Z07:00"))?;
        let after = after
            .strip_prefix(':')
            .ok_or_else(|| cannot(value, rest, "Z07:00"))?;
        let (minutes, after) = digits(after, 2).ok_or_else(|| cannot(value, rest, "Z07:00"))?;
        if hours > 24 {
            return Err(format!(
                "parsing time {}: time zone offset hour out of range",
                quote(value)
            ));
        }
        if minutes > 60 {
            return Err(format!(
                "parsing time {}: time zone offset minute out of range",
                quote(value)
            ));
        }
        rest = after;
        let total = (hours * 60 + minutes) as i32;
        if sign == '-' { -total } else { total }
    } else {
        return Err(cannot(value, rest, "Z07:00"));
    };
    if !rest.is_empty() {
        return Err(format!(
            "parsing time {}: extra text: {}",
            quote(value),
            quote(rest)
        ));
    }
    Ok(Stamp {
        year: i64::from(year),
        month,
        day,
        hour,
        minute,
        second,
        nanos,
        nano_digits,
        offset_minutes,
    })
}

fn format_stamp(stamp: &Stamp) -> String {
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second
    );
    if stamp.nanos != 0 {
        let fraction = format!("{:09}", stamp.nanos);
        let _ = stamp.nano_digits;
        out.push('.');
        out.push_str(fraction.trim_end_matches('0'));
    }
    if stamp.offset_minutes == 0 {
        out.push('Z');
    } else {
        let sign = if stamp.offset_minutes < 0 { '-' } else { '+' };
        let absolute = stamp.offset_minutes.abs();
        out.push_str(&format!("{sign}{:02}:{:02}", absolute / 60, absolute % 60));
    }
    out
}

/// Parses like `time.Time.UnmarshalJSON` on the string body and returns what
/// `json.Marshal` would print for the resulting value.
pub(crate) fn canonical_rfc3339(value: &str) -> Result<String, String> {
    parse_stamp(value).map(|stamp| format_stamp(&stamp))
}

/// `time.Now().UTC()` rendered as `RFC3339Nano`.
pub(crate) fn now_rfc3339_nano() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs() as i64;
    let nanos = now.subsec_nanos();
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days algorithm.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format_stamp(&Stamp {
        year,
        month,
        day,
        hour: (second_of_day / 3_600) as u32,
        minute: ((second_of_day % 3_600) / 60) as u32,
        second: (second_of_day % 60) as u32,
        nanos,
        nano_digits: 9,
        offset_minutes: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_trims_fraction_and_normalizes_utc() {
        assert_eq!(
            canonical_rfc3339("2026-11-01T03:40:18.372100Z").unwrap(),
            "2026-11-01T03:40:18.3721Z"
        );
        assert_eq!(
            canonical_rfc3339("2020-01-02T03:04:05+00:00").unwrap(),
            "2020-01-02T03:04:05Z"
        );
        assert_eq!(
            canonical_rfc3339("2020-01-02T03:04:05-07:30").unwrap(),
            "2020-01-02T03:04:05-07:30"
        );
    }

    #[test]
    fn errors_use_go_parse_error_wording() {
        assert_eq!(
            canonical_rfc3339("yesterday").unwrap_err(),
            "parsing time \"yesterday\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"yesterday\" as \"2006\""
        );
        assert_eq!(
            canonical_rfc3339("2020-13-01T00:00:00Z").unwrap_err(),
            "parsing time \"2020-13-01T00:00:00Z\": month out of range"
        );
    }

    #[test]
    fn now_is_parseable_utc() {
        let now = now_rfc3339_nano();
        assert_eq!(canonical_rfc3339(&now).unwrap(), now);
        assert!(now.ends_with('Z'));
    }
}
