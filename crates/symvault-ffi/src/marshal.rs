//! `json.Marshal` of a vault entry, byte for byte.
//!
//! Go decodes every JSON number in an entry's `data` into a `float64` and
//! prints it with `strconv`'s `'f'`/`'e'` rule, and it sorts object keys. The
//! shared `symvault-gojson` formatter covers string escaping; this module adds
//! the number rule and an order-independent object writer.

use std::io;

use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};
use symvault_gojson::GoFormatter;

/// Go's `float64` rendering inside `encoding/json`.
pub(crate) fn go_float(value: f64) -> String {
    let magnitude = value.abs();
    if magnitude != 0.0 && !(1e-6..1e21).contains(&magnitude) {
        // 'e' form: shortest digits, exponent with a sign and at least two
        // digits, then Go trims a single leading zero of a negative exponent.
        let text = format!("{value:e}");
        let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
        let (sign, digits) = match exponent.strip_prefix('-') {
            Some(digits) => ('-', digits),
            None => ('+', exponent),
        };
        let digits = if sign == '+' && digits.len() < 2 {
            format!("0{digits}")
        } else {
            digits.to_owned()
        };
        return format!("{mantissa}e{sign}{digits}");
    }
    format!("{value}")
}

struct GoNumbers;

impl Formatter for GoNumbers {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        GoFormatter.write_string_fragment(writer, fragment)
    }

    fn write_f64<W>(&mut self, writer: &mut W, value: f64) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        writer.write_all(go_float(value).as_bytes())
    }

    fn write_number_str<W>(&mut self, writer: &mut W, value: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        // Go decodes every number into a float64 and prints that.
        match value.parse::<f64>() {
            Ok(number) if number.is_finite() => writer.write_all(go_float(number).as_bytes()),
            _ => writer.write_all(value.as_bytes()),
        }
    }

    fn write_u64<W>(&mut self, writer: &mut W, value: u64) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        writer.write_all(go_float(value as f64).as_bytes())
    }

    fn write_i64<W>(&mut self, writer: &mut W, value: i64) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        writer.write_all(go_float(value as f64).as_bytes())
    }
}

/// Marshals `entry` the way the Go bridge does. `Entry`'s own `Serialize`
/// writes Go's struct field order and omission rules; object keys inside
/// `data` come out sorted because `serde_json::Map` is a `BTreeMap` here (the
/// `object_keys_are_sorted` test fails if a dependency enables `preserve_order`).
pub(crate) fn marshal_entry(entry: &symvault_store::Entry) -> Result<String, String> {
    let mut buffer = Vec::with_capacity(256);
    let mut serializer = Serializer::with_formatter(&mut buffer, GoNumbers);
    entry
        .serialize(&mut serializer)
        .map_err(|error| error.to_string())?;
    String::from_utf8(buffer).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_keys_are_sorted() {
        let value: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn floats_follow_go_strconv() {
        assert_eq!(go_float(1.0), "1");
        assert_eq!(go_float(1.5), "1.5");
        assert_eq!(go_float(-0.0), "-0");
        assert_eq!(go_float(1e21), "1e+21");
        assert_eq!(go_float(1e-7), "1e-7");
        assert_eq!(
            go_float(12_345_678_901_234_567_890.0),
            "12345678901234567000"
        );
        assert_eq!(go_float(1.5e-10), "1.5e-10");
        assert_eq!(go_float(1e25), "1e+25");
    }
}
