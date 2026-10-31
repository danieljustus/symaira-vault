//! `gopkg.in/yaml.v3` compatible block-style emission for the CLI's
//! `--output yaml`.
//!
//! The Go CLI marshals plain structs and maps with the library defaults:
//! four-space indentation, mapping keys in declaration order (structs) or
//! sorted (maps), a sequence under a mapping key indented by one level, a
//! sequence of mappings written `- key: value` with the continuation lines two
//! columns in, and empty collections as `[]`/`{}`. Strings are plain unless
//! `yaml.v3` would not read them back as the same string, in which case the
//! scalar is single- or double-quoted exactly as its emitter picks.
//!
//! This is intentionally not a general YAML library: only the value shapes the
//! CLI renders (null, bool, integers, strings, sequences, mappings) are
//! supported.

use serde_json::Value;

/// An ordered YAML value.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    /// Convert a JSON value keeping `serde_json`'s map iteration order (sorted
    /// unless the workspace enables `preserve_order`), which is what a Go map
    /// marshals to.
    pub fn from_json(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(flag) => Self::Bool(*flag),
            Value::Number(number) => number
                .as_i64()
                .map(Self::Int)
                .or_else(|| number.as_f64().map(Self::Float))
                .unwrap_or(Self::Null),
            Value::String(text) => Self::Str(text.clone()),
            Value::Array(items) => Self::Seq(items.iter().map(Self::from_json).collect()),
            Value::Object(map) => Self::Map(
                map.iter()
                    .map(|(key, value)| (key.clone(), Self::from_json(value)))
                    .collect(),
            ),
        }
    }
}

/// Marshal `node` like `yaml.Marshal`/`yaml.NewEncoder(...).Encode`.
pub fn to_string(node: &Node) -> String {
    let mut out = String::new();
    match node {
        Node::Map(entries) if !entries.is_empty() => emit_map(entries, 0, &mut out),
        Node::Seq(items) if !items.is_empty() => emit_seq(items, 0, &mut out),
        other => {
            out.push_str(&scalar_text(other, 0));
            out.push('\n');
        }
    }
    out
}

fn indent(out: &mut String, width: usize) {
    for _ in 0..width {
        out.push(' ');
    }
}

fn is_collection(node: &Node) -> bool {
    matches!(node, Node::Seq(items) if !items.is_empty())
        || matches!(node, Node::Map(entries) if !entries.is_empty())
}

fn emit_map(entries: &[(String, Node)], width: usize, out: &mut String) {
    for (key, value) in entries {
        indent(out, width);
        out.push_str(&string_scalar(key, width));
        out.push(':');
        if is_collection(value) {
            out.push('\n');
            // yaml.v3 `increase_indent`: a collection under a mapping key
            // aligns to the next multiple of the indentation (4); one that is
            // itself a sequence item only skips the `- ` indicator (+2).
            let inner_width = 4 * ((width + 4) / 4);
            match value {
                Node::Map(inner) => emit_map(inner, inner_width, out),
                Node::Seq(inner) => emit_seq(inner, inner_width, out),
                _ => unreachable!("collection"),
            }
        } else {
            out.push(' ');
            out.push_str(&scalar_text(value, width));
            out.push('\n');
        }
    }
}

fn emit_seq(items: &[Node], width: usize, out: &mut String) {
    for item in items {
        indent(out, width);
        out.push('-');
        if is_collection(item) {
            let mut nested = String::new();
            match item {
                Node::Map(inner) => emit_map(inner, width + 2, &mut nested),
                Node::Seq(inner) => emit_seq(inner, width + 2, &mut nested),
                _ => unreachable!("collection"),
            }
            // The first line of the nested block sits after the dash.
            out.push(' ');
            out.push_str(&nested[width + 2..]);
        } else {
            out.push(' ');
            out.push_str(&scalar_text(item, width));
            out.push('\n');
        }
    }
}

fn scalar_text(node: &Node, width: usize) -> String {
    match node {
        Node::Null => "null".to_owned(),
        Node::Bool(true) => "true".to_owned(),
        Node::Bool(false) => "false".to_owned(),
        Node::Int(number) => number.to_string(),
        Node::Float(number) => format_float(*number),
        Node::Str(text) => string_scalar(text, width),
        Node::Seq(_) => "[]".to_owned(),
        Node::Map(_) => "{}".to_owned(),
    }
}

fn format_float(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e15 {
        format!("{number:.1}")
    } else {
        number.to_string()
    }
}

/// How yaml.v3 renders a string.
fn string_scalar(text: &str, width: usize) -> String {
    if text.is_empty() {
        return "\"\"".to_owned();
    }
    if text.contains('\n') {
        // Multi-line strings use the literal block style.
        let chomp = match text.strip_suffix('\n') {
            Some(rest) if !rest.ends_with('\n') => "",
            Some(_) => "+",
            None => "-",
        };
        let body = text.strip_suffix('\n').unwrap_or(text);
        if body
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return double_quoted(text);
        }
        let mut out = format!("|{chomp}");
        for line in body.split('\n') {
            out.push('\n');
            if !line.is_empty() {
                indent(&mut out, width + 4);
                out.push_str(line);
            }
        }
        return out;
    }
    if text.chars().any(|c| c.is_control() || c == '\u{feff}') {
        return double_quoted(text);
    }
    if resolves_to_non_string(text) {
        return double_quoted(text);
    }
    if needs_single_quotes(text) {
        return format!("'{}'", text.replace('\'', "''"));
    }
    text.to_owned()
}

fn double_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => out.push_str(&format!("\\x{:02X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Whether `yaml.v3`'s resolver would read the plain scalar as something other
/// than a string (its encoder then forces double quotes).
fn resolves_to_non_string(text: &str) -> bool {
    if matches!(
        text,
        "~" | "null"
            | "Null"
            | "NULL"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | "y"
            | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
            | ".inf"
            | ".Inf"
            | ".INF"
            | "+.inf"
            | "+.Inf"
            | "+.INF"
            | "-.inf"
            | "-.Inf"
            | "-.INF"
            | ".nan"
            | ".NaN"
            | ".NAN"
            | "<<"
    ) {
        return true;
    }
    let digits = text.replace('_', "");
    if digits.parse::<i64>().is_ok() || digits.parse::<u64>().is_ok() {
        return true;
    }
    if let Some(rest) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0o"))
        .or_else(|| digits.strip_prefix("0b"))
        && !rest.is_empty()
    {
        let radix = match &digits[..2] {
            "0x" => 16,
            "0o" => 8,
            _ => 2,
        };
        if i64::from_str_radix(rest, radix).is_ok() {
            return true;
        }
    }
    if digits.parse::<f64>().is_ok()
        && digits
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | 'e' | 'E'))
    {
        return true;
    }
    is_timestamp(text)
}

/// `yaml.v3`'s timestamp forms: a date, optionally followed by `T`/`t`/space
/// and a time with seconds.
fn is_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digit = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_digit);
    if !(digit(0) && digit(1) && digit(2) && digit(3) && bytes.get(4) == Some(&b'-')) {
        return false;
    }
    let rest = &text[5..];
    let (month, rest) = split_digits(rest);
    if month.is_empty() || month.len() > 2 || !rest.starts_with('-') {
        return false;
    }
    let (day, rest) = split_digits(&rest[1..]);
    if day.is_empty() || day.len() > 2 {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    let Some(time) = rest
        .strip_prefix('T')
        .or_else(|| rest.strip_prefix('t'))
        .or_else(|| rest.strip_prefix(' '))
    else {
        return false;
    };
    let (hour, time) = split_digits(time);
    if hour.is_empty() || hour.len() > 2 || !time.starts_with(':') {
        return false;
    }
    let (minute, time) = split_digits(&time[1..]);
    if minute.len() != 2 || !time.starts_with(':') {
        return false;
    }
    let (second, _zone) = split_digits(&time[1..]);
    !second.is_empty() && second.len() <= 2
}

fn split_digits(text: &str) -> (&str, &str) {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    text.split_at(end)
}

/// Plain scalars that must be quoted for syntax reasons; yaml.v3 then picks
/// single quotes.
fn needs_single_quotes(text: &str) -> bool {
    let first = text.chars().next().unwrap_or(' ');
    if matches!(
        first,
        '?' | ':'
            | ','
            | '['
            | ']'
            | '{'
            | '}'
            | '#'
            | '&'
            | '*'
            | '!'
            | '|'
            | '>'
            | '\''
            | '"'
            | '%'
            | '@'
            | '`'
    ) {
        // `?`, `:` and `-` only start an indicator when followed by a space.
        if matches!(first, '?' | ':') {
            return text.len() == 1 || text.as_bytes().get(1) == Some(&b' ');
        }
        return true;
    }
    if first == '-' && (text.len() == 1 || text.as_bytes().get(1) == Some(&b' ')) {
        return true;
    }
    if text.starts_with("---") || text.starts_with("...") {
        return true;
    }
    text.starts_with(' ')
        || text.ends_with(' ')
        || text.ends_with(':')
        || text.contains(": ")
        || text.contains(" #")
        || text.contains('\t')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn render(value: Value) -> String {
        to_string(&Node::from_json(&value))
    }

    #[test]
    fn mappings_and_sequences_use_four_space_indentation() {
        assert_eq!(
            render(json!({"recipients": ["age1abc"], "count": 1})),
            "count: 1\nrecipients:\n    - age1abc\n"
        );
        assert_eq!(
            to_string(&Node::Seq(vec![
                Node::Map(vec![
                    ("path".into(), Node::Str("a/first".into())),
                    ("has".into(), Node::Bool(true)),
                ]),
                Node::Map(vec![("path".into(), Node::Str("b".into()))]),
            ])),
            "- path: a/first\n  has: true\n- path: b\n"
        );
        assert_eq!(
            to_string(&Node::Map(vec![(
                "matches".into(),
                Node::Seq(vec![Node::Map(vec![
                    ("path".into(), Node::Str("work/example".into())),
                    ("fields".into(), Node::Seq(vec![Node::Str("url".into())])),
                    (
                        "meta".into(),
                        Node::Map(vec![("k".into(), Node::Str("v".into()))])
                    ),
                ])])
            )])),
            "matches:\n    - path: work/example\n      fields:\n        - url\n      meta:\n        k: v\n"
        );
        assert_eq!(render(json!({"deleted": true})), "deleted: true\n");
        assert_eq!(render(json!([])), "[]\n");
        assert_eq!(render(json!({"a": []})), "a: []\n");
        assert_eq!(
            render(json!({"fields": {"notes": "a,b"}, "totp": null})),
            "fields:\n    notes: a,b\ntotp: null\n"
        );
    }

    #[test]
    fn strings_are_quoted_like_yaml_v3() {
        for (input, want) in [
            ("***", "'***'"),
            ("", "\"\""),
            ("true", "\"true\""),
            ("null", "\"null\""),
            ("yes", "\"yes\""),
            ("12", "\"12\""),
            ("1.5", "\"1.5\""),
            ("2026-10-31", "\"2026-10-31\""),
            ("2026-10-31T10:00:00Z", "\"2026-10-31T10:00:00Z\""),
            ("2026-10-31 22:01", "2026-10-31 22:01"),
            ("a: b", "'a: b'"),
            ("it's: x", "'it''s: x'"),
            (" lead", "' lead'"),
            ("Val-Alpha-001", "Val-Alpha-001"),
            ("https://example.test", "https://example.test"),
            ("a,b", "a,b"),
            ("tab\there", "\"tab\\there\""),
            ("bell\u{7}", "\"bell\\x07\""),
        ] {
            assert_eq!(string_scalar(input, 0), want, "{input:?}");
        }
        assert_eq!(string_scalar("a\nb", 0), "|-\n    a\n    b");
        assert_eq!(string_scalar("a\nb\n", 0), "|\n    a\n    b");
    }
}
