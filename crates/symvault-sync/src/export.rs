use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, io, io::Write};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("export I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("export JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("export CSV failed: {0}")]
    Csv(#[from] csv::Error),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExportEntry {
    pub path: String,
    pub data: BTreeMap<String, Value>,
}

/// Writes the Go JSON export shape, including its two-space indentation and
/// trailing newline. BTreeMap preserves encoding/json's sorted map keys.
pub fn json<W: Write>(output: W, entries: &[ExportEntry]) -> Result<(), ExportError> {
    json_with_mapping(output, entries, &BTreeMap::new())
}

pub fn json_with_mapping<W: Write>(
    output: W,
    entries: &[ExportEntry],
    mapping: &BTreeMap<String, String>,
) -> Result<(), ExportError> {
    let mut stream = JsonStream::new(output, mapping);
    for entry in entries {
        stream.write_entry(entry)?;
    }
    stream.finish()
}

/// Entry-at-a-time JSON export with the same bytes as the batch API.
pub struct JsonStream<'a, W: Write> {
    output: W,
    mapping: &'a BTreeMap<String, String>,
    started: bool,
}
impl<'a, W: Write> JsonStream<'a, W> {
    pub fn new(output: W, mapping: &'a BTreeMap<String, String>) -> Self {
        Self {
            output,
            mapping,
            started: false,
        }
    }
    pub fn write_entry(&mut self, entry: &ExportEntry) -> Result<(), ExportError> {
        use serde_json::ser::Formatter;
        self.output
            .write_all(if self.started { b",\n" } else { b"[\n" })?;
        let data: BTreeMap<_, _> = entry
            .data
            .iter()
            .map(|(key, value)| (self.mapping.get(key).unwrap_or(key), value))
            .collect();
        let row = serde_json::json!({"data": data, "path": entry.path});
        let rendered = go_json_numbers(&serde_json::to_string_pretty(&row)?);
        for (index, line) in rendered.lines().enumerate() {
            if index > 0 {
                self.output.write_all(b"\n")?;
            }
            self.output.write_all(b"  ")?;
            symvault_gojson::GoFormatter.write_string_fragment(&mut self.output, line)?;
        }
        self.started = true;
        Ok(())
    }
    pub fn finish(mut self) -> Result<(), ExportError> {
        self.output
            .write_all(if self.started { b"\n]\n" } else { b"[]" })?;
        Ok(())
    }
}

fn go_json_numbers(rendered: &str) -> String {
    let bytes = rendered.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let (mut index, mut in_string, mut escaped) = (0, false, false);
    while index < bytes.len() {
        if in_string {
            let byte = bytes[index];
            output.push(byte);
            index += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if bytes[index] == b'"' {
            output.push(bytes[index]);
            index += 1;
            in_string = true;
        } else if bytes[index] == b'-' || bytes[index].is_ascii_digit() {
            let start = index;
            while bytes
                .get(index)
                .is_some_and(|byte| !matches!(*byte, b',' | b']' | b'}' | b' ' | b'\n' | b'\t'))
            {
                index += 1;
            }
            let token = std::str::from_utf8(&bytes[start..index]).expect("JSON number is ASCII");
            if token.contains(['.', 'e', 'E']) {
                let value: f64 = token.parse().expect("serde_json emitted a valid number");
                output.extend_from_slice(go_json_float(value).as_bytes());
            } else {
                output.extend_from_slice(&bytes[start..index]);
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).expect("JSON output is UTF-8")
}

/// Writes the Go CSV export shape: path first, then sorted non-attachment
/// fields. Attachment fields are intentionally omitted because CSV is lossy.
pub fn csv<W: Write>(output: W, entries: &[ExportEntry]) -> Result<(), ExportError> {
    csv_with_mapping(output, entries, &BTreeMap::new(), None)
}

pub fn csv_with_mapping<W: Write>(
    mut output: W,
    entries: &[ExportEntry],
    mapping: &BTreeMap<String, String>,
    mut notices: Option<&mut dyn Write>,
) -> Result<(), ExportError> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut fields = std::collections::BTreeSet::new();
    for entry in entries {
        for key in entry.data.keys() {
            if !is_attachment(key) {
                fields.insert(key.clone());
            }
        }
    }
    let mut headers = vec!["path".to_owned()];
    headers.extend(
        fields
            .iter()
            .map(|key| mapping.get(key).unwrap_or(key).clone()),
    );
    write_csv_record(&mut output, &headers)?;
    for entry in entries {
        let mut row = Vec::with_capacity(headers.len());
        row.push(entry.path.clone());
        row.extend(fields.iter().map(|key| {
            if key == "__path__" {
                entry.path.clone()
            } else {
                entry.data.get(key).map(value_string).unwrap_or_default()
            }
        }));
        write_csv_record(&mut output, &row)?;
        if entry.data.keys().any(|key| is_attachment(key))
            && let Some(writer) = notices.as_mut()
        {
            writeln!(
                writer,
                "attachment data omitted for entry {}; use --format json for a lossless export",
                entry.path
            )?;
        }
    }

    Ok(())
}

fn value_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "<nil>".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) if value.is_f64() => {
            go_float(value.as_f64().expect("finite JSON number"))
        }
        Value::Number(value) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(value_string)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::Object(values) => format!(
            "map[{}]",
            values
                .iter()
                .map(|(key, value)| format!("{key}:{}", value_string(value)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

fn go_float(value: f64) -> String {
    go_float_with_exponent_range(value, -4, 6, true)
}

fn go_json_float(value: f64) -> String {
    go_float_with_exponent_range(value, -6, 21, false)
}

fn go_float_with_exponent_range(
    value: f64,
    min_exponent: i32,
    max_exponent: i32,
    pad_exponent: bool,
) -> String {
    if value == 0.0 && value.is_sign_negative() {
        return "-0".to_owned();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific float");
    let exponent: i32 = exponent.parse().expect("float exponent");
    if !(min_exponent..max_exponent).contains(&exponent) {
        let sign = if exponent < 0 { "-" } else { "+" };
        if pad_exponent {
            format!("{mantissa}e{sign}{:02}", exponent.abs())
        } else {
            format!("{mantissa}e{sign}{}", exponent.abs())
        }
    } else {
        value.to_string()
    }
}

fn is_attachment(key: &str) -> bool {
    key.starts_with("file_b64_") || matches!(key, "chunk_count" | "chunk_size")
}

fn write_csv_record(output: &mut impl Write, fields: &[String]) -> io::Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.write_all(b",")?;
        }
        // encoding/csv additionally quotes leading Unicode whitespace and
        // PostgreSQL's end-of-data sentinel, unlike csv::Writer's defaults.
        let quote = field == "\\."
            || field.contains([',', '\"', '\r', '\n'])
            || field.chars().next().is_some_and(char::is_whitespace);
        if quote {
            output.write_all(b"\"")?;
        }
        output.write_all(field.replace('"', "\"\"").as_bytes())?;
        if quote {
            output.write_all(b"\"")?;
        }
    }
    output.write_all(b"\n")
}
