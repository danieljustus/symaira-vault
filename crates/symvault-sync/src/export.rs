use csv::Writer;
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
pub fn json<W: Write>(mut output: W, entries: &[ExportEntry]) -> Result<(), ExportError> {
    if entries.is_empty() {
        output.write_all(b"[]")?;
        return Ok(());
    }
    let rows: Vec<BTreeMap<&str, Value>> = entries
        .iter()
        .map(|entry| {
            BTreeMap::from([
                (
                    "data",
                    Value::Object(entry.data.clone().into_iter().collect()),
                ),
                ("path", Value::String(entry.path.clone())),
            ])
        })
        .collect();
    serde_json::to_writer_pretty(&mut output, &rows)?;
    output.write_all(b"\n")?;
    Ok(())
}

/// Writes the Go CSV export shape: path first, then sorted non-attachment
/// fields. Attachment fields are intentionally omitted because CSV is lossy.
pub fn csv<W: Write>(output: W, entries: &[ExportEntry]) -> Result<(), ExportError> {
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
    headers.extend(fields.iter().cloned());
    let mut writer = Writer::from_writer(output);
    writer.write_record(&headers)?;
    for entry in entries {
        let mut row = Vec::with_capacity(headers.len());
        row.push(entry.path.clone());
        row.extend(
            fields
                .iter()
                .map(|key| entry.data.get(key).map(value_string).unwrap_or_default()),
        );
        writer.write_record(row)?;
    }
    writer.flush()?;
    Ok(())
}

fn value_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "<nil>".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .map(value_string)
            .collect::<Vec<_>>()
            .join(" "),
        Value::Object(_) => "map[]".to_owned(),
    }
}

fn is_attachment(key: &str) -> bool {
    key.starts_with("file_b64_") || matches!(key, "chunk_count" | "chunk_size")
}
