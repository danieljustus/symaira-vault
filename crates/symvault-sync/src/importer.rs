mod onepux;
mod pass;
mod totp;
pub use onepux::parse_1pux;
pub use pass::{import_pass, import_pass_with_gpg, parse_pass_entry};
pub use totp::parse_totp;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

const MAX_IMPORT_BYTES: usize = 100 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("unsupported import format: {0}")]
    Unsupported(String),
    #[error("import exceeds {0} bytes")]
    Limit(usize),
    #[error("import parse failed: {0}")]
    Parse(String),
    #[error("import I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImportedEntry {
    pub path: String,
    pub data: BTreeMap<String, Value>,
    /// Go's production importer leaves this slice nil when no warnings exist;
    /// preserve that wire-level `null` rather than normalizing it to `[]`.
    pub warnings: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Csv,
    Bitwarden,
    OnePassword,
    Pass,
    Apple,
    Chrome,
    Firefox,
}

pub fn normalize_path(value: &str) -> String {
    let mut s = value.trim().trim_matches('/').replace(' ', "-");
    for c in ['"', '*', '?', '<', '>', '|', ':', '\\'] {
        s = s.replace(c, "");
    }
    s.replace("..", "-")
}
pub fn apply_prefix(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        path.to_owned()
    } else if path.is_empty() {
        prefix.to_owned()
    } else {
        format!("{prefix}/{path}")
    }
}

pub fn parse(format: Format, bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::Limit(MAX_IMPORT_BYTES));
    }
    match format {
        Format::Csv | Format::Apple | Format::Chrome | Format::Firefox => {
            parse_csv_profile(format, bytes, None)
        }
        Format::Bitwarden => parse_bitwarden(bytes),
        Format::OnePassword => parse_1pux(bytes),
        Format::Pass => Err(ImportError::Parse(
            "pass imports require a directory adapter".into(),
        )),
    }
}
pub fn parse_csv(
    bytes: &[u8],
    mapping: Option<&BTreeMap<String, String>>,
) -> Result<Vec<ImportedEntry>, ImportError> {
    parse_csv_profile(Format::Csv, bytes, mapping)
}

/// Parses generic CSV or one of the production password-manager profiles.
pub fn parse_csv_profile(
    format: Format,
    bytes: &[u8],
    mapping: Option<&BTreeMap<String, String>>,
) -> Result<Vec<ImportedEntry>, ImportError> {
    if !matches!(
        format,
        Format::Csv | Format::Apple | Format::Chrome | Format::Firefox
    ) {
        return Err(ImportError::Unsupported(format!("{format:?}")));
    }
    validate_csv_quotes(bytes)?;
    let default_mapping = default_csv_mapping(format);
    let mapping = mapping.unwrap_or(&default_mapping);
    // Go normalizes CRLF even inside quoted fields.
    let normalized: Vec<u8> = bytes
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| {
            (b != b'\r' || (bytes.get(i + 1).is_some() && bytes.get(i + 1) != Some(&b'\n')))
                .then_some(b)
        })
        .collect();
    let mut reader = csv::ReaderBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .flexible(true)
        .from_reader(normalized.as_slice());
    let mut columns = BTreeMap::new();
    for (index, column) in reader
        .headers()
        .map_err(|e| ImportError::Parse(format!("read csv header: {e}")))?
        .iter()
        .enumerate()
    {
        let column = column.trim();
        if !column.is_empty() {
            columns.insert(column.to_owned(), index);
            columns.insert(column.to_lowercase(), index);
        }
    }
    let mut result = Vec::new();
    let mut used = std::collections::BTreeSet::new();
    for row in reader.records() {
        let row = row.map_err(|e| ImportError::Parse(format!("read csv row: {e}")))?;
        if row.iter().all(|v| v.trim().is_empty()) {
            continue;
        }
        let get = |column: &str| {
            columns
                .get(column)
                .or_else(|| columns.get(&column.to_lowercase()))
                .and_then(|i| row.get(*i))
        };
        let mut path = String::new();
        let mut data = BTreeMap::new();
        let mut warnings = None;
        for (field, col) in mapping {
            let Some(val) = get(col) else { continue };
            match field.as_str() {
                "title" | "path" => {
                    if path.is_empty() && !val.is_empty() {
                        path = normalize_path(val)
                    }
                }
                "otp" | "totp.secret" => {
                    if !val.is_empty() {
                        insert_totp(&mut data, &mut warnings, val);
                    }
                }
                _ => {
                    data.insert(field.clone(), Value::String(val.into()));
                }
            }
        }
        if path.is_empty()
            && matches!(format, Format::Chrome | Format::Firefox)
            && let Some(url) = get("url")
        {
            path = normalize_path(&host_from_url(url).to_lowercase());
        }
        if format != Format::Csv && !path.is_empty() {
            let base = path.clone();
            let mut suffix = 2;
            while used.contains(&path) {
                path = format!("{base}-{suffix}");
                suffix += 1;
            }
            used.insert(path.clone());
        }
        result.push(ImportedEntry {
            path,
            data,
            warnings,
            secret_type: None,
        });
    }
    Ok(result)
}

// csv intentionally accepts malformed quoting; Go's default encoding/csv
// rejects it. Validate quote structure before passing bytes to that reader.
fn validate_csv_quotes(bytes: &[u8]) -> Result<(), ImportError> {
    enum State {
        Start,
        Bare,
        Quoted,
        Closed,
    }
    let mut state = State::Start;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'\r' && (bytes.get(index + 1).is_none() || bytes.get(index + 1) == Some(&b'\n'))
        {
            continue;
        }
        state = match (&state, byte) {
            (State::Start, b'"') => State::Quoted,
            (State::Start | State::Bare, b',' | b'\n') => State::Start,
            (State::Bare, b'"') => {
                return Err(ImportError::Parse("bare quote in non-quoted-field".into()));
            }
            (State::Start | State::Bare, _) => State::Bare,
            (State::Quoted, b'"') => State::Closed,
            (State::Quoted, _) => State::Quoted,
            (State::Closed, b'"') => State::Quoted,
            (State::Closed, b',' | b'\n') => State::Start,
            (State::Closed, _) => {
                return Err(ImportError::Parse(
                    "extraneous or missing quote in quoted-field".into(),
                ));
            }
        };
    }
    if matches!(state, State::Quoted) {
        return Err(ImportError::Parse(
            "extraneous or missing quote in quoted-field".into(),
        ));
    }
    Ok(())
}

fn host_from_url(raw: &str) -> &str {
    let mut raw = raw.trim();
    if let Some((_, tail)) = raw.split_once("://") {
        raw = tail;
    }
    if let Some((_, tail)) = raw.split_once('@') {
        raw = tail;
    }
    raw = raw.split(['/', '?', '#']).next().unwrap_or("");
    if raw.starts_with('[')
        && let Some(end) = raw.find(']')
    {
        return &raw[..=end];
    }
    raw.split(':').next().unwrap_or("")
}

#[derive(Default, Deserialize)]
struct Bw {
    #[serde(default, deserialize_with = "null_default")]
    folders: Vec<BwFolder>,
    #[serde(default, deserialize_with = "null_default")]
    items: Vec<BwItem>,
}
#[derive(Default, Deserialize)]
struct BwFolder {
    #[serde(default, deserialize_with = "null_default")]
    id: String,
    #[serde(default, deserialize_with = "null_default")]
    name: String,
}
#[derive(Default, Deserialize)]
struct BwItem {
    #[serde(rename = "type", default, deserialize_with = "null_default")]
    kind: i64,
    #[serde(default, deserialize_with = "null_default")]
    name: String,
    #[serde(rename = "folderId", default, deserialize_with = "null_default")]
    folder_id: String,
    #[serde(default, deserialize_with = "null_default")]
    notes: String,
    #[serde(default, deserialize_with = "null_default")]
    login: BwLogin,
    #[serde(default, deserialize_with = "null_default")]
    card: BwCard,
    #[serde(default, deserialize_with = "null_default")]
    fields: Vec<BwField>,
}
#[derive(Default, Deserialize)]
struct BwLogin {
    #[serde(default, deserialize_with = "null_default")]
    username: String,
    #[serde(default, deserialize_with = "null_default")]
    password: String,
    #[serde(default, deserialize_with = "null_default")]
    totp: String,
    #[serde(default, deserialize_with = "null_default")]
    uris: Vec<BwUri>,
}
#[derive(Default, Deserialize)]
struct BwUri {
    #[serde(default, deserialize_with = "null_default")]
    uri: String,
}
#[derive(Default, Deserialize)]
struct BwCard {
    #[serde(rename = "cardholderName", default, deserialize_with = "null_default")]
    cardholder: String,
    #[serde(default, deserialize_with = "null_default")]
    number: String,
    #[serde(rename = "expMonth", default, deserialize_with = "null_default")]
    exp_month: String,
    #[serde(rename = "expYear", default, deserialize_with = "null_default")]
    exp_year: String,
    #[serde(default, deserialize_with = "null_default")]
    code: String,
}
#[derive(Default, Deserialize)]
struct BwField {
    #[serde(default, deserialize_with = "null_default")]
    name: String,
    #[serde(default, deserialize_with = "null_default")]
    value: String,
}
pub fn parse_bitwarden(bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    let x = Option::<Bw>::deserialize(&mut serde_json::Deserializer::from_slice(bytes))
        .map_err(|e| ImportError::Parse(format!("parse bitwarden export: {e}")))?
        .unwrap_or_default();
    let folders: xhash::HashMap<String, String> = x
        .folders
        .into_iter()
        .filter(|f| !f.id.is_empty())
        .map(|f| (f.id, f.name))
        .collect();
    let mut out = Vec::new();
    for item in x.items {
        if item.kind != 1 && item.kind != 2 {
            continue;
        }
        let path = normalize_path(&apply_prefix(
            folders
                .get(&item.folder_id)
                .map(String::as_str)
                .unwrap_or(""),
            &item.name,
        ));
        let mut d = BTreeMap::new();
        let mut warnings = None;
        if item.kind == 1 {
            d.insert("username".into(), Value::String(item.login.username));
            d.insert("password".into(), Value::String(item.login.password));
            d.insert(
                "url".into(),
                Value::String(
                    item.login
                        .uris
                        .first()
                        .map(|u| u.uri.clone())
                        .unwrap_or_default(),
                ),
            );
            d.insert(
                "urls".into(),
                Value::Array(
                    item.login
                        .uris
                        .into_iter()
                        .filter(|u| !u.uri.is_empty())
                        .map(|u| Value::String(u.uri))
                        .collect(),
                ),
            );
            d.insert("notes".into(), Value::String(item.notes));
        } else {
            d.insert("card_number".into(), Value::String(item.card.number));
            d.insert("cardholder".into(), Value::String(item.card.cardholder));
            d.insert("expiry_month".into(), Value::String(item.card.exp_month));
            d.insert("expiry_year".into(), Value::String(item.card.exp_year));
            d.insert("cvc".into(), Value::String(item.card.code));
            d.insert("subtype".into(), Value::String("card".into()));
        }
        for f in item.fields {
            if f.name.is_empty() {
                continue;
            }
            if item.kind == 1 && f.name.eq_ignore_ascii_case("totp") {
                if !f.value.is_empty() {
                    insert_totp(&mut d, &mut warnings, &f.value);
                }
            } else {
                d.insert(f.name, Value::String(f.value));
            }
        }
        if item.kind == 1 && !item.login.totp.is_empty() {
            insert_totp(&mut d, &mut warnings, &item.login.totp);
        }
        out.push(ImportedEntry {
            path,
            data: d,
            warnings,
            secret_type: (item.kind == 2).then(|| "payment".into()),
        });
    }
    Ok(out)
}
fn insert_totp(
    data: &mut BTreeMap<String, Value>,
    warnings: &mut Option<Vec<String>>,
    value: &str,
) {
    match parse_totp(value) {
        Ok(totp) => {
            data.insert("totp".into(), totp);
        }
        Err(error) => warnings
            .get_or_insert_with(Vec::new)
            .push(format!("totp: {error}")),
    }
}
mod xhash {
    pub type HashMap<K, V> = std::collections::HashMap<K, V>;
}

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn default_csv_mapping(format: Format) -> BTreeMap<String, String> {
    let defaults: &[(&str, &str)] = match format {
        Format::Csv => &[
            ("title", "title"),
            ("username", "username"),
            ("password", "password"),
            ("url", "url"),
            ("notes", "notes"),
            ("otp", "otp"),
        ],
        Format::Apple => &[
            ("title", "Title"),
            ("username", "Username"),
            ("password", "Password"),
            ("url", "URL"),
            ("notes", "Notes"),
            ("otp", "OTPAuth"),
        ],
        Format::Chrome => &[
            ("title", "name"),
            ("username", "username"),
            ("password", "password"),
            ("url", "url"),
            ("notes", "note"),
        ],
        Format::Firefox => &[
            ("username", "username"),
            ("password", "password"),
            ("url", "url"),
        ],
        _ => return default_csv_mapping(Format::Csv),
    };
    defaults
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Match built-in profiles in the production Go priority order.
pub fn detect_csv_profile(header: &[String]) -> Format {
    let columns: std::collections::BTreeSet<_> =
        header.iter().map(|c| c.trim().to_lowercase()).collect();
    for (format, required) in [
        (
            Format::Apple,
            &["title", "url", "username", "password", "otpauth"][..],
        ),
        (
            Format::Chrome,
            &["name", "url", "username", "password", "note"][..],
        ),
        (
            Format::Firefox,
            &["url", "username", "password", "httprealm"][..],
        ),
    ] {
        if required.iter().all(|column| columns.contains(*column)) {
            return format;
        }
    }
    Format::Csv
}

// Go unmarshals JSON null array elements into the element type's zero value.
fn null_default_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<Vec<Option<T>>>::deserialize(deserializer)?
        .unwrap_or_default()
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect())
}
