mod cxf;
mod onepux;
pub use cxf::parse as parse_cxf;
mod pass;
mod totp;
pub use onepux::parse_1pux;
pub use pass::{import_pass, import_pass_with_gpg, parse_pass_entry};
pub use totp::parse_totp;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

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
    Cxf,
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
    match format {
        Format::Cxf => parse_cxf(bytes),
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
        .has_headers(false)
        .terminator(csv::Terminator::Any(b'\n'))
        .flexible(true)
        .from_reader(normalized.as_slice());
    // csv-core silently strips a UTF-8 BOM at the beginning of a stream.
    // Go's encoding/csv leaves it in the first header name, so restore those
    // three bytes before applying the Go field mapping below.
    let has_bom = bytes.starts_with(b"\xEF\xBB\xBF");
    // Go's csvColumnIndex inserts the exact and lower-case keys into one map
    // in header order.  Keeping one map matters for duplicate headers: a
    // later case-folded key can overwrite an earlier exact key.
    let mut columns: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let mut header = csv::ByteRecord::new();
    if !reader
        .read_byte_record(&mut header)
        .map_err(|e| ImportError::Parse(format!("read csv header: {e}")))?
    {
        return Ok(Vec::new());
    }
    for (index, column_bytes) in header.iter().enumerate() {
        let column = if has_bom && index == 0 {
            let mut with_bom = Vec::with_capacity(3 + column_bytes.len());
            with_bom.extend_from_slice(b"\xEF\xBB\xBF");
            with_bom.extend_from_slice(column_bytes);
            with_bom
        } else {
            column_bytes.to_vec()
        };
        let column = trim_go_space_bytes(&column);
        if !column.is_empty() {
            columns.insert(column.to_vec(), index);
            columns.insert(lower_go_bytes(column), index);
        }
    }
    let mut result = Vec::new();
    let mut used = std::collections::BTreeSet::new();
    let mut row = csv::ByteRecord::new();
    while reader
        .read_byte_record(&mut row)
        .map_err(|e| ImportError::Parse(format!("read csv row: {e}")))?
    {
        let raw_row: Vec<Vec<u8>> = row.iter().map(ToOwned::to_owned).collect();
        let row: Vec<String> = row.iter().map(go_string_from_bytes).collect();
        if row.iter().all(|v| v.trim().is_empty()) {
            continue;
        }
        let get = |column: &str| {
            columns
                .get(column.as_bytes())
                .or_else(|| columns.get(&lower_go_bytes(column.as_bytes())))
                .and_then(|i| row.get(*i))
        };
        let get_raw = |column: &str| {
            columns
                .get(column.as_bytes())
                .or_else(|| columns.get(&lower_go_bytes(column.as_bytes())))
                .and_then(|i| raw_row.get(*i))
        };
        let mut path = String::new();
        let mut path_key = None;
        let mut data = BTreeMap::new();
        let mut warnings = None;
        for (field, col) in mapping {
            let Some(val) = get(col) else { continue };
            match field.as_str() {
                "title" | "path" => {
                    if path.is_empty() && !val.is_empty() {
                        path = normalize_path(val);
                        path_key = get_raw(col).map(|raw| normalize_path_key(raw));
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
            path_key = Some(normalize_path_key(path.as_bytes()));
        }
        if format != Format::Csv && !path.is_empty() {
            let base = path.clone();
            let base_key = path_key
                .take()
                .unwrap_or_else(|| normalize_path_key(path.as_bytes()));
            let mut candidate_key = base_key.clone();
            let mut suffix = 2;
            while used.contains(&candidate_key) {
                path = format!("{base}-{suffix}");
                candidate_key = path_key_with_suffix(&base_key, suffix);
                suffix += 1;
            }
            used.insert(candidate_key);
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

/// Convert Go strings containing arbitrary bytes to the Unicode string that
/// encoding/json emits. `String::from_utf8_lossy` is not equivalent here: it
/// collapses an invalid multi-byte sequence into one replacement character,
/// while Go's JSON encoder emits one U+FFFD for each invalid byte.
fn go_string_from_bytes(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len());
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                result.push_str(valid);
                break;
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                // `valid_up_to` ends on a UTF-8 character boundary.
                result.push_str(
                    std::str::from_utf8(&remaining[..valid_len])
                        .expect("valid UTF-8 prefix reported by from_utf8"),
                );
                result.push('\u{FFFD}');
                // Consume exactly one invalid byte. This matches Go's
                // encoding/json behavior for both malformed and truncated
                // UTF-8 sequences.
                remaining = &remaining[valid_len + 1..];
            }
        }
    }
    result
}

// Keep a separate identity key for profile path de-duplication. Go performs
// path normalization on strings that may contain invalid UTF-8, then compares
// those raw strings. The user-visible ImportedEntry must be valid Rust UTF-8,
// so comparing only the repaired display path would incorrectly merge values
// such as 0xFF and 0xFE.
fn normalize_path_key(bytes: &[u8]) -> Vec<u8> {
    let trimmed = trim_go_space_bytes(bytes);
    let trimmed = trimmed
        .iter()
        .skip_while(|byte| **byte == b'/')
        .copied()
        .collect::<Vec<_>>();
    let mut normalized = trimmed
        .into_iter()
        .rev()
        .skip_while(|byte| *byte == b'/')
        .collect::<Vec<_>>();
    normalized.reverse();
    normalized.retain(|byte| {
        !matches!(
            *byte,
            b'"' | b'*' | b'?' | b'<' | b'>' | b'|' | b':' | b'\\'
        )
    });
    for byte in &mut normalized {
        if *byte == b' ' {
            *byte = b'-';
        }
    }
    let mut key = Vec::with_capacity(normalized.len());
    let mut index = 0;
    while index < normalized.len() {
        if normalized.get(index) == Some(&b'.') && normalized.get(index + 1) == Some(&b'.') {
            key.push(b'-');
            index += 2;
        } else {
            key.push(normalized[index]);
            index += 1;
        }
    }
    key
}

fn path_key_with_suffix(base: &[u8], suffix: usize) -> Vec<u8> {
    let mut key = base.to_vec();
    key.push(b'-');
    key.extend(suffix.to_string().as_bytes());
    key
}

fn trim_go_space_bytes(mut bytes: &[u8]) -> &[u8] {
    while let Some((character, width)) = first_utf8_char(bytes) {
        if !character.is_whitespace() {
            break;
        }
        bytes = &bytes[width..];
    }
    while let Some((character, width)) = last_utf8_char(bytes) {
        if !character.is_whitespace() {
            break;
        }
        bytes = &bytes[..bytes.len() - width];
    }
    bytes
}

fn first_utf8_char(bytes: &[u8]) -> Option<(char, usize)> {
    for width in 1..=bytes.len().min(4) {
        let Ok(value) = std::str::from_utf8(&bytes[..width]) else {
            continue;
        };
        let character = value.chars().next()?;
        if character.len_utf8() == width && value.len() == width {
            return Some((character, width));
        }
    }
    None
}

fn last_utf8_char(bytes: &[u8]) -> Option<(char, usize)> {
    for width in 1..=bytes.len().min(4) {
        let start = bytes.len() - width;
        let Ok(value) = std::str::from_utf8(&bytes[start..]) else {
            continue;
        };
        let character = value.chars().next()?;
        if character.len_utf8() == width && value.len() == width {
            return Some((character, width));
        }
    }
    None
}

fn lower_go_bytes(bytes: &[u8]) -> Vec<u8> {
    // strings.ToLower ranges over Go strings, so malformed bytes become
    // RuneError in the folded alias. Keep the original raw key above: a real
    // U+FFFD header appearing later still overwrites this alias exactly as it
    // does in Go's one-map insertion order.
    go_string_from_bytes(bytes).to_lowercase().into_bytes()
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
    let repaired = replace_invalid_utf8_in_json_strings(bytes);
    let x = Option::<Bw>::deserialize(&mut serde_json::Deserializer::from_slice(&repaired))
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

fn replace_invalid_utf8_in_json_strings(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len());
    let (mut index, mut in_string, mut escaped) = (0, false, false);
    while index < bytes.len() {
        let byte = bytes[index];
        if !in_string {
            result.push(byte);
            in_string = byte == b'"';
            index += 1;
            continue;
        }
        if escaped {
            result.push(byte);
            escaped = false;
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                result.push(byte);
                in_string = false;
                index += 1;
            }
            b'\\' => {
                result.push(byte);
                escaped = true;
                index += 1;
            }
            0..=0x7f => {
                result.push(byte);
                index += 1;
            }
            _ => match std::str::from_utf8(&bytes[index..]) {
                Ok(valid) => {
                    result.extend_from_slice(valid.as_bytes());
                    break;
                }
                Err(error) if error.valid_up_to() > 0 => {
                    let end = index + error.valid_up_to();
                    result.extend_from_slice(&bytes[index..end]);
                    index = end;
                }
                Err(_) => {
                    // Go encoding/json replaces each invalid byte inside a string.
                    result.extend_from_slice(br"\uFFFD");
                    index += 1;
                }
            },
        }
    }
    result
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
