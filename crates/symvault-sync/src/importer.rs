mod cxf;
mod gojson;
mod gourl;
mod onepux;
pub use cxf::parse as parse_cxf;
mod pass;
mod totp;
pub use onepux::parse_1pux;
pub use pass::{import_pass, import_pass_with_gpg, parse_pass_entry, parse_pass_entry_bytes};
pub use totp::{parse_totp, parse_totp_bytes};

use gojson::{Context, GoDecode, GoStruct, Reader, decode_struct};
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
    /// A diagnostic reproduced verbatim from the Go importer (for example the
    /// `encoding/json` errors of the Bitwarden parser).
    #[error("{0}")]
    Decode(String),
    #[error("distinct CSV paths collapse to the same UTF-8 path: {0}")]
    PathCollision(String),
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

/// Resolves an importer name the way Go's `importer.New` does: the name is
/// matched exactly (no trimming or case folding), and names without an
/// importer, including the generic `json`/`yaml` extension names the CLI
/// detects, are rejected with Go's `unsupported import format` text.
pub fn format_from_name(name: &str) -> Result<Format, ImportError> {
    match name {
        "1password" => Ok(Format::OnePassword),
        "bitwarden" => Ok(Format::Bitwarden),
        "pass" => Ok(Format::Pass),
        "csv" => Ok(Format::Csv),
        "cxf" => Ok(Format::Cxf),
        "apple" => Ok(Format::Apple),
        "chrome" => Ok(Format::Chrome),
        "firefox" => Ok(Format::Firefox),
        other => Err(ImportError::Unsupported(other.to_owned())),
    }
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
    let mut emitted_paths = BTreeMap::<String, Vec<u8>>::new();
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
        let raw_path_key = path_key
            .clone()
            .unwrap_or_else(|| normalize_path_key(path.as_bytes()));
        if format != Format::Csv && !path.is_empty() {
            let base = path.clone();
            let base_key = raw_path_key.clone();
            let mut candidate_key = base_key.clone();
            let mut suffix = 2;
            while used.contains(&candidate_key) {
                path = format!("{base}-{suffix}");
                candidate_key = path_key_with_suffix(&base_key, suffix);
                suffix += 1;
            }
            used.insert(candidate_key);
        }
        if !path.is_empty() {
            if let Some(previous_key) = emitted_paths.get(&path) {
                if previous_key != &raw_path_key {
                    return Err(ImportError::PathCollision(path));
                }
            } else {
                emitted_paths.insert(path.clone(), raw_path_key);
            }
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

/// A port of the record scanner of Go's `encoding/csv` (`Reader.readRecord`
/// with `Comma=','`, no comments, `LazyQuotes=false`, `FieldsPerRecord=-1`).
///
/// The `csv` crate accepts malformed quoting, so quote structure is validated
/// by this scanner first. It reproduces Go's record/line/column bookkeeping so
/// a rejected source reports Go's exact diagnostic
/// (`parse error on line 2, column 18: extraneous or missing " in quoted-field`).
struct GoCsvScanner<'a> {
    data: &'a [u8],
    offset: usize,
    num_line: usize,
}

#[derive(Debug)]
struct GoCsvError {
    start_line: usize,
    line: usize,
    column: usize,
    bare_quote: bool,
}

impl std::fmt::Display for GoCsvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = if self.bare_quote {
            "bare \" in non-quoted-field"
        } else {
            "extraneous or missing \" in quoted-field"
        };
        if self.start_line == self.line {
            write!(
                f,
                "parse error on line {}, column {}: {reason}",
                self.line, self.column
            )
        } else {
            write!(
                f,
                "record on line {}; parse error on line {}, column {}: {reason}",
                self.start_line, self.line, self.column
            )
        }
    }
}

fn length_nl(line: &[u8]) -> usize {
    usize::from(line.last() == Some(&b'\n'))
}

impl<'a> GoCsvScanner<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            num_line: 0,
        }
    }

    /// `Reader.readLine`: one line with `\r\n` folded to `\n`, a trailing `\r`
    /// dropped before EOF, and `true` once the input is exhausted.
    fn read_line(&mut self) -> (Vec<u8>, bool) {
        let rest = &self.data[self.offset..];
        let (raw, eof) = match rest.iter().position(|byte| *byte == b'\n') {
            Some(end) => (&rest[..=end], false),
            None => (rest, true),
        };
        self.offset += raw.len();
        self.num_line += 1;
        let mut line = raw.to_vec();
        let mut at_eof = eof;
        if !raw.is_empty() && eof {
            at_eof = false;
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        let n = line.len();
        if n >= 2 && line[n - 2] == b'\r' && line[n - 1] == b'\n' {
            line[n - 2] = b'\n';
            line.pop();
        }
        (line, at_eof)
    }

    /// `Reader.readRecord`: `Ok(None)` at end of input.
    fn read_record(&mut self) -> Result<Option<Vec<Vec<u8>>>, GoCsvError> {
        let (mut line, eof) = loop {
            let (line, eof) = self.read_line();
            if !eof && line.len() == length_nl(&line) {
                continue;
            }
            break (line, eof);
        };
        if eof {
            return Ok(None);
        }
        let rec_line = self.num_line;
        let (mut pos_line, mut pos_col) = (self.num_line, 1_usize);
        let mut fields: Vec<Vec<u8>> = Vec::new();
        'field: loop {
            if line.first() != Some(&b'"') {
                let comma = line.iter().position(|byte| *byte == b',');
                let field_len = comma.unwrap_or_else(|| line.len() - length_nl(&line));
                if let Some(quote) = line[..field_len].iter().position(|byte| *byte == b'"') {
                    return Err(GoCsvError {
                        start_line: rec_line,
                        line: self.num_line,
                        column: pos_col + quote,
                        bare_quote: true,
                    });
                }
                fields.push(line[..field_len].to_vec());
                if let Some(comma) = comma {
                    line.drain(..=comma);
                    pos_col += comma + 1;
                    continue 'field;
                }
                break 'field;
            }
            line.remove(0);
            pos_col += 1;
            let mut field: Vec<u8> = Vec::new();
            loop {
                if let Some(quote) = line.iter().position(|byte| *byte == b'"') {
                    field.extend_from_slice(&line[..quote]);
                    line.drain(..=quote);
                    pos_col += quote + 1;
                    match line.first() {
                        Some(b'"') => {
                            field.push(b'"');
                            line.remove(0);
                            pos_col += 1;
                        }
                        Some(b',') => {
                            line.remove(0);
                            pos_col += 1;
                            fields.push(field);
                            continue 'field;
                        }
                        _ if length_nl(&line) == line.len() => {
                            fields.push(field);
                            break 'field;
                        }
                        _ => {
                            return Err(GoCsvError {
                                start_line: rec_line,
                                line: self.num_line,
                                column: pos_col - 1,
                                bare_quote: false,
                            });
                        }
                    }
                } else if !line.is_empty() {
                    pos_col += line.len();
                    field.extend_from_slice(&line);
                    (line, _) = self.read_line();
                    if !line.is_empty() {
                        pos_line += 1;
                        pos_col = 1;
                    }
                } else {
                    return Err(GoCsvError {
                        start_line: rec_line,
                        line: pos_line,
                        column: pos_col,
                        bare_quote: false,
                    });
                }
            }
        }
        Ok(Some(fields))
    }
}

/// Rejects a source Go's CSV reader rejects, with Go's text: the first record
/// is the header (`read csv header`), every later one a row (`read csv row`).
fn validate_csv_quotes(bytes: &[u8]) -> Result<(), ImportError> {
    let mut scanner = GoCsvScanner::new(bytes);
    let mut first = true;
    loop {
        match scanner.read_record() {
            Ok(Some(_)) => first = false,
            Ok(None) => return Ok(()),
            Err(error) => {
                let stage = if first { "header" } else { "row" };
                return Err(ImportError::Decode(format!("read csv {stage}: {error}")));
            }
        }
    }
}

/// The reason text of a Go `*os.PathError` for `error` (`no such file or
/// directory`, `permission denied`, `is a directory`, ...), without Rust's
/// ` (os error N)` suffix.
#[must_use]
pub fn go_io_reason(error: &std::io::Error) -> String {
    #[cfg(windows)]
    match error.raw_os_error() {
        Some(2) => return "The system cannot find the file specified.".to_owned(),
        Some(3) => return "The system cannot find the path specified.".to_owned(),
        Some(5) => return "Access is denied.".to_owned(),
        _ => {}
    }
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::NotFound => "no such file or directory".to_owned(),
        ErrorKind::PermissionDenied => "permission denied".to_owned(),
        ErrorKind::IsADirectory => "is a directory".to_owned(),
        ErrorKind::NotADirectory => "not a directory".to_owned(),
        ErrorKind::AlreadyExists => "file exists".to_owned(),
        _ => {
            let text = error.to_string();
            match text.rfind(" (os error ") {
                Some(end) => text[..end].to_lowercase(),
                None => text,
            }
        }
    }
}

/// The header record of a CSV source as Go's `csv.Reader.Read` returns it, or
/// `None` when the source is empty or its first record is malformed. The
/// command sniffs this record to pick a built-in profile.
#[must_use]
pub fn csv_header_record(bytes: &[u8]) -> Option<Vec<String>> {
    match GoCsvScanner::new(bytes).read_record() {
        Ok(Some(fields)) => Some(
            fields
                .iter()
                .map(|field| go_string_from_bytes(field))
                .collect(),
        ),
        _ => None,
    }
}

/// The human-readable source name of a built-in CSV profile (`Detected <name>
/// CSV export from header row`).
#[must_use]
pub fn csv_profile_name(format: Format) -> Option<&'static str> {
    match format {
        Format::Apple => Some("Apple Passwords (iCloud Keychain)"),
        Format::Chrome => Some("Chrome / Chromium"),
        Format::Firefox => Some("Firefox"),
        _ => None,
    }
}

/// The field to column mapping in effect for a CSV import: the user mapping
/// when given, otherwise the profile (or generic) default.
#[must_use]
pub fn csv_effective_mapping(
    format: Format,
    user: Option<&BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    user.cloned().unwrap_or_else(|| default_csv_mapping(format))
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

// Bitwarden export shape. Go decodes it with encoding/json into these structs
// (`internal/importer/bitwarden.go`); `gojson` reproduces that decode, so the
// fields keep Go's zero values for null/missing keys and the types are the
// ones whose mismatches Go reports (`brand` is decoded though never imported).
#[derive(Default)]
struct Bw {
    folders: Vec<BwFolder>,
    items: Vec<BwItem>,
}
#[derive(Default)]
struct BwFolder {
    id: String,
    name: String,
}
#[derive(Default)]
struct BwItem {
    kind: i64,
    name: String,
    folder_id: String,
    notes: String,
    login: BwLogin,
    card: BwCard,
    fields: Vec<BwField>,
}
#[derive(Default)]
struct BwLogin {
    username: String,
    password: String,
    totp: String,
    uris: Vec<BwUri>,
}
#[derive(Default)]
struct BwUri {
    uri: String,
}
#[derive(Default)]
struct BwCard {
    cardholder: String,
    brand: String,
    number: String,
    exp_month: String,
    exp_year: String,
    code: String,
}
#[derive(Default)]
struct BwField {
    name: String,
    value: String,
}
gojson::go_struct!(Bw, "bitwardenExport", { "folders" => folders, "items" => items });
gojson::go_struct!(BwFolder, "bitwardenFolder", { "id" => id, "name" => name });
gojson::go_struct!(BwItem, "bitwardenItem", {
    "type" => kind, "name" => name, "folderId" => folder_id, "login" => login,
    "card" => card, "notes" => notes, "fields" => fields,
});
gojson::go_struct!(BwLogin, "bitwardenLogin", {
    "username" => username, "password" => password, "totp" => totp, "uris" => uris,
});
gojson::go_struct!(BwUri, "bitwardenURI", { "uri" => uri });
gojson::go_struct!(BwField, "bitwardenField", { "name" => name, "value" => value });
gojson::go_struct!(BwCard, "bitwardenCard", {
    "cardholderName" => cardholder, "brand" => brand, "number" => number,
    "expMonth" => exp_month, "expYear" => exp_year, "code" => code,
});
pub fn parse_bitwarden(bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    let mut x = Bw::default();
    gojson::decode_document(bytes, &mut x)
        .map_err(|e| ImportError::Decode(format!("parse bitwarden export: {e}")))?;
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
