use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    path::Path,
};
use thiserror::Error;

const MAX_IMPORT_BYTES: usize = 100 * 1024 * 1024;
const MAX_ZIP_ENTRY: u64 = 100 * 1024 * 1024;

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
}

pub fn normalize_path(value: &str) -> String {
    let mut s = value.trim().trim_matches('/').replace(' ', "-");
    for c in ['"', '*', '?', '<', '>', '|', ':', '\\'] {
        s = s.replace(c, "");
    }
    while s.contains("..") {
        s = s.replace("..", "-");
    }
    s
}
pub fn apply_prefix(prefix: &str, path: &str) -> String {
    let p = normalize_path(prefix);
    if p.is_empty() {
        normalize_path(path)
    } else if path.is_empty() {
        p
    } else {
        format!("{p}/{}", normalize_path(path))
    }
}
pub fn parse(format: Format, bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::Limit(MAX_IMPORT_BYTES));
    }
    match format {
        Format::Csv => parse_csv(bytes, None),
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
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let headers = reader
        .headers()
        .map_err(|e| ImportError::Parse(format!("read csv header: {e}")))?
        .clone();
    let mut result = Vec::new();
    for row in reader.records() {
        let row = row.map_err(|e| ImportError::Parse(format!("read csv row: {e}")))?;
        if row.iter().all(|v| v.trim().is_empty()) {
            continue;
        }
        let get = |column: &str| {
            headers
                .iter()
                .position(|h| h.trim().eq_ignore_ascii_case(column))
                .and_then(|i| row.get(i))
                .unwrap_or("")
                .to_owned()
        };
        let map = mapping.cloned().unwrap_or_else(|| {
            [
                ("title".into(), "title".into()),
                ("username".into(), "username".into()),
                ("password".into(), "password".into()),
                ("url".into(), "url".into()),
                ("notes".into(), "notes".into()),
                ("otp".into(), "otp".into()),
            ]
            .into_iter()
            .collect()
        });
        let mut path = String::new();
        let mut data = BTreeMap::new();
        let warnings = None;
        for (field, col) in map {
            let val = get(&col);
            if val.is_empty() {
                continue;
            }
            match field.as_str() {
                "title" | "path" => path = normalize_path(&val),
                "otp" | "totp.secret" => {
                    data.insert("totp".into(), Value::String(val));
                }
                _ => {
                    data.insert(field, Value::String(val));
                }
            }
        }
        if path.is_empty() {
            path = normalize_path(&get("url"));
        }
        if path.is_empty() {
            path = "entry".into();
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
#[derive(Deserialize)]
struct Bw {
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}
#[derive(Deserialize)]
struct BwFolder {
    id: String,
    name: String,
}
#[derive(Deserialize)]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    name: String,
    #[serde(rename = "folderId", default)]
    folder_id: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    login: BwLogin,
    #[serde(default)]
    card: BwCard,
    #[serde(default)]
    fields: Vec<BwField>,
}
#[derive(Default, Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    uris: Vec<BwUri>,
}
#[derive(Default, Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: String,
}
#[derive(Default, Deserialize)]
struct BwCard {
    #[serde(rename = "cardholderName", default)]
    cardholder: String,
    #[serde(default)]
    number: String,
    #[serde(rename = "expMonth", default)]
    exp_month: String,
    #[serde(rename = "expYear", default)]
    exp_year: String,
    #[serde(default)]
    code: String,
}
#[derive(Deserialize)]
struct BwField {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}
pub fn parse_bitwarden(bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    let x: Bw = serde_json::from_slice(bytes)
        .map_err(|e| ImportError::Parse(format!("parse bitwarden export: {e}")))?;
    let folders: xhash::HashMap<String, String> =
        x.folders.into_iter().map(|f| (f.id, f.name)).collect();
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
        let warnings = None;
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
            if !item.login.totp.is_empty() {
                d.insert("totp".into(), Value::String(item.login.totp));
            }
        } else {
            d.insert("card_number".into(), Value::String(item.card.number));
            d.insert("cardholder".into(), Value::String(item.card.cardholder));
            d.insert("expiry_month".into(), Value::String(item.card.exp_month));
            d.insert("expiry_year".into(), Value::String(item.card.exp_year));
            d.insert("cvc".into(), Value::String(item.card.code));
        }
        for f in item.fields {
            if !f.name.is_empty() {
                d.insert(f.name, Value::String(f.value));
            }
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
#[derive(Deserialize)]
struct One {
    #[serde(default)]
    accounts: Vec<OneAccount>,
}
#[derive(Deserialize)]
struct OneAccount {
    #[serde(default)]
    vaults: Vec<OneVault>,
}
#[derive(Deserialize)]
struct OneVault {
    #[serde(default)]
    items: Vec<OneItem>,
}
#[derive(Deserialize)]
struct OneItem {
    #[serde(rename = "categoryUuid", default)]
    category: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    trashed: bool,
    #[serde(default)]
    details: OneDetails,
    #[serde(default)]
    overview: OneOverview,
}
#[derive(Default, Deserialize)]
struct OneDetails {
    #[serde(rename = "loginFields", default)]
    login: Vec<OneLogin>,
    #[serde(rename = "notesPlain", default)]
    notes: String,
    #[serde(default)]
    sections: Vec<OneSection>,
}
#[derive(Deserialize)]
struct OneLogin {
    #[serde(default)]
    designation: String,
    #[serde(default)]
    value: String,
}
#[derive(Default, Deserialize)]
struct OneOverview {
    #[serde(default)]
    urls: Vec<OneUrl>,
    #[serde(default)]
    tags: Vec<String>,
}
#[derive(Deserialize)]
struct OneUrl {
    #[serde(default)]
    url: String,
}
#[derive(Default, Deserialize)]
struct OneSection {
    #[serde(default)]
    fields: Vec<OneField>,
}
#[derive(Deserialize)]
struct OneField {
    #[serde(default)]
    n: String,
    #[serde(default)]
    t: String,
    #[serde(default)]
    v: Value,
}
pub fn parse_1pux(bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ImportError::Parse(format!("open 1pux zip: {e}")))?;
    let mut raw = Vec::new();
    for i in 0..zip.len() {
        let mut f = zip
            .by_index(i)
            .map_err(|e| ImportError::Parse(e.to_string()))?;
        if f.name().ends_with("export.json") {
            if f.size() > MAX_ZIP_ENTRY {
                return Err(ImportError::Limit(MAX_ZIP_ENTRY as usize));
            }
            f.read_to_end(&mut raw)?;
            break;
        }
    }
    if raw.is_empty() {
        return Err(ImportError::Parse(
            "export.json not found in 1pux zip".into(),
        ));
    }
    let x: One = serde_json::from_slice(&raw)
        .map_err(|e| ImportError::Parse(format!("parse export.json: {e}")))?;
    let mut out = Vec::new();
    for a in x.accounts {
        for v in a.vaults {
            for i in v.items {
                if i.trashed || i.category != "001" {
                    continue;
                }
                let mut d = BTreeMap::new();
                let w = None;
                d.insert(
                    "username".into(),
                    Value::String(
                        i.details
                            .login
                            .iter()
                            .find(|x| x.designation.eq_ignore_ascii_case("username"))
                            .map(|x| x.value.clone())
                            .unwrap_or_default(),
                    ),
                );
                d.insert(
                    "password".into(),
                    Value::String(
                        i.details
                            .login
                            .iter()
                            .find(|x| x.designation.eq_ignore_ascii_case("password"))
                            .map(|x| x.value.clone())
                            .unwrap_or_default(),
                    ),
                );
                d.insert(
                    "url".into(),
                    Value::String(
                        i.overview
                            .urls
                            .first()
                            .map(|x| x.url.clone())
                            .unwrap_or_default(),
                    ),
                );
                d.insert("notes".into(), Value::String(i.details.notes));
                d.insert(
                    "tags".into(),
                    Value::Array(i.overview.tags.into_iter().map(Value::String).collect()),
                );
                for s in i.details.sections {
                    for f in s.fields {
                        let is_totp = f.n.to_ascii_lowercase().contains("totp")
                            || f.t.to_ascii_lowercase().contains("one-time password");
                        if is_totp {
                            f.v.get("otp")
                                .and_then(Value::as_str)
                                .or_else(|| f.v.as_str())
                                .map(|v| d.insert("totp".into(), Value::String(v.into())));
                        }
                    }
                }
                out.push(ImportedEntry {
                    path: i.title,
                    data: d,
                    warnings: w,
                    secret_type: None,
                });
            }
        }
    }
    Ok(out)
}
/// Parses one decrypted `pass` entry. Directory traversal is delegated to the
/// caller so production can use a capability-scoped adapter and tests can use a fake.
pub fn parse_pass_entry(path: &Path, content: &str) -> ImportedEntry {
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines = normalized.trim_end_matches('\n').split('\n');
    let password = lines.next().unwrap_or_default();
    let mut d = BTreeMap::new();
    d.insert("password".into(), Value::String(password.into()));
    let mut notes: Vec<String> = Vec::new();
    for l in lines {
        if let Some(v) = l.strip_prefix("url: ") {
            d.insert("url".into(), Value::String(v.trim().into()));
        } else if let Some(v) = l.strip_prefix("username: ") {
            d.insert("username".into(), Value::String(v.trim().into()));
        } else {
            notes.push(l.into());
        }
    }
    if !notes.is_empty() {
        d.insert("notes".into(), Value::String(notes.join("\n")));
    }
    ImportedEntry {
        path: normalize_path(path.to_string_lossy().trim_end_matches(".gpg")),
        data: d,
        warnings: None,
        secret_type: None,
    }
}
mod xhash {
    pub type HashMap<K, V> = std::collections::HashMap<K, V>;
}
