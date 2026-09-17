// 1Password `.1pux` import parity.
//
// The shape and limits in this module intentionally follow
// `internal/importer/onepux.go`.  The parent importer wires this module into
// the public format dispatcher.

use super::{ImportError, ImportedEntry, parse_totp};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};

const LOGIN_CATEGORY: &str = "001";
const MAX_IMPORT_BYTES: usize = 100 * 1024 * 1024;
const MAX_ZIP_ENTRY: u64 = 100 * 1024 * 1024;

#[derive(Default, Deserialize)]
struct Export {
    #[serde(default, deserialize_with = "super::null_default")]
    accounts: Vec<Account>,
}

#[derive(Default, Deserialize)]
struct Account {
    #[serde(default, deserialize_with = "super::null_default")]
    vaults: Vec<Vault>,
}

#[derive(Default, Deserialize)]
struct Vault {
    #[serde(default, deserialize_with = "super::null_default")]
    items: Vec<Item>,
}

#[derive(Default, Deserialize)]
struct Item {
    #[serde(
        rename = "categoryUuid",
        default,
        deserialize_with = "super::null_default"
    )]
    category: String,
    #[serde(default, deserialize_with = "super::null_default")]
    title: String,
    #[serde(default, deserialize_with = "super::null_default")]
    trashed: bool,
    #[serde(default, deserialize_with = "super::null_default")]
    details: Details,
    #[serde(default, deserialize_with = "super::null_default")]
    overview: Overview,
}

#[derive(Default, Deserialize)]
struct Details {
    #[serde(
        rename = "loginFields",
        default,
        deserialize_with = "super::null_default"
    )]
    login: Vec<LoginField>,
    #[serde(
        rename = "notesPlain",
        default,
        deserialize_with = "super::null_default"
    )]
    notes: String,
    #[serde(default, deserialize_with = "super::null_default")]
    sections: Vec<Section>,
}

#[derive(Default, Deserialize)]
struct LoginField {
    #[serde(default, deserialize_with = "super::null_default")]
    designation: String,
    #[serde(default, deserialize_with = "super::null_default")]
    value: String,
}

#[derive(Default, Deserialize)]
struct Overview {
    #[serde(default, deserialize_with = "super::null_default")]
    urls: Vec<Url>,
    #[serde(default, deserialize_with = "super::null_default")]
    tags: Vec<String>,
}

#[derive(Default, Deserialize)]
struct Url {
    #[serde(default, deserialize_with = "super::null_default")]
    url: String,
}

#[derive(Default, Deserialize)]
struct Section {
    #[serde(default, deserialize_with = "super::null_default")]
    fields: Vec<Field>,
}

#[derive(Default, Deserialize)]
struct Field {
    #[serde(default, deserialize_with = "super::null_default")]
    n: String,
    #[serde(default, deserialize_with = "super::null_default")]
    t: String,
    #[serde(default, deserialize_with = "super::null_default")]
    title: String,
    #[serde(default)]
    v: Value,
}

/// Parse a 1Password export with the same total-input and entry limits as Go.
pub fn parse_1pux(bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    parse_1pux_with_limits(bytes, MAX_IMPORT_BYTES, MAX_ZIP_ENTRY)
}

fn parse_1pux_with_limits(
    bytes: &[u8],
    max_import_bytes: usize,
    max_zip_entry: u64,
) -> Result<Vec<ImportedEntry>, ImportError> {
    if bytes.len() >= max_import_bytes {
        return Err(ImportError::Limit(max_import_bytes));
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ImportError::Parse(format!("open 1pux zip: {e}")))?;
    let mut raw = None;
    for index in 0..zip.len() {
        let file = zip
            .by_index(index)
            .map_err(|e| ImportError::Parse(e.to_string()))?;
        if file.name() != "export.json" && !file.name().ends_with("/export.json") {
            continue;
        }
        let mut data = Vec::new();
        file.take(max_zip_entry).read_to_end(&mut data)?;
        if data.len() as u64 >= max_zip_entry {
            return Err(ImportError::Limit(max_zip_entry as usize));
        }
        raw = Some(data);
        break;
    }
    let raw = raw.ok_or_else(|| ImportError::Parse("export.json not found in 1pux zip".into()))?;
    let mut decoder = serde_json::Deserializer::from_slice(&raw);
    let export = Option::<Export>::deserialize(&mut decoder)
        .map_err(|e| ImportError::Parse(format!("parse export.json: {e}")))?
        .unwrap_or_default();
    decoder
        .end()
        .map_err(|e| ImportError::Parse(format!("parse export.json: {e}")))?;

    let mut entries = Vec::new();
    for account in export.accounts {
        for vault in account.vaults {
            for item in vault.items {
                if item.category != LOGIN_CATEGORY || item.trashed {
                    continue;
                }
                let (username, password) = credentials(&item.details.login);
                let mut data = BTreeMap::new();
                data.insert("username".into(), Value::String(username));
                data.insert("password".into(), Value::String(password));
                data.insert(
                    "url".into(),
                    Value::String(
                        item.overview
                            .urls
                            .first()
                            .map(|u| u.url.clone())
                            .unwrap_or_default(),
                    ),
                );
                data.insert("notes".into(), Value::String(item.details.notes));
                data.insert(
                    "tags".into(),
                    Value::Array(item.overview.tags.into_iter().map(Value::String).collect()),
                );
                let mut warnings = None;
                if let Some(otp) = first_totp(&item.details.sections) {
                    insert_totp(&mut data, &mut warnings, &otp);
                }
                entries.push(ImportedEntry {
                    path: item.title,
                    data,
                    warnings,
                    secret_type: None,
                });
            }
        }
    }
    Ok(entries)
}

fn credentials(fields: &[LoginField]) -> (String, String) {
    let mut username = String::new();
    let mut password = String::new();
    for field in fields {
        match field.designation.to_ascii_lowercase().as_str() {
            "username" => username = field.value.clone(),
            "password" => password = field.value.clone(),
            _ => {}
        }
    }
    (username, password)
}

fn first_totp(sections: &[Section]) -> Option<String> {
    for section in sections {
        for field in &section.fields {
            let name = format!("{} {} {}", field.t, field.n, field.title).to_ascii_lowercase();
            if !name.contains("one-time password") && !name.contains("totp") {
                continue;
            }
            let value = field
                .v
                .get("otp")
                .and_then(Value::as_str)
                .or_else(|| field.v.as_str())
                .unwrap_or_default();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_with(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
        out.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        out.write_all(payload).unwrap();
        out.finish().unwrap().into_inner()
    }

    #[test]
    fn matches_go_duplicate_credentials_and_first_totp() {
        let export = br#"{"accounts":[{"vaults":[{"items":[
          {"categoryUuid":"001","title":"login","details":{"loginFields":[
            {"designation":"username","value":"old"},{"designation":"Username","value":"new"},
            {"designation":"password","value":"old-pw"},{"designation":"PASSWORD","value":"new-pw"}],
            "notesPlain":"n","sections":[{"fields":[
              {"t":"one-time password","v":{"otp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}},
              {"n":"totp","v":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]},
            "overview":{"urls":[{"url":"https://example.test"}],"tags":[]}},
          {"categoryUuid":"001","title":"trashed","trashed":true},
          {"categoryUuid":"webforms.generic","title":"ignored"}
        ]}]}]}"#;
        let entries = parse_1pux(&zip_with("nested/export.json", export)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data["username"], "new");
        assert_eq!(entries[0].data["password"], "new-pw");
        assert_eq!(
            entries[0].data["totp"]["secret"],
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn recognizes_empty_export_and_rejects_missing_export() {
        let empty = zip_with("export.json", b"");
        assert!(
            matches!(parse_1pux(&empty), Err(ImportError::Parse(message)) if message.contains("parse export.json"))
        );
        let missing = zip_with("other.json", b"{}");
        assert!(
            matches!(parse_1pux(&missing), Err(ImportError::Parse(message)) if message.contains("not found"))
        );
    }

    #[test]
    fn entry_limit_is_checked_after_reading_the_limited_stream() {
        let zip = zip_with("export.json", br#"{}"#);
        assert!(matches!(
            parse_1pux_with_limits(&zip, usize::MAX, 2),
            Err(ImportError::Limit(2))
        ));
        assert!(matches!(
            parse_1pux_with_limits(&zip, zip.len(), MAX_ZIP_ENTRY),
            Err(ImportError::Limit(limit)) if limit == zip.len()
        ));
    }

    #[test]
    fn first_invalid_totp_stops_selection_and_records_one_warning() {
        let export = br#"{"accounts":[{"vaults":[{"items":[
          {"categoryUuid":"001","title":"login","details":{"sections":[{"fields":[
            {"n":"totp","v":"bad"},
            {"n":"totp","v":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]}}
        ]}]}]}"#;
        let entries = parse_1pux(&zip_with("export.json", export)).unwrap();
        assert!(entries[0].data.get("totp").is_none());
        assert_eq!(entries[0].warnings.as_deref().unwrap().len(), 1);
    }
}
