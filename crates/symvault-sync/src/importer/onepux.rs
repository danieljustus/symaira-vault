// 1Password `.1pux` import parity.
//
// The shape and limits in this module intentionally follow
// `internal/importer/onepux.go`.  The parent importer wires this module into
// the public format dispatcher.

use super::gojson::{
    self, Context, GoDecode, GoStruct, RawMessage, Reader, decode_struct, go_struct,
};
use super::{ImportError, ImportedEntry, insert_totp};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};

const LOGIN_CATEGORY: &str = "001";
const MAX_IMPORT_BYTES: usize = 100 * 1024 * 1024;
const MAX_ZIP_ENTRY: u64 = 100 * 1024 * 1024;

// `export.json` is decoded like Go's `json.Unmarshal` into the typed structs of
// `internal/importer/onepux.go`: `null` is a no-op, keys match
// case-insensitively (exact match first), a value of the wrong JSON kind is a
// Go `UnmarshalTypeError` with Go's struct/field context, and a field value
// stays raw (`json.RawMessage`) until the OTP lookup decodes it.

#[derive(Default)]
struct Export {
    accounts: Vec<Account>,
}
go_struct!(Export, "onePUXExport", { "accounts" => accounts });

#[derive(Default)]
struct Account {
    vaults: Vec<Vault>,
}
go_struct!(Account, "onePUXAccount", { "vaults" => vaults });

#[derive(Default)]
struct Vault {
    items: Vec<Item>,
}
go_struct!(Vault, "onePUXVault", { "items" => items });

#[derive(Default)]
struct Item {
    category: String,
    title: String,
    trashed: bool,
    details: Details,
    overview: Overview,
}
go_struct!(Item, "onePUXItem", {
    "categoryUuid" => category, "title" => title, "trashed" => trashed,
    "details" => details, "overview" => overview,
});

#[derive(Default)]
struct Details {
    login: Vec<LoginField>,
    sections: Vec<Section>,
    notes: String,
}
go_struct!(Details, "onePUXDetails", {
    "loginFields" => login, "sections" => sections, "notesPlain" => notes,
});

#[allow(dead_code)]
#[derive(Default)]
struct LoginField {
    field_type: String,
    designation: String,
    value: String,
}
go_struct!(LoginField, "onePUXLoginField", {
    "fieldType" => field_type, "designation" => designation, "value" => value,
});

#[allow(dead_code)]
#[derive(Default)]
struct Section {
    title: String,
    fields: Vec<Field>,
}
go_struct!(Section, "onePUXSection", { "title" => title, "fields" => fields });

#[derive(Default)]
struct Field {
    title: String,
    n: String,
    t: String,
    v: RawMessage,
}
go_struct!(Field, "onePUXField", { "title" => title, "n" => n, "t" => t, "v" => v });

#[derive(Default)]
struct Overview {
    urls: Vec<Url>,
    tags: Vec<String>,
}
go_struct!(Overview, "onePUXOverview", { "urls" => urls, "tags" => tags });

#[derive(Default)]
struct Url {
    url: String,
}
go_struct!(Url, "onePUXURL", { "url" => url });

/// The anonymous `struct { OTP string `json:"otp"` }` Go decodes a field value
/// into first.
#[derive(Default)]
struct OtpObject {
    otp: String,
}
go_struct!(OtpObject, "", { "otp" => otp });

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
        return Err(ImportError::Decode(format!(
            "import source exceeds maximum size of {max_import_bytes} bytes"
        )));
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| {
        ImportError::Decode(format!("open 1pux zip: {}", super::cxf::zip_open_error(&e)))
    })?;
    let mut raw = None;
    for index in 0..zip.len() {
        let file = zip
            .by_index(index)
            .map_err(|e| ImportError::Parse(e.to_string()))?;
        let name = file.name().map_err(|e| ImportError::Parse(e.to_string()))?;
        if name != "export.json" && !name.ends_with("/export.json") {
            continue;
        }
        let mut data = Vec::new();
        file.take(max_zip_entry)
            .read_to_end(&mut data)
            .map_err(|e| ImportError::Decode(format!("read export.json: {e}")))?;
        if data.len() as u64 >= max_zip_entry {
            return Err(ImportError::Decode(format!(
                "zip entry exceeds maximum size of {max_zip_entry} bytes"
            )));
        }
        raw = Some(data);
        break;
    }
    let raw = raw.ok_or_else(|| ImportError::Decode("export.json not found in 1pux zip".into()))?;
    let mut export = Export::default();
    gojson::unmarshal_document(&raw, &mut export)
        .map_err(|error| ImportError::Decode(format!("parse export.json: {error}")))?;

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
            let value = otp_value(&field.v.0);
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Go's `onePUXOTPValue`: the `otp` of an object value, else a bare string
/// value; anything `json.Unmarshal` rejects (including an empty or absent
/// value) yields the empty string.
fn otp_value(raw: &[u8]) -> String {
    let mut object = OtpObject::default();
    if gojson::unmarshal_document(raw, &mut object).is_ok() && !object.otp.is_empty() {
        return object.otp;
    }
    let mut text = String::new();
    if gojson::unmarshal_document(raw, &mut text).is_ok() {
        return text;
    }
    String::new()
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
            matches!(parse_1pux(&empty), Err(ImportError::Decode(message)) if message == "parse export.json: unexpected end of JSON input")
        );
        let missing = zip_with("other.json", b"{}");
        assert!(
            matches!(parse_1pux(&missing), Err(ImportError::Decode(message)) if message == "export.json not found in 1pux zip")
        );
    }

    #[test]
    fn entry_limit_is_checked_after_reading_the_limited_stream() {
        let zip = zip_with("export.json", br#"{}"#);
        assert!(matches!(
            parse_1pux_with_limits(&zip, usize::MAX, 2),
            Err(ImportError::Decode(message)) if message == "zip entry exceeds maximum size of 2 bytes"
        ));
        let limit = zip.len();
        assert!(matches!(
            parse_1pux_with_limits(&zip, limit, MAX_ZIP_ENTRY),
            Err(ImportError::Decode(message))
                if message == format!("import source exceeds maximum size of {limit} bytes")
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
        assert!(!entries[0].data.contains_key("totp"));
        assert_eq!(entries[0].warnings.as_deref().unwrap().len(), 1);
    }
}
