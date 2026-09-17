use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{Cursor, Read},
};
use zip::ZipArchive;

use super::{ImportError, ImportedEntry, apply_prefix, normalize_path, parse_totp};

const MAX_IMPORT_BYTES: usize = 100 * 1024 * 1024;
const MAX_ZIP_ENTRY: u64 = 100 * 1024 * 1024;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Default)]
struct CxfExport {
    #[serde(default, deserialize_with = "super::null_default")]
    version: CxfVersion,
    #[serde(default, deserialize_with = "super::null_default_vec")]
    accounts: Vec<CxfAccount>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Default)]
struct CxfVersion {
    #[serde(default, deserialize_with = "super::null_default")]
    major: i64,
    #[serde(default, deserialize_with = "super::null_default")]
    minor: i64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Default)]
struct CxfAccount {
    #[serde(default, deserialize_with = "super::null_default")]
    id: String,
    #[serde(default, deserialize_with = "super::null_default")]
    username: String,
    #[serde(default, deserialize_with = "super::null_default")]
    email: String,
    #[serde(default, deserialize_with = "super::null_default_vec")]
    collections: Vec<CxfCollection>,
    #[serde(default, deserialize_with = "super::null_default_vec")]
    items: Vec<CxfItem>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Default)]
struct CxfCollection {
    #[serde(default, deserialize_with = "super::null_default")]
    id: String,
    #[serde(default, deserialize_with = "super::null_default")]
    title: String,
    #[serde(default, deserialize_with = "super::null_default")]
    name: String,
    #[serde(default, deserialize_with = "super::null_default_vec")]
    items: Vec<CxfLinkedItem>,
    #[serde(rename = "subCollections", default, deserialize_with = "super::null_default_vec")]
    sub_collections: Vec<CxfCollection>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Default)]
struct CxfLinkedItem {
    #[serde(default, deserialize_with = "super::null_default")]
    item: String,
    #[serde(default, deserialize_with = "super::null_default")]
    account: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
struct CxfItem {
    #[serde(default, deserialize_with = "super::null_default")]
    id: String,
    #[serde(default, deserialize_with = "super::null_default")]
    title: String,
    #[serde(default, deserialize_with = "super::null_default")]
    name: String,
    #[serde(default, deserialize_with = "super::null_default")]
    scope: CxfScope,
    #[serde(default, deserialize_with = "super::null_default_vec")]
    credentials: Vec<Value>,
    #[serde(default, deserialize_with = "super::null_default_vec")]
    tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
struct CxfScope {
    #[serde(default, deserialize_with = "super::null_default_vec")]
    urls: Vec<String>,
}

// Parse a FIDO Credential Exchange Format archive using the same bounded
/// selection and item mapping rules as the Go importer.
pub fn parse(bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    if bytes.len() >= MAX_IMPORT_BYTES {
        return Err(ImportError::Limit(MAX_IMPORT_BYTES));
    }
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| ImportError::Parse(format!("open cxf zip: {error}")))?;
    let payload = read_payload(&mut archive)?;
    let export: Option<CxfExport> = serde_json::from_slice(&payload)
        .map_err(|error| ImportError::Parse(format!("parse CXF JSON document: {error}")))?;

    let mut entries = Vec::new();
    for account in export.unwrap_or_default().accounts {
        entries.extend(account_entries(account));
    }
    Ok(entries)
}

struct JsonCandidate {
    index: usize,
    name: String,
    size: u64,
}

fn read_payload<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<u8>, ImportError> {
    let mut candidates = Vec::new();
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|error| ImportError::Parse(format!("inspect cxf zip: {error}")))?;
        if file.is_dir() || !file.name().to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        candidates.push(JsonCandidate {
            index,
            name: file.name().to_owned(),
            size: file.size(),
        });
    }
    if candidates.is_empty() {
        return Err(ImportError::Parse(
            "no CXF JSON document found in cxf zip".into(),
        ));
    }

    let mut selected = &candidates[0];
    let mut preferred = false;
    for candidate in &candidates {
        let basename = candidate.name.rsplit('/').next().unwrap_or(&candidate.name);
        if basename.eq_ignore_ascii_case("cxf.json")
            || basename.eq_ignore_ascii_case("payload.json")
        {
            selected = candidate;
            preferred = true;
            break;
        }
    }
    if !preferred {
        for candidate in candidates.iter().skip(1) {
            if candidate.size > selected.size {
                selected = candidate;
            }
        }
    }
    if selected.size >= MAX_ZIP_ENTRY {
        return Err(ImportError::Parse(format!(
            "zip entry exceeds maximum size of {MAX_ZIP_ENTRY} bytes"
        )));
    }

    let mut file = archive
        .by_index(selected.index)
        .map_err(|error| ImportError::Parse(format!("open {}: {error}", selected.name)))?;
    let mut payload = Vec::new();
    file.by_ref()
        .take(MAX_ZIP_ENTRY)
        .read_to_end(&mut payload)
        .map_err(|error| ImportError::Parse(format!("read {}: {error}", selected.name)))?;
    if payload.len() as u64 >= MAX_ZIP_ENTRY {
        return Err(ImportError::Parse(format!(
            "zip entry exceeds maximum size of {MAX_ZIP_ENTRY} bytes"
        )));
    }
    Ok(payload)
}

fn account_entries(account: CxfAccount) -> Vec<ImportedEntry> {
    let items_by_id: HashMap<String, CxfItem> = account
        .items
        .iter()
        .filter(|item| !item.id.is_empty())
        .cloned()
        .map(|item| (item.id.clone(), item))
        .collect();
    let mut placed = HashSet::new();
    let mut entries = Vec::new();

    fn add(
        item: &CxfItem,
        collection_path: &str,
        placed: &mut HashSet<String>,
        entries: &mut Vec<ImportedEntry>,
    ) {
        if collection_path.is_empty() && !item.id.is_empty() && placed.contains(&item.id) {
            return;
        }
        if let Some(entry) = item_entry(item, collection_path) {
            if !collection_path.is_empty() && !item.id.is_empty() {
                placed.insert(item.id.clone());
            }
            entries.push(entry);
        }
    }

    fn walk(
        collections: &[CxfCollection],
        parent_path: &str,
        items_by_id: &HashMap<String, CxfItem>,
        placed: &mut HashSet<String>,
        entries: &mut Vec<ImportedEntry>,
    ) {
        for collection in collections {
            let collection_path = apply_prefix(parent_path, collection_title(collection));
            for linked in &collection.items {
                if let Some(item) = items_by_id.get(&linked.item) {
                    add(item, &collection_path, placed, entries);
                }
            }
            walk(
                &collection.sub_collections,
                &collection_path,
                items_by_id,
                placed,
                entries,
            );
        }
    }

    walk(
        &account.collections,
        "",
        &items_by_id,
        &mut placed,
        &mut entries,
    );
    for item in &account.items {
        add(item, "", &mut placed, &mut entries);
    }
    entries
}

fn item_entry(item: &CxfItem, collection_path: &str) -> Option<ImportedEntry> {
    let mut data = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut urls = Vec::new();
    let mut has_basic_auth = false;
    let mut secret_type = None;

    for credential in &item.credentials {
        let Some(object) = credential.as_object() else {
            continue;
        };
        let Some(credential_type) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        if credential_type.is_empty() {
            continue;
        }
        match normalize_type(credential_type).as_str() {
            "basicauth" => {
                has_basic_auth = true;
                apply_basic_auth(object, &mut data, &mut urls, &mut warnings);
            }
            "totp" => apply_totp(object, &mut data, &mut warnings),
            "note" => apply_note(object, &mut data, &mut warnings),
            "passkey" => apply_passkey(credential, &mut data),
            "sshkey" | "cryptographickey" => {
                apply_ssh_key(object, &mut data, &mut secret_type, &mut warnings)
            }
            "creditcard" => apply_credit_card(object, &mut data, &mut secret_type, &mut warnings),
            "file" | "address" => skip_credential(credential_type, &mut warnings),
            _ => skip_credential(credential_type, &mut warnings),
        }
    }

    if has_basic_auth {
        let scope_urls = non_empty_strings(&item.scope.urls);
        let urls = if scope_urls.is_empty() {
            non_empty_strings(&urls)
        } else {
            scope_urls
        };
        if !urls.is_empty() {
            data.insert("url".into(), Value::String(urls[0].clone()));
            data.insert(
                "urls".into(),
                Value::Array(urls.into_iter().map(Value::String).collect()),
            );
        }
    }
    if !item.tags.is_empty() {
        data.insert(
            "tags".into(),
            Value::Array(item.tags.iter().cloned().map(Value::String).collect()),
        );
    }
    if data.is_empty() {
        return None;
    }
    let path = normalize_path(&apply_prefix(collection_path, item_title(item)));
    if path.is_empty() {
        return None;
    }
    Some(ImportedEntry {
        path,
        data,
        warnings: (!warnings.is_empty()).then_some(warnings),
        secret_type,
    })
}

fn apply_basic_auth(
    object: &Map<String, Value>,
    data: &mut BTreeMap<String, Value>,
    urls: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let username = match field_value_named(object.get("username"), "cxfBasicAuth", "username") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: basic-auth: {error}"));
            return;
        }
    };
    let password = match field_value_named(object.get("password"), "cxfBasicAuth", "password") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: basic-auth: {error}"));
            return;
        }
    };
    let credential_urls = match string_vec_named(object.get("urls"), "cxfBasicAuth", "urls") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: basic-auth: {error}"));
            return;
        }
    };
    data.insert("username".into(), Value::String(username));
    data.insert("password".into(), Value::String(password));
    *urls = credential_urls;
}

fn apply_totp(
    object: &Map<String, Value>,
    data: &mut BTreeMap<String, Value>,
    warnings: &mut Vec<String>,
) {
    let secret = match string_field_named(object.get("secret"), "cxfTOTP", "secret", "string") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: totp: {error}"));
            return;
        }
    };
    let algorithm = match string_field_named(object.get("algorithm"), "cxfTOTP", "algorithm", "string") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: totp: {error}"));
            return;
        }
    };
    let issuer = match string_field_named(object.get("issuer"), "cxfTOTP", "issuer", "string") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: totp: {error}"));
            return;
        }
    };
    let username = match string_field_named(object.get("username"), "cxfTOTP", "username", "string") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: totp: {error}"));
            return;
        }
    };
    let _ = (issuer, username);
    let digits = match integer_field_named(object.get("digits"), "cxfTOTP", "digits", "int") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: totp: {error}"));
            return;
        }
    };
    let period = match integer_field_named(object.get("period"), "cxfTOTP", "period", "int") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: totp: {error}"));
            return;
        }
    };
    if secret.is_empty() {
        warnings.push("totp: empty TOTP secret".into());
        return;
    }
    let input = if secret.to_ascii_lowercase().starts_with("otpauth://") {
        secret
    } else {
        let algorithm = if algorithm.is_empty() {
            "SHA1"
        } else {
            &algorithm
        };
        let digits = if digits == 0 { 6 } else { digits };
        let period = if period == 0 { 30 } else { period };
        format!(
            "otpauth://totp/CXF?secret={secret}&algorithm={algorithm}&digits={digits}&period={period}"
        )
    };
    match parse_totp(&input) {
        Ok(value) => {
            data.insert("totp".into(), value);
        }
        Err(error) => warnings.push(format!("totp: {error}")),
    }
}

fn apply_note(
    object: &Map<String, Value>,
    data: &mut BTreeMap<String, Value>,
    warnings: &mut Vec<String>,
) {
    let content = match field_value_named(object.get("content"), "cxfNote", "content") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: note: {error}"));
            return;
        }
    };
    if content.is_empty() {
        return;
    }
    match data.get_mut("notes") {
        Some(Value::String(existing)) if !existing.is_empty() => {
            existing.push_str("\n\n");
            existing.push_str(&content);
        }
        _ => {
            data.insert("notes".into(), Value::String(content));
        }
    }
}

fn apply_passkey(credential: &Value, data: &mut BTreeMap<String, Value>) {
    if !data.contains_key("passkey") {
        data.insert("passkey".into(), credential.clone());
        return;
    }
    let first = data.remove("passkey").expect("passkey exists");
    match data.get_mut("passkeys") {
        Some(Value::Array(values)) => values.push(credential.clone()),
        _ => {
            data.insert(
                "passkeys".into(),
                Value::Array(vec![first.clone(), credential.clone()]),
            );
        }
    }
    data.insert("passkey".into(), first);
}

fn apply_ssh_key(
    object: &Map<String, Value>,
    data: &mut BTreeMap<String, Value>,
    secret_type: &mut Option<String>,
    warnings: &mut Vec<String>,
) {
    for field in ["keyType", "keyComment"] {
        if let Err(error) = string_field_named(object.get(field), "cxfSSHKey", field, "string") {
            warnings.push(format!("cxf: ssh-key: {error}"));
            return;
        }
    }
    let private_key = match string_field_named(object.get("privateKey"), "cxfSSHKey", "privateKey", "string") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: ssh-key: {error}"));
            return;
        }
    };
    let private_key_pem = match string_field_named(object.get("privateKeyPem"), "cxfSSHKey", "privateKeyPem", "string") {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("cxf: ssh-key: {error}"));
            return;
        }
    };
    let key = if private_key.is_empty() {
        private_key_pem
    } else {
        private_key
    };
    if key.is_empty() {
        return;
    }
    data.insert("private_key".into(), Value::String(ssh_key_material(&key)));
    *secret_type = Some("ssh_key".into());
}

fn apply_credit_card(
    object: &Map<String, Value>,
    data: &mut BTreeMap<String, Value>,
    secret_type: &mut Option<String>,
    warnings: &mut Vec<String>,
) {
    let fields = [
        "number",
        "fullName",
        "cardType",
        "verificationNumber",
        "expiryDate",
    ];
    let mut values = BTreeMap::new();
    for field in fields {
        match field_value_named(object.get(field), "cxfCreditCard", field) {
            Ok(value) => {
                values.insert(field, value);
            }
            Err(error) => {
                warnings.push(format!("cxf: credit-card: {error}"));
                return;
            }
        }
    }
    let (month, year) =
        split_year_month(values.get("expiryDate").map(String::as_str).unwrap_or(""));
    data.insert(
        "card_number".into(),
        Value::String(values.remove("number").unwrap_or_default()),
    );
    data.insert(
        "cardholder".into(),
        Value::String(values.remove("fullName").unwrap_or_default()),
    );
    data.insert("expiry_month".into(), Value::String(month));
    data.insert("expiry_year".into(), Value::String(year));
    data.insert(
        "cvc".into(),
        Value::String(values.remove("verificationNumber").unwrap_or_default()),
    );
    data.insert("subtype".into(), Value::String("card".into()));
    *secret_type = Some("payment".into());
}

fn skip_credential(credential_type: &str, warnings: &mut Vec<String>) {
    warnings.push(format!(
        "cxf: skipped credential type {credential_type:?}: not supported by Symaira Vault"
    ));
}

fn field_value_named(
    value: Option<&Value>,
    struct_name: &str,
    field_name: &str,
) -> Result<String, String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(Value::Object(object)) => string_field_named(
            object.get("value"),
            struct_name,
            field_name,
            r#"struct { Value string "json:\"value\"" }"#,
        ),
        Some(other) => Err(go_unmarshal_field_error(
            other,
            struct_name,
            field_name,
            r#"struct { Value string "json:\"value\"" }"#,
        )),
    }
}

fn string_field_named(
    value: Option<&Value>,
    struct_name: &str,
    field_name: &str,
    target_type: &str,
) -> Result<String, String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(other) => Err(go_unmarshal_field_error(
            other,
            struct_name,
            field_name,
            target_type,
        )),
    }
}

fn integer_field_named(
    value: Option<&Value>,
    struct_name: &str,
    field_name: &str,
    target_type: &str,
) -> Result<i64, String> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(number)) => number
            .as_i64()
            .ok_or_else(|| go_unmarshal_field_error(value.unwrap(), struct_name, field_name, target_type)),
        Some(other) => Err(go_unmarshal_field_error(
            other,
            struct_name,
            field_name,
            target_type,
        )),
    }
}

fn string_vec_named(
    value: Option<&Value>,
    struct_name: &str,
    field_name: &str,
) -> Result<Vec<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                Value::String(value) => Ok(value.clone()),
                Value::Null => Ok(String::new()),
                other => Err(go_unmarshal_field_error(
                    other,
                    struct_name,
                    &format!("{field_name}[{index}]"),
                    "string",
                )),
            })
            .collect(),
        Some(other) => Err(go_unmarshal_field_error(
            other,
            struct_name,
            field_name,
            "[]string",
        )),
    }
}

fn go_unmarshal_field_error(
    value: &Value,
    struct_name: &str,
    field_name: &str,
    target_type: &str,
) -> String {
    format!(
        "json: cannot unmarshal {} into Go struct field {struct_name}.{field_name} of type {target_type}",
        json_type(value)
    )
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn normalize_type(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', '_'], "")
}

fn ssh_key_material(value: &str) -> String {
    if value.contains("-----BEGIN") {
        return value.into();
    }
    let decoded = general_purpose::URL_SAFE
        .decode(value)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value));
    match decoded {
        Ok(bytes) if !bytes.is_empty() => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
            for chunk in encoded.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
                pem.push('\n');
            }
            pem.push_str("-----END PRIVATE KEY-----\n");
            pem
        }
        _ => value.into(),
    }
}

fn non_empty_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn split_year_month(value: &str) -> (String, String) {
    value
        .split_once('-')
        .map(|(month, year)| (month.into(), year.into()))
        .unwrap_or_default()
}

fn item_title(item: &CxfItem) -> &str {
    if item.title.is_empty() {
        &item.name
    } else {
        &item.title
    }
}

fn collection_title(collection: &CxfCollection) -> &str {
    if collection.title.is_empty() {
        &collection.name
    } else {
        &collection.title
    }
}
