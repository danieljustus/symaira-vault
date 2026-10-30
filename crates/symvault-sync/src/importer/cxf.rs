use base64::{Engine as _, engine::general_purpose};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{Cursor, Read},
};
use zip::{ZipArchive, result::ZipError};

use super::gojson::{
    self, Context, EditableValue, GoDecode, GoStruct, RawMessage, Reader, decode_struct, go_struct,
};
use super::{ImportError, ImportedEntry, apply_prefix, normalize_path, parse_totp};

const MAX_IMPORT_BYTES: usize = 100 * 1024 * 1024;
const MAX_ZIP_ENTRY: u64 = 100 * 1024 * 1024;

// The CXF document is decoded like Go's `json.Unmarshal` into the same typed
// structs as `internal/importer/cxf.go`: `null` is a no-op, keys match
// case-insensitively (exact match first), a value of the wrong JSON kind is a
// Go `UnmarshalTypeError` with Go's struct/field context, and credentials stay
// raw (`json.RawMessage`) until their `type` selects the struct to decode.

#[allow(dead_code)]
#[derive(Default)]
struct CxfExport {
    version: CxfVersion,
    accounts: Vec<CxfAccount>,
}
go_struct!(CxfExport, "cxfExport", { "version" => version, "accounts" => accounts });

#[allow(dead_code)]
#[derive(Default)]
struct CxfVersion {
    major: i64,
    minor: i64,
}
go_struct!(CxfVersion, "cxfVersion", { "major" => major, "minor" => minor });

#[allow(dead_code)]
#[derive(Default)]
struct CxfAccount {
    id: String,
    username: String,
    email: String,
    collections: Vec<CxfCollection>,
    items: Vec<CxfItem>,
}
go_struct!(CxfAccount, "cxfAccount", {
    "id" => id, "username" => username, "email" => email,
    "collections" => collections, "items" => items,
});

#[allow(dead_code)]
#[derive(Default)]
struct CxfCollection {
    id: String,
    title: String,
    name: String,
    items: Vec<CxfLinkedItem>,
    sub_collections: Vec<CxfCollection>,
}
go_struct!(CxfCollection, "cxfCollection", {
    "id" => id, "title" => title, "name" => name,
    "items" => items, "subCollections" => sub_collections,
});

#[allow(dead_code)]
#[derive(Default)]
struct CxfLinkedItem {
    item: String,
    account: String,
}
go_struct!(CxfLinkedItem, "cxfLinkedItem", { "item" => item, "account" => account });

#[derive(Default)]
struct CxfItem {
    id: String,
    title: String,
    name: String,
    scope: CxfScope,
    credentials: Vec<RawMessage>,
    tags: Vec<String>,
}
go_struct!(CxfItem, "cxfItem", {
    "id" => id, "title" => title, "name" => name, "scope" => scope,
    "credentials" => credentials, "tags" => tags,
});

#[derive(Default)]
struct CxfScope {
    urls: Vec<String>,
}
go_struct!(CxfScope, "cxfScope", { "urls" => urls });

#[derive(Default)]
struct CxfBasicAuth {
    username: EditableValue,
    password: EditableValue,
    urls: Vec<String>,
}
go_struct!(CxfBasicAuth, "cxfBasicAuth", {
    "username" => username, "password" => password, "urls" => urls,
});

#[allow(dead_code)]
#[derive(Default)]
struct CxfTotp {
    secret: String,
    period: i64,
    digits: i64,
    algorithm: String,
    issuer: String,
    username: String,
}
go_struct!(CxfTotp, "cxfTOTP", {
    "secret" => secret, "period" => period, "digits" => digits,
    "algorithm" => algorithm, "issuer" => issuer, "username" => username,
});

#[derive(Default)]
struct CxfNote {
    content: EditableValue,
}
go_struct!(CxfNote, "cxfNote", { "content" => content });

#[allow(dead_code)]
#[derive(Default)]
struct CxfSshKey {
    key_type: String,
    private_key: String,
    private_key_pem: String,
    key_comment: String,
}
go_struct!(CxfSshKey, "cxfSSHKey", {
    "keyType" => key_type, "privateKey" => private_key,
    "privateKeyPem" => private_key_pem, "keyComment" => key_comment,
});

#[allow(dead_code)]
#[derive(Default)]
struct CxfCreditCard {
    number: EditableValue,
    full_name: EditableValue,
    card_type: EditableValue,
    verification_number: EditableValue,
    expiry_date: EditableValue,
}
go_struct!(CxfCreditCard, "cxfCreditCard", {
    "number" => number, "fullName" => full_name, "cardType" => card_type,
    "verificationNumber" => verification_number, "expiryDate" => expiry_date,
});

/// Go's text for a failure of `zip.NewReader`.
fn zip_open_error(error: &ZipError) -> String {
    match error {
        ZipError::InvalidArchive(_) | ZipError::UnsupportedArchive(_) => {
            "zip: not a valid zip file".into()
        }
        other => other.to_string(),
    }
}

/// A diagnostic reproduced verbatim from Go's `Parse`, like the Bitwarden
/// importer's: the CLI prints `parse import source: <text>` on both sides.
fn go_error(text: impl Into<String>) -> ImportError {
    ImportError::Decode(text.into())
}

/// Parse a FIDO Credential Exchange Format archive using the same bounded
/// selection and item mapping rules as the Go importer.
pub fn parse(bytes: &[u8]) -> Result<Vec<ImportedEntry>, ImportError> {
    if bytes.len() >= MAX_IMPORT_BYTES {
        return Err(go_error(format!(
            "import source exceeds maximum size of {MAX_IMPORT_BYTES} bytes"
        )));
    }
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| go_error(format!("open cxf zip: {}", zip_open_error(&error))))?;
    let payload = read_payload(&mut archive)?;
    let mut export = CxfExport::default();
    gojson::unmarshal_document(&payload, &mut export)
        .map_err(|error| go_error(format!("parse CXF JSON document: {error}")))?;

    let mut entries = Vec::new();
    for account in &export.accounts {
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
            .map_err(|error| go_error(format!("inspect cxf zip: {error}")))?;
        let name = file
            .name()
            .map_err(|error| go_error(format!("inspect cxf zip: {error}")))?;
        if file.is_dir() || !name.to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        candidates.push(JsonCandidate {
            index,
            name: name.into_owned(),
            size: file.size(),
        });
    }
    if candidates.is_empty() {
        return Err(go_error("no CXF JSON document found in cxf zip"));
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
        return Err(go_error(format!(
            "zip entry exceeds maximum size of {MAX_ZIP_ENTRY} bytes"
        )));
    }

    let mut file = archive
        .by_index(selected.index)
        .map_err(|error| go_error(format!("open {}: {error}", selected.name)))?;
    let mut payload = Vec::new();
    file.by_ref()
        .take(MAX_ZIP_ENTRY)
        .read_to_end(&mut payload)
        .map_err(|error| go_error(format!("read {}: {error}", selected.name)))?;
    if payload.len() as u64 >= MAX_ZIP_ENTRY {
        return Err(go_error(format!(
            "zip entry exceeds maximum size of {MAX_ZIP_ENTRY} bytes"
        )));
    }
    Ok(payload)
}

fn account_entries(account: &CxfAccount) -> Vec<ImportedEntry> {
    let items_by_id: HashMap<&str, &CxfItem> = account
        .items
        .iter()
        .filter(|item| !item.id.is_empty())
        .map(|item| (item.id.as_str(), item))
        .collect();
    let mut placed = HashSet::new();
    let mut entries = Vec::new();

    fn add<'a>(
        item: &'a CxfItem,
        collection_path: &str,
        placed: &mut HashSet<&'a str>,
        entries: &mut Vec<ImportedEntry>,
    ) {
        if collection_path.is_empty() && !item.id.is_empty() && placed.contains(item.id.as_str()) {
            return;
        }
        if let Some(entry) = item_entry(item, collection_path) {
            if !collection_path.is_empty() && !item.id.is_empty() {
                placed.insert(item.id.as_str());
            }
            entries.push(entry);
        }
    }

    fn walk<'a>(
        collections: &[CxfCollection],
        parent_path: &str,
        items_by_id: &HashMap<&str, &'a CxfItem>,
        placed: &mut HashSet<&'a str>,
        entries: &mut Vec<ImportedEntry>,
    ) {
        for collection in collections {
            let collection_path = apply_prefix(parent_path, collection_title(collection));
            for linked in &collection.items {
                if let Some(item) = items_by_id.get(linked.item.as_str()) {
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

/// Go's `cxfParseCredential`: the credential as a generic map plus its
/// exact-key `type` string. `None` when Go would skip the credential (not an
/// object, `null`, or no non-empty string `type`).
fn parse_credential(raw: &[u8]) -> Option<(Map<String, Value>, String)> {
    let credential = gojson::unmarshal_object(raw)?;
    let credential_type = match credential.get("type") {
        Some(Value::String(value)) if !value.is_empty() => value.clone(),
        _ => return None,
    };
    Some((credential, credential_type))
}

fn item_entry(item: &CxfItem, collection_path: &str) -> Option<ImportedEntry> {
    let mut data = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut urls = Vec::new();
    let mut has_basic_auth = false;
    let mut secret_type = None;

    for raw in &item.credentials {
        let raw = raw.0.as_slice();
        let Some((credential, credential_type)) = parse_credential(raw) else {
            continue;
        };
        match normalize_type(&credential_type).as_str() {
            "basicauth" => {
                has_basic_auth = true;
                apply_basic_auth(raw, &mut data, &mut urls, &mut warnings);
            }
            "totp" => apply_totp(raw, &mut data, &mut warnings),
            "note" => apply_note(raw, &mut data, &mut warnings),
            "passkey" => apply_passkey(Value::Object(credential), &mut data),
            "sshkey" | "cryptographickey" => {
                apply_ssh_key(raw, &mut data, &mut secret_type, &mut warnings)
            }
            "creditcard" => apply_credit_card(raw, &mut data, &mut secret_type, &mut warnings),
            _ => skip_credential(&credential_type, &mut warnings),
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

/// Decodes a credential's raw JSON into its typed struct. A failure becomes
/// the `cxf: <label>: <Go error>` warning and the credential is dropped.
fn decode_credential<S: GoStruct + Default>(
    raw: &[u8],
    label: &str,
    warnings: &mut Vec<String>,
) -> Option<S> {
    let mut credential = S::default();
    match gojson::unmarshal_document(raw, &mut credential) {
        Ok(()) => Some(credential),
        Err(error) => {
            warnings.push(format!("cxf: {label}: {error}"));
            None
        }
    }
}

fn apply_basic_auth(
    raw: &[u8],
    data: &mut BTreeMap<String, Value>,
    urls: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(credential) = decode_credential::<CxfBasicAuth>(raw, "basic-auth", warnings) else {
        return;
    };
    data.insert("username".into(), Value::String(credential.username.0));
    data.insert("password".into(), Value::String(credential.password.0));
    *urls = credential.urls;
}

fn apply_totp(raw: &[u8], data: &mut BTreeMap<String, Value>, warnings: &mut Vec<String>) {
    let Some(credential) = decode_credential::<CxfTotp>(raw, "totp", warnings) else {
        return;
    };
    let secret = credential.secret.trim();
    if secret.is_empty() {
        warnings.push("totp: empty TOTP secret".into());
        return;
    }
    let result = if secret.to_ascii_lowercase().starts_with("otpauth://") {
        parse_totp(secret)
    } else {
        let algorithm = credential.algorithm.trim().to_uppercase();
        let algorithm = if algorithm.is_empty() {
            "SHA1"
        } else {
            &algorithm
        };
        let digits = credential.digits;
        let period = credential.period;
        super::totp::validated_totp(
            secret,
            algorithm,
            if digits == 0 { 6 } else { digits },
            if period == 0 { 30 } else { period },
        )
    };
    match result {
        Ok(value) => {
            data.insert("totp".into(), value);
        }
        Err(error) => warnings.push(format!("totp: {error}")),
    }
}

fn apply_note(raw: &[u8], data: &mut BTreeMap<String, Value>, warnings: &mut Vec<String>) {
    let Some(credential) = decode_credential::<CxfNote>(raw, "note", warnings) else {
        return;
    };
    let content = credential.content.0;
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

fn apply_passkey(credential: Value, data: &mut BTreeMap<String, Value>) {
    if !data.contains_key("passkey") {
        data.insert("passkey".into(), credential);
        return;
    }
    match data.get_mut("passkeys") {
        Some(Value::Array(values)) => values.push(credential),
        _ => {
            let first = data.get("passkey").cloned().expect("passkey exists");
            data.insert("passkeys".into(), Value::Array(vec![first, credential]));
        }
    }
}

fn apply_ssh_key(
    raw: &[u8],
    data: &mut BTreeMap<String, Value>,
    secret_type: &mut Option<String>,
    warnings: &mut Vec<String>,
) {
    let Some(credential) = decode_credential::<CxfSshKey>(raw, "ssh-key", warnings) else {
        return;
    };
    let key = if credential.private_key.is_empty() {
        credential.private_key_pem
    } else {
        credential.private_key
    };
    if key.is_empty() {
        return;
    }
    data.insert("private_key".into(), Value::String(ssh_key_material(&key)));
    *secret_type = Some("ssh_key".into());
}

fn apply_credit_card(
    raw: &[u8],
    data: &mut BTreeMap<String, Value>,
    secret_type: &mut Option<String>,
    warnings: &mut Vec<String>,
) {
    let Some(credential) = decode_credential::<CxfCreditCard>(raw, "credit-card", warnings) else {
        return;
    };
    let (month, year) = split_year_month(&credential.expiry_date.0);
    data.insert("card_number".into(), Value::String(credential.number.0));
    data.insert("cardholder".into(), Value::String(credential.full_name.0));
    data.insert("expiry_month".into(), Value::String(month));
    data.insert("expiry_year".into(), Value::String(year));
    data.insert(
        "cvc".into(),
        Value::String(credential.verification_number.0),
    );
    data.insert("subtype".into(), Value::String("card".into()));
    *secret_type = Some("payment".into());
}

fn skip_credential(credential_type: &str, warnings: &mut Vec<String>) {
    warnings.push(format!(
        "cxf: skipped credential type {}: not supported by Symaira Vault",
        symvault_core::go_quote(credential_type)
    ));
}

fn normalize_type(value: &str) -> String {
    symvault_core::go_to_lower(value.trim()).replace(['-', '_'], "")
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
