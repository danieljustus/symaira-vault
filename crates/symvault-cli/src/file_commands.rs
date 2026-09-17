//! Native file attachment add/get operations over the shared encrypted store.

use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use symvault_crypto::Identity;
use symvault_store::{AttachmentInfo, Entry, Store, StoreError};
use symvault_sync::{GoTime, safeio};

pub const DEFAULT_MAX_ATTACHMENT_SIZE: u64 = 1 << 20;

#[derive(Debug)]
pub struct AddOptions {
    pub path: String,
    pub field: String,
    pub source: PathBuf,
    pub secret_type: String,
    pub max_size: u64,
    pub shred: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AddResult {
    pub filename: String,
    pub source: PathBuf,
    pub path: String,
    pub field: String,
    pub size: usize,
    pub sha256: String,
    pub shredded: bool,
}

#[derive(Debug)]
pub struct GetOptions {
    pub query: String,
    pub field: String,
    pub output: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GetResult {
    pub path: String,
    pub field: String,
    pub output: PathBuf,
    pub size: usize,
}

pub fn add(root: &Path, identity: &Identity, options: &AddOptions) -> Result<AddResult, String> {
    if options.field.is_empty() {
        return Err("--field is required".to_owned());
    }
    let metadata = fs::metadata(&options.source)
        .map_err(|error| format!("cannot stat source file: {error}"))?;
    if metadata.len() > options.max_size {
        return Err(format!(
            "source file is {} bytes, exceeds the {} byte limit (override with --max-size)",
            metadata.len(),
            options.max_size
        ));
    }
    let content =
        fs::read(&options.source).map_err(|error| format!("cannot read source file: {error}"))?;
    let filename = options
        .source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| "source path has no file name".to_owned())?;
    let sha256 = digest(&content);
    let encoded = STANDARD.encode(&content);
    let source = options.source.clone();

    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
    let mut entry = match store.get(&options.path, identity) {
        Ok(entry) => entry,
        Err(StoreError::EntryNotFound(_)) => Entry::default(),
        Err(error) => return Err(format!("cannot read entry: {error}")),
    };
    entry
        .data
        .insert(options.field.clone(), Value::String(encoded));
    entry.secret_metadata.attachments.insert(
        options.field.clone(),
        AttachmentInfo {
            filename: filename.clone(),
            size: content.len() as i64,
            sha256: sha256.clone(),
        },
    );
    if entry.secret_metadata.secret_type.is_empty() {
        entry.secret_metadata.secret_type = options.secret_type.clone();
    }
    // Go's file command calls WriteEntry directly, so it does not add a
    // pending write-history record here.
    store
        .write_entry_with_recipients_at(
            &options.path,
            &entry,
            identity,
            &GoTime::now().to_rfc3339_nano(),
            None,
        )
        .map_err(|error| format!("cannot write attachment: {error}"))?;

    let shredded = if options.shred {
        shred_source(&options.source).is_ok()
    } else {
        false
    };
    Ok(AddResult {
        filename,
        source,
        path: options.path.clone(),
        field: options.field.clone(),
        size: content.len(),
        sha256,
        shredded,
    })
}

pub fn get(root: &Path, identity: &Identity, options: &GetOptions) -> Result<GetResult, String> {
    let (path, explicit_field) = split_path_field(&options.query);
    let field = if options.field.is_empty() {
        explicit_field
    } else {
        options.field.clone()
    };
    let store = Store::open(root, identity).map_err(|error| error.to_string())?;
    let entry = store
        .get(&path, identity)
        .map_err(|error| format!("cannot read entry: {error}"))?;
    let (field, attachment) = resolve_attachment_field(&entry, &field)?;
    let content = decode_attachment_content(&entry, &field)?;
    if let Some(attachment) = attachment {
        let actual = digest(&content);
        if actual != attachment.sha256 {
            eprintln!(
                "Warning: sha256 mismatch for {path}#{field} (expected {}, got {actual})",
                attachment.sha256
            );
        }
    }
    safeio::write_atomic(&options.output, &content)
        .map_err(|error| format!("cannot write output file: {error}"))?;
    Ok(GetResult {
        path,
        field,
        output: options.output.clone(),
        size: content.len(),
    })
}

fn split_path_field(query: &str) -> (String, String) {
    query
        .rfind('#')
        .filter(|index| *index > 0)
        .map(|index| (query[..index].to_owned(), query[index + 1..].to_owned()))
        .unwrap_or_else(|| (query.to_owned(), String::new()))
}

fn resolve_attachment_field(
    entry: &Entry,
    explicit: &str,
) -> Result<(String, Option<AttachmentInfo>), String> {
    if !explicit.is_empty() {
        return Ok((
            explicit.to_owned(),
            entry.secret_metadata.attachments.get(explicit).cloned(),
        ));
    }
    match entry.secret_metadata.attachments.len() {
        0 => Err("entry has no recorded attachment fields; specify --field".to_owned()),
        1 => entry
            .secret_metadata
            .attachments
            .iter()
            .next()
            .map(|(field, info)| (field.clone(), Some(info.clone())))
            .ok_or_else(|| "entry has no recorded attachment fields; specify --field".to_owned()),
        _ => {
            let mut fields: Vec<_> = entry.secret_metadata.attachments.keys().cloned().collect();
            fields.sort();
            Err(format!(
                "entry has multiple attachment fields ({}); specify --field",
                fields.join(", ")
            ))
        }
    }
}

fn decode_attachment_content(entry: &Entry, field: &str) -> Result<Vec<u8>, String> {
    let encoded = entry
        .data
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("field {field:?} is not string-encoded content"))?;
    let encoded = if let Some(manifest) = encoded.strip_prefix("chunked-v1:") {
        if manifest.is_empty() {
            return Err(format!(
                "invalid chunk manifest in field {field:?}: no chunks specified"
            ));
        }
        let mut combined = String::new();
        for chunk in manifest.split(',') {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return Err(format!(
                    "invalid chunk manifest in field {field:?}: empty chunk name"
                ));
            }
            let value = entry
                .data
                .get(chunk)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("chunk field {chunk:?} not found in entry"))?;
            combined.push_str(value);
        }
        combined
    } else {
        encoded.to_owned()
    };
    STANDARD
        .decode(encoded)
        .map_err(|error| format!("decode attachment content: {error}"))
}

fn digest(content: &[u8]) -> String {
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn shred_source(path: &Path) -> Result<(), String> {
    let length = fs::metadata(path).map_err(|error| error.to_string())?.len() as usize;
    fs::write(path, vec![0u8; length]).map_err(|error| error.to_string())?;
    fs::remove_file(path).map_err(|error| error.to_string())
}
