//! Import external password-manager exports into an encrypted vault.
//!
//! Parsing is completed before the vault is opened or any write callback is
//! invoked. The dispatcher supplies the production write and replacement callbacks,
//! which keeps this module usable with an in-memory test backend and leaves
//! session, Git, and audit policy at the CLI boundary.

use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use symvault_crypto::Identity;
use symvault_store::StoreError;
use symvault_sync::importer::{self, Format};

const MAX_IMPORT_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportOptions {
    pub source: PathBuf,
    pub format: Option<String>,
    pub dry_run: bool,
    pub prefix: String,
    pub skip_existing: bool,
    pub overwrite: bool,
    pub mapping: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportResult {
    pub format: String,
    pub imported: usize,
    pub skipped: usize,
}

/// Resolves an explicit format or the formats that the Go command derives
/// from a source extension without guessing which JSON exporter was used.
pub fn resolve_format(explicit: Option<&str>, source: &Path) -> Result<Format, String> {
    if let Some(value) = explicit {
        return parse_format(value);
    }
    match source.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("csv") => Ok(Format::Csv),
        Some(extension) if extension.eq_ignore_ascii_case("zip") => Ok(Format::Cxf),
        Some(extension) => Err(format!(
            "cannot detect format from file extension {:?}; use --format to specify",
            format!(".{extension}")
        )),
        None => {
            Err("cannot detect format from file extension \"\"; use --format to specify".into())
        }
    }
}

pub fn parse_format(value: &str) -> Result<Format, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "cxf" => Ok(Format::Cxf),
        "csv" => Ok(Format::Csv),
        "apple" => Ok(Format::Apple),
        "chrome" => Ok(Format::Chrome),
        "firefox" => Ok(Format::Firefox),
        "bitwarden" => Ok(Format::Bitwarden),
        "1password" | "1pux" => Ok(Format::OnePassword),
        "pass" => Ok(Format::Pass),
        other => Err(format!("unsupported import format: {other}")),
    }
}

pub fn format_name(format: Format) -> &'static str {
    match format {
        Format::Cxf => "cxf",
        Format::Csv => "csv",
        Format::Apple => "apple",
        Format::Chrome => "chrome",
        Format::Firefox => "firefox",
        Format::Bitwarden => "bitwarden",
        Format::OnePassword => "1password",
        Format::Pass => "pass",
    }
}

/// Parses and applies an import. `import_fields` and `replace_fields` are supplied by
/// the CLI's write boundary so imports use the same encrypted-store and Git
/// lifecycle as ordinary entry mutations.
pub fn run_import<ImportFields, ReplaceFields, SetSecretType>(
    root: &Path,
    identity: &Identity,
    options: &ImportOptions,
    mut import_fields: ImportFields,
    mut replace_fields: ReplaceFields,
    mut set_secret_type: SetSecretType,
) -> Result<ImportResult, String>
where
    ImportFields: FnMut(&Path, &Identity, &str, BTreeMap<String, Value>) -> Result<(), String>,
    ReplaceFields: FnMut(&Path, &Identity, &str, BTreeMap<String, Value>) -> Result<(), String>,
    SetSecretType: FnMut(&Path, &Identity, &str, &str) -> Result<(), String>,
{
    if options.skip_existing && options.overwrite {
        return Err("--skip-existing and --overwrite cannot be used together".into());
    }
    let format = resolve_format(options.format.as_deref(), &options.source)?;
    let mapping = crate::export_commands::parse_mapping(&options.mapping)?;
    let metadata =
        fs::metadata(&options.source).map_err(|error| format!("stat import source: {error}"))?;
    if metadata.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "import source exceeds maximum size of {MAX_IMPORT_BYTES} bytes"
        ));
    }
    let bytes =
        fs::read(&options.source).map_err(|error| format!("open import source: {error}"))?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err(format!(
            "import source exceeds maximum size of {MAX_IMPORT_BYTES} bytes"
        ));
    }
    let csv_mapping = (!mapping.is_empty()).then_some(mapping);
    let entries = if format == Format::Csv
        || format == Format::Apple
        || format == Format::Chrome
        || format == Format::Firefox
    {
        // Reparse CSV with an explicit mapping only after the source has
        // passed the size and format checks. Other formats ignore CSV mapping.
        importer::parse_csv_profile(format, &bytes, csv_mapping.as_ref())
            .map_err(format_import_error)?
    } else {
        importer::parse(format, &bytes).map_err(format_import_error)?
    };

    // Parsing errors happen before Store::open and before any callback. This
    // preserves an existing vault when an input is malformed.
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| format!("open vault: {error}"))?;

    let mut imported = 0;
    let mut skipped = 0;
    for entry in entries {
        let path = importer::apply_prefix(&options.prefix, &entry.path);
        if path.is_empty() {
            skipped += 1;
            continue;
        }
        let exists = match store.get(&path, identity) {
            Ok(_) => true,
            Err(StoreError::EntryNotFound(_)) => false,
            Err(error) => return Err(format!("cannot check entry {path}: {error}")),
        };
        if exists && options.skip_existing {
            skipped += 1;
            continue;
        }
        if options.dry_run {
            imported += 1;
            continue;
        }
        let secret_type = entry.secret_type;
        let data = entry.data;
        if exists && options.overwrite {
            replace_fields(root, identity, &path, data)
                .map_err(|error| format!("cannot overwrite entry {path}: {error}"))?;
        } else {
            import_fields(root, identity, &path, data)
                .map_err(|error| format!("cannot write entry {path}: {error}"))?;
        }
        if let Some(secret_type) = secret_type.as_deref() {
            set_secret_type(root, identity, &path, secret_type)
                .map_err(|error| format!("cannot set secret metadata {path}: {error}"))?;
        }
        imported += 1;
    }
    Ok(ImportResult {
        format: format_name(format).to_owned(),
        imported,
        skipped,
    })
}

fn format_import_error(error: importer::ImportError) -> String {
    format!("parse import source: {error}")
}
