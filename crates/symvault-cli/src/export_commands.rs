//! Vault entry export for the user-facing CLI.
//!
//! The dispatcher supplies confirmation, unlock, and audit callbacks. Keeping
//! those boundaries injectable lets the export contract be tested without a
//! real keychain while preserving the production order: warn and confirm,
//! unlock, read entries, write output, then record the audit event.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

use symvault_crypto::Identity;
use symvault_sync::export::{self, ExportEntry};

use symvault_store::audit::{self, LogEntry, RotationConfig};
use symvault_sync::GoTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportFormat {
    Csv,
    Json,
}

impl ExportFormat {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            other => Err(format!("unsupported export format: {other}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportOptions {
    pub format: ExportFormat,
    pub mapping: BTreeMap<String, String>,
    pub output: Option<std::path::PathBuf>,
    pub yes: bool,
    pub quiet: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportResult {
    pub entries: usize,
    pub wrote_output: bool,
    pub canceled: bool,
}

/// Records the successful export through the production Go-compatible keyring
/// adapter. The CLI's runtime factory owns the native keyring and fallback
/// policy; this child module only supplies the audit event.
pub(crate) fn audit_export(
    vault: &Path,
    keyring: &dyn symvault_core::session::Keyring,
) -> Result<(), String> {
    let mut logger =
        audit::open_with_keyring("symvault", vault, keyring, RotationConfig::default())
            .map_err(|error| format!("open audit log: {error}"))?;
    logger
        .append(LogEntry {
            timestamp: go_timestamp_seconds(),
            agent: "symvault".to_owned(),
            action: "export".to_owned(),
            ok: true,
            ..LogEntry::default()
        })
        .map_err(|error| format!("write audit log: {error}"))
}

pub(crate) fn go_timestamp_seconds() -> String {
    let value = GoTime::now().to_rfc3339_nano();
    value
        .find('.')
        .map(|index| {
            let suffix = value[index..]
                .find('Z')
                .map_or(value.len(), |offset| index + offset);
            format!("{}{}", &value[..index], &value[suffix..])
        })
        .unwrap_or(value)
}

/// Parses Go's `field=column,field2=column2` mapping syntax.
pub fn parse_mapping(value: &str) -> Result<BTreeMap<String, String>, String> {
    if value.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut mapping = BTreeMap::new();
    for raw_pair in value.split(',') {
        let pair = raw_pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (field, column) = pair
            .split_once('=')
            .ok_or_else(|| format!("invalid mapping pair: {pair:?}"))?;
        let field = field.trim();
        let column = column.trim();
        if field.is_empty() || column.is_empty() {
            return Err(format!("empty field or column in mapping: {pair:?}"));
        }
        mapping.insert(field.to_owned(), column.to_owned());
    }
    Ok(mapping)
}

/// Renders the same JSON or CSV byte contract as the sync exporter.
///
/// The shared formatters own mapping order and attachment handling.
pub fn render(
    format: ExportFormat,
    entries: &[ExportEntry],
    mapping: &BTreeMap<String, String>,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    match format {
        ExportFormat::Json => export::json_with_mapping(&mut output, entries, mapping),
        ExportFormat::Csv => export::csv_with_mapping(&mut output, entries, mapping, None),
    }
    .map_err(|error| error.to_string())?;
    Ok(output)
}

/// Runs export after the dispatcher has supplied the security-sensitive
/// callbacks. `confirm` is called before `unlock`, and `audit` is called only
/// after successful output. Audit failure follows Go: it is reported as a
/// warning and does not discard an already completed export.
pub fn run_export<Confirm, Unlock, Audit>(
    vault: &Path,
    options: &ExportOptions,
    confirm: Confirm,
    unlock: Unlock,
    audit: Audit,
) -> Result<ExportResult, String>
where
    Confirm: FnOnce() -> Result<bool, String>,
    Unlock: FnOnce() -> Result<Identity, String>,
    Audit: FnOnce(&Path, usize) -> Result<(), String>,
{
    const WARNING: &str =
        "WARNING: Vault export produces unencrypted output. All secrets will be in plaintext.";
    if !options.yes || !options.quiet {
        eprintln!("{WARNING}");
    }
    if !options.yes && !confirm()? {
        eprintln!("Export canceled.");
        return Ok(ExportResult {
            entries: 0,
            wrote_output: false,
            canceled: true,
        });
    }

    let identity = unlock().map_err(|error| format!("unlock vault: {error}"))?;
    let store = symvault_store::Store::open_with_legacy_migration(vault, &identity)
        .map_err(|error| format!("open vault: {error}"))?;
    let paths = store
        .list(&identity)
        .map_err(|error| format!("list entries: {error}"))?;
    if paths.is_empty() {
        return Ok(ExportResult {
            entries: 0,
            wrote_output: false,
            canceled: false,
        });
    }
    let entries = paths
        .iter()
        .map(|path| {
            let entry = store
                .get(path, &identity)
                .map_err(|error| format!("read entry {path}: {error}"))?;
            Ok(ExportEntry {
                path: path.clone(),
                data: entry.data,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if options.format == ExportFormat::Csv {
        for entry in &entries {
            if has_attachment(&entry.data) {
                eprintln!(
                    "attachment data omitted for entry {}; use --format json for a lossless export",
                    entry.path
                );
            }
        }
    }
    let output = render(options.format, &entries, &options.mapping)?;
    write_output(options.output.as_deref(), &output)?;
    if let Err(error) = audit(vault, entries.len()) {
        eprintln!("Warning: audit log write failed: {error}");
    }
    Ok(ExportResult {
        entries: entries.len(),
        wrote_output: true,
        canceled: false,
    })
}

fn has_attachment(data: &BTreeMap<String, serde_json::Value>) -> bool {
    data.keys().any(|key| {
        key.starts_with("file_b64_") || matches!(key.as_str(), "chunk_count" | "chunk_size")
    })
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<(), String> {
    match path {
        None => io::stdout()
            .write_all(bytes)
            .map_err(|error| format!("write export: {error}")),
        Some(path) => {
            let mut options = OpenOptions::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .map_err(|error| format!("create output file: {error}"))?;
            set_private_permissions(&file)?;
            file.write_all(bytes)
                .map_err(|error| format!("write output file: {error}"))?;
            file.flush()
                .map_err(|error| format!("flush output file: {error}"))
        }
    }
}

fn set_private_permissions(file: &fs::File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file
            .metadata()
            .map_err(|error| format!("inspect output file: {error}"))?
            .permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .map_err(|error| format!("protect output file: {error}"))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entries() -> Vec<ExportEntry> {
        vec![ExportEntry {
            path: "work/example".into(),
            data: BTreeMap::from([
                ("password".into(), json!("secret")),
                ("username".into(), json!("alice")),
                ("file_b64_0001".into(), json!("ignored-in-csv")),
            ]),
        }]
    }

    #[test]
    fn mapping_matches_go_whitespace_and_error_rules() {
        assert_eq!(
            parse_mapping(" title = Name, username=Login, ").unwrap(),
            BTreeMap::from([
                (String::from("title"), String::from("Name")),
                (String::from("username"), String::from("Login"))
            ])
        );
        assert!(parse_mapping("title").is_err());
        assert!(parse_mapping("=Name").is_err());
        assert!(parse_mapping("title=").is_err());
    }

    #[test]
    fn json_and_csv_apply_mapping_and_csv_omits_attachments() {
        let mapping = BTreeMap::from([
            (String::from("username"), String::from("user")),
            (String::from("password"), String::from("secret")),
        ]);
        let json =
            String::from_utf8(render(ExportFormat::Json, &entries(), &mapping).unwrap()).unwrap();
        assert!(json.contains("\"user\": \"alice\""));
        assert!(json.contains("file_b64_0001"));
        let csv =
            String::from_utf8(render(ExportFormat::Csv, &entries(), &mapping).unwrap()).unwrap();
        assert!(csv.starts_with("path,secret,user\n"));
        assert!(!csv.contains("file_b64_0001"));
    }

    #[test]
    fn empty_render_matches_go() {
        assert_eq!(
            render(ExportFormat::Json, &[], &BTreeMap::new()).unwrap(),
            b"[]"
        );
        assert!(
            render(ExportFormat::Csv, &[], &BTreeMap::new())
                .unwrap()
                .is_empty()
        );
    }
}
