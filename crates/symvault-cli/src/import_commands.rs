//! Import external password-manager exports into an encrypted vault.
//!
//! The command follows `cmd/admin/import.go` step for step so that its
//! diagnostics, progress lines and check order are byte-identical:
//!
//! 1. [`prepare`] runs everything Go does before it opens the vault: format
//!    resolution and CSV header sniffing, the dry-run report, flag conflicts,
//!    the quarantine ID line, mapping validation, opening and size-checking
//!    the source, and parsing it. A malformed source therefore fails before
//!    the vault is touched, and a failed parse never invokes a write callback.
//! 2. [`apply`] walks the parsed entries inside the opened vault and prints
//!    one progress line per entry.
//!
//! The dispatcher supplies the production write and replacement callbacks,
//! which keeps this module usable with an in-memory test backend and leaves
//! session, Git, and audit policy at the CLI boundary. Pinned by
//! `tests/import_command_contract.rs` (IO-001).

use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use symvault_crypto::Identity;
use symvault_store::StoreError;
use symvault_sync::importer::{self, Format, ImportError};

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
    /// The batch ID of a `--quarantine` import; `Some` selects quarantine mode.
    pub quarantine_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportResult {
    pub format: String,
    pub imported: usize,
    pub skipped: usize,
}

/// A source that passed every pre-vault check of the Go command.
#[derive(Debug)]
pub struct Prepared {
    pub format: Format,
    pub entries: Vec<importer::ImportedEntry>,
    /// Go's `options.Prefix`: the trimmed `--prefix`, or the quarantine path.
    pub prefix: String,
}

/// Progress output of the command; every line is suppressed by `--quiet`.
pub struct Reporter<'a> {
    out: &'a mut dyn Write,
    quiet: bool,
}

impl<'a> Reporter<'a> {
    pub fn new(out: &'a mut dyn Write, quiet: bool) -> Self {
        Self { out, quiet }
    }

    pub fn line(&mut self, text: &str) {
        if !self.quiet {
            let _ = writeln!(self.out, "{text}");
        }
    }
}

/// Go's `filepath.Ext`: the suffix from the final dot of the final path
/// element, empty when there is none (so a dotfile `.csv` has extension `.csv`).
fn go_ext(path: &Path) -> String {
    let text = path.to_string_lossy();
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    let base_start = text.rfind(separators).map_or(0, |index| index + 1);
    let base = &text[base_start..];
    base.rfind('.')
        .map_or("", |index| &base[index..])
        .to_owned()
}

/// The format name `detectFormatFromExt` derives from a source extension.
/// `.json` and `.yaml` yield names the command does not support, which the
/// caller reports as `unsupported import format`.
fn detect_format_from_ext(source: &Path) -> Result<String, String> {
    let ext = go_ext(source).to_lowercase();
    match ext.as_str() {
        ".csv" => Ok("csv".to_owned()),
        ".zip" => Ok("cxf".to_owned()),
        ".json" => Ok("json".to_owned()),
        ".yaml" | ".yml" => Ok("yaml".to_owned()),
        _ => Err(format!(
            "cannot detect format from file extension {}; use --format to specify",
            symvault_core::go_quote(&ext)
        )),
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

fn is_csv_format(format: Format) -> bool {
    matches!(
        format,
        Format::Csv | Format::Apple | Format::Chrome | Format::Firefox
    )
}

/// Go's `sniffCSVProfile`: the built-in profile that the header row of a
/// `.csv` source matches, or the generic format when it matches none or the
/// source cannot be read.
fn sniff_csv_profile(source: &Path) -> Format {
    let Ok(file) = fs::File::open(source) else {
        return Format::Csv;
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_IMPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Format::Csv;
    }
    match importer::csv_header_record(&bytes) {
        Some(header) => importer::detect_csv_profile(&header),
        None => Format::Csv,
    }
}

fn parse_user_mapping(mapping: &str) -> Result<BTreeMap<String, String>, String> {
    crate::export_commands::parse_mapping(mapping)
}

/// `reportDryRunImport`: the resolved format and, for CSV imports, the
/// field to column mapping in effect, sorted as `field=column` strings.
fn report_dry_run(
    format: Format,
    mapping: &str,
    reporter: &mut Reporter<'_>,
) -> Result<(), String> {
    reporter.line(&format!("Import format: {}", format_name(format)));
    if !is_csv_format(format) {
        return Ok(());
    }
    let user = if mapping.is_empty() {
        None
    } else {
        Some(
            parse_user_mapping(mapping)
                .map_err(|error| format!("invalid CSV mapping: parse csv mapping: {error}"))?,
        )
    };
    let effective = importer::csv_effective_mapping(format, user.as_ref());
    let mut parts: Vec<String> = effective
        .iter()
        .map(|(field, column)| format!("{field}={column}"))
        .collect();
    parts.sort();
    reporter.line(&format!("CSV mapping: {}", parts.join(", ")));
    Ok(())
}

/// The text of a failed read of the opened source, per the Go parser that
/// would have consumed it.
fn read_error(format: Format, source: &Path, error: &io::Error) -> String {
    let reason = importer::go_io_reason(error);
    let path = source.display();
    match format {
        Format::Csv | Format::Apple | Format::Chrome | Format::Firefox => {
            format!("parse import source: read csv header: read {path}: {reason}")
        }
        Format::Bitwarden => {
            format!("parse import source: parse bitwarden export: read {path}: {reason}")
        }
        Format::OnePassword | Format::Cxf | Format::Pass => {
            format!("parse import source: read import source: read {path}: {reason}")
        }
    }
}

fn format_import_error(error: ImportError) -> String {
    let text = match error {
        ImportError::Parse(message) | ImportError::Decode(message) => message,
        other => other.to_string(),
    };
    format!("parse import source: {text}")
}

/// Everything the Go command does before it opens the vault, in Go's order.
pub fn prepare(options: &ImportOptions, reporter: &mut Reporter<'_>) -> Result<Prepared, String> {
    // An empty --format is the same as none: Go compares the raw flag value.
    let explicit = options.format.as_deref().filter(|value| !value.is_empty());
    let name = match explicit {
        Some(value) => value.trim().to_lowercase(),
        None => detect_format_from_ext(&options.source)?,
    };
    let mut format = importer::format_from_name(&name).map_err(|error| error.to_string())?;

    // Sniff `.csv` sources against the built-in profiles unless --format was
    // given. A detected profile is announced on stdout.
    if format == Format::Csv && explicit.is_none() {
        let profile = sniff_csv_profile(&options.source);
        if profile != Format::Csv {
            if let Some(name) = importer::csv_profile_name(profile) {
                reporter.line(&format!("Detected {name} CSV export from header row"));
            }
            format = profile;
        }
    }

    if options.dry_run {
        report_dry_run(format, &options.mapping, reporter)?;
    }
    if options.skip_existing && options.overwrite {
        return Err("--skip-existing and --overwrite cannot be used together".into());
    }
    if options.quarantine_id.is_some() && !options.prefix.is_empty() {
        return Err("--quarantine and --prefix cannot be used together".into());
    }
    let prefix = match options.quarantine_id.as_deref() {
        Some(id) => {
            reporter.line(&format!("Quarantine import ID: {id}"));
            format!("quarantine/{id}")
        }
        None => options.prefix.trim_matches('/').to_owned(),
    };

    let user_mapping = parse_user_mapping(&options.mapping)
        .map_err(|error| format!("invalid CSV mapping: {error}"))?;
    // Go keys the user mapping on the flag string, not on its pair count: a
    // mapping of "," maps nothing instead of falling back to the defaults.
    let user_mapping = (!options.mapping.is_empty()).then_some(user_mapping);

    let path = options.source.display();
    let mut file = fs::File::open(&options.source).map_err(|error| {
        format!(
            "open import source: open {path}: {}",
            importer::go_io_reason(&error)
        )
    })?;
    let size = file
        .metadata()
        .map_err(|error| {
            format!(
                "stat import source: stat {path}: {}",
                importer::go_io_reason(&error)
            )
        })?
        .len();
    if size > MAX_IMPORT_BYTES {
        return Err(format!(
            "import source exceeds maximum size of {MAX_IMPORT_BYTES} bytes"
        ));
    }

    let entries = if format == Format::Pass {
        // A pass store is a directory tree: the parser walks the path itself.
        importer::import_pass(&options.source).map_err(format_import_error)?
    } else {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| read_error(format, &options.source, &error))?;
        let parsed = match format {
            Format::Csv | Format::Apple | Format::Chrome | Format::Firefox => {
                importer::parse_csv_profile(format, &bytes, user_mapping.as_ref())
            }
            Format::Bitwarden => importer::parse_bitwarden(&bytes),
            Format::OnePassword | Format::Cxf => {
                if bytes.len() as u64 >= MAX_IMPORT_BYTES {
                    // Go's archive importers read through a limit reader and
                    // reject a source that fills it.
                    return Err(format!(
                        "parse import source: import source exceeds maximum size of {MAX_IMPORT_BYTES} bytes"
                    ));
                }
                if format == Format::Cxf {
                    importer::parse_cxf(&bytes)
                } else {
                    importer::parse_1pux(&bytes)
                }
            }
            Format::Pass => unreachable!("handled above"),
        };
        parsed.map_err(format_import_error)?
    };
    Ok(Prepared {
        format,
        entries,
        prefix,
    })
}

/// Lexical `path.Clean` of a relative slash path (Go's `path.Join` cleans).
fn go_path_clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
}

/// Go's `importEntryPath`: the entry path trimmed of edge slashes and joined
/// to the prefix with `path.Join` semantics.
fn import_entry_path(prefix: &str, entry_path: &str) -> String {
    let entry_path = entry_path.trim_matches('/');
    if prefix.is_empty() {
        return entry_path.to_owned();
    }
    if entry_path.is_empty() {
        return prefix.to_owned();
    }
    go_path_clean(&format!("{prefix}/{entry_path}"))
}

/// Go's `validateRawEntryPath` diagnostic for an entry path the store rejected:
/// `entry path "<trimmed>": invalid path: <reason>`, with the reasons of
/// corekit's `fsutil.ValidatePath` in its check order.
fn go_invalid_path_text(path: &str) -> Option<String> {
    let trimmed = path.trim();
    let quoted = symvault_core::go_quote(trimmed);
    let normalized = trimmed.replace('\\', "/");
    let segments: Vec<&str> = normalized.split('/').collect();
    let reason = if trimmed.is_empty() {
        "path is empty".to_owned()
    } else if trimmed.contains('\0') {
        "path contains null byte".to_owned()
    } else if let Some(control) = trimmed.chars().find(|c| u32::from(*c) < 0x20) {
        format!(
            "path contains control character 0x{:02x}",
            u32::from(control)
        )
    } else if normalized.starts_with('/') {
        "path must be relative".to_owned()
    } else if segments.contains(&"..") {
        "path contains '..' segment".to_owned()
    } else if segments.len() > 1 && segments.contains(&"") {
        "path contains empty segment (double slash)".to_owned()
    } else if segments.contains(&".") {
        // A different Go check with its own wording and no `invalid path:`.
        return Some(format!(
            "entry path {quoted} contains invalid path segment \".\""
        ));
    } else {
        return None;
    };
    Some(format!("entry path {quoted}: invalid path: {reason}"))
}

/// The text of a failed existence check. Go's vault service reports a read
/// failure as `cannot read entry <path>: <error>` and the CLI error then
/// appends its cause, so the store diagnostic appears twice.
fn check_error(root: &Path, path: &str, error: &StoreError) -> String {
    let detail = match error {
        StoreError::InvalidEntryPath(invalid) => {
            go_invalid_path_text(invalid).unwrap_or_else(|| error.to_string())
        }
        // Go stats the entry file inside the vault's entries root first, so a
        // name the file system refuses is reported by that stat.
        StoreError::Read { path: file, source } if is_name_too_long(source) => {
            let relative = file.strip_prefix(root).unwrap_or(file);
            let relative = relative.to_string_lossy().replace('\\', "/");
            format!("statat {relative}: file name too long")
        }
        other => other.to_string(),
    };
    format!("cannot check entry: cannot read entry {path}: {detail}: {detail}")
}

fn is_name_too_long(error: &io::Error) -> bool {
    // ENAMETOOLONG is 63 on macOS and the BSDs, 36 on Linux.
    matches!(error.raw_os_error(), Some(63 | 36))
}

/// Writes the parsed entries into the vault, applying prefix, skip-existing,
/// overwrite and dry-run per entry. Progress goes through `reporter`.
#[allow(clippy::too_many_arguments)] // The three callbacks are the write boundary.
pub fn apply<ImportFields, ReplaceFields, SetSecretType>(
    root: &Path,
    identity: &Identity,
    prepared: Prepared,
    options: &ImportOptions,
    reporter: &mut Reporter<'_>,
    mut import_fields: ImportFields,
    mut replace_fields: ReplaceFields,
    mut set_secret_type: SetSecretType,
) -> Result<ImportResult, String>
where
    ImportFields: FnMut(&Path, &Identity, &str, BTreeMap<String, Value>) -> Result<(), String>,
    ReplaceFields: FnMut(&Path, &Identity, &str, BTreeMap<String, Value>) -> Result<(), String>,
    SetSecretType: FnMut(&Path, &Identity, &str, &str) -> Result<(), String>,
{
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| format!("open vault: {error}"))?;
    let reader = store.read_session(identity);
    let mut imported = 0;
    let mut skipped = 0;
    for entry in prepared.entries {
        let path = import_entry_path(&prepared.prefix, &entry.path);
        if path.is_empty() {
            skipped += 1;
            reporter.line("Skipped entry with empty path");
            continue;
        }
        let exists = match reader.get(&path) {
            Ok(_) => true,
            Err(StoreError::EntryNotFound(_)) => false,
            Err(error) => return Err(check_error(root, &path, &error)),
        };
        if exists && options.skip_existing {
            skipped += 1;
            reporter.line(&format!("Skipped existing: {path}"));
            continue;
        }
        if options.dry_run {
            reporter.line(&format!("Would import: {path}"));
            imported += 1;
            continue;
        }
        let secret_type = entry.secret_type;
        let data = entry.data;
        if exists && options.overwrite {
            replace_fields(root, identity, &path, data)
                .map_err(|error| format!("cannot overwrite entry: {error}"))?;
        } else {
            import_fields(root, identity, &path, data)
                .map_err(|error| format!("cannot write entry: {error}"))?;
        }
        if let Some(secret_type) = secret_type.as_deref() {
            set_secret_type(root, identity, &path, secret_type)
                .map_err(|error| format!("cannot set secret metadata: {error}"))?;
        }
        reporter.line(&format!("Imported: {path}"));
        imported += 1;
    }
    Ok(ImportResult {
        format: format_name(prepared.format).to_owned(),
        imported,
        skipped,
    })
}

/// Parses and applies an import without progress output. `import_fields` and
/// `replace_fields` are supplied by the CLI's write boundary so imports use the
/// same encrypted-store and Git lifecycle as ordinary entry mutations.
#[allow(dead_code)] // The CLI drives prepare/apply directly; tests use this wrapper.
pub fn run_import<ImportFields, ReplaceFields, SetSecretType>(
    root: &Path,
    identity: &Identity,
    options: &ImportOptions,
    import_fields: ImportFields,
    replace_fields: ReplaceFields,
    set_secret_type: SetSecretType,
) -> Result<ImportResult, String>
where
    ImportFields: FnMut(&Path, &Identity, &str, BTreeMap<String, Value>) -> Result<(), String>,
    ReplaceFields: FnMut(&Path, &Identity, &str, BTreeMap<String, Value>) -> Result<(), String>,
    SetSecretType: FnMut(&Path, &Identity, &str, &str) -> Result<(), String>,
{
    let mut sink = io::sink();
    let mut reporter = Reporter::new(&mut sink, true);
    // Parsing errors happen before the vault is opened and before any
    // callback, which preserves an existing vault when an input is malformed.
    let prepared = prepare(options, &mut reporter)?;
    apply(
        root,
        identity,
        prepared,
        options,
        &mut reporter,
        import_fields,
        replace_fields,
        set_secret_type,
    )
}

pub fn generate_import_id() -> Result<String, String> {
    let date = time::OffsetDateTime::now_utc().date();
    let mut random = [0_u8; 4];
    getrandom::fill(&mut random).map_err(|error| format!("generate import ID: {error}"))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "import-{:04}{:02}{:02}-{suffix}",
        date.year(),
        u8::from(date.month()),
        date.day()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_matches_go_filepath_ext() {
        for (path, ext) in [
            ("a.csv", ".csv"),
            (".csv", ".csv"),
            ("data.", "."),
            ("data", ""),
            ("dir.csv/inner", ""),
            ("a.tar.zip", ".zip"),
            ("/abs/dir.d/file", ""),
        ] {
            assert_eq!(go_ext(Path::new(path)), ext, "{path}");
        }
    }

    #[test]
    fn path_clean_matches_go() {
        for (input, want) in [
            ("a/b", "a/b"),
            ("a//b", "a/b"),
            ("a/../b", "b"),
            ("../b", "../b"),
            ("./a", "a"),
            ("a/./b/", "a/b"),
            ("a/../..", ".."),
            ("a/..", "."),
        ] {
            assert_eq!(go_path_clean(input), want, "{input}");
        }
    }

    #[test]
    fn entry_path_joins_like_go() {
        assert_eq!(import_entry_path("", "/a/b/"), "a/b");
        assert_eq!(import_entry_path("p", ""), "p");
        assert_eq!(import_entry_path("a/../b", "x"), "b/x");
        assert_eq!(import_entry_path("..", "x"), "../x");
        assert_eq!(import_entry_path(".", "x"), "x");
    }
}
