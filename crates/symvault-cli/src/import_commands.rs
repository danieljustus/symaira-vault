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
        self.line_bytes(text.as_bytes());
    }

    /// A line made of exact Go string bytes: an entry path that is not valid
    /// UTF-8 is echoed unchanged, like Go prints it.
    pub fn line_bytes(&mut self, bytes: &[u8]) {
        if !self.quiet {
            let _ = self.out.write_all(bytes);
            let _ = self.out.write_all(b"\n");
        }
    }
}

/// The failure of [`apply`], as the exact bytes Go would print: an entry path
/// that is not valid UTF-8 appears in the text unchanged, so the message is
/// not always a `String`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyError(pub Vec<u8>);

impl ApplyError {
    /// The message as text, with each invalid byte replaced.
    #[must_use]
    pub fn lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl From<String> for ApplyError {
    fn from(message: String) -> Self {
        Self(message.into_bytes())
    }
}

impl From<Vec<u8>> for ApplyError {
    fn from(message: Vec<u8>) -> Self {
        Self(message)
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.lossy())
    }
}

/// Concatenates byte fragments (Go builds these messages from raw strings).
fn bytes_of(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
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

/// Lexical `path.Clean` of a relative slash path (Go's `path.Join` cleans), on
/// the exact bytes: Go's `path` package never decodes the string.
fn go_path_clean(path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in path.split(|byte| *byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                if parts.last().is_some_and(|last| *last != b"..".as_slice()) {
                    parts.pop();
                } else {
                    parts.push(b"..");
                }
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        b".".to_vec()
    } else {
        parts.join(&b'/')
    }
}

/// Go's `importEntryPath`: the entry path trimmed of edge slashes and joined
/// to the prefix with `path.Join` semantics. The entry path is the exact Go
/// byte string.
fn import_entry_path(prefix: &str, entry_path: &[u8]) -> Vec<u8> {
    let start = entry_path
        .iter()
        .position(|byte| *byte != b'/')
        .unwrap_or(entry_path.len());
    let end = entry_path
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(start, |index| index + 1);
    let entry_path = &entry_path[start..end];
    if prefix.is_empty() {
        return entry_path.to_vec();
    }
    if entry_path.is_empty() {
        return prefix.as_bytes().to_vec();
    }
    go_path_clean(&bytes_of(&[prefix.as_bytes(), b"/", entry_path]))
}

/// Go's `validateRawEntryPath` diagnostic for an entry path the store rejected:
/// `entry path "<trimmed>": invalid path: <reason>`, with the reasons of
/// corekit's `fsutil.ValidatePath` in its check order. Every test is on ASCII
/// bytes, which Go's rune decoding also sees one by one inside an invalid
/// sequence, so the bytes need no decoding; only the quoting is byte-aware.
pub(crate) fn go_invalid_path_text(path: &[u8]) -> Option<Vec<u8>> {
    let trimmed = importer::go_trim_space(path);
    let quoted = importer::go_quote_bytes(trimmed);
    let normalized: Vec<u8> = trimmed
        .iter()
        .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
        .collect();
    let segments: Vec<&[u8]> = normalized.split(|byte| *byte == b'/').collect();
    let has = |wanted: &[u8]| segments.contains(&wanted);
    let reason = if trimmed.is_empty() {
        "path is empty".to_owned()
    } else if trimmed.contains(&0) {
        "path contains null byte".to_owned()
    } else if let Some(control) = trimmed.iter().find(|byte| **byte < 0x20) {
        format!("path contains control character 0x{control:02x}")
    } else if normalized.starts_with(b"/") {
        "path must be relative".to_owned()
    } else if has(b"..") {
        "path contains '..' segment".to_owned()
    } else if segments.len() > 1 && has(b"") {
        "path contains empty segment (double slash)".to_owned()
    } else if has(b".") {
        // A different Go check with its own wording and no `invalid path:`.
        return Some(
            format!("entry path {quoted} contains invalid path segment \".\"").into_bytes(),
        );
    } else {
        return None;
    };
    Some(format!("entry path {quoted}: invalid path: {reason}").into_bytes())
}

/// The text of a failed existence check. Go's vault service reports a read
/// failure as `cannot read entry <path>: <error>` and the CLI error then
/// appends its cause, so the store diagnostic appears twice.
fn check_error(root: &Path, path: &[u8], error: &StoreError) -> ApplyError {
    let detail: Vec<u8> = match error {
        StoreError::InvalidEntryPath(invalid) => go_invalid_path_text(invalid.as_bytes())
            .unwrap_or_else(|| error.to_string().into_bytes()),
        // Go stats the entry file inside the vault's entries root first, so a
        // name the file system refuses is reported by that stat.
        StoreError::Read { path: file, source } if is_name_too_long(source) => {
            // The store reports the canonical path; the root may be reached
            // through a symlinked ancestor (macOS `/var` -> `/private/var`).
            let canonical = root.canonicalize().ok();
            let relative = file
                .strip_prefix(root)
                .ok()
                .or_else(|| canonical.as_deref().and_then(|c| file.strip_prefix(c).ok()))
                .unwrap_or(file);
            let relative = relative.to_string_lossy().replace('\\', "/");
            format!("statat {relative}: file name too long").into_bytes()
        }
        other => other.to_string().into_bytes(),
    };
    check_failure(path, &detail)
}

fn check_failure(path: &[u8], detail: &[u8]) -> ApplyError {
    ApplyError(bytes_of(&[
        b"cannot check entry: cannot read entry ",
        path,
        b": ",
        detail,
        b": ",
        detail,
    ]))
}

fn is_name_too_long(error: &io::Error) -> bool {
    // ENAMETOOLONG is 63 on macOS and the BSDs, 36 on Linux.
    matches!(error.raw_os_error(), Some(63 | 36))
}

/// Whether the vault already holds an entry file for a path that is not valid
/// UTF-8 (`entries/<path>.age`, then the legacy root-level `<path>.age`).
/// Unix file names are byte strings, so the exact bytes name the file; a file
/// system that refuses such a name simply has no such entry.
fn raw_entry_exists(root: &Path, path: &[u8], pseudonymized: bool) -> bool {
    if pseudonymized {
        // Entry files are named by a hash of the path, never by its bytes.
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let file = |base: &Path| {
            let mut name = path.to_vec();
            name.extend_from_slice(b".age");
            fs::symlink_metadata(base.join(std::ffi::OsStr::from_bytes(&name)))
                .is_ok_and(|metadata| metadata.file_type().is_file())
        };
        file(&root.join("entries")) || file(root)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, path);
        false
    }
}

/// Go's message for `os.Open`/`os.Mkdir` failures, which uses the lower-case C
/// error text. `EILSEQ` is the error a file system returns for a name that is
/// not valid UTF-8; everything else goes through the shared Go wording.
fn go_os_reason(error: &io::Error) -> String {
    // EILSEQ is 92 on macOS and the BSDs, 84 on Linux.
    if matches!(error.raw_os_error(), Some(92 | 84)) {
        "illegal byte sequence".to_owned()
    } else {
        importer::go_io_reason(error)
    }
}

/// Creates the entry file of a path that is not valid UTF-8, the way Go's
/// writer does, and reports what happens.
///
/// Go creates the parent directories one by one, then a temporary
/// `<path>.age.tmp-<digits>` file inside `entries/`. macOS refuses a name that
/// is not valid UTF-8 (`EILSEQ`), so the import fails there with the exact
/// Go text, produced here by the same system calls. A file system that
/// accepts the name (Linux) gets Go's own persistence: the file is created
/// under the raw name while the manifest and index keys, which Go
/// JSON-encodes, collapse every invalid byte to U+FFFD. The native store
/// holds entry paths as text and cannot persist that state, so the probe is
/// undone and the import stops with an explicit refusal instead of writing a
/// different entry (ADR 0030).
fn create_entry_failure(root: &Path, path: &[u8], pseudonymized: bool) -> Vec<u8> {
    let refusal =
        |detail: &str| bytes_of(&[b"cannot create entry ", path, b": ", detail.as_bytes()]);
    if pseudonymized {
        // Go hashes the raw bytes into a hex file name, which every file
        // system accepts; the native store hashes text only.
        return refusal(
            "entry path is not valid UTF-8; the native store cannot pseudonymize such a path",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        let entries = root.join("entries");
        let failure = |action: &str, target: &Path, error: &io::Error| {
            let reason = go_os_reason(error);
            let described = bytes_of(&[
                action.as_bytes(),
                b" ",
                target.as_os_str().as_bytes(),
                b": ",
                reason.as_bytes(),
            ]);
            bytes_of(&[
                b"cannot create entry ",
                path,
                b": ",
                &described,
                b": ",
                &described,
            ])
        };
        let mut created: Vec<PathBuf> = Vec::new();
        let undo = |created: &[PathBuf]| {
            for directory in created.iter().rev() {
                let _ = fs::remove_dir(directory);
            }
        };
        let mut components: Vec<&[u8]> = path.split(|byte| *byte == b'/').collect();
        let file_name = components.pop().unwrap_or_default();
        let mut directory = entries.clone();
        for component in components {
            directory = directory.join(std::ffi::OsStr::from_bytes(component));
            match fs::create_dir(&directory) {
                Ok(()) => created.push(directory.clone()),
                Err(error)
                    if error.kind() == io::ErrorKind::AlreadyExists && directory.is_dir() => {}
                Err(error) => {
                    undo(&created);
                    return failure("mkdir", &directory, &error);
                }
            }
        }
        let mut random = [0_u8; 4];
        let suffix = match getrandom::fill(&mut random) {
            Ok(()) => u32::from_le_bytes(random),
            Err(_) => 0,
        };
        let mut name = file_name.to_vec();
        name.extend_from_slice(format!(".age.tmp-{suffix}").as_bytes());
        let temporary = directory.join(std::ffi::OsStr::from_bytes(&name));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => {
                drop(file);
                let _ = fs::remove_file(&temporary);
                undo(&created);
                refusal(
                    "entry path is not valid UTF-8 and this file system accepts such a name; the native store only persists UTF-8 entry paths",
                )
            }
            Err(error) => {
                undo(&created);
                failure("open", &temporary, &error)
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        refusal("entry path is not valid UTF-8; the native store only persists UTF-8 entry paths")
    }
}

/// Writes the parsed entries into the vault, applying prefix, skip-existing,
/// overwrite and dry-run per entry. Progress goes through `reporter`.
///
/// The write callbacks receive the exact Go byte length of every string value
/// whose text differs in length (Go's field limit counts raw bytes).
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
) -> Result<ImportResult, ApplyError>
where
    ImportFields: FnMut(
        &Path,
        &Identity,
        &str,
        BTreeMap<String, Value>,
        &BTreeMap<String, usize>,
    ) -> Result<(), String>,
    ReplaceFields: FnMut(
        &Path,
        &Identity,
        &str,
        BTreeMap<String, Value>,
        &BTreeMap<String, usize>,
    ) -> Result<(), String>,
    SetSecretType: FnMut(&Path, &Identity, &str, &str) -> Result<(), String>,
{
    let store = symvault_store::Store::open_with_legacy_migration(root, identity)
        .map_err(|error| format!("open vault: {error}"))?;
    let reader = store.read_session(identity);
    let pseudonymized = store.config().pseudonymize_paths;
    let mut imported = 0;
    let mut skipped = 0;
    for entry in prepared.entries {
        let path = import_entry_path(&prepared.prefix, entry.path_bytes());
        if path.is_empty() {
            skipped += 1;
            reporter.line("Skipped entry with empty path");
            continue;
        }
        // A path that is valid UTF-8 goes through the store; any other path
        // is a Go byte string the store cannot represent, so it is checked
        // and written on the exact bytes.
        let text = std::str::from_utf8(&path).ok();
        let exists = match text {
            Some(text) => match reader.get(text) {
                Ok(_) => true,
                Err(StoreError::EntryNotFound(_)) => false,
                Err(error) => return Err(check_error(root, &path, &error)),
            },
            None => {
                if let Some(detail) = go_invalid_path_text(&path) {
                    return Err(check_failure(&path, &detail));
                }
                raw_entry_exists(root, &path, pseudonymized)
            }
        };
        if exists && options.skip_existing {
            skipped += 1;
            reporter.line_bytes(&bytes_of(&[b"Skipped existing: ", &path]));
            continue;
        }
        if options.dry_run {
            reporter.line_bytes(&bytes_of(&[b"Would import: ", &path]));
            imported += 1;
            continue;
        }
        let secret_type = entry.secret_type;
        let data = entry.data;
        let Some(text) = text else {
            // Go checks the field lengths before it touches the file system.
            let lengths = entry.raw_value_len;
            crate::write_commands::validate_field_lengths(&data, &lengths)
                .map_err(|error| format!("cannot write entry: {error}"))?;
            let failure = create_entry_failure(root, &path, pseudonymized);
            return Err(ApplyError(bytes_of(&[b"cannot write entry: ", &failure])));
        };
        if exists && options.overwrite {
            replace_fields(root, identity, text, data, &entry.raw_value_len)
                .map_err(|error| format!("cannot overwrite entry: {error}"))?;
        } else {
            import_fields(root, identity, text, data, &entry.raw_value_len)
                .map_err(|error| format!("cannot write entry: {error}"))?;
        }
        if let Some(secret_type) = secret_type.as_deref() {
            set_secret_type(root, identity, text, secret_type)
                .map_err(|error| format!("cannot set secret metadata: {error}"))?;
        }
        reporter.line(&format!("Imported: {text}"));
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
    ImportFields: FnMut(
        &Path,
        &Identity,
        &str,
        BTreeMap<String, Value>,
        &BTreeMap<String, usize>,
    ) -> Result<(), String>,
    ReplaceFields: FnMut(
        &Path,
        &Identity,
        &str,
        BTreeMap<String, Value>,
        &BTreeMap<String, usize>,
    ) -> Result<(), String>,
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
    .map_err(|error| error.lossy())
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
            assert_eq!(go_path_clean(input.as_bytes()), want.as_bytes(), "{input}");
        }
    }

    #[test]
    fn invalid_path_text_quotes_raw_bytes_like_go() {
        // Recorded from the Go oracle (`invalid-bytes-dry-run-control-char`):
        // the message quotes the trimmed path with strconv.Quote semantics,
        // which spells an invalid byte as `\xff`.
        assert_eq!(
            go_invalid_path_text(b"a\xff\x01b").unwrap(),
            br#"entry path "a\xff\x01b": invalid path: path contains control character 0x01"#
        );
        assert_eq!(
            go_invalid_path_text(b"x//\xff").unwrap(),
            br#"entry path "x//\xff": invalid path: path contains empty segment (double slash)"#
        );
        assert!(go_invalid_path_text(b"\xff\x7fx").is_none());
    }

    #[test]
    fn creating_an_invalid_path_never_leaves_the_probe_behind() {
        let root = tempfile::tempdir().expect("vault root");
        std::fs::create_dir(root.path().join("entries")).expect("entries");
        // macOS refuses the name (EILSEQ, Go's text); a file system that
        // accepts it gets the explicit refusal. Both start the same way and
        // neither leaves a directory or a temporary file behind.
        let message = create_entry_failure(root.path(), b"a/b\xff/c", false);
        assert!(
            message.starts_with(b"cannot create entry a/b\xff/c: "),
            "{}",
            String::from_utf8_lossy(&message)
        );
        let leftovers: Vec<_> = std::fs::read_dir(root.path().join("entries"))
            .expect("entries")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let message = create_entry_failure(root.path(), b"\xff", true);
        assert_eq!(
            message,
            b"cannot create entry \xff: entry path is not valid UTF-8; the native store cannot pseudonymize such a path"
        );
        assert!(!raw_entry_exists(root.path(), b"\xff", true));
        assert!(!raw_entry_exists(root.path(), b"\xff", false));
    }

    #[test]
    fn entry_path_joins_like_go() {
        assert_eq!(import_entry_path("", b"/a/b/"), b"a/b");
        assert_eq!(import_entry_path("p", b""), b"p");
        assert_eq!(import_entry_path("a/../b", b"x"), b"b/x");
        assert_eq!(import_entry_path("..", b"x"), b"../x");
        assert_eq!(import_entry_path(".", b"x"), b"x");
        // Invalid bytes pass through the join untouched.
        assert_eq!(import_entry_path("p", b"//\xff/x//"), b"p/\xff/x");
        assert_eq!(import_entry_path("", b"/\xff\xfe/"), b"\xff\xfe");
    }
}
