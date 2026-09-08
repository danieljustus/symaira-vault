//! Keyed JSONL audit chains and local rotation/export primitives.
//!
//! The wire format intentionally follows `internal/audit`: fields are serialized
//! in declaration order, empty optional fields are omitted, and each HMAC is
//! `HMAC-SHA256(key, previous_hmac || canonical_json(entry_without_hmac))`.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const HMAC_KEY_BYTES: usize = 32;
const KEY_FILE: &str = "audit-hmac-key";
const LOG_PREFIX: &str = "audit-";
const LOG_SUFFIX: &str = ".log";
const ROTATED_MARKER: &str = ".rotated.";

/// A structured audit event. Its JSON field names and omission rules match Go.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct LogEntry {
    #[serde(rename = "ts")]
    pub timestamp: String,
    pub agent: String,
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub field: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub transport: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub reason: String,
    #[serde(rename = "share_id", skip_serializing_if = "String::is_empty", default)]
    pub share_id: String,
    #[serde(
        rename = "from_agent",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub from_agent: String,
    #[serde(rename = "to_agent", skip_serializing_if = "String::is_empty", default)]
    pub to_agent: String,
    #[serde(
        rename = "share_action",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub share_action: String,
    #[serde(rename = "dur_ms", skip_serializing_if = "is_zero_i64", default)]
    pub dur_ms: i64,
    #[serde(rename = "token_id", skip_serializing_if = "String::is_empty", default)]
    pub token_id: String,
    #[serde(rename = "req_id", skip_serializing_if = "String::is_empty", default)]
    pub request_id: String,
    #[serde(rename = "sess_id", skip_serializing_if = "String::is_empty", default)]
    pub session_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub kid: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hmac: String,
    #[serde(
        rename = "argv_hash",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub argv_hash: String,
    pub ok: bool,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

/// Non-sensitive result of chain verification.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub total: usize,
    pub verified: usize,
    pub legacy: usize,
    pub tampered: usize,
    pub unverifiable: usize,
    pub first_bad_idx: isize,
}

/// A key whose formatting never reveals its bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct AuditKey(Vec<u8>);

impl AuditKey {
    /// Creates a key, rejecting lengths that cannot be used by the Go keystore.
    pub fn new(bytes: impl AsRef<[u8]>) -> io::Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != HMAC_KEY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HMAC key must be exactly 32 bytes",
            ));
        }
        Ok(Self(bytes.to_vec()))
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for AuditKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditKey(<redacted>)")
    }
}
impl fmt::Display for AuditKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Drop for AuditKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Returns the eight-hex-character key-generation ID used by Go (`kid`).
#[must_use]
pub fn key_fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Returns Go's canonical JSON bytes: HMAC is omitted by `omitempty`.
#[must_use]
pub fn canonical_json(entry: &LogEntry) -> Vec<u8> {
    let mut without_hmac = entry.clone();
    without_hmac.hmac.clear();
    serde_json::to_vec(&without_hmac).unwrap_or_default()
}

/// Computes one Go-compatible chain HMAC.
#[must_use]
pub fn compute_hmac(key: &[u8], previous: &[u8], entry: &LogEntry) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts every key length");
    mac.update(previous);
    mac.update(&canonical_json(entry));
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_entries(data: &[u8]) -> Vec<LogEntry> {
    BufReader::new(data)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| {
            let line = line.trim();
            (!line.is_empty())
                .then(|| serde_json::from_str(line).ok())
                .flatten()
        })
        .collect()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).ok())
        .collect()
}

fn trial_order(keys: &BTreeMap<String, AuditKey>, current_kid: &str) -> Vec<String> {
    let mut result = Vec::with_capacity(keys.len());
    if keys.contains_key(current_kid) {
        result.push(current_kid.to_owned());
    }
    result.extend(
        keys.keys()
            .filter(|kid| kid.as_str() != current_kid)
            .cloned(),
    );
    result
}

/// Verifies parsed Go JSONL semantics, including legacy prefixes and key IDs.
#[must_use]
pub fn verify_jsonl(
    data: &[u8],
    keys: &BTreeMap<String, AuditKey>,
    current_kid: &str,
) -> VerifyResult {
    verify_entries(&parse_entries(data), keys, current_kid).0
}

/// Verifies entries and returns one status per parsed entry for export consumers.
#[must_use]
pub fn verify_entries(
    entries: &[LogEntry],
    keys: &BTreeMap<String, AuditKey>,
    current_kid: &str,
) -> (VerifyResult, Vec<String>) {
    let mut result = VerifyResult {
        valid: true,
        first_bad_idx: -1,
        total: entries.len(),
        ..VerifyResult::default()
    };
    let mut statuses = vec![String::new(); entries.len()];
    let order = trial_order(keys, current_kid);
    let mut previous = Vec::new();
    let mut chain_started = false;

    for (index, entry) in entries.iter().enumerate() {
        if entry.hmac.is_empty() {
            if chain_started {
                result.tampered += 1;
                result.valid = false;
                statuses[index] = "tampered".to_owned();
                if result.first_bad_idx < 0 {
                    result.first_bad_idx = index as isize;
                }
            } else {
                result.legacy += 1;
                statuses[index] = "legacy".to_owned();
                previous.clear();
            }
            continue;
        }
        let Some(stored) = hex_decode(&entry.hmac) else {
            result.tampered += 1;
            result.valid = false;
            statuses[index] = "tampered".to_owned();
            if result.first_bad_idx < 0 {
                result.first_bad_idx = index as isize;
            }
            continue;
        };

        let mut matched = false;
        let mut known = false;
        if !entry.kid.is_empty() {
            if let Some(key) = keys.get(&entry.kid) {
                known = true;
                let expected = hex_decode(&compute_hmac(key.bytes(), &previous, entry))
                    .expect("computed HMAC is valid hex");
                matched = expected.len() == stored.len()
                    && expected
                        .iter()
                        .zip(&stored)
                        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
                        == 0;
            }
        } else {
            for kid in &order {
                let key = &keys[kid];
                let expected = hex_decode(&compute_hmac(key.bytes(), &previous, entry))
                    .expect("computed HMAC is valid hex");
                if expected.len() == stored.len()
                    && expected
                        .iter()
                        .zip(&stored)
                        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
                        == 0
                {
                    matched = true;
                    known = true;
                    break;
                }
            }
        }
        if matched {
            result.verified += 1;
            statuses[index] = "verified".to_owned();
        } else if known {
            result.tampered += 1;
            result.valid = false;
            statuses[index] = "tampered".to_owned();
            if result.first_bad_idx < 0 {
                result.first_bad_idx = index as isize;
            }
        } else {
            result.unverifiable += 1;
            statuses[index] = "unverifiable".to_owned();
        }
        previous = stored;
        chain_started = true;
    }
    (result, statuses)
}

/// Local key archive manager. Raw key files are private (`0600`) and are only
/// intended for the isolated Rust audit adapter; production Go keyring files
/// remain the oracle and are never replaced by this type.
#[derive(Clone, Debug)]
pub struct KeyStore {
    directory: PathBuf,
}

impl KeyStore {
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            directory: directory.as_ref().to_owned(),
        }
    }

    fn current_path(&self) -> PathBuf {
        self.directory.join(KEY_FILE)
    }

    /// Loads the current key, or creates a random 32-byte key on first use.
    pub fn load_or_create(&self) -> io::Result<AuditKey> {
        match fs::read(self.current_path()) {
            Ok(bytes) => AuditKey::new(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut bytes = [0u8; HMAC_KEY_BYTES];
                getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
                fs::create_dir_all(&self.directory)?;
                write_private(&self.current_path(), &bytes)?;
                let key = AuditKey::new(bytes)?;
                bytes.zeroize();
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }

    /// Rotates the current key, archiving by the old key's `kid`.
    /// Returns `(new_key, archive_path)`, with `None` for bootstrap.
    pub fn rotate(&self) -> io::Result<(AuditKey, Option<PathBuf>)> {
        let current = self.current_path();
        let old = match fs::read(&current) {
            Ok(bytes) => Some(AuditKey::new(bytes)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        fs::create_dir_all(&self.directory)?;
        let archive = old.as_ref().map(|key| {
            self.directory.join(format!(
                "{KEY_FILE}{ROTATED_MARKER}{}",
                key_fingerprint(key.bytes())
            ))
        });
        if let Some(path) = &archive {
            fs::rename(&current, path)?;
        }
        let mut bytes = [0u8; HMAC_KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
        if let Err(error) = write_private(&current, &bytes) {
            if let Some(path) = &archive {
                let _ = fs::rename(path, &current);
            }
            return Err(error);
        }
        let key = AuditKey::new(bytes)?;
        bytes.zeroize();
        Ok((key, archive))
    }

    /// Returns all valid archived generations keyed by their computed `kid`.
    pub fn archived(&self) -> io::Result<BTreeMap<String, AuditKey>> {
        let mut result = BTreeMap::new();
        if !self.directory.exists() {
            return Ok(result);
        }
        for item in fs::read_dir(&self.directory)? {
            let item = item?;
            let name = item.file_name().to_string_lossy().into_owned();
            if !name.starts_with(&format!("{KEY_FILE}{ROTATED_MARKER}")) {
                continue;
            }
            if let Ok(key) = AuditKey::new(fs::read(item.path())?) {
                result.insert(key_fingerprint(key.bytes()), key);
            }
        }
        Ok(result)
    }

    /// Removes oldest archives over count and archives at or beyond max age.
    pub fn enforce_retention(
        &self,
        max_backups: usize,
        max_age: Option<Duration>,
    ) -> io::Result<()> {
        let mut files = Vec::new();
        if !self.directory.exists() {
            return Ok(());
        }
        for item in fs::read_dir(&self.directory)? {
            let item = item?;
            let name = item.file_name().to_string_lossy().into_owned();
            if name.starts_with(&format!("{KEY_FILE}{ROTATED_MARKER}"))
                && item.file_type()?.is_file()
            {
                files.push((
                    item.path(),
                    item.metadata()?.modified().unwrap_or(UNIX_EPOCH),
                ));
            }
        }
        files.sort_by_key(|(_, modified)| *modified);
        let now = SystemTime::now();
        let delete_count = files.len().saturating_sub(max_backups);
        for (index, (path, modified)) in files.into_iter().enumerate() {
            let too_old =
                max_age.is_some_and(|age| now.duration_since(modified).unwrap_or_default() >= age);
            if index < delete_count || too_old {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_private_mode(&file)
}

fn set_private_mode(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Configuration for file rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationConfig {
    pub max_file_size: u64,
    pub max_backups: usize,
    pub max_age: Option<Duration>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,
            max_backups: 5,
            max_age: Some(Duration::from_secs(30 * 86_400)),
        }
    }
}

/// Appends a keyed chain and rotates its current file before a write when due.
pub struct Logger {
    path: PathBuf,
    key: AuditKey,
    kid: String,
    previous: Vec<u8>,
    file: Option<File>,
    rotation: RotationConfig,
}

impl fmt::Debug for Logger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Logger")
            .field("path", &self.path)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl Logger {
    pub fn open(
        path: impl AsRef<Path>,
        key: AuditKey,
        rotation: RotationConfig,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let previous = last_hmac(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        Ok(Self {
            kid: key_fingerprint(key.bytes()),
            path,
            key,
            previous,
            file: Some(file),
            rotation,
        })
    }

    /// Writes exactly one newline-terminated JSON object.
    pub fn append(&mut self, mut entry: LogEntry) -> io::Result<()> {
        let modified = self
            .file
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .and_then(|meta| meta.modified().ok());
        let age_due = self.rotation.max_age.is_some_and(|age| {
            modified.is_some_and(|time| {
                SystemTime::now().duration_since(time).unwrap_or_default() >= age
            })
        });
        let size_due = self.file.as_ref().is_some_and(|file| {
            file.metadata()
                .is_ok_and(|meta| meta.len() >= self.rotation.max_file_size)
        });
        if size_due || age_due {
            self.rotate_at(SystemTime::now())?;
        }
        if entry.timestamp.is_empty() {
            entry.timestamp = "1970-01-01T00:00:00Z".to_owned();
        }
        entry.kid = self.kid.clone();
        entry.hmac = compute_hmac(self.key.bytes(), &self.previous, &entry);
        let bytes =
            serde_json::to_vec(&entry).map_err(|error| io::Error::other(error.to_string()))?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("audit logger is closed"))?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        self.previous = hex_decode(&entry.hmac).expect("computed HMAC is valid hex");
        Ok(())
    }

    /// Rotates the current file using Go's timestamp shape.
    pub fn rotate_at(&mut self, when: SystemTime) -> io::Result<()> {
        if self
            .file
            .as_ref()
            .map_or(0, |file| file.metadata().map_or(0, |meta| meta.len()))
            == 0
        {
            return Ok(());
        }
        if let Some(file) = self.file.take() {
            file.sync_all()?;
            drop(file);
        }
        let stamp = timestamp_stamp(when);
        let target = PathBuf::from(format!("{}.rotated.{stamp}", self.path.display()));
        fs::rename(&self.path, &target)?;
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.path)?,
        );
        self.enforce_log_retention()?;
        Ok(())
    }

    fn enforce_log_retention(&self) -> io::Result<()> {
        let Some(parent) = self.path.parent() else {
            return Ok(());
        };
        let current = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let prefix = format!("{current}{ROTATED_MARKER}");
        let mut rotated = Vec::new();
        for item in fs::read_dir(parent)? {
            let item = item?;
            let name = item.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) {
                rotated.push((
                    item.path(),
                    item.metadata()?.modified().unwrap_or(UNIX_EPOCH),
                ));
            }
        }
        rotated.sort_by_key(|(_, modified)| *modified);
        let delete_count = rotated.len().saturating_sub(self.rotation.max_backups);
        for (path, _) in rotated.into_iter().take(delete_count) {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

fn last_hmac(path: &Path) -> io::Result<Vec<u8>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let mut last = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        match serde_json::from_str::<LogEntry>(line.trim()) {
            Ok(entry) if !entry.hmac.is_empty() => {
                last = hex_decode(&entry.hmac).unwrap_or_default();
            }
            _ => {}
        }
    }
    Ok(last)
}

fn timestamp_stamp(when: SystemTime) -> String {
    let seconds = when
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = seconds / 86_400;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        remainder / 3600,
        (remainder % 3600) / 60,
        remainder % 60
    )
}

// Howard Hinnant's proleptic Gregorian conversion, kept local to avoid a date
// dependency for a filename-only operation.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + i64::from(m <= 2), m, d)
}

/// An export row containing the original event plus optional redaction/status.
#[derive(Clone, Debug, Serialize)]
pub struct ExportEntry {
    #[serde(flatten)]
    pub entry: LogEntry,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub verify_status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub redacted_path: String,
    pub original_index: usize,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source_file: String,
}

/// Filters used by the JSON export surface.
#[derive(Clone, Debug, Default)]
pub struct ExportOptions {
    pub action: Option<String>,
    pub failed_only: bool,
    pub redact_paths: bool,
    pub verify_hmac: bool,
}

/// Export result with stable counts.
#[derive(Clone, Debug, Serialize)]
pub struct ExportResult {
    pub entries: Vec<ExportEntry>,
    pub total: usize,
    pub verified: usize,
    pub legacy: usize,
    pub tampered: usize,
}

/// Hashes a path with Go's `redacted:` plus six-byte SHA-256 prefix format.
#[must_use]
pub fn redact_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(path.as_bytes());
    format!(
        "redacted:{}",
        digest[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Exports current and rotated JSONL files in lexical (chronological) order.
pub fn export_directory(
    directory: impl AsRef<Path>,
    agent: &str,
    options: &ExportOptions,
    keys: &BTreeMap<String, AuditKey>,
    current_kid: &str,
) -> io::Result<ExportResult> {
    let directory = directory.as_ref();
    let current = format!("{LOG_PREFIX}{agent}{LOG_SUFFIX}");
    let prefix = format!("{current}{ROTATED_MARKER}");
    let mut paths = Vec::new();
    for item in fs::read_dir(directory)? {
        let item = item?;
        let name = item.file_name().to_string_lossy().into_owned();
        if name == current || name.starts_with(&prefix) {
            paths.push(item.path());
        }
    }
    paths.sort_by_key(|path| path.file_name().map(|name| name.to_os_string()));

    let mut entries = Vec::new();
    let mut sources = Vec::new();
    for path in paths {
        let source = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        for entry in parse_entries(&fs::read(path)?) {
            entries.push(entry);
            sources.push(source.clone());
        }
    }
    let (verification, statuses) = if options.verify_hmac {
        let (verification, statuses) = verify_entries(&entries, keys, current_kid);
        (Some(verification), statuses)
    } else {
        (None, vec![String::new(); entries.len()])
    };

    let mut exported = Vec::new();
    for (index, entry) in entries.into_iter().enumerate() {
        if options.failed_only && entry.ok
            || options
                .action
                .as_deref()
                .is_some_and(|action| action != entry.action)
        {
            continue;
        }
        let mut row = ExportEntry {
            entry,
            verify_status: statuses[index].clone(),
            redacted_path: String::new(),
            original_index: index,
            source_file: sources[index].clone(),
        };
        if options.redact_paths {
            row.redacted_path = redact_path(&row.entry.path);
            row.entry.path.clear();
        }
        exported.push(row);
    }
    let mut result = ExportResult {
        total: exported.len(),
        entries: exported,
        verified: 0,
        legacy: 0,
        tampered: 0,
    };
    for row in &result.entries {
        match row.verify_status.as_str() {
            "verified" => result.verified += 1,
            "legacy" => result.legacy += 1,
            "tampered" => result.tampered += 1,
            _ => {}
        }
    }
    // Keep the local binding explicit: verification is intentionally performed
    // before filters so excluded entries cannot hide a broken chain.
    let _ = verification;
    Ok(result)
}
