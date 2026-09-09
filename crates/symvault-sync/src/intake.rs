use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use thiserror::Error;

pub const MAX_FILE_SIZE: u64 = 1 << 20;
pub const MAX_BATCH_SIZE: u64 = 32 << 20;
pub const MAX_FILES: usize = 100;
pub const ATTACHMENT_FIELD: &str = "attachment";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceType {
    Text,
    Env,
    Json,
    Certificate,
    Key,
    Image,
    Pdf,
    Archive,
    Other,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub source_path: String,
    pub source_name: String,
    pub source_type: SourceType,
    pub size: u64,
    pub sha256: String,
    pub mtime: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    pub path: String,
    pub field: String,
    pub confidence: f64,
    #[serde(skip)]
    pub(crate) value: Option<String>,
    pub warning: Option<String>,
    pub attachment: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileResult {
    pub file: String,
    pub status: String,
    pub reason: Option<String>,
    pub provenance: Option<Provenance>,
    pub suggestions: Vec<Suggestion>,
}
#[derive(Debug, Error)]
pub enum IntakeError {
    #[error("source is not a stable regular file: {0}")]
    InvalidSource(String),
    #[error("source exceeds limit")]
    Limit,
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
}
fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn source_type(name: &str, data: &[u8]) -> SourceType {
    let ext = Path::new(name)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if data.starts_with(b"\x89PNG") || data.starts_with(b"\xff\xd8\xff") {
        return SourceType::Image;
    }
    if data.starts_with(b"%PDF-") {
        return SourceType::Pdf;
    }
    if data.starts_with(b"PK\x03\x04") {
        return SourceType::Archive;
    }
    let t = String::from_utf8_lossy(data);
    let trimmed = t.trim();
    if trimmed.starts_with("-----BEGIN ") {
        return if trimmed.contains("CERTIFICATE") {
            SourceType::Certificate
        } else {
            SourceType::Key
        };
    }
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_slice::<serde_json::Value>(data).is_ok()
    {
        return SourceType::Json;
    }
    if ext == "env"
        || t.lines().filter(|l| l.contains('=')).count() * 2
            >= t.lines().filter(|l| !l.trim().is_empty()).count().max(1)
    {
        return SourceType::Env;
    }
    if data
        .iter()
        .all(|b| *b == b'\n' || *b == b'\r' || *b == b'\t' || *b >= 0x20)
    {
        SourceType::Text
    } else {
        SourceType::Other
    }
}
fn field(k: &str) -> (&str, f64) {
    match k.trim().to_ascii_lowercase().as_str() {
        "username" | "user" | "login" | "email" => ("username", 0.95),
        "password" | "pass" | "secret" => ("password", 0.95),
        "token" | "api_key" | "apikey" => ("token", 0.9),
        "totp" | "otp" | "2fa" => ("totp", 0.85),
        "client_id" => ("client_id", 0.8),
        "client_secret" => ("client_secret", 0.85),
        "certificate" | "cert" => ("certificate", 0.8),
        "notes" | "note" | "comment" => ("notes", 0.5),
        _ => ("", 0.6),
    }
}
pub fn suggestions(data: &[u8], kind: SourceType, name: &str) -> Vec<Suggestion> {
    let path = proposed_path(name);
    let attachment = || {
        vec![Suggestion {
            path: path.clone(),
            field: ATTACHMENT_FIELD.into(),
            confidence: 1.,
            value: None,
            warning: None,
            attachment: true,
        }]
    };
    match kind {
        SourceType::Env | SourceType::Text => {
            let mut out = Vec::new();
            for line in String::from_utf8_lossy(data).lines() {
                let (k, v) = if kind == SourceType::Env {
                    line.split_once('=').map(|(a, b)| (a, b.trim()))
                } else {
                    line.split_once(':').map(|(a, b)| (a, b.trim()))
                }
                .unwrap_or(("", ""));
                if k.is_empty() || v.is_empty() {
                    continue;
                }
                let (canonical, confidence) = field(k);
                out.push(Suggestion {
                    path: path.clone(),
                    field: if canonical.is_empty() {
                        k.trim().to_ascii_lowercase()
                    } else {
                        canonical.into()
                    },
                    confidence,
                    value: Some(v.into()),
                    warning: None,
                    attachment: false,
                });
            }
            if out.is_empty() { attachment() } else { out }
        }
        SourceType::Json => {
            let Ok(serde_json::Value::Object(obj)) = serde_json::from_slice(data) else {
                return attachment();
            };
            let mut out = Vec::new();
            for (k, v) in obj {
                if let Some(v) = v.as_str() {
                    if v.is_empty() {
                        continue;
                    }
                    let (c, cfg) = field(&k);
                    out.push(Suggestion {
                        path: path.clone(),
                        field: if c.is_empty() {
                            k.to_ascii_lowercase()
                        } else {
                            c.into()
                        },
                        confidence: cfg,
                        value: Some(v.to_owned()),
                        warning: None,
                        attachment: false,
                    });
                }
            }
            if out.is_empty() { attachment() } else { out }
        }
        _ => attachment(),
    }
}
pub fn proposed_path(name: &str) -> String {
    let mut s = Path::new(name)
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or("entry")
        .to_owned();
    if let Some(ext) = Path::new(&s).extension().and_then(|x| x.to_str()) {
        s.truncate(s.len() - ext.len() - 1);
    }
    for c in ['/', '\\', ':', ' '] {
        s = s.replace(c, "_");
    }
    while s.contains("..") {
        s = s.replace("..", "_");
    }
    let s = s.trim_matches(['.', '_']).to_owned();
    if s.is_empty() { "entry".into() } else { s }
}
#[derive(Clone, Debug)]
pub struct Spool {
    root: PathBuf,
}
impl Spool {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, IntakeError> {
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: root.as_ref().into(),
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn stage(
        &self,
        path: impl AsRef<Path>,
        limit: u64,
    ) -> Result<(Vec<u8>, Provenance), IntakeError> {
        let path = path.as_ref();
        let m =
            fs::symlink_metadata(path).map_err(|e| IntakeError::InvalidSource(e.to_string()))?;
        if !m.is_file() {
            return Err(IntakeError::InvalidSource(path.display().to_string()));
        }
        if m.len() > limit {
            return Err(IntakeError::Limit);
        }
        let data = fs::read(path)?;
        if data.len() as u64 > limit {
            return Err(IntakeError::Limit);
        }
        let after = fs::metadata(path)?;
        if after.len() != m.len() || after.modified().ok() != m.modified().ok() {
            return Err(IntakeError::InvalidSource(
                "source changed during intake".into(),
            ));
        }
        let dst = self.root.join(format!(
            "{}-{}",
            std::process::id(),
            proposed_path(&path.to_string_lossy())
        ));
        fs::write(&dst, &data)?;
        Ok((
            data.clone(),
            Provenance {
                source_path: path.to_string_lossy().into(),
                source_name: path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or("entry")
                    .into(),
                source_type: source_type(&path.to_string_lossy(), &data),
                size: data.len() as u64,
                sha256: sha(&data),
                mtime: after
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs()),
            },
        ))
    }
}
#[derive(Clone, Debug)]
pub struct Options {
    pub max_file_size: u64,
    pub max_batch_size: u64,
    pub max_files: usize,
    pub debounce: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            max_file_size: MAX_FILE_SIZE,
            max_batch_size: MAX_BATCH_SIZE,
            max_files: MAX_FILES,
            debounce: Duration::from_secs(5),
        }
    }
}
pub fn process(spool: &Spool, path: impl AsRef<Path>, opts: &Options) -> FileResult {
    let path = path.as_ref();
    match spool.stage(path, opts.max_file_size) {
        Ok((data, mut p)) => {
            p.source_type = source_type(&p.source_name, &data);
            FileResult {
                file: path.to_string_lossy().into(),
                status: "ok".into(),
                reason: None,
                provenance: Some(p.clone()),
                suggestions: suggestions(&data, p.source_type, &p.source_name),
            }
        }
        Err(IntakeError::Limit) => FileResult {
            file: path.to_string_lossy().into(),
            status: "skipped".into(),
            reason: Some("source exceeds limit".into()),
            provenance: None,
            suggestions: Vec::new(),
        },
        Err(e) => FileResult {
            file: path.to_string_lossy().into(),
            status: "skipped".into(),
            reason: Some(e.to_string()),
            provenance: None,
            suggestions: Vec::new(),
        },
    }
}
/// A sink keeps quarantine writes testable without a vault, keychain, OCR, or network service.
pub trait QuarantineSink {
    fn write(
        &mut self,
        path: &str,
        fields: &BTreeMap<String, String>,
        attachment: &[u8],
        provenance: &Provenance,
    ) -> io::Result<()>;
    fn contains_hash(&self, hash: &str) -> bool;
}
pub fn quarantine<S: QuarantineSink>(
    sink: &mut S,
    results: &[(FileResult, Vec<u8>)],
    import_id: &str,
    dry_run: bool,
) -> io::Result<Vec<String>> {
    let mut written = Vec::new();
    for (r, data) in results {
        if r.status != "ok" {
            continue;
        }
        let Some(p) = r.provenance.as_ref() else {
            continue;
        };
        if sink.contains_hash(&p.sha256) {
            continue;
        }
        let path = format!("quarantine/{import_id}/{}", proposed_path(&p.source_name));
        let mut fields = BTreeMap::new();
        for s in &r.suggestions {
            if !s.attachment {
                fields
                    .entry(s.field.clone())
                    .or_insert_with(|| s.value.clone().unwrap_or_default());
            }
        }
        if !dry_run {
            sink.write(&path, &fields, data, p)?;
        }
        written.push(path);
    }
    Ok(written)
}
#[derive(Clone, Debug)]
pub struct Watcher {
    pub dir: PathBuf,
    pub options: Options,
    seen: BTreeMap<String, String>,
}
impl Watcher {
    pub fn new(dir: impl AsRef<Path>, options: Options) -> Result<Self, IntakeError> {
        if !dir.as_ref().is_dir() {
            return Err(IntakeError::InvalidSource(
                dir.as_ref().display().to_string(),
            ));
        }
        Ok(Self {
            dir: dir.as_ref().into(),
            options,
            seen: BTreeMap::new(),
        })
    }
    pub fn scan_at(
        &mut self,
        now: SystemTime,
        spool: &Spool,
    ) -> Result<Vec<FileResult>, IntakeError> {
        let mut paths = Vec::new();
        for e in fs::read_dir(&self.dir)? {
            let e = e?;
            if e.file_name().to_string_lossy().starts_with('.') || !e.file_type()?.is_file() {
                continue;
            }
            let m = e.metadata()?;
            if now
                .duration_since(m.modified().unwrap_or(now))
                .unwrap_or_default()
                < self.options.debounce
            {
                continue;
            }
            let key = format!("{}:{}:{:?}", e.path().display(), m.len(), m.modified().ok());
            if self.seen.contains_key(&key) {
                continue;
            }
            paths.push((e.path(), key));
        }
        paths.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out = Vec::new();
        for (p, key) in paths {
            let r = process(spool, &p, &self.options);
            if let Some(prov) = r.provenance.as_ref().filter(|_| r.status == "ok") {
                self.seen.insert(key, prov.sha256.clone());
            }
            out.push(r);
        }
        Ok(out)
    }
    pub fn scan(&mut self, spool: &Spool) -> Result<Vec<FileResult>, IntakeError> {
        self.scan_at(SystemTime::now(), spool)
    }
}

#[must_use]
pub fn encode_attachment(data: &[u8]) -> String {
    STANDARD.encode(data)
}
