use crate::approval::ApprovalQueue;
use crate::broker::{self, ApiSubstitution, ApiTemplate, ApiTemplateDefinition};
use crate::call::{
    CommandExecutor, ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore,
    ReadOnlyUnavailableTool, SecureInputPreflightError, ToolCallResult, ToolCallRuntime,
    WriteApprovalDecision, normalize_scope_path, write_approval_decision,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    fs,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use symvault_core::policy::{Action, Engine, EvalContext};
use symvault_core::secret_ref::SecretHandle;
use symvault_crypto::{Identity, SecretBytes};
use symvault_platform::approval::{
    self as approval_prompt, ApprovalRequest, ApprovalResult, RiskLevel, SecureInputError,
    SecureInputRequest, format_go_duration,
};
use symvault_store::{
    Entry, Store, StoreError, WriteRecord,
    sharing::{SHARE_STORE_FILE, ShareFilter, ShareStore},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[path = "go_unicode_15.rs"]
mod go_unicode_15;

pub type SharedAuditLogger = Arc<Mutex<symvault_store::audit::Logger>>;

const MAX_API_TEMPLATE_BYTES: u64 = 64 * 1024;

/// Load one API template at request time so on-disk endpoint, method,
/// or credential-reference revocations take effect without restarting MCP.
pub fn load_api_template_definition(
    vault_root: &Path,
    name: &str,
) -> Result<ApiTemplateDefinition, String> {
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(format!("invalid template name: {name:?}"));
    }
    let root = fs::canonicalize(vault_root).map_err(|error| format!("read vault root: {error}"))?;
    let directory = match fs::canonicalize(root.join("templates")) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match fs::symlink_metadata(root.join("templates")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    load_builtin_api_template(name)
                }
                _ => Err("template directory is unavailable".into()),
            };
        }
        Err(error) => return Err(format!("read template directory: {error}")),
    };
    if !directory.starts_with(&root) {
        return Err("template directory escapes the vault root".into());
    }
    let path = directory.join(format!("{name}.yaml"));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return load_builtin_api_template(name);
        }
        Err(error) => return Err(format!("read template: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("template must be a regular file".into());
    }
    let canonical = fs::canonicalize(&path).map_err(|error| format!("read template: {error}"))?;
    if !canonical.starts_with(&directory) {
        return Err("template path escapes the template directory".into());
    }
    let file = fs::File::open(&canonical).map_err(|error| format!("read template: {error}"))?;
    if file
        .metadata()
        .map_err(|error| format!("stat template: {error}"))?
        .len()
        > MAX_API_TEMPLATE_BYTES
    {
        return Err("template exceeds the 65536-byte limit".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_API_TEMPLATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read template: {error}"))?;
    if bytes.len() as u64 > MAX_API_TEMPLATE_BYTES {
        return Err("template exceeds the 65536-byte limit".into());
    }
    serde_yaml_ng::from_slice(&bytes).map_err(|error| format!("parse template: {error}"))
}

fn load_builtin_api_template(name: &str) -> Result<ApiTemplateDefinition, String> {
    // Share the authoritative Go assets; custom files always take precedence.
    let yaml = match name {
        "anthropic" => include_str!("../../../internal/mcp/apitemplates/builtin/anthropic.yaml"),
        "cloudflare" => include_str!("../../../internal/mcp/apitemplates/builtin/cloudflare.yaml"),
        "gemini" => include_str!("../../../internal/mcp/apitemplates/builtin/gemini.yaml"),
        "github" => include_str!("../../../internal/mcp/apitemplates/builtin/github.yaml"),
        "gitlab" => include_str!("../../../internal/mcp/apitemplates/builtin/gitlab.yaml"),
        "linear" => include_str!("../../../internal/mcp/apitemplates/builtin/linear.yaml"),
        "notion" => include_str!("../../../internal/mcp/apitemplates/builtin/notion.yaml"),
        "npm" => include_str!("../../../internal/mcp/apitemplates/builtin/npm.yaml"),
        "openai" => include_str!("../../../internal/mcp/apitemplates/builtin/openai.yaml"),
        "openrouter" => include_str!("../../../internal/mcp/apitemplates/builtin/openrouter.yaml"),
        "perplexity" => include_str!("../../../internal/mcp/apitemplates/builtin/perplexity.yaml"),
        "resend" => include_str!("../../../internal/mcp/apitemplates/builtin/resend.yaml"),
        "sentry" => include_str!("../../../internal/mcp/apitemplates/builtin/sentry.yaml"),
        "slack" => include_str!("../../../internal/mcp/apitemplates/builtin/slack.yaml"),
        "stripe" => include_str!("../../../internal/mcp/apitemplates/builtin/stripe.yaml"),
        "telegram" => include_str!("../../../internal/mcp/apitemplates/builtin/telegram.yaml"),
        "vercel" => include_str!("../../../internal/mcp/apitemplates/builtin/vercel.yaml"),
        _ => return Err(format!("template {name:?} not found")),
    };
    serde_yaml_ng::from_str(yaml).map_err(|error| format!("parse template: {error}"))
}

#[derive(Default)]
struct ResolvedRunFiles {
    content: BTreeMap<String, Vec<u8>>,
    redactions: Vec<Vec<u8>>,
    audit: Vec<String>,
}

enum RunFilesError {
    Tool(String),
    Denied(String),
}

/// Human-approval seam for the MCP share lifecycle.
///
/// Go calls the package-level `IsTTYPresent`/`RequestApproval`, which open the
/// controlling terminal directly. Keeping the same behaviour behind a seam lets
/// the protocol tests drive approve/deny/error without a real TTY, and makes the
/// "never read approval from MCP stdin" rule structurally true: there is no
/// stdin path in this interface at all.
pub trait ApprovalSeam: Send + Sync {
    fn is_tty_present(&self) -> bool;
    fn request(&self, request: &ApprovalRequest) -> ApprovalResult;
}

/// Production seam: the real controlling-terminal prompt.
pub struct PlatformApproval;

impl ApprovalSeam for PlatformApproval {
    fn is_tty_present(&self) -> bool {
        approval_prompt::is_tty_present()
    }

    fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
        approval_prompt::request_approval(request)
    }
}

/// Boundary for collecting a user-supplied secret. The production platform
/// implementation reads only the controlling terminal; tests inject a fake.
pub trait SecureInputSeam: Send + Sync {
    fn is_tty_present(&self) -> bool;
    fn prompt(&self, request: &SecureInputRequest) -> Result<String, SecureInputError>;
}

pub struct PlatformSecureInput;

impl SecureInputSeam for PlatformSecureInput {
    fn is_tty_present(&self) -> bool {
        approval_prompt::is_tty_present()
    }

    fn prompt(&self, request: &SecureInputRequest) -> Result<String, SecureInputError> {
        approval_prompt::request_secure_input(request)
    }
}

/// Go's `handleApproveShare` prompt timeout.
const SHARE_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

const MCP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Go's MCP `rate_limit` pre-call hook is a fixed one-minute window. Keep this
/// state at the concrete runtime boundary so it is shared by every protocol
/// call in one session without introducing another quota file or counter
/// format. `limit == 0` intentionally denies every call when explicitly
/// configured; `None` means the profile did not enable the hook.
#[derive(Debug)]
struct MinuteRateLimiter {
    limit: i64,
    window_started: Instant,
    count: i64,
}

impl MinuteRateLimiter {
    fn new(limit: i64) -> Self {
        Self {
            limit,
            window_started: Instant::now(),
            count: 0,
        }
    }

    fn allow_at(&mut self, now: Instant) -> bool {
        if self.count == 0 || now.duration_since(self.window_started) > MCP_RATE_LIMIT_WINDOW {
            self.window_started = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= self.limit
    }

    fn allow(&mut self) -> bool {
        self.allow_at(Instant::now())
    }
}

/// A store-backed projection for the portable read-only MCP tools.
///
/// The adapter owns the decrypted identity handle and delegates all filesystem
/// traversal and decryption to `symvault-store`. It never discovers a vault or
/// platform provider implicitly.
pub struct StoreReadOnlyAdapter {
    store: Store,
    identity: Identity,
}

impl StoreReadOnlyAdapter {
    pub fn open(root: impl AsRef<Path>, identity: Identity) -> Result<Self, String> {
        let store = Store::open(root, &identity).map_err(store_error)?;
        Ok(Self { store, identity })
    }

    pub fn root(&self) -> &Path {
        self.store.root()
    }

    fn project(path: &str, entry: Entry) -> ReadOnlyEntry {
        ReadOnlyEntry {
            path: if entry.path.is_empty() {
                path.to_owned()
            } else {
                entry.path
            },
            fields: entry.data,
            secret_type: entry.secret_metadata.secret_type,
            usage_hint: entry.secret_metadata.usage_hint,
            auto_rotate: entry.secret_metadata.auto_rotate,
            expires_at: entry.secret_metadata.expires_at,
            created: entry.metadata.created,
            updated: entry.metadata.updated,
            version: entry.metadata.version,
            tags: entry.metadata.tags,
            classification: entry.classification,
        }
    }
}

impl ReadOnlyStore for StoreReadOnlyAdapter {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String> {
        let paths = self.store.list(&self.identity).map_err(store_error)?;
        paths
            .into_iter()
            .map(|path| {
                self.store
                    .get(&path, &self.identity)
                    .map(|entry| Self::project(&path, entry))
                    .map_err(store_error)
            })
            .collect()
    }

    fn get(&self, path: &str) -> Result<Option<ReadOnlyEntry>, String> {
        #[cfg(test)]
        tests::API_REVIEW_READS.with(|count| count.set(count.get() + 1));
        match self.store.get(path, &self.identity) {
            Ok(entry) => Ok(Some(Self::project(path, entry))),
            Err(StoreError::EntryNotFound(_)) => Ok(None),
            Err(error) => Err(store_error(error)),
        }
    }

    fn resolve_secret_ref_at_path(
        &self,
        reference: &str,
        expected_path: &str,
    ) -> Result<String, String> {
        if let Some(index) = reference.rfind('.').filter(|index| *index > 0) {
            let candidate_path = &reference[..index];
            let candidate_field = &reference[index + 1..];
            if let Ok(entry) = self.store.get(candidate_path, &self.identity)
                && let Some(value) = entry.data.get(candidate_field)
            {
                if candidate_path != expected_path {
                    return Err("secret ref target changed during resolution".into());
                }
                if candidate_field.is_empty() {
                    return Ok(format_go_secret_map(&entry.data));
                }
                return Ok(format_go_secret_value(value));
            }
        }
        if reference != expected_path {
            return Err("secret ref target changed during resolution".into());
        }
        let entry = self
            .store
            .get(reference, &self.identity)
            .map_err(store_error)?;
        Ok(format_go_secret_map(&entry.data))
    }

    fn resolve_secret_ref_path(&self, reference: &str) -> Result<String, String> {
        if let Some(index) = reference.rfind('.').filter(|index| *index > 0) {
            let candidate_path = &reference[..index];
            let candidate_field = &reference[index + 1..];
            if let Ok(entry) = self.store.get(candidate_path, &self.identity)
                && entry.data.contains_key(candidate_field)
            {
                return Ok(candidate_path.to_owned());
            }
        }
        Ok(reference.to_owned())
    }

    fn delete_entry(&self, path: &str) -> Result<(), String> {
        self.store
            .delete_entry_with_identity(path, &self.identity)
            .map_err(store_error)?;
        if let Err(error) =
            symvault_sync::auto_commit_entry(&self.store, &self.identity, path, "Delete")
        {
            eprintln!("Warning: auto-commit failed: {error}");
        }
        Ok(())
    }

    fn set_field(&self, path: &str, field: &str, value: Value, now: &str) -> Result<(), String> {
        let (mut entry, existing) = match self.store.get(path, &self.identity) {
            Ok(entry) => (entry, true),
            Err(StoreError::EntryNotFound(_)) => (Entry::default(), false),
            Err(error) => return Err(store_error(error)),
        };
        validate_field_lengths(field, &value)?;
        match (entry.data.get_mut(field), &value) {
            (Some(Value::Object(existing)), Value::Object(incoming)) => {
                merge_json_objects(existing, incoming);
            }
            _ => {
                entry.data.insert(field.to_owned(), value);
            }
        }
        if field == "password" {
            const WEAK_PASSWORD_TAG: &str = "weak-password";
            let weak = entry
                .data
                .get(field)
                .and_then(Value::as_str)
                .map(symvault_core::password::assess_password_strength)
                .is_some_and(|assessment| assessment.weak);
            entry.metadata.tags.retain(|tag| tag != WEAK_PASSWORD_TAG);
            if weak {
                entry.metadata.tags.push(WEAK_PASSWORD_TAG.into());
            }
        }
        self.store
            .write_entry_with_recipients_at(
                path,
                &entry,
                &self.identity,
                now,
                (!existing)
                    .then(|| WriteRecord {
                        field: field.to_owned(),
                        action: "set".into(),
                        ..WriteRecord::default()
                    })
                    .as_ref(),
            )
            .map_err(store_error)?;
        if let Err(error) =
            symvault_sync::auto_commit_entry(&self.store, &self.identity, path, "Update")
        {
            eprintln!("Warning: auto-commit failed: {error}");
        }
        Ok(())
    }
}

const MAX_FIELD_LENGTH: usize = 4096;

/// Match Go's ValidateFieldLengths: string values are bounded by UTF-8 byte
/// length and nested objects are checked recursively. Arrays intentionally
/// retain the Go behavior, which only descends through map[string]any values.
fn validate_field_lengths(field: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::String(value) if value.len() > MAX_FIELD_LENGTH => Err(format!(
            "field {field:?} exceeds maximum length of {MAX_FIELD_LENGTH} characters"
        )),
        Value::Object(values) => values
            .iter()
            .find_map(|(name, value)| validate_field_lengths(name, value).err())
            .map_or(Ok(()), Err),
        _ => Ok(()),
    }
}

fn merge_json_objects(
    destination: &mut serde_json::Map<String, Value>,
    source: &serde_json::Map<String, Value>,
) {
    for (name, value) in source {
        match (destination.get_mut(name), value) {
            (Some(Value::Object(existing)), Value::Object(incoming)) => {
                merge_json_objects(existing, incoming);
            }
            _ => {
                destination.insert(name.clone(), value.clone());
            }
        }
    }
}

/// A concrete `tools/call` runtime over the encrypted Rust store.
pub struct StoreReadOnlyRuntime {
    inner: ReadOnlyRuntime<StoreReadOnlyAdapter>,
    share_store: Mutex<ShareStore>,
    share_root: PathBuf,
    grant_signing_key: Option<SecretBytes>,
    policy: Option<Engine>,
    audit: Option<SharedAuditLogger>,
    rate_limiter: Mutex<Option<MinuteRateLimiter>>,
    agent_name: String,
    transport: String,
    unavailable_tools: Vec<String>,
    now_unix: Option<i64>,
    approval: Arc<dyn ApprovalSeam>,
    secure_input: Arc<dyn SecureInputSeam>,
    approval_cache: Mutex<HashSet<String>>,
    approval_key_counter: std::sync::atomic::AtomicI64,
    approval_mode: String,
    require_approval: bool,
    approval_timeout: Duration,
    approval_queue_attached: bool,
    command_executor: Option<Arc<dyn CommandExecutor>>,
    allowed_executables: Vec<String>,
    clipboard: Arc<dyn symvault_core::platform::Clipboard>,
    clipboard_clear_cancel: Mutex<Option<mpsc::Sender<()>>>,
    clipboard_auto_clear_duration: Duration,
}

impl StoreReadOnlyRuntime {
    pub fn open(
        root: impl AsRef<Path>,
        identity: Identity,
        config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        _quota: Option<Arc<symvault_core::persistent_quota::QuotaCounter>>,
    ) -> Result<Self, String> {
        Self::open_with_audit(root, identity, config, policy, None)
    }

    pub fn open_with_audit(
        root: impl AsRef<Path>,
        identity: Identity,
        mut config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        audit: Option<SharedAuditLogger>,
    ) -> Result<Self, String> {
        if config.available_tools.is_empty() {
            return Err("MCP runtime tool registry is empty".into());
        }
        let adapter = StoreReadOnlyAdapter::open(root, identity)?;
        let root = adapter.root().to_path_buf();
        let share_store = ShareStore::read(root.join(SHARE_STORE_FILE))
            .map_err(|error| format!("load share store: {error}"))?;
        config.vault_dir = root.to_string_lossy().into_owned();
        config.vault_unlocked = true;
        let agent_name = config.agent_name.clone();
        let transport = config.transport.clone();
        let approval_mode = config.approval_mode.clone();
        let require_approval = config.require_approval;
        let approval_timeout = config.approval_timeout;
        let allowed_executables = config.allowed_executables.clone();
        let now_unix = config.now_unix;
        let unavailable_tools = config
            .unavailable_tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        config
            .available_tools
            .retain(|name| !unavailable_tools.iter().any(|blocked| blocked == name));
        Ok(Self {
            inner: ReadOnlyRuntime::new(adapter, config),
            share_store: Mutex::new(share_store),
            grant_signing_key: None,
            share_root: root,
            policy,
            audit,
            rate_limiter: Mutex::new(None),
            agent_name,
            transport,
            unavailable_tools,
            now_unix,
            approval: Arc::new(PlatformApproval),
            secure_input: Arc::new(PlatformSecureInput),
            approval_cache: Mutex::new(HashSet::new()),
            approval_key_counter: std::sync::atomic::AtomicI64::new(0),
            approval_mode,
            require_approval,
            approval_timeout,
            approval_queue_attached: false,
            command_executor: None,
            allowed_executables,
            clipboard: Arc::new(symvault_core::platform::UnavailablePlatform),
            clipboard_clear_cancel: Mutex::new(None),
            clipboard_auto_clear_duration: Duration::from_secs(30),
        })
    }

    pub fn from_store(
        store: Store,
        identity: Identity,
        config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        _quota: Option<Arc<symvault_core::persistent_quota::QuotaCounter>>,
    ) -> Result<Self, String> {
        Self::from_store_with_audit(store, identity, config, policy, None)
    }

    pub fn from_store_with_audit(
        store: Store,
        identity: Identity,
        mut config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        audit: Option<SharedAuditLogger>,
    ) -> Result<Self, String> {
        if config.available_tools.is_empty() {
            return Err("MCP runtime tool registry is empty".into());
        }
        let adapter = StoreReadOnlyAdapter { store, identity };
        let share_store = ShareStore::read(adapter.root().join(SHARE_STORE_FILE))
            .map_err(|error| format!("load share store: {error}"))?;
        config.vault_dir = adapter.root().to_string_lossy().into_owned();
        config.vault_unlocked = true;
        let agent_name = config.agent_name.clone();
        let transport = config.transport.clone();
        let approval_mode = config.approval_mode.clone();
        let require_approval = config.require_approval;
        let approval_timeout = config.approval_timeout;
        let allowed_executables = config.allowed_executables.clone();
        let share_root = adapter.root().to_path_buf();
        let now_unix = config.now_unix;
        let unavailable_tools = config
            .unavailable_tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        config
            .available_tools
            .retain(|name| !unavailable_tools.iter().any(|blocked| blocked == name));
        Ok(Self {
            inner: ReadOnlyRuntime::new(adapter, config),
            share_store: Mutex::new(share_store),
            grant_signing_key: None,
            share_root,
            policy,
            audit,
            rate_limiter: Mutex::new(None),
            agent_name,
            transport,
            unavailable_tools,
            now_unix,
            approval: Arc::new(PlatformApproval),
            secure_input: Arc::new(PlatformSecureInput),
            approval_cache: Mutex::new(HashSet::new()),
            approval_key_counter: std::sync::atomic::AtomicI64::new(0),
            approval_mode,
            require_approval,
            approval_timeout,
            approval_queue_attached: false,
            command_executor: None,
            allowed_executables,
            clipboard: Arc::new(symvault_core::platform::UnavailablePlatform),
            clipboard_clear_cancel: Mutex::new(None),
            clipboard_auto_clear_duration: Duration::from_secs(30),
        })
    }

    /// Replaces the controlling-terminal approval seam. Production callers keep
    /// the default; tests inject a synthetic human without touching a TTY.
    #[must_use]
    pub fn with_approval_seam(mut self, seam: Arc<dyn ApprovalSeam>) -> Self {
        self.approval = seam;
        self
    }

    #[must_use]
    pub fn with_secure_input_seam(mut self, seam: Arc<dyn SecureInputSeam>) -> Self {
        self.secure_input = seam;
        self
    }

    /// Installs the application-owned clipboard backend. The default remains
    /// unavailable so constructing a runtime never touches the host clipboard.
    #[must_use]
    pub fn with_clipboard(
        mut self,
        clipboard: Arc<dyn symvault_core::platform::Clipboard>,
    ) -> Self {
        self.clipboard = clipboard;
        self
    }

    #[must_use]
    pub fn with_clipboard_auto_clear_duration(mut self, duration: Duration) -> Self {
        self.clipboard_auto_clear_duration = duration;
        self
    }

    /// Connects prompt-mode write authorization to the live local approval
    /// queue exposed by the HTTP server. Callers without that API stay closed.
    #[must_use]
    pub fn with_approval_queue(mut self, queue: Arc<ApprovalQueue>) -> Self {
        self.inner = self.inner.with_approval_queue(queue);
        self.approval_queue_attached = true;
        self
    }

    /// Enables the Go-compatible fixed one-minute MCP pre-call limiter for
    /// this session. The CLI supplies `Some(limit)` only when the profile
    /// lists `rate_limit` in `PreCallHooks`; `None` preserves the disabled
    /// hook behavior. This setter is intentionally separate from profile
    /// hourly/day fields, which Go exposes in `whoami` without enforcing.
    pub fn set_rate_limit_per_minute(&self, limit: Option<i64>) {
        if let Ok(mut limiter) = self.rate_limiter.lock() {
            *limiter = limit.map(MinuteRateLimiter::new);
        }
    }

    fn rate_limit_denied(&self) -> Option<i64> {
        let Ok(mut limiter) = self.rate_limiter.lock() else {
            return Some(0);
        };
        let limiter = limiter.as_mut()?;
        if limiter.allow() {
            None
        } else {
            Some(limiter.limit)
        }
    }

    fn append_audit(&self, action: &str, path: &str, ok: bool) {
        let Some(audit) = &self.audit else {
            return;
        };
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        let entry = symvault_store::audit::LogEntry {
            timestamp,
            agent: self.agent_name.clone(),
            action: action.into(),
            path: path.into(),
            transport: self.transport.clone(),
            reason: if !ok { action.into() } else { String::new() },
            ok,
            ..symvault_store::audit::LogEntry::default()
        };
        if let Ok(mut logger) = audit.lock() {
            let _ = logger.append(entry);
        }
    }

    fn approve_write(
        &self,
        tool: &str,
        path: &str,
        field: Option<&str>,
        mode: &str,
    ) -> Result<(), String> {
        match write_approval_decision(mode) {
            WriteApprovalDecision::Allow => return Ok(()),
            WriteApprovalDecision::Deny => {
                self.append_audit(&format!("approval.{tool}.denied"), path, false);
                return Err(if mode == "deny" {
                    format!("{tool} denied: approval mode is 'deny'")
                } else {
                    // Go's profile loader validates configured modes before
                    // runtime construction. Public Rust runtime configs can
                    // bypass the loader, so fail closed here.
                    format!("{tool} denied: unknown approval mode {mode:?}")
                });
            }
            WriteApprovalDecision::Prompt => {}
        }

        if !self.approval.is_tty_present() {
            self.append_audit(&format!("approval.{tool}.denied"), path, false);
            return Err(format!(
                "{tool} requires approval but no TTY or GUI dialog available"
            ));
        }

        let clipboard_cache_key = if tool == "copy_to_clipboard" {
            Some(format!(
                "{}:{tool}:{}",
                self.agent_name,
                normalize_scope_path(path)
            ))
        } else {
            None
        };
        if let Some(cache_key) = clipboard_cache_key.as_ref()
            && self
                .approval_cache
                .lock()
                .is_ok_and(|cache| cache.contains(cache_key))
        {
            self.append_audit(&format!("approval.{tool}.remembered"), path, true);
            return Ok(());
        }

        self.append_audit(&format!("approval.{tool}.requested"), path, true);
        // Go sanitizes the path and field independently in RenderSummary.
        // Keep those boundaries: an unterminated escape in the path must not
        // consume the following literal field label or field name.
        let safe_path = sanitize_approval_summary(path);
        let description = match tool {
            "set_entry_field" => {
                let safe_field = sanitize_approval_summary(field.unwrap_or(""));
                if safe_field.is_empty() {
                    format!("set field on {safe_path}")
                } else {
                    format!("set field on {safe_path} field {safe_field}")
                }
            }
            "secure_input" | "request_credential" => format!("{tool} for {safe_path}"),
            "copy_to_clipboard" => {
                format!("copy password from {safe_path} to clipboard")
            }
            _ => format!("delete entry on {safe_path}"),
        };
        let request = ApprovalRequest {
            operation: tool.to_owned(),
            details: description,
            timeout: if self.approval_timeout.is_zero() {
                Duration::from_secs(30)
            } else {
                self.approval_timeout
            },
            agent_name: self.agent_name.clone(),
            working_dir: std::env::current_dir()
                .map(|directory| directory.to_string_lossy().into_owned())
                .unwrap_or_default(),
            risk_level: if tool == "copy_to_clipboard" {
                RiskLevel::High
            } else {
                RiskLevel::Critical
            },
            secrets_accessed: self
                .approval_key_counter
                .load(std::sync::atomic::Ordering::Acquire),
            can_remember: tool == "copy_to_clipboard",
            ..ApprovalRequest::default()
        };
        let result = self.approval.request(&request);
        if let Some(error) = result.error {
            // The Go helper leaves the requested audit event in place but does
            // not write a denied event for prompt I/O failures.
            return Err(format!("{tool} approval failed: {error}"));
        }
        if !result.approved {
            self.append_audit(&format!("approval.{tool}.denied"), path, false);
            return Err(format!("{tool} denied: user did not approve"));
        }
        if result.remembered
            && let Some(cache_key) = clipboard_cache_key
        {
            if let Ok(mut cache) = self.approval_cache.lock() {
                cache.insert(cache_key);
            }
            self.append_audit(&format!("approval.{tool}.remembered"), path, true);
        }
        self.approval_key_counter
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.append_audit(&format!("approval.{tool}.granted"), path, true);
        Ok(())
    }

    fn run_command(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let Some(executor) = &self.command_executor else {
            return Err("run_command has no configured command executor".into());
        };
        if arguments
            .get("working_dir")
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            self.append_audit("run_command", "<invalid:working_dir>", false);
            return Ok(ToolCallResult::error(
                "argument \"working_dir\" must be a string",
            ));
        }
        let Some(command_value) = arguments.get("command") else {
            self.append_audit("run_command", "<invalid>", false);
            return Ok(ToolCallResult::error(
                "missing required argument \"command\"",
            ));
        };
        let Some(command_values) = command_value.as_array() else {
            self.append_audit("run_command", "<invalid>", false);
            return Ok(ToolCallResult::error(
                "argument \"command\" must be an array",
            ));
        };
        if command_values.is_empty() {
            self.append_audit("run_command", "<invalid>", false);
            return Ok(ToolCallResult::error("command array must not be empty"));
        }
        let mut command = Vec::with_capacity(command_values.len());
        for (index, value) in command_values.iter().enumerate() {
            let Some(value) = value.as_str() else {
                self.append_audit("run_command", "<invalid>", false);
                return Ok(ToolCallResult::error(format!(
                    "command[{index}] must be a string"
                )));
            };
            command.push(value.to_owned());
        }
        if !self.allowed_executables.is_empty() {
            let executable = Path::new(&command[0])
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            if !self
                .allowed_executables
                .iter()
                .any(|allowed| allowed == &executable)
            {
                return Err(format!(
                    "command execution denied: executable {executable:?} not in agent allowlist"
                ));
            }
        }
        let timeout_seconds = match parse_command_timeout(arguments.get("timeout")) {
            Ok(timeout) => timeout,
            Err(error) => {
                self.append_audit("run_command", "<invalid:timeout>", false);
                return Ok(ToolCallResult::error(error));
            }
        };
        let env_value = arguments.get("env").filter(|value| !value.is_null());
        let mut env_refs = BTreeMap::new();
        if let Some(value) = env_value {
            let Some(env) = value.as_object() else {
                self.append_audit("run_command", "<invalid>", false);
                return Ok(ToolCallResult::error("argument \"env\" must be an object"));
            };
            for (name, reference) in env {
                let Some(reference) = reference.as_str() else {
                    return Ok(ToolCallResult::error(format!(
                        "env.{name} value must be a string secret reference"
                    )));
                };
                env_refs.insert(name.clone(), reference.to_owned());
            }
        }
        let denied = denied_env_names(env_refs.keys());
        if !denied.is_empty() {
            self.append_audit("run_command", "<validation-denied-env>", false);
            return Ok(ToolCallResult::error(format!(
                "env contains denied keys: {}",
                denied.join(", ")
            )));
        }
        let mut resolved_paths = BTreeMap::new();
        for (name, reference) in &env_refs {
            let candidate_path = extract_path_from_secret_ref(reference);
            if !self.inner.scope_allows(&candidate_path) {
                self.append_audit("scope_denied", &candidate_path, false);
                return Err(format!(
                    "access denied: secret ref path {candidate_path:?} outside allowed scope"
                ));
            }
            if let Some(policy) = &self.policy {
                let result = policy.evaluate(EvalContext {
                    agent_id: self.agent_name.clone(),
                    path: candidate_path.clone(),
                    action_type: "run".into(),
                    tool_name: "run_command".into(),
                    ..EvalContext::default()
                });
                if !result.matched || result.action != Action::Allow {
                    self.append_audit("policy_denied", &candidate_path, false);
                    return Err(if !result.matched {
                        "policy: no matching rule (default deny)".into()
                    } else {
                        format!("policy denied by rule {:?}", result.rule_name)
                    });
                }
            }
            let path = self
                .inner
                .resolve_secret_ref_path(reference)
                .map_err(|error| {
                    format!("cannot resolve secret ref path {reference:?}: {error}")
                })?;
            if !self.inner.scope_allows(&path) {
                self.append_audit("scope_denied", &path, false);
                return Err(format!(
                    "access denied: secret ref path {path:?} outside allowed scope"
                ));
            }
            if let Some(policy) = &self.policy {
                let result = policy.evaluate(EvalContext {
                    agent_id: self.agent_name.clone(),
                    path: path.clone(),
                    action_type: "run".into(),
                    tool_name: "run_command".into(),
                    ..EvalContext::default()
                });
                if !result.matched || result.action != Action::Allow {
                    self.append_audit("policy_denied", &path, false);
                    return Err(if !result.matched {
                        "policy: no matching rule (default deny)".into()
                    } else {
                        format!("policy denied by rule {:?}", result.rule_name)
                    });
                }
            }
            resolved_paths.insert(name.clone(), path);
        }
        let mut environment = BTreeMap::new();
        for (name, reference) in &env_refs {
            let expected_path = resolved_paths
                .get(name)
                .expect("every validated command secret has a resolved path");
            let value = match self
                .inner
                .resolve_secret_ref_at_path(reference, expected_path)
            {
                Ok(value) => value,
                Err(error) => {
                    return Ok(ToolCallResult::error(format!(
                        "cannot resolve secret ref {reference:?}: {error}"
                    )));
                }
            };
            environment.insert(name.clone(), value);
        }
        let files = match self.resolve_run_command_files(arguments.get("files")) {
            Ok(files) => files,
            Err(RunFilesError::Tool(message)) => return Ok(ToolCallResult::error(message)),
            Err(RunFilesError::Denied(message)) => return Err(message),
        };
        // run_command's environment contains only resolved vault references,
        // matching Go KnownSecrets. Literal execute_with_secret env_vars are
        // not included here and remain visible unless generic scanning flags them.
        let mut redactions = files.redactions.clone();
        redactions.extend(
            environment
                .values()
                .filter(|value| !value.is_empty())
                .map(|value| value.as_bytes().to_vec()),
        );
        let mode = if self.approval_mode.is_empty() && self.require_approval {
            "prompt"
        } else {
            self.approval_mode.as_str()
        };
        if matches!(mode, "deny" | "prompt") {
            self.append_audit("approval_denied", "run_command", false);
            return Err("run_command denied: approval required but cannot be granted".into());
        }
        let working_directory = arguments
            .get("working_dir")
            .and_then(Value::as_str)
            .filter(|directory| !directory.is_empty())
            .map(Path::new);
        // Never place argument strings or secret refs in audit logs.
        let execution = match executor.run(
            &command,
            &environment,
            &files.content,
            &redactions,
            working_directory,
            Duration::from_secs(timeout_seconds),
        ) {
            Ok(execution) => execution,
            Err(error) => {
                self.append_audit("run_command", "<execution-failed>", false);
                return Ok(ToolCallResult::error(error));
            }
        };
        let audit_path = if files.audit.is_empty() {
            "<command>".to_owned()
        } else {
            format!("<command>, files=[{}]", files.audit.join(", "))
        };
        self.append_audit("run_command", &audit_path, !execution.timed_out);
        let stdout = crate::render::embed_as_data("command_output", &execution.stdout)
            .map_err(|error| format!("embed command output: {error}"))?;
        let stderr = crate::render::embed_as_data("command_output", &execution.stderr)
            .map_err(|error| format!("embed command output: {error}"))?;
        if execution.timed_out {
            return Ok(ToolCallResult::error(format!(
                "command timed out after {timeout_seconds}s\nExit code: {}\nStdout: {stdout}\nStderr: {stderr}",
                execution.exit_code
            )));
        }
        Ok(ToolCallResult::text(
            symvault_gojson::to_string(&json!({
                "exit_code": execution.exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": execution.duration.as_millis().min(i64::MAX as u128) as i64,
            }))
            .map_err(|error| error.to_string())?,
        ))
    }

    fn check_execute_with_secret_approval(
        &self,
        command: &[String],
        environment: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        let mode = if self.approval_mode.is_empty() {
            if self.require_approval {
                "prompt"
            } else {
                "none"
            }
        } else {
            self.approval_mode.as_str()
        };
        match mode {
            "none" | "auto" => return Ok(()),
            "deny" => {
                self.append_audit("approval.execute_with_secret.denied", "", false);
                return Err("execute_with_secret denied: approval mode is 'deny'".into());
            }
            "prompt" => {}
            // RuntimeConfig is public and may be constructed without the
            // profile validator, so unknown modes must never bypass approval.
            _ => {
                self.append_audit("approval.execute_with_secret.denied", "", false);
                return Err(format!(
                    "execute_with_secret denied: unknown approval mode {mode:?}"
                ));
            }
        }

        // This Rust platform seam currently supports controlling-TTY approval
        // only. Fail closed before consulting remembered approvals, matching
        // Go's no-TTY/no-GUI guard ordering.
        if !self.approval.is_tty_present() {
            self.append_audit("approval.execute_with_secret.denied", "", false);
            return Err(
                "execute_with_secret requires approval but no TTY or GUI dialog available".into(),
            );
        }

        let cache_key = format!("{}:execute_with_secret:", self.agent_name);
        if self
            .approval_cache
            .lock()
            .is_ok_and(|cache| cache.contains(&cache_key))
        {
            self.append_audit("approval.execute_with_secret.remembered", "", true);
            return Ok(());
        }

        self.append_audit("approval.execute_with_secret.requested", "", true);

        // Go currently puts raw command arguments in the approval prompt.
        // This port intentionally redacts every resolved environment value so
        // a command that repeats an injected value cannot expose it to the UI.
        // Environment names remain visible, sorted by BTreeMap iteration.
        let known_values = environment.values().cloned().collect::<Vec<_>>();
        let safe_command = command
            .iter()
            .map(|argument| {
                symvault_core::redact::redact_known_values(argument, &known_values, "[REDACTED]").0
            })
            .collect::<Vec<_>>();
        let summary = format!(
            "agent {:?} requests to execute command [{}] with secret injection (env vars: [{}])",
            self.agent_name,
            safe_command.join(" "),
            environment.keys().cloned().collect::<Vec<_>>().join(" ")
        );
        let working_dir = std::env::current_dir()
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let approval = self.approval.request(&ApprovalRequest {
            operation: "execute_with_secret".into(),
            details: summary,
            // Go treats an explicitly configured zero timeout like an absent
            // value and falls back to 30 seconds.
            timeout: if self.approval_timeout.is_zero() {
                Duration::from_secs(30)
            } else {
                self.approval_timeout
            },
            agent_name: self.agent_name.clone(),
            working_dir,
            risk_level: RiskLevel::High,
            secrets_accessed: self
                .approval_key_counter
                .load(std::sync::atomic::Ordering::Acquire),
            can_remember: true,
            ..ApprovalRequest::default()
        });
        if let Some(error) = &approval.error {
            // Go records the operation-level denial in the handler, but does
            // not emit approval.execute_with_secret.denied for prompt errors.
            return Err(format!("execute_with_secret approval failed: {error}"));
        }
        if !approval.approved {
            self.append_audit("approval.execute_with_secret.denied", "", false);
            return Err("execute_with_secret denied: user did not approve".into());
        }
        if approval.remembered {
            if let Ok(mut cache) = self.approval_cache.lock() {
                cache.insert(cache_key);
            }
            self.append_audit("approval.execute_with_secret.remembered", "", true);
        }
        self.approval_key_counter
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.append_audit("approval.execute_with_secret.granted", "", true);
        Ok(())
    }

    fn execute_with_secret(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let Some(executor) = &self.command_executor else {
            return Err("execute_with_secret has no configured command executor".into());
        };
        let Some(command_value) = arguments.get("command") else {
            self.append_audit("execute_with_secret", "<invalid:missing-command>", false);
            return Ok(ToolCallResult::error(
                "missing required argument \"command\"",
            ));
        };
        let Some(command_values) = command_value.as_array() else {
            self.append_audit("execute_with_secret", "<invalid:command-not-array>", false);
            return Ok(ToolCallResult::error(
                "argument \"command\" must be an array",
            ));
        };
        if command_values.is_empty() {
            self.append_audit("execute_with_secret", "<invalid:empty-command>", false);
            return Ok(ToolCallResult::error("command array must not be empty"));
        }
        let mut command = Vec::with_capacity(command_values.len());
        for (index, value) in command_values.iter().enumerate() {
            let Some(value) = value.as_str() else {
                self.append_audit("execute_with_secret", "<invalid:command-type>", false);
                return Ok(ToolCallResult::error(format!(
                    "command[{index}] must be a string"
                )));
            };
            command.push(value.to_owned());
        }
        if !self.allowed_executables.is_empty() {
            let executable = Path::new(&command[0])
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            if !self
                .allowed_executables
                .iter()
                .any(|allowed| allowed == &executable)
            {
                self.append_audit("execute_with_secret", &command[0], false);
                return Err(format!(
                    "command execution denied: executable {executable:?} not in agent allowlist"
                ));
            }
        }
        let timeout_seconds = match parse_command_timeout(arguments.get("timeout")) {
            Ok(timeout) => timeout,
            Err(error) => {
                self.append_audit("execute_with_secret", "<invalid:timeout>", false);
                return Ok(ToolCallResult::error(error));
            }
        };
        let Some(refs_value) = arguments.get("secret_refs") else {
            self.append_audit(
                "execute_with_secret",
                "<invalid:missing-secret_refs>",
                false,
            );
            return Ok(ToolCallResult::error(
                "missing required argument \"secret_refs\"",
            ));
        };
        let mut environment = BTreeMap::new();
        let mut secret_values = BTreeMap::new();
        let mut secret_refs = Vec::new();
        let mut ref_names = HashSet::new();
        if !refs_value.is_null() {
            let Some(refs) = refs_value.as_array() else {
                self.append_audit(
                    "execute_with_secret",
                    "<invalid:secret_refs-not-array>",
                    false,
                );
                return Ok(ToolCallResult::error(
                    "argument \"secret_refs\" must be an array",
                ));
            };
            for (index, value) in refs.iter().enumerate() {
                let Some(reference) = value.as_str() else {
                    self.append_audit("execute_with_secret", "<invalid:secret_ref-type>", false);
                    return Ok(ToolCallResult::error(format!(
                        "secret_refs[{index}] must be a string"
                    )));
                };
                let (entry_path, field) = match parse_op_ref(reference) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        self.append_audit("execute_with_secret", reference, false);
                        return Ok(ToolCallResult::error(format!(
                            "invalid secret ref {reference:?}: {error}"
                        )));
                    }
                };
                let generated_name = generate_env_var_name(&entry_path, &field);
                self.authorize_run_secret_path(&entry_path, "execute_with_secret")
                    .map_err(run_files_error)?;
                let resolver_ref = if field.is_empty() {
                    entry_path.clone()
                } else {
                    format!("{entry_path}.{field}")
                };
                let resolved_path = self
                    .inner
                    .resolve_secret_ref_path(&resolver_ref)
                    .map_err(|error| format!("cannot resolve secret ref {reference:?}: {error}"))?;
                self.authorize_run_secret_path(&resolved_path, "execute_with_secret")
                    .map_err(run_files_error)?;
                let value = self
                    .inner
                    .resolve_secret_ref_at_path(&resolver_ref, &resolved_path)
                    .map_err(|error| {
                        self.append_audit("execute_with_secret", reference, false);
                        format!("cannot resolve secret ref {reference:?}: {error}")
                    });
                let value = match value {
                    Ok(value) => value,
                    Err(error) => {
                        let detail = error
                            .strip_prefix("cannot resolve secret ref ")
                            .and_then(|rest| rest.split_once(": ").map(|(_, detail)| detail))
                            .unwrap_or(&error);
                        let detail = detail.strip_prefix("entry not found: ").map_or_else(
                            || detail.to_owned(),
                            |path| format!("secret ref not found: {path}"),
                        );
                        return Ok(ToolCallResult::error(format!(
                            "cannot resolve secret ref {reference:?}: {detail}"
                        )));
                    }
                };
                if !ref_names.insert(generated_name.clone()) {
                    self.append_audit("execute_with_secret", reference, false);
                    return Ok(ToolCallResult::error(format!(
                        "duplicate environment variable name {generated_name:?} from secret ref {reference:?}"
                    )));
                }
                environment.insert(generated_name.clone(), value.clone());
                secret_values.insert(generated_name, value);
                secret_refs.push(reference.to_owned());
            }
        }
        secret_refs.sort();
        if let Some(value) = arguments.get("env_vars").filter(|value| !value.is_null()) {
            let Some(env_vars) = value.as_object() else {
                self.append_audit(
                    "execute_with_secret",
                    "<invalid:env_vars-not-object>",
                    false,
                );
                return Ok(ToolCallResult::error(
                    "argument \"env_vars\" must be an object",
                ));
            };
            for (name, value) in env_vars {
                let Some(value) = value.as_str() else {
                    self.append_audit(
                        "execute_with_secret",
                        "<invalid:env_vars-value-type>",
                        false,
                    );
                    return Ok(ToolCallResult::error(format!(
                        "env_vars.{name} value must be a string"
                    )));
                };
                environment.insert(name.clone(), value.to_owned());
            }
        }
        let denied = denied_env_names(environment.keys());
        if !denied.is_empty() {
            self.append_audit("execute_with_secret", "<validation-denied-env>", false);
            return Ok(ToolCallResult::error(format!(
                "env_vars contains denied keys: {}",
                denied.join(", ")
            )));
        }
        if let Err(error) = self.check_execute_with_secret_approval(&command, &environment) {
            self.append_audit("execute_with_secret", "<approval-denied>", false);
            return Err(error);
        }
        let working_directory = arguments
            .get("working_dir")
            .and_then(Value::as_str)
            .filter(|directory| !directory.is_empty())
            .map(Path::new);
        let files = BTreeMap::new();
        let redactions = secret_values
            .values()
            .filter(|value| !value.is_empty())
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let known_values = secret_values.values().cloned().collect::<Vec<_>>();
        let execution = match executor.run(
            &command,
            &environment,
            &files,
            &redactions,
            working_directory,
            Duration::from_secs(timeout_seconds),
        ) {
            Ok(execution) => execution,
            Err(error) => {
                self.append_audit("execute_with_secret", "<execution-failed>", false);
                let (error, _) =
                    symvault_core::redact::redact_known_values(&error, &known_values, "***");
                return Ok(ToolCallResult::error(error));
            }
        };
        let audit_path = execute_with_secret_audit_path(
            &command,
            &secret_refs,
            &known_values,
            execution.exit_code,
        );
        self.append_audit(
            "execute_with_secret",
            &audit_path,
            execution.exit_code == 0 && !execution.timed_out,
        );
        let (stdout, _) =
            symvault_core::redact::redact_known_values(&execution.stdout, &known_values, "***");
        let (stderr, _) =
            symvault_core::redact::redact_known_values(&execution.stderr, &known_values, "***");
        let stdout = crate::render::sanitize_for_mcp(&stdout);
        let stderr = crate::render::sanitize_for_mcp(&stderr);
        let stdout = crate::render::embed_as_data("command_output", &stdout)
            .map_err(|error| format!("embed command output: {error}"))?;
        let stderr = crate::render::embed_as_data("command_output", &stderr)
            .map_err(|error| format!("embed command output: {error}"))?;
        if execution.timed_out {
            return Ok(ToolCallResult::error(format!(
                "command timed out after {timeout_seconds}s\nExit code: {}\nStdout: {stdout}\nStderr: {stderr}",
                execution.exit_code
            )));
        }
        Ok(ToolCallResult::text(
            symvault_gojson::to_string(&json!({
                "exit_code": execution.exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": execution.duration.as_millis().min(i64::MAX as u128) as i64,
            }))
            .map_err(|error| error.to_string())?,
        ))
    }

    fn execute_api_request(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let Some(name) = arguments.get("template").and_then(Value::as_str) else {
            self.append_audit("execute_api_request", "<invalid:missing-template>", false);
            return Ok(ToolCallResult::error(
                "missing required argument \"template\"",
            ));
        };
        let Some(endpoint) = arguments.get("endpoint").and_then(Value::as_str) else {
            self.append_audit("execute_api_request", "<invalid:missing-endpoint>", false);
            return Ok(ToolCallResult::error(
                "missing required argument \"endpoint\"",
            ));
        };
        let timeout = match api_timeout(arguments.get("timeout")) {
            Ok(timeout) => timeout,
            Err(error) => {
                self.append_audit("execute_api_request", "<invalid:timeout>", false);
                return Ok(ToolCallResult::error(error));
            }
        };
        let definition = match load_api_template_definition(&self.share_root, name) {
            Ok(definition) => definition,
            Err(error) => {
                self.append_audit(
                    "execute_api_request",
                    &format!("<template-error:{name}>"),
                    false,
                );
                return Ok(ToolCallResult::error(format!(
                    "cannot load template {name:?}: {error}"
                )));
            }
        };

        if let Err(error) = validate_api_template_definition(&definition) {
            self.append_audit(
                "execute_api_request",
                &format!("<template-error:{name}>"),
                false,
            );
            return Ok(ToolCallResult::error(format!(
                "cannot load template {name:?}: {error}"
            )));
        }
        let method = arguments
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let body = arguments
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let endpoint = match normalize_api_endpoint(endpoint) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                self.append_audit("execute_api_request", "<invalid:endpoint>", false);
                return Ok(ToolCallResult::error(format!(
                    "invalid endpoint {endpoint:?}: {error}"
                )));
            }
        };
        let runtime_template = ApiTemplate {
            base_url: definition.base_url,
            allowed_endpoints: definition.allowed_endpoints,
            allowed_methods: definition.allowed_methods,
            default_headers: definition.default_headers,
            allow_private: definition.allow_private,
        };
        if let Err(error) = broker::validate_api_request(&runtime_template, &method, &endpoint) {
            let audit_target = if error == "method not allowed by template" {
                format!("<method-denied:{name}>")
            } else if error == "endpoint not allowed by template" {
                format!("<endpoint-denied:{name}>")
            } else {
                format!("<blocked-target:{name}>")
            };
            self.append_audit("execute_api_request", &audit_target, false);
            return Ok(ToolCallResult::error(match error.as_str() {
                "method not allowed by template" => format!("method not allowed: {method}"),
                "endpoint not allowed by template" => {
                    format!("endpoint not allowed: {endpoint}")
                }
                _ => error,
            }));
        }

        if let Err(error) = self.check_execute_api_request_approval() {
            self.append_audit("execute_api_request", "<approval-denied>", false);
            return Err(error);
        }

        let entry_path = match api_entry_path(&definition.entry_ref) {
            Ok(path) => path,
            Err(error) => {
                self.append_audit(
                    "execute_api_request",
                    &format!("<template-error:{name}>"),
                    false,
                );
                return Ok(ToolCallResult::error(format!(
                    "invalid entry_ref for {name:?}: {error}"
                )));
            }
        };
        if !self.inner.scope_allows(&entry_path) {
            self.append_audit(
                "execute_api_request",
                &format!("<scope-denied:{name}>"),
                false,
            );
            return Err(format!(
                "access denied: template entry path {entry_path:?} outside allowed scope"
            ));
        }

        // Security hardening pending Go alignment: path-less Go API arguments
        // bypass entry policy. Reuse the command secret-use authorization boundary
        // before resolving the template entry's credentials.
        self.authorize_run_secret_path(&entry_path, "execute_api_request")
            .map_err(run_files_error)?;

        // Resolve only after scope, policy and approval. The accessor returns
        // the authorized entry projection and response-redaction strings.
        let (entry_fields, mut known_values) = self
            .inner
            .resolve_api_entry_at_path(&entry_path)
            .map_err(|error| {
                self.append_audit(
                    "execute_api_request",
                    &format!("<vault-error:{name}>"),
                    false,
                );
                format!("cannot load credentials for {name:?}: {error}")
            })?;

        let substitutions =
            match resolve_api_substitutions(&definition.substitutions, &entry_fields) {
                Ok(values) => values,
                Err(error) => {
                    self.append_audit(
                        "execute_api_request",
                        &format!("<substitution-error:{name}>"),
                        false,
                    );
                    return Ok(ToolCallResult::error(format!(
                        "cannot resolve substitutions for {name:?}: {error}"
                    )));
                }
            };
        let mut request_url = api_request_url(
            &runtime_template.base_url,
            &endpoint,
            &definition.substitutions,
            &substitutions,
        )?;
        let request_body =
            apply_api_body_substitutions(&body, &definition.substitutions, &substitutions);
        let mut request_headers = runtime_template.default_headers.clone();
        let caller_headers = match arguments.get("headers") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::Object(headers)) => {
                let mut parsed = BTreeMap::new();
                for (key, value) in headers {
                    let Some(value) = value.as_str() else {
                        self.append_audit(
                            "execute_api_request",
                            "<invalid:header-value-not-string>",
                            false,
                        );
                        return Ok(ToolCallResult::error(format!(
                            "headers[{key:?}] must be a string"
                        )));
                    };
                    parsed.insert(key.clone(), value.to_owned());
                }
                parsed
            }
            Some(_) => {
                self.append_audit("execute_api_request", "<invalid:headers-not-object>", false);
                return Ok(ToolCallResult::error(
                    "argument \"headers\" must be an object",
                ));
            }
        };
        overlay_api_headers(&mut request_headers, caller_headers);
        apply_api_header_substitutions(
            &mut request_headers,
            &definition.substitutions,
            &substitutions,
        );
        let (auth_header, auth_query) = match api_auth(&definition.auth_type, &entry_fields) {
            Ok(auth) => auth,
            Err(error) => {
                self.append_audit(
                    "execute_api_request",
                    &format!("<auth-error:{name}>"),
                    false,
                );
                return Ok(ToolCallResult::error(format!(
                    "cannot resolve auth for {name:?}: {error}"
                )));
            }
        };
        if let Some((header, value)) = auth_header {
            set_api_header(&mut request_headers, &header, value);
        }
        if let Some((key, value)) = auth_query {
            request_url = set_api_query_parameter(&request_url, &key, &value)?;
            known_values.push(api_query_escape(&value));
            known_values.extend(api_query_substitution_redaction_values(
                &runtime_template.base_url,
                &endpoint,
                &definition.substitutions,
                &substitutions,
            )?);
        }
        for value in substitutions.values() {
            known_values.extend(api_substitution_redaction_values(value));
        }
        if definition.auth_type == "basic"
            && let (Some(user), Some(password)) = (
                entry_fields.get("username").and_then(Value::as_str),
                api_field(&entry_fields, &["credential", "password"]),
            )
        {
            known_values.push(BASE64_STANDARD.encode(format!("{user}:{password}")));
        }
        if !request_body.is_empty()
            && !request_headers
                .keys()
                .any(|key| key.eq_ignore_ascii_case("content-type"))
        {
            request_headers.insert("Content-Type".into(), "application/json".into());
        }
        // The broker's generic transport merges defaults after supplied values.
        // API requests already applied Go's defaults -> caller -> substitutions
        // -> auth order, so pass the merged headers once and no remaining defaults.
        let transport_template = ApiTemplate {
            default_headers: BTreeMap::new(),
            ..runtime_template.clone()
        };

        #[cfg(test)]
        tests::API_REVIEW_REQUESTS.with(|count| count.set(count.get() + 1));
        let response = match broker::execute_http_for_api(
            &transport_template,
            &method,
            &endpoint,
            &request_url,
            &request_headers,
            request_body.as_bytes(),
            broker::ApiResponseBounds {
                timeout,
                response_limit: broker::API_RESPONSE_LIMIT,
            },
        ) {
            Ok(response) => response,
            Err(error) => {
                self.append_audit(
                    "execute_api_request",
                    &format!("template={name}, endpoint={endpoint}, method={method}, status=error"),
                    false,
                );
                return Ok(ToolCallResult::error(format!("request failed: {error}")));
            }
        };
        let raw_body = go_json_text(&response.body);
        let (body, body_sanitized) = sanitize_api_value(&raw_body, &known_values);
        let mut headers = response.headers;
        let mut header_sanitized = false;
        for value in headers.values_mut() {
            let (sanitized, changed) = sanitize_api_value(value, &known_values);
            *value = sanitized;
            header_sanitized |= changed;
        }
        let content_type = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        let response_sanitized = response.sanitized || body_sanitized || header_sanitized;
        if response_sanitized {
            self.append_audit(
                "execute_api_request",
                &format!(
                    "template={name}, endpoint={endpoint}, method={method}, status={}, sanitized=true",
                    response.status
                ),
                true,
            );
        }
        let ok = response.status < 400;
        self.append_audit(
            "execute_api_request",
            &format!(
                "template={name}, endpoint={endpoint}, method={method}, status={}",
                response.status
            ),
            ok,
        );
        let text = symvault_gojson::to_string(&json!({
            "status_code": response.status,
            "headers": headers,
            "body": body,
            "body_truncated": response.body_truncated,
            "content_type": content_type,
        }))
        .map_err(|error| format!("marshal API response: {error}"))?;
        Ok(ToolCallResult::text(text))
    }

    fn check_execute_api_request_approval(&self) -> Result<(), String> {
        let mode = if self.approval_mode.is_empty() {
            if self.require_approval {
                "prompt"
            } else {
                "none"
            }
        } else {
            self.approval_mode.as_str()
        };
        match mode {
            "none" | "auto" => Ok(()),
            "deny" => {
                self.append_audit("approval.execute_api_request.denied", "", false);
                Err("execute_api_request denied: approval mode is 'deny'".into())
            }
            "prompt" => {
                if !self.approval_queue_attached && !self.approval.is_tty_present() {
                    self.append_audit("approval.execute_api_request.denied", "", false);
                    return Err(
                        "execute_api_request requires approval but no TTY or GUI dialog available"
                            .into(),
                    );
                }
                self.append_audit("approval.execute_api_request.requested", "", true);
                let request = ApprovalRequest {
                    operation: "execute_api_request".into(),
                    details: format!(
                        "agent {:?} requests to execute an API request",
                        self.agent_name
                    ),
                    timeout: if self.approval_timeout.is_zero() {
                        Duration::from_secs(30)
                    } else {
                        self.approval_timeout
                    },
                    agent_name: self.agent_name.clone(),
                    working_dir: std::env::current_dir()
                        .map(|directory| directory.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    risk_level: RiskLevel::Critical,
                    secrets_accessed: self
                        .approval_key_counter
                        .load(std::sync::atomic::Ordering::Acquire),
                    can_remember: false,
                    ..ApprovalRequest::default()
                };
                if self.approval_queue_attached {
                    if let Err(error) = self.inner.request_approval_queue(
                        "execute_api_request",
                        "",
                        true,
                        "agent API request requires approval",
                    ) {
                        if error.contains("denied") || error.contains("expired") {
                            self.append_audit("approval.execute_api_request.denied", "", false);
                        }
                        return Err(error);
                    }
                } else {
                    let outcome = self.approval.request(&request);
                    if let Some(error) = outcome.error {
                        return Err(format!("execute_api_request approval failed: {error}"));
                    }
                    if !outcome.approved {
                        self.append_audit("approval.execute_api_request.denied", "", false);
                        return Err("execute_api_request denied: user did not approve".into());
                    }
                }
                self.approval_key_counter
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                self.append_audit("approval.execute_api_request.granted", "", true);
                Ok(())
            }
            _ => {
                self.append_audit("approval.execute_api_request.denied", "", false);
                Err(format!(
                    "execute_api_request denied: unknown approval mode {mode:?}"
                ))
            }
        }
    }

    fn resolve_run_command_files(
        &self,
        raw: Option<&Value>,
    ) -> Result<ResolvedRunFiles, RunFilesError> {
        let mut files = ResolvedRunFiles::default();
        let Some(raw) = raw.filter(|value| !value.is_null()) else {
            return Ok(files);
        };
        let Some(file_map) = raw.as_object() else {
            self.append_audit("run_command", "<invalid>", false);
            return Err(RunFilesError::Tool(
                "argument \"files\" must be an object".into(),
            ));
        };

        let mut audit = Vec::with_capacity(file_map.len());
        for (name, spec) in file_map {
            let (reference, encoding) = parse_run_file_spec(spec)
                .map_err(|message| RunFilesError::Tool(format!("files.{name}: {message}")))?;
            let candidate_path = extract_path_from_secret_ref(&reference);
            self.authorize_run_secret_path(&candidate_path, "run_command")?;
            let path = self
                .inner
                .resolve_secret_ref_path(&reference)
                .map_err(|error| {
                    RunFilesError::Tool(format!("cannot resolve secret ref {reference:?}: {error}"))
                })?;
            self.authorize_run_secret_path(&path, "run_command")?;
            let source = self
                .inner
                .resolve_secret_ref_at_path(&reference, &path)
                .map_err(|error| {
                    RunFilesError::Tool(format!("cannot resolve secret ref {reference:?}: {error}"))
                })?;
            let content = if encoding == "base64" {
                BASE64_STANDARD.decode(source.as_bytes()).map_err(|_| {
                    RunFilesError::Tool(format!(
                        "files.{name}: cannot base64-decode resolved value"
                    ))
                })?
            } else {
                source.as_bytes().to_vec()
            };
            if !source.is_empty() {
                files.redactions.push(source.as_bytes().to_vec());
            }
            if !content.is_empty() && content != source.as_bytes() {
                files.redactions.push(content.clone());
            }
            files.content.insert(name.clone(), content);
            audit.push(format!("{name}:{reference}"));
        }
        audit.sort();
        files.audit = audit;
        Ok(files)
    }

    fn authorize_run_secret_path(&self, path: &str, tool_name: &str) -> Result<(), RunFilesError> {
        if !self.inner.scope_allows(path) {
            self.append_audit("scope_denied", path, false);
            return Err(RunFilesError::Denied(format!(
                "access denied: secret ref path {path:?} outside allowed scope"
            )));
        }
        if let Some(policy) = &self.policy {
            let result = policy.evaluate(EvalContext {
                agent_id: self.agent_name.clone(),
                path: path.to_owned(),
                action_type: "run".into(),
                tool_name: tool_name.into(),
                ..EvalContext::default()
            });
            if !result.matched || result.action != Action::Allow {
                self.append_audit("policy_denied", path, false);
                return Err(RunFilesError::Denied(if !result.matched {
                    "policy: no matching rule (default deny)".into()
                } else {
                    format!("policy denied by rule {:?}", result.rule_name)
                }));
            }
        }
        Ok(())
    }

    /// Supplies the caller-owned key without copying it into public runtime config.
    pub fn with_grant_signing_key(mut self, key: SecretBytes) -> Self {
        self.grant_signing_key = Some(key);
        self
    }

    /// Injects the CLI-owned secret resolver and child-process runner.
    #[must_use]
    pub fn with_command_executor(mut self, executor: Arc<dyn CommandExecutor>) -> Self {
        self.command_executor = Some(executor);
        self
    }

    fn request_share(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let required = |name| {
            crate::call::required_string(arguments, name).inspect_err(|_| {
                self.append_audit("share_request", "<invalid>", false);
            })
        };
        let to_agent = match required("to_agent") {
            Ok(value) => value,
            Err(error) => return Ok(error),
        };
        let path = match required("secret_path") {
            Ok(value) => value,
            Err(error) => return Ok(error),
        };
        // Go's unseal handler misses path scope because it receives a handle;
        // derive the path here so a handle cannot bypass the agent boundary.
        if !self.inner.scope_allows(path) {
            self.append_audit("share_request", path, false);
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }
        let field = arguments
            .get("secret_field")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ttl_text = arguments.get("ttl").and_then(Value::as_str).unwrap_or("");
        let ttl = if ttl_text.is_empty() {
            0
        } else {
            match symvault_core::config::parse_go_duration(ttl_text) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(ToolCallResult::error(format!(
                        "invalid ttl {ttl_text:?}: {error}"
                    )));
                }
            }
        };
        if ttl < 0 {
            return Ok(ToolCallResult::error("ttl must be a positive duration"));
        }
        let now = self
            .now_unix
            .and_then(|unix| OffsetDateTime::from_unix_timestamp(unix).ok())
            .unwrap_or_else(OffsetDateTime::now_utc)
            .format(&Rfc3339)
            .map_err(|error| format!("format share clock: {error}"))?;
        let grant = self
            .share_store
            .lock()
            .map_err(|_| "share store lock poisoned".to_owned())?
            .create_at(
                &self.share_root,
                &self.agent_name,
                to_agent,
                path,
                field,
                ttl,
                &now,
                self.grant_signing_key.as_ref().map(SecretBytes::as_bytes),
            )
            .map_err(|error| format!("failed to create share grant: {error}"))?;
        self.append_audit("share_request", path, true);
        symvault_gojson::to_string(&serde_json::json!({
            "grant_id": grant.id,
            "status": grant.status,
            "from_agent": grant.from_agent,
            "to_agent": grant.to_agent,
            "secret_path": grant.secret_path,
        }))
        .map(ToolCallResult::text)
        .map_err(|error| error.to_string())
    }

    /// Go's `handleApproveShare`: a pending grant is only ever approved after a
    /// human answers the controlling-terminal prompt, and the agent that
    /// requested the share can never approve it. A non-approval answer rejects
    /// the grant instead of leaving it pending.
    fn approve_share(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let grant_id = match crate::call::required_string(arguments, "grant_id") {
            Ok(value) => value,
            Err(error) => {
                self.append_audit("share_approve", "<invalid>", false);
                return Ok(error);
            }
        };

        let quoted =
            || serde_json::to_string(grant_id).unwrap_or_else(|_| format!("\"{grant_id}\""));
        let grant = {
            let share_store = self
                .share_store
                .lock()
                .map_err(|_| "share store lock poisoned".to_owned())?;
            share_store
                .grants()
                .iter()
                .find(|grant| grant.id == grant_id)
                .cloned()
        };
        let Some(grant) = grant else {
            self.append_audit("share_approve", grant_id, false);
            return Ok(ToolCallResult::error(format!(
                "share grant {} not found",
                quoted()
            )));
        };
        if grant.status != "pending" {
            return Ok(ToolCallResult::error(format!(
                "share grant {} is not pending (status: {})",
                quoted(),
                grant.status
            )));
        }
        // Reject self-approval before any prompt is rendered: the agent that
        // requested the share cannot also answer for the human.
        if self.agent_name == grant.from_agent {
            self.append_audit("share_approve_denied", &grant.secret_path, false);
            return Ok(ToolCallResult::error(
                "the requesting agent cannot approve its own share request",
            ));
        }
        if !self.approval.is_tty_present() {
            self.append_audit("share_approve", &grant.secret_path, false);
            return Ok(ToolCallResult::error(
                "cannot approve share: no TTY available for human confirmation",
            ));
        }

        let short_id: String = grant.id.chars().take(8).collect();
        let mut details = format!(
            "Share {short_id}: {} → {}, path: {}\nAgent requesting approval: {}",
            grant.from_agent, grant.to_agent, grant.secret_path, self.agent_name
        );
        if !grant.secret_field.is_empty() {
            details.push_str(&format!(", field: {}", grant.secret_field));
        }
        if grant.ttl > 0 {
            details.push_str(&format!(
                ", ttl: {}",
                format_go_duration(Duration::from_nanos(u64::try_from(grant.ttl).unwrap_or(0)))
            ));
        }

        let approval = self.approval.request(&ApprovalRequest {
            operation: "approve_share".into(),
            details,
            timeout: SHARE_APPROVAL_TIMEOUT,
            ..ApprovalRequest::default()
        });
        if let Some(error) = &approval.error {
            self.append_audit("share_approve", &grant.secret_path, false);
            return Ok(ToolCallResult::error(format!("approval failed: {error}")));
        }

        let now = self
            .now_unix
            .and_then(|unix| OffsetDateTime::from_unix_timestamp(unix).ok())
            .unwrap_or_else(OffsetDateTime::now_utc)
            .format(&Rfc3339)
            .map_err(|error| format!("format approval clock: {error}"))?;
        let mut share_store = self
            .share_store
            .lock()
            .map_err(|_| "share store lock poisoned".to_owned())?;
        if approval.approved {
            // Go records the deciding agent when one exists, otherwise "human".
            let approved_by = if self.agent_name.is_empty() {
                "human"
            } else {
                self.agent_name.as_str()
            };
            share_store
                .approve_at_for_agent(
                    &self.share_root,
                    grant_id,
                    &self.agent_name,
                    approved_by,
                    &now,
                )
                .map_err(|error| format!("failed to approve share grant: {error}"))?;
            self.append_audit("share_approve", &grant.secret_path, true);
            return Ok(ToolCallResult::text(format!(
                "Share grant {grant_id} approved"
            )));
        }

        share_store
            .reject_at(&self.share_root, grant_id)
            .map_err(|error| format!("failed to reject share grant: {error}"))?;
        self.append_audit("share_reject", &grant.secret_path, true);
        Ok(ToolCallResult::text(format!(
            "Share grant {grant_id} rejected"
        )))
    }

    fn list_shares(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let share_store = self
            .share_store
            .lock()
            .map_err(|_| "share store lock poisoned".to_owned())?;
        render_list_shares(&share_store, &self.agent_name, arguments)
    }

    fn revoke_share(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let grant_id = match crate::call::required_string(arguments, "grant_id") {
            Ok(value) => value,
            Err(error) => {
                self.append_audit("share_revoke", "<invalid>", false);
                return Ok(error);
            }
        };
        let now = self
            .now_unix
            .and_then(|unix| OffsetDateTime::from_unix_timestamp(unix).ok())
            .unwrap_or_else(OffsetDateTime::now_utc)
            .format(&Rfc3339)
            .map_err(|error| format!("format revoke clock: {error}"))?;
        let mut share_store = self
            .share_store
            .lock()
            .map_err(|_| "share store lock poisoned".to_owned())?;
        match share_store.revoke_at_for_agent(&self.share_root, grant_id, &self.agent_name, &now) {
            Ok(grant) => {
                self.append_audit("share_revoke", &grant.secret_path, true);
                Ok(ToolCallResult::text(format!(
                    "Share grant {grant_id} revoked"
                )))
            }
            Err(StoreError::Config(message)) if message.starts_with("only the source agent ") => {
                Ok(ToolCallResult::error(message))
            }
            Err(StoreError::Config(message))
                if message == format!("share grant {grant_id} not found") =>
            {
                self.append_audit("share_revoke", grant_id, false);
                let quoted =
                    serde_json::to_string(grant_id).unwrap_or_else(|_| format!("\"{grant_id}\""));
                Ok(ToolCallResult::error(format!(
                    "share grant {quoted} not found"
                )))
            }
            Err(StoreError::Config(message)) => Ok(ToolCallResult::error(format!(
                "failed to revoke share grant: {message}"
            ))),
            Err(error) => Ok(ToolCallResult::error(format!(
                "failed to revoke share grant: {error}"
            ))),
        }
    }

    fn secret_unseal(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let handle_text = match crate::call::required_string(arguments, "handle") {
            Ok(handle) => handle,
            Err(result) => {
                self.append_audit("secret_unseal", "<invalid>", false);
                return Ok(result);
            }
        };
        let Some(handle) = SecretHandle::parse(handle_text) else {
            self.append_audit("secret_unseal", handle_text, false);
            return Ok(ToolCallResult::error(format!(
                "invalid handle format: {handle_text}"
            )));
        };
        if handle.field.is_none() {
            self.append_audit("secret_unseal", &handle.path, false);
            return Ok(ToolCallResult::error(
                "secret_unseal requires a field handle",
            ));
        }
        let path = handle.path.as_str();
        let entry_path = handle
            .field
            .as_deref()
            .map_or_else(|| path.to_owned(), |field| format!("{path}/{field}"));
        if !self.inner.scope_allows(path) {
            self.append_audit("secret_unseal", &entry_path, false);
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }

        let handle_key = format!("{}:secret_unseal:{handle_text}", self.agent_name);
        let is_remembered = self
            .approval_cache
            .lock()
            .is_ok_and(|cache| cache.contains(&handle_key));
        if !is_remembered {
            let mode = if self.approval_mode.is_empty() {
                if self.require_approval {
                    "prompt"
                } else {
                    "none"
                }
            } else {
                self.approval_mode.as_str()
            };
            let remember_handle = match mode {
                "none" | "auto" => false,
                "deny" => {
                    self.append_audit("approval.secret_unseal.denied", &entry_path, false);
                    self.append_audit("secret_unseal", &entry_path, false);
                    return Ok(ToolCallResult::error(
                        "secret_unseal denied: approval mode is 'deny'",
                    ));
                }
                "prompt" => match self.request_secret_unseal_approval(&entry_path) {
                    Ok(remembered) => remembered,
                    Err(error) => {
                        self.append_audit("secret_unseal", &entry_path, false);
                        return Ok(ToolCallResult::error(error));
                    }
                },
                _ => {
                    self.append_audit("secret_unseal", &entry_path, false);
                    return Ok(ToolCallResult::error(
                        "secret_unseal denied: invalid approval mode",
                    ));
                }
            };
            if remember_handle {
                if let Ok(mut cache) = self.approval_cache.lock() {
                    cache.insert(handle_key);
                }
                self.append_audit("secret_unseal_remembered", &entry_path, true);
            }
        }

        let result = self.inner.secret_unseal(&handle)?;
        if !result.is_error {
            self.append_audit("secret_unseal", &entry_path, true);
        } else if !result.text.starts_with("max secrets per session exceeded") {
            self.append_audit("secret_unseal", &entry_path, false);
        }
        Ok(result)
    }

    fn request_secret_unseal_approval(&self, path: &str) -> Result<bool, String> {
        let path_key = format!(
            "{}:secret_unseal:{}",
            self.agent_name,
            normalize_scope_path(path)
        );
        let path_remembered = self
            .approval_cache
            .lock()
            .is_ok_and(|cache| cache.contains(&path_key));
        if path_remembered {
            self.append_audit("approval.secret_unseal.remembered", path, true);
            return Ok(true);
        }
        if !self.approval.is_tty_present() {
            self.append_audit("approval.secret_unseal.denied", path, false);
            return Err(
                "secret_unseal requires approval but no TTY or GUI dialog available".into(),
            );
        }
        self.append_audit("approval.secret_unseal.requested", path, true);
        let details = path
            .chars()
            .filter(|character| !character.is_control())
            .collect::<String>();
        let approval = self.approval.request(&ApprovalRequest {
            operation: "secret_unseal".into(),
            details: format!("unseal secret on {details}"),
            agent_name: self.agent_name.clone(),
            risk_level: RiskLevel::High,
            secrets_accessed: self
                .approval_key_counter
                .load(std::sync::atomic::Ordering::Acquire),
            can_remember: true,
            ..ApprovalRequest::default()
        });
        if let Some(error) = &approval.error {
            return Err(format!("secret_unseal approval failed: {error}"));
        }
        if !approval.approved {
            self.append_audit("approval.secret_unseal.denied", path, false);
            return Err("secret_unseal denied: user did not approve".into());
        }
        if approval.remembered {
            if let Ok(mut cache) = self.approval_cache.lock() {
                cache.insert(path_key);
            }
            self.append_audit("approval.secret_unseal.remembered", path, true);
        }
        self.approval_key_counter
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.append_audit("approval.secret_unseal.granted", path, true);
        Ok(approval.remembered)
    }

    fn audit_target(name: &str, arguments: &Value) -> String {
        match name {
            "fetch" => arguments
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("<invalid>")
                .to_owned(),
            "search" => arguments
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("<invalid>")
                .to_owned(),
            "secret_unseal" => arguments
                .get("handle")
                .and_then(Value::as_str)
                .and_then(SecretHandle::parse)
                .map(|handle| match handle.field {
                    Some(field) => format!("{}/{field}", handle.path),
                    None => handle.path,
                })
                .unwrap_or_else(|| "<invalid>".into()),
            _ => arguments
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(name)
                .to_owned(),
        }
    }

    fn authorize_policy(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        let handle_path = (name == "secret_unseal")
            .then(|| arguments.get("handle").and_then(Value::as_str))
            .flatten()
            .and_then(SecretHandle::parse)
            .map(|handle| handle.path);
        let path = match name {
            "fetch" => arguments.get("id").and_then(Value::as_str),
            "secret_unseal" => handle_path.as_deref(),
            _ => arguments.get("path").and_then(Value::as_str),
        }
        .unwrap_or_default();
        // Go's executeTool evaluates policy only after extracting a non-empty
        // entry path. `health`, `symaira_whoami`, and query-only `search`/find
        // therefore bypass the path policy. Fetch uses `id`; applying the
        // configured get policy there is intentionally stricter than the Go
        // middleware's path-only extraction and prevents an ID-based bypass.
        if path.is_empty() {
            return Ok(());
        }
        let action_type = match name {
            "list_entries" => "list",
            "find_entries" => "find",
            "get_entry" | "get_entry_value" | "get_entry_metadata" | "secret_unseal" | "fetch" => {
                "get"
            }
            "set_entry_field" | "secure_input" | "request_credential" => "set",
            "delete_entry" | "symaira_delete" => "delete",
            "run_command" | "execute_with_secret" | "execute_api_request" => "run",
            "generate_password" | "generate_totp" | "generate_template" => "generate",
            _ => "read",
        };
        let result = policy.evaluate(EvalContext {
            agent_id: self.agent_name.clone(),
            path: path.to_owned(),
            action_type: action_type.to_owned(),
            tool_name: name.to_owned(),
            ..EvalContext::default()
        });
        if result.matched && result.action == Action::Allow {
            return Ok(());
        }
        self.append_audit("policy_denied", path, false);
        Err(ToolCallResult::error(format!(
            "policy denied tool {name:?}{}",
            if result.rule_name.is_empty() {
                String::new()
            } else {
                format!(" by rule {:?}", result.rule_name)
            }
        )))
    }

    fn audit_self(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        // Go accepts a positive numeric limit, truncates fractions, caps at
        // 100, and falls back to 50 for missing/invalid/non-positive values.
        let limit = arguments
            .get("limit")
            .and_then(|value| match value {
                Value::Number(number) => number.as_f64(),
                Value::String(value) => value.parse::<f64>().ok(),
                _ => None,
            })
            .filter(|value| *value > 0.0)
            .map(|value| (value as usize).min(100))
            .unwrap_or(50);

        let Some(audit) = &self.audit else {
            return Ok(ToolCallResult::text("[]"));
        };
        let path = audit
            .lock()
            .map_err(|_| "audit logger lock poisoned".to_owned())?
            .path()
            .to_owned();
        let file = match symvault_sync::safeio::open_read(&path) {
            Ok(Some(file)) => file,
            Ok(None) => return Ok(ToolCallResult::text("[]")),
            Err(error) => {
                return Ok(ToolCallResult::error(format!(
                    "cannot read audit log: {error}"
                )));
            }
        };

        #[derive(serde::Serialize)]
        struct AuditEvent {
            #[serde(rename = "ts")]
            timestamp: String,
            tool: String,
            #[serde(skip_serializing_if = "String::is_empty")]
            path: String,
            status: String,
            #[serde(skip_serializing_if = "String::is_empty")]
            code: String,
        }

        let mut events = VecDeque::with_capacity(limit);
        let mut saw_event = false;
        let mut reader = BufReader::new(file);
        let mut raw_line = Vec::with_capacity(GO_SCANNER_MAX_TOKEN_SIZE);
        loop {
            raw_line.clear();
            let has_line = match read_scan_line(&mut reader, &mut raw_line) {
                Ok(bytes_read) => bytes_read,
                Err(error) => {
                    return Ok(ToolCallResult::error(format!(
                        "error reading audit log: {error}"
                    )));
                }
            };
            if !has_line {
                break;
            }
            if raw_line.last() == Some(&b'\n') {
                raw_line.pop();
            }
            if raw_line.last() == Some(&b'\r') {
                raw_line.pop();
            }
            let line = go_json_text(&raw_line);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<GoAuditEntry>(line) else {
                continue;
            };
            saw_event = true;
            let entry = entry.0;
            let event = AuditEvent {
                timestamp: entry.timestamp,
                tool: entry.action,
                path: entry.path,
                status: if entry.ok { "ok" } else { "error" }.into(),
                code: entry.reason,
            };
            if limit > 0 {
                if events.len() == limit {
                    events.pop_front();
                }
                events.push_back(event);
            }
        }
        if !saw_event {
            return Ok(ToolCallResult::text("null"));
        }
        symvault_gojson::to_string(&events)
            .map(ToolCallResult::text)
            .map_err(|error| error.to_string())
    }
}

// Reuse the complete audit schema: even fields omitted from the response must
// reject invalid types as Go does. Visit in wire order so duplicate/case-folded
// fields and null (which leaves the earlier value unchanged) match Go.
struct GoAuditEntry(symvault_store::audit::LogEntry);

impl<'de> serde::Deserialize<'de> for GoAuditEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = GoAuditEntry;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an audit entry object or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(GoAuditEntry(Default::default()))
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut entry = symvault_store::audit::LogEntry::default();
                while let Some(key) = map.next_key::<String>()? {
                    macro_rules! field {
                        ($name:ident) => {
                            if let Some(value) = map.next_value()? {
                                entry.$name = value;
                            }
                        };
                    }
                    let key: String = key
                        .chars()
                        .map(|ch| match ch {
                            'ſ' => 's',
                            'K' => 'k',
                            _ => ch.to_ascii_lowercase(),
                        })
                        .collect();
                    match key.as_str() {
                        "ts" => field!(timestamp),
                        "agent" => field!(agent),
                        "action" => field!(action),
                        "path" => field!(path),
                        "field" => field!(field),
                        "transport" => field!(transport),
                        "reason" => field!(reason),
                        "share_id" => field!(share_id),
                        "from_agent" => field!(from_agent),
                        "to_agent" => field!(to_agent),
                        "share_action" => field!(share_action),
                        "dur_ms" => field!(dur_ms),
                        "token_id" => field!(token_id),
                        "req_id" => field!(request_id),
                        "sess_id" => field!(session_id),
                        "kid" => field!(kid),
                        "hmac" => field!(hmac),
                        "argv_hash" => field!(argv_hash),
                        "ok" => field!(ok),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(GoAuditEntry(entry))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// Match encoding/json's replacement policy: each invalid UTF-8 byte becomes
/// U+FFFD, including each byte in a truncated multi-byte sequence.
fn go_json_text(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                output.push_str(text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                // Utf8Error guarantees the prefix before valid_up_to is UTF-8.
                output.push_str(
                    std::str::from_utf8(&remaining[..valid])
                        .expect("valid UTF-8 prefix before decoding error"),
                );
                output.push('\u{FFFD}');
                remaining = &remaining[valid + 1..];
            }
        }
    }
    output
}

const GO_SCANNER_MAX_TOKEN_SIZE: usize = 64 * 1024;

/// Read one ScanLines token without allowing a hostile audit file to grow the
/// buffer beyond Go's default Scanner limit. The returned bytes retain the
/// delimiter so the caller can apply ScanLines' CRLF trimming.
fn read_scan_line<R: BufRead>(reader: &mut R, line: &mut Vec<u8>) -> std::io::Result<bool> {
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            if line.is_empty() {
                return Ok(false);
            }
            if line.len() >= GO_SCANNER_MAX_TOKEN_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bufio.Scanner: token too long",
                ));
            }
            return Ok(true);
        }
        let take = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |index| index + 1);
        if line.len() + take > GO_SCANNER_MAX_TOKEN_SIZE
            || (line.len() + take == GO_SCANNER_MAX_TOKEN_SIZE && chunk[take - 1] != b'\n')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bufio.Scanner: token too long",
            ));
        }
        let has_newline = chunk[take - 1] == b'\n';
        line.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if has_newline {
            return Ok(true);
        }
    }
}

impl ToolCallRuntime for StoreReadOnlyRuntime {
    fn authorize(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult> {
        if let Err(error) = self.inner.authorize(name, arguments) {
            let path = Self::audit_target(name, arguments);
            if !self.unavailable_tools.iter().any(|tool| tool == name) {
                self.append_audit("tool_denied", &path, false);
            }
            return Err(error);
        }
        self.authorize_policy(name, arguments)?;
        Ok(())
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String> {
        // Go registers rate limiting as a pre-call hook. It runs only after
        // tool availability, argument decoding, and authorization have
        // succeeded, and hook failures are returned as handler errors so the
        // protocol emits JSON-RPC -32603. Keep the check here rather than in
        // authorize: callers may inspect authorization without dispatching a
        // call, and denied/unknown tools must not consume the window.
        if let Some(limit) = self.rate_limit_denied() {
            return Err(format!(
                "rate limit exceeded: max {limit} requests per minute"
            ));
        }
        let mut approval_failed = false;
        let result = if matches!(name, "set_entry_field" | "delete_entry" | "symaira_delete")
            && !self.approval_queue_attached
        {
            let mut approve = |tool: &str, path: &str, field: Option<&str>, mode: &str| {
                let result = self.approve_write(tool, path, field, mode);
                approval_failed = result.is_err();
                result
            };
            self.inner
                .call_with_write_approval(name, arguments, &mut approve)
        } else if matches!(name, "secure_input" | "request_credential") {
            self.secure_input_tool(name, arguments)
        } else if name == "symaira_audit_self" {
            self.audit_self(arguments)
        } else if name == "list_shares" {
            self.list_shares(arguments)
        } else if name == "request_share" {
            self.request_share(arguments)
        } else if name == "approve_share" {
            self.approve_share(arguments)
        } else if name == "revoke_share" {
            self.revoke_share(arguments)
        } else if name == "secret_unseal" {
            self.secret_unseal(arguments)
        } else if name == "execute_with_secret" {
            self.execute_with_secret(arguments)
        } else if name == "execute_api_request" {
            self.execute_api_request(arguments)
        } else if name == "copy_to_clipboard" {
            self.copy_to_clipboard(arguments)
        } else if name == "run_command" {
            self.run_command(arguments)
        } else {
            self.inner.call(name, arguments)
        };
        match name {
            "symaira_audit_self" => {}
            "generate_template" => {
                if let Some(kind) = arguments
                    .get("template_type")
                    .and_then(Value::as_str)
                    .filter(|kind| !kind.is_empty())
                {
                    let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                    self.append_audit(
                        if ok {
                            "template_generated"
                        } else {
                            "template_failed"
                        },
                        kind,
                        ok,
                    );
                }
            }
            "sanitize_output" => {
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit(
                    "sanitize_output",
                    if ok { "<scan>" } else { "<invalid>" },
                    ok,
                );
            }
            "generate_password" => {
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("generate", "password", ok);
            }
            "generate_totp" => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("generate_totp", path, ok);
            }
            "set_entry_field" if !approval_failed => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("set", path, ok);
            }
            "delete_entry" if !approval_failed => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("delete", path, ok);
            }
            "list_entries" => {
                let prefix = arguments
                    .get("prefix")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("list", prefix, ok);
            }
            "find_entries" => {
                let path = arguments
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("find", path, ok);
            }
            "get_entry" => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("get", path, ok);
            }
            "get_entry_value" => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("get_value", path, ok);
            }
            "get_entry_metadata" => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("get_metadata", path, ok);
            }
            "search" => {
                let query = arguments
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("search_openai", query, ok);
            }
            "fetch" => {
                let id = arguments
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("fetch_openai", id, ok);
            }
            "list_shares" => {
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("share_list", "", ok);
            }
            "run_command" => {}
            _ => {}
        }
        result
    }
}

impl StoreReadOnlyRuntime {
    fn copy_to_clipboard(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let preflight = match self.inner.clipboard_preflight(arguments) {
            Ok(preflight) => preflight,
            Err(SecureInputPreflightError::Tool(result)) => {
                self.append_audit("copy_to_clipboard", "<invalid>", false);
                return Ok(result);
            }
            Err(SecureInputPreflightError::Handler(error)) => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<clipboard-denied>");
                self.append_audit("copy_to_clipboard", path, false);
                return Err(error);
            }
        };

        if self.approval_queue_attached
            && write_approval_decision(&preflight.approval_mode) == WriteApprovalDecision::Prompt
        {
            self.append_audit(
                "approval.copy_to_clipboard.requested",
                &preflight.path,
                true,
            );
            if let Err(error) = self.inner.request_approval_queue(
                "copy_to_clipboard",
                &preflight.path,
                true,
                "copy password to clipboard",
            ) {
                if error.contains("denied") || error.contains("expired") {
                    self.append_audit("approval.copy_to_clipboard.denied", &preflight.path, false);
                }
                return Err(error);
            }
            self.approval_key_counter
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.append_audit("approval.copy_to_clipboard.granted", &preflight.path, true);
        } else {
            self.approve_write(
                "copy_to_clipboard",
                &preflight.path,
                None,
                &preflight.approval_mode,
            )?;
        }

        let password = match self.inner.clipboard_password(&preflight.path) {
            Ok(password) => password,
            Err(error) => {
                self.append_audit("copy_to_clipboard", &preflight.path, false);
                return Err(error);
            }
        };
        if password.is_error {
            self.append_audit("copy_to_clipboard", &preflight.path, false);
            return Ok(password);
        }
        if let Err(error) = self.clipboard.set(password.text.as_bytes()) {
            self.append_audit("copy_to_clipboard", &preflight.path, false);
            return Ok(ToolCallResult::error(format!(
                "clipboard copy failed: {error}"
            )));
        }
        self.start_clipboard_auto_clear();
        self.append_audit("copy_to_clipboard", &preflight.path, true);
        Ok(ToolCallResult::text(r#"{"success": true}"#))
    }

    fn start_clipboard_auto_clear(&self) {
        if self.clipboard_auto_clear_duration.is_zero() {
            return;
        }
        let (cancel, receiver) = mpsc::channel();
        if let Ok(mut active) = self.clipboard_clear_cancel.lock() {
            if let Some(previous) = active.replace(cancel.clone()) {
                let _ = previous.send(());
            }
        } else {
            return;
        }
        let clipboard = Arc::clone(&self.clipboard);
        let delay = self.clipboard_auto_clear_duration;
        let clear_claimed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(unix)]
        let signal_registration = approval_prompt::register_stdio_clipboard_auto_clear(
            cancel.clone(),
            Arc::clone(&clear_claimed),
        );
        thread::spawn(move || {
            #[cfg(unix)]
            let _signal_registration = signal_registration;
            if matches!(
                receiver.recv_timeout(delay),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) && !clear_claimed.swap(true, std::sync::atomic::Ordering::AcqRel)
            {
                let _ = clipboard.clear();
            }
        });
    }

    fn secure_input_tool(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String> {
        let audit_path = arguments
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("<invalid>");
        let preflight = match self.inner.secure_input_preflight(arguments) {
            Ok(preflight) => preflight,
            Err(SecureInputPreflightError::Tool(result)) => {
                self.append_audit(name, audit_path, false);
                return Ok(result);
            }
            Err(SecureInputPreflightError::Handler(error)) => {
                self.append_audit(name, audit_path, false);
                return Err(error);
            }
        };

        if let Err(error) = self.approve_write(
            name,
            &preflight.path,
            Some(&preflight.field),
            &preflight.approval_mode,
        ) {
            return Ok(ToolCallResult::error(error));
        }
        if !self.secure_input.is_tty_present() {
            self.append_audit(name, &preflight.path, false);
            return Err("secure input unavailable on this host (no controlling TTY)".into());
        }

        let title = if name == "request_credential" {
            "Symaira Vault: Agent requesting credential"
        } else {
            "Symaira Vault: Secure Input"
        };
        let request = SecureInputRequest {
            title: title.into(),
            path: preflight.path.clone(),
            field: preflight.field.clone(),
            description: preflight.description,
            timeout: Duration::from_secs(60),
        };
        let value = match self.secure_input.prompt(&request) {
            Ok(value) => value.trim().to_owned(),
            Err(SecureInputError::Canceled) => {
                self.append_audit(name, &preflight.path, false);
                return Ok(ToolCallResult::error("secure input canceled by user"));
            }
            Err(SecureInputError::Timeout) => {
                self.append_audit(name, &preflight.path, false);
                return Ok(ToolCallResult::error("secure input timed out"));
            }
            Err(SecureInputError::Empty) => {
                self.append_audit(name, &preflight.path, false);
                return Ok(ToolCallResult::error(
                    "secure input canceled: empty value provided",
                ));
            }
            Err(SecureInputError::NoTty) => {
                self.append_audit(name, &preflight.path, false);
                return Err("secure input unavailable on this host (no controlling TTY)".into());
            }
            Err(error) => {
                self.append_audit(name, &preflight.path, false);
                return Err(format!("secure input failed: {error}"));
            }
        };
        if value.is_empty() {
            self.append_audit(name, &preflight.path, false);
            return Ok(ToolCallResult::error(
                "secure input canceled: empty value provided",
            ));
        }
        let result = self
            .inner
            .store_secure_input(&preflight.path, &preflight.field, &value);
        self.append_audit(name, &preflight.path, result.is_ok());
        result
    }
}

fn render_list_shares(
    share_store: &ShareStore,
    agent_name: &str,
    arguments: &Value,
) -> Result<ToolCallResult, String> {
    let filter = ShareFilter {
        status: arguments
            .get("status")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        from_agent: arguments
            .get("from_agent")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        to_agent: arguments
            .get("to_agent")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        secret_path: arguments
            .get("secret_path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    };
    let grants = share_store.list_for_agent_filtered(agent_name, Some(&filter));
    symvault_gojson::to_string(&grants)
        .map(ToolCallResult::text)
        .map_err(|error| error.to_string())
}

fn store_error(error: StoreError) -> String {
    error.to_string()
}

/// Strip the ANSI/OSC and control bytes Go removes before rendering an
/// approval summary. User-controlled paths and field names are terminal text,
/// never escape sequences.
fn sanitize_approval_summary(input: &str) -> String {
    // Port Go's byte-oriented stripTerminalControl state machine. Iterating
    // UTF-8 bytes preserves its C1 behavior and its treatment of simple ESC,
    // OSC backslashes, and the TAB/LF/CR exceptions.
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut state = 0_u8;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match state {
            0 => match byte {
                0x1b if bytes.get(index + 1) == Some(&b'[') => {
                    state = 2;
                    index += 1;
                }
                0x1b if bytes.get(index + 1) == Some(&b']') => {
                    state = 3;
                    index += 1;
                }
                0x1b => {}
                byte if byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r') => {}
                0x7f => {}
                byte => output.push(byte),
            },
            2 => {
                if !(byte == b'[' || byte == b';' || byte.is_ascii_digit()) {
                    state = 0;
                }
            }
            3 => {
                if byte == 0x07 || byte == b'\\' {
                    state = 0;
                }
            }
            _ => unreachable!("approval-summary sanitizer state"),
        }
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn format_go_secret_map(values: &BTreeMap<String, Value>) -> String {
    let values = values
        .iter()
        .map(|(key, value)| format!("{key}:{}", format_go_secret_value(value)))
        .collect::<Vec<_>>();
    format!("map[{}]", values.join(" "))
}

fn format_go_secret_value(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(format_go_secret_value)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::Object(values) => format!(
            "map[{}]",
            values
                .iter()
                .map(|(key, value)| format!("{key}:{}", format_go_secret_value(value)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

/// The connected handlers in this bounded runtime. The catalog remains owned by
/// the protocol layer; this list is the injected availability registry used
/// by authorization and whoami.
pub fn read_only_tool_names() -> Vec<String> {
    [
        "generate_template",
        "symaira_search",
        "search",
        "fetch",
        "sanitize_output",
        "get_auth_status",
        "symaira_audit_self",
        "health",
        "symaira_whoami",
        "list_entries",
        "generate_password",
        "generate_totp",
        "copy_to_clipboard",
        "set_entry_field",
        "delete_entry",
        "find_entries",
        "get_entry",
        "get_entry_value",
        "get_entry_metadata",
        "secret_unseal",
        "run_command",
        "symaira_delete",
        "list_shares",
        "approve_share",
        "revoke_share",
        "request_share",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn parse_command_timeout(value: Option<&Value>) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(30);
    };
    let number = match value {
        Value::Number(number) => number
            .as_f64()
            .ok_or_else(|| "argument \"timeout\" must be numeric".to_owned())?,
        Value::String(string) => string
            .parse::<f64>()
            .map_err(|_| "argument \"timeout\" must be numeric".to_owned())?,
        _ => return Err("argument \"timeout\" must be numeric".into()),
    };
    if !number.is_finite() {
        return Err("argument \"timeout\" must be a finite number".into());
    }
    if number.fract() != 0.0 {
        return Err("argument \"timeout\" must be a whole number of seconds".into());
    }
    if !(1.0..=300.0).contains(&number) {
        return Err("argument \"timeout\" must be between 1 and 300 seconds".into());
    }
    Ok(number as u64)
}

fn api_timeout(value: Option<&Value>) -> Result<Duration, String> {
    let Some(value) = value else {
        return Ok(Duration::from_secs(30));
    };
    let number = match value {
        Value::Number(number) => number
            .as_f64()
            .ok_or_else(|| "argument \"timeout\" must be numeric".to_owned())?,
        Value::String(string) => string
            .parse::<f64>()
            .map_err(|_| "argument \"timeout\" must be numeric".to_owned())?,
        _ => return Err("argument \"timeout\" must be numeric".into()),
    };
    if !number.is_finite() {
        return Err("argument \"timeout\" must be a finite number".into());
    }
    if number.fract() != 0.0 {
        return Err("argument \"timeout\" must be a whole number of seconds".into());
    }
    Ok(Duration::from_secs((number as u64).clamp(1, 300)))
}

fn normalize_api_endpoint(endpoint: &str) -> Result<String, String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err("endpoint is required".into());
    }
    if !endpoint.starts_with('/') {
        return Err("endpoint must start with '/'".into());
    }
    let mut decoded = Vec::with_capacity(endpoint.len());
    let bytes = endpoint.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("invalid URL encoding".into());
            }
            let Some(high) = (bytes[index + 1] as char).to_digit(16) else {
                return Err("invalid URL encoding".into());
            };
            let Some(low) = (bytes[index + 2] as char).to_digit(16) else {
                return Err("invalid URL encoding".into());
            };
            decoded.push(((high << 4) | low) as u8);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8_lossy(&decoded);
    if [endpoint, decoded.as_ref()]
        .iter()
        .any(|path| path.split('/').any(|part| part == "." || part == ".."))
    {
        return Err("dot-segments are not allowed".into());
    }
    let trailing_slash = endpoint.ends_with('/');
    let mut components = Vec::new();
    for component in endpoint.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value),
        }
    }
    let mut normalized = format!("/{}", components.join("/"));
    if trailing_slash && normalized != "/" {
        normalized.push('/');
    }
    Ok(normalized)
}

fn validate_api_template_definition(definition: &ApiTemplateDefinition) -> Result<(), String> {
    if definition.base_url.is_empty() {
        return Err("base_url is required".into());
    }
    if definition.auth_type.is_empty() {
        return Err("auth_type is required".into());
    }
    if definition.entry_ref.trim().is_empty() {
        return Err("entry_ref is required".into());
    }
    // Unknown auth names are parsed by Go too; api_auth reports them only after
    // approval and the scoped entry read. The template's remaining structure
    // is still validated here.
    if definition.auth_type == "none" && definition.substitutions.is_empty() {
        return Err("auth_type \"none\" requires at least one substitution".into());
    }
    let mut seen = HashSet::new();
    for (index, substitution) in definition.substitutions.iter().enumerate() {
        let label = format!("substitutions[{index}]");
        let placeholder = substitution.placeholder.as_str();
        let has_alnum = placeholder.bytes().any(|byte| byte.is_ascii_alphanumeric());
        let has_delimiter = placeholder.contains("__")
            || placeholder
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_');
        if placeholder.len() < 4
            || !placeholder
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
            || !has_alnum
            || !has_delimiter
        {
            return Err(format!("{label}: invalid placeholder {placeholder:?}"));
        }
        if !seen.insert(placeholder) {
            return Err(format!("{label}: duplicate placeholder {placeholder:?}"));
        }
        if substitution.field.is_empty() {
            return Err(format!(
                "{label}: field is required for placeholder {placeholder:?}"
            ));
        }
        if substitution
            .surfaces
            .iter()
            .any(|surface| !matches!(surface.as_str(), "path" | "query" | "header" | "body"))
        {
            return Err(format!("{label}: unsupported substitution surface"));
        }
    }
    Ok(())
}

fn api_entry_path(reference: &str) -> Result<String, String> {
    let path = reference.trim();
    if path.is_empty() {
        return Err("entry_ref is required".into());
    }
    let path = if let Some(reference) = path.strip_prefix("op://") {
        let parts = reference.split('/').collect::<Vec<_>>();
        if parts.len() < 2 {
            return Err("expected at least vault/entry".into());
        }
        if parts.len() > 2 {
            return Err("entry_ref must reference an entry, not a field".into());
        }
        parts[1]
    } else {
        path
    };
    if path.is_empty() {
        return Err("entry_ref must reference an entry".into());
    }
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("entry_ref must be a normalized vault entry path".into());
    }
    Ok(path.to_owned())
}

fn substitution_surfaces(substitution: &ApiSubstitution) -> &[String] {
    &substitution.surfaces
}

fn substitution_applies(substitution: &ApiSubstitution, surface: &str) -> bool {
    substitution.surfaces.is_empty() && matches!(surface, "path" | "query")
        || substitution_surfaces(substitution)
            .iter()
            .any(|item| item == surface)
}

fn resolve_api_substitutions(
    substitutions: &[ApiSubstitution],
    fields: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    for substitution in substitutions {
        let value = fields
            .get(&substitution.field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "no value for placeholder {:?} (expected vault entry field {:?})",
                    substitution.placeholder, substitution.field
                )
            })?;
        values.insert(substitution.placeholder.clone(), value.to_owned());
    }
    Ok(values)
}

fn api_request_url(
    base_url: &str,
    endpoint: &str,
    substitutions: &[ApiSubstitution],
    values: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&format!("{}{}", base_url.trim_end_matches('/'), endpoint))
        .map_err(|_| "invalid template URL")?;
    let mut path = url.path().to_owned();
    let mut query = url.query().unwrap_or_default().to_owned();
    for substitution in substitutions {
        let Some(value) = values.get(&substitution.placeholder) else {
            continue;
        };
        if substitution_applies(substitution, "path") {
            path = path.replace(&substitution.placeholder, value);
        }
        if substitution_applies(substitution, "query") {
            query = query.replace(&substitution.placeholder, value);
        }
    }
    url.set_path(&path);
    if !query.is_empty() || url.query().is_some() {
        url.set_query(Some(&query));
    }
    Ok(url.to_string())
}

fn apply_api_body_substitutions(
    body: &str,
    substitutions: &[ApiSubstitution],
    values: &BTreeMap<String, String>,
) -> String {
    let mut body = body.to_owned();
    for substitution in substitutions {
        if substitution_applies(substitution, "body")
            && let Some(value) = values.get(&substitution.placeholder)
        {
            body = body.replace(&substitution.placeholder, value);
        }
    }
    body
}

fn apply_api_header_substitutions(
    headers: &mut BTreeMap<String, String>,
    substitutions: &[ApiSubstitution],
    values: &BTreeMap<String, String>,
) {
    for substitution in substitutions {
        if substitution_applies(substitution, "header")
            && let Some(value) = values.get(&substitution.placeholder)
        {
            for header in headers.values_mut() {
                *header = header.replace(&substitution.placeholder, value);
            }
        }
    }
}

fn overlay_api_headers(target: &mut BTreeMap<String, String>, incoming: BTreeMap<String, String>) {
    for (name, value) in incoming {
        set_api_header(target, &name, value);
    }
}

fn set_api_header(headers: &mut BTreeMap<String, String>, name: &str, value: String) {
    headers.retain(|existing, _| !existing.eq_ignore_ascii_case(name));
    headers.insert(name.to_owned(), value);
}

fn api_field<'a>(fields: &'a BTreeMap<String, Value>, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        fields
            .get(*name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    })
}

type ApiAuthHeader = Option<(String, String)>;
type ApiAuthQuery = Option<(String, String)>;
type ApiAuthResult = Result<(ApiAuthHeader, ApiAuthQuery), String>;

fn api_auth(auth_type: &str, fields: &BTreeMap<String, Value>) -> ApiAuthResult {
    match auth_type {
        "bearer" => {
            let token = api_field(fields, &["credential", "token", "password"])
                .ok_or_else(|| "no bearer token found in vault entry (expected fields: credential, token, or password)".to_owned())?;
            Ok((
                Some(("Authorization".into(), format!("Bearer {token}"))),
                None,
            ))
        }
        "basic" => {
            let username = api_field(fields, &["username"]);
            let password = api_field(fields, &["credential", "password"]);
            let (Some(username), Some(password)) = (username, password) else {
                return Err(
                    "basic auth requires username and password fields in vault entry".into(),
                );
            };
            Ok((
                Some((
                    "Authorization".into(),
                    format!(
                        "Basic {}",
                        BASE64_STANDARD.encode(format!("{username}:{password}"))
                    ),
                )),
                None,
            ))
        }
        "header" => {
            let name = api_field(fields, &["header_name"]);
            let value = api_field(fields, &["header_value", "credential", "token", "password"]);
            let (Some(name), Some(value)) = (name, value) else {
                return Err("header auth requires header_name and header_value (or credential/token/password) fields in vault entry".into());
            };
            Ok((Some((name.to_owned(), value.to_owned())), None))
        }
        "query_param" => {
            let name = api_field(fields, &["param_name"]);
            let value = api_field(fields, &["param_value", "credential", "token", "password"]);
            let (Some(name), Some(value)) = (name, value) else {
                return Err("query_param auth requires param_name and param_value (or credential/token/password) fields in vault entry".into());
            };
            Ok((None, Some((name.to_owned(), value.to_owned()))))
        }
        "none" => Ok((None, None)),
        other => Err(format!("unsupported auth type: {other}")),
    }
}

fn set_api_query_parameter(url: &str, name: &str, value: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(url).map_err(|_| "invalid template URL")?;
    let mut pairs = BTreeMap::<String, Vec<String>>::new();
    for (key, value) in url.query_pairs() {
        pairs
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    pairs.insert(name.to_owned(), vec![value.to_owned()]);
    let encoded = pairs
        .into_iter()
        .flat_map(|(key, values)| values.into_iter().map(move |value| (key.clone(), value)))
        .map(|(key, value)| format!("{}={}", api_query_escape(&key), api_query_escape(&value)))
        .collect::<Vec<_>>()
        .join("&");
    url.set_query(Some(&encoded));
    Ok(url.to_string())
}

fn api_query_escape(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            b' ' => "+".into(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

// Go net/url.PathEscape preserves these reserved path-segment bytes.
fn api_path_escape(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'$'
            | b'&'
            | b'+'
            | b':'
            | b'='
            | b'@' => (byte as char).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

// Go URL.EscapedPath additionally preserves slash, comma and semicolon.
fn api_escaped_path(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'$'
            | b'&'
            | b'+'
            | b':'
            | b'='
            | b'@'
            | b'/'
            | b','
            | b';' => (byte as char).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn api_substitution_redaction_values(value: &str) -> Vec<String> {
    // Preserve Go escaping while covering the URL serializer used by the request.
    let mut url = reqwest::Url::parse("http://localhost/").expect("static URL");
    url.set_path(&format!("/{value}"));
    let path = url
        .path()
        .strip_prefix('/')
        .unwrap_or(url.path())
        .to_owned();
    // A placeholder suffix makes trailing dot-segments literal. Retain this
    // contextual spelling as well as the standalone normalized path.
    url.set_path(&format!("/{value}x"));
    let suffixed_path = url
        .path()
        .strip_prefix('/')
        .unwrap_or(url.path())
        .strip_suffix('x')
        .unwrap_or_default()
        .to_owned();
    url.set_query(Some(value));
    // Keep earlier, more aggressively escaped forms for upstream re-encoding.
    let query = api_query_escape(value);
    let percent_encoded = query.replace('+', "%20");
    vec![
        value.to_owned(),
        percent_encoded.replace("%2F", "/"),
        percent_encoded,
        query,
        api_path_escape(value),
        api_escaped_path(value),
        path,
        suffixed_path,
        url.query().unwrap_or_default().to_owned(),
    ]
}

fn api_query_substitution_redaction_values(
    base_url: &str,
    endpoint: &str,
    substitutions: &[ApiSubstitution],
    values: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    // Reuse the request renderer without substitutions to retain the actual
    // template query, including literal percent bytes bordering placeholders.
    let mut url = reqwest::Url::parse(&api_request_url(base_url, endpoint, &[], &BTreeMap::new())?)
        .map_err(|_| "invalid template URL")?;
    let template_query = url.query().unwrap_or_default().to_owned();
    let mut known = Vec::new();
    for pair in template_query.split('&') {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        let mut tainted = false;
        let mut tainted_key = false;
        let mut rendered = pair.to_owned();
        for substitution in substitutions {
            if substitution_applies(substitution, "query")
                && let Some(value) = values.get(&substitution.placeholder)
            {
                tainted |= pair.contains(&substitution.placeholder);
                tainted_key |= key.contains(&substitution.placeholder);
                rendered = rendered.replace(&substitution.placeholder, value);
            }
        }
        if !tainted {
            continue;
        }
        // Decode complete rendered fields and mirror query authentication's
        // Go encoding. An injected '=' or '&' can taint both keys and values;
        // unrelated query fields and the original non-secret key stay public.
        url.set_query(Some(&rendered));
        for (index, (key, value)) in url.query_pairs().enumerate() {
            if tainted_key || index != 0 {
                known.push(api_query_escape(&key));
            }
            known.push(api_query_escape(&value));
        }
    }
    Ok(known)
}

fn sanitize_api_value(text: &str, known_values: &[String]) -> (String, bool) {
    let (known_sanitized, exact_count) =
        symvault_core::redact::redact_known_values(text, known_values, "***");
    let mut scanner = symvault_core::redact::Scanner::new(vec![Box::new(
        symvault_core::redact::PatternDetector::new().with_marker("***"),
    )]);
    match scanner.scan(
        &known_sanitized,
        &symvault_core::redact::ScanOptions::default(),
    ) {
        Ok(result) => {
            let changed = exact_count > 0 || result.text != known_sanitized;
            (result.text, changed)
        }
        Err(error) => {
            let safe = error.safe_result.text;
            (safe, true)
        }
    }
}

fn parse_run_file_spec(raw: &Value) -> Result<(String, &str), String> {
    match raw {
        Value::String(reference) => Ok((reference.clone(), "")),
        Value::Object(spec) => {
            let reference = spec
                .get("ref")
                .and_then(Value::as_str)
                .filter(|reference| !reference.is_empty())
                .ok_or_else(|| "missing required \"ref\" string".to_owned())?;
            let encoding = match spec.get("encoding") {
                None | Some(Value::Null) => "",
                Some(Value::String(encoding)) => encoding.as_str(),
                Some(_) => return Err("\"encoding\" must be a string".into()),
            };
            if !encoding.is_empty() && encoding != "base64" {
                return Err(format!(
                    "unsupported encoding {encoding:?} (supported: base64)"
                ));
            }
            Ok((reference.to_owned(), encoding))
        }
        _ => {
            Err("must be a string secret reference or {\"ref\":...,\"encoding\":...} object".into())
        }
    }
}

fn extract_path_from_secret_ref(reference: &str) -> String {
    reference.rfind('.').filter(|index| *index > 0).map_or_else(
        || reference.to_owned(),
        |index| reference[..index].to_owned(),
    )
}

fn denied_env_names<'a>(names: impl Iterator<Item = &'a String>) -> Vec<String> {
    const DENIED: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "NODE_OPTIONS",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "BASH_ENV",
        "ENV",
        "RUBYOPT",
        "PERL5OPT",
        "PERL5LIB",
        "PATH",
    ];
    let mut denied = names
        .filter(|name| DENIED.contains(&name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    denied.sort();
    denied
}

fn parse_op_ref(reference: &str) -> Result<(String, String), &'static str> {
    let Some(reference) = reference.strip_prefix("op://") else {
        return Err("expected op:// prefix");
    };
    let parts = reference.split('/').collect::<Vec<_>>();
    if parts.len() < 2 {
        return Err("expected at least vault/entry");
    }
    if parts.len() == 2 {
        return Ok((parts[1].to_owned(), String::new()));
    }
    Ok((
        parts[1..parts.len() - 1].join("/"),
        parts[parts.len() - 1].to_owned(),
    ))
}

fn generate_env_var_name(entry_path: &str, field: &str) -> String {
    let mut parts = entry_path.split('/').map(str::to_owned).collect::<Vec<_>>();
    if !field.is_empty() {
        parts.push(field.to_owned());
    }
    parts
        .iter()
        .map(|part| {
            part.chars()
                .map(|character| {
                    let code = character as u32;
                    let uppercase = go_unicode_15::SIMPLE_UPPER
                        .binary_search_by_key(&code, |(source, _)| *source)
                        .ok()
                        .and_then(|index| char::from_u32(go_unicode_15::SIMPLE_UPPER[index].1))
                        .unwrap_or(character);
                    if go_unicode15_contains(go_unicode_15::LETTER_RANGES, uppercase)
                        || go_unicode15_contains(go_unicode_15::DECIMAL_DIGIT_RANGES, uppercase)
                        || uppercase == '_'
                    {
                        uppercase
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("_")
}

fn go_unicode15_contains(ranges: &[(u32, u32)], character: char) -> bool {
    let code = character as u32;
    let index = ranges.partition_point(|(_, end)| *end < code);
    ranges
        .get(index)
        .is_some_and(|(start, end)| *start <= code && code <= *end)
}

fn execute_with_secret_audit_path(
    command: &[String],
    secret_refs: &[String],
    known_values: &[String],
    exit_code: i32,
) -> String {
    let redacted_command = command
        .iter()
        .map(|argument| {
            symvault_core::redact::redact_known_values(argument, known_values, "[REDACTED]").0
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "command=[{redacted_command}], refs=[{}], exit={exit_code}",
        secret_refs.join(" ")
    )
}

fn run_files_error(error: RunFilesError) -> String {
    match error {
        RunFilesError::Tool(message) | RunFilesError::Denied(message) => message,
    }
}

pub fn unavailable_tool(
    name: impl Into<String>,
    code: impl Into<String>,
    reason: impl Into<String>,
) -> ReadOnlyUnavailableTool {
    ReadOnlyUnavailableTool {
        name: name.into(),
        code: code.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::ApprovalSeam;
    use super::{
        MCP_RATE_LIMIT_WINDOW, MinuteRateLimiter, StoreReadOnlyRuntime, denied_env_names,
        execute_with_secret_audit_path, generate_env_var_name, parse_command_timeout,
        parse_run_file_spec, render_list_shares,
    };
    use crate::approval::ApprovalQueue;
    use crate::{CommandExecution, CommandExecutor, ReadOnlyRuntimeConfig, ToolCallRuntime};
    use serde_json::{Value, json};
    use std::time::{Duration, Instant};
    use std::{
        collections::BTreeMap,
        fs,
        path::Path,
        sync::{Arc, Mutex},
    };
    use symvault_platform::approval::{ApprovalRequest, ApprovalResult, RiskLevel};
    use symvault_store::{Entry, Store, sharing::ShareStore};
    use tempfile::tempdir;

    #[test]
    fn rate_limit_window_starts_on_first_call_and_resets_without_sleep() {
        let start = Instant::now();
        let mut limiter = MinuteRateLimiter {
            limit: 1,
            window_started: start,
            count: 0,
        };

        assert!(limiter.allow_at(start), "first call starts the window");
        assert!(!limiter.allow_at(start + Duration::from_secs(1)));
        assert!(limiter.allow_at(start + MCP_RATE_LIMIT_WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn list_shares_applies_go_agent_scope_then_exact_filters() {
        let dir = tempdir().expect("external test temp directory");
        let path = dir.path().canonicalize().unwrap().join("mcp-shares.json");
        fs::write(
            &path,
            r#"{"version":1,"grants":[{"id":"one","from_agent":"alice","to_agent":"bob","secret_path":"prod/a","status":"pending","created_at":"2026-01-02T03:04:05Z"},{"id":"two","from_agent":"alice","to_agent":"charlie","secret_path":"prod/b","status":"approved","created_at":"2026-01-02T03:04:05Z"},{"id":"three","from_agent":"mallory","to_agent":"eve","secret_path":"prod/c","status":"approved","created_at":"2026-01-02T03:04:05Z"}]}"#,
        )
        .expect("write Go-shaped share fixture");
        let shares = ShareStore::read(&path).expect("read share fixture");

        let all = render_list_shares(&shares, "alice", &json!({})).expect("list shares");
        let all_json: serde_json::Value = serde_json::from_str(&all.text).expect("JSON result");
        assert_eq!(all_json.as_array().expect("array").len(), 2);
        assert!(
            all_json
                .as_array()
                .expect("array")
                .iter()
                .all(|grant| grant["from_agent"] == "alice")
        );

        let filtered = render_list_shares(
            &shares,
            "alice",
            &json!({"status":"approved", "to_agent":"charlie"}),
        )
        .expect("filtered list shares");
        let filtered_json: serde_json::Value =
            serde_json::from_str(&filtered.text).expect("filtered JSON result");
        assert_eq!(filtered_json.as_array().expect("array").len(), 1);
        assert_eq!(filtered_json[0]["id"], "two");

        // GetString in Go defaults non-string values to empty filters.
        let invalid = render_list_shares(&shares, "alice", &json!({"status":true}))
            .expect("invalid filter defaults");
        let invalid_json: serde_json::Value =
            serde_json::from_str(&invalid.text).expect("invalid-filter JSON result");
        assert_eq!(invalid_json.as_array().expect("array").len(), 2);
    }

    struct FakeCommandExecutor;

    impl CommandExecutor for FakeCommandExecutor {
        fn run(
            &self,
            command: &[String],
            environment: &BTreeMap<String, String>,
            files: &BTreeMap<String, Vec<u8>>,
            additional_redactions: &[Vec<u8>],
            working_directory: Option<&Path>,
            timeout: Duration,
        ) -> Result<CommandExecution, String> {
            assert_eq!(command, ["sh", "-c", "echo ok"]);
            assert_eq!(
                environment,
                &BTreeMap::from([("TOKEN".into(), "synthetic-secret".into())])
            );
            assert_eq!(working_directory, None);
            assert!(files.is_empty());
            assert_eq!(additional_redactions, [b"synthetic-secret".to_vec()]);
            assert_eq!(timeout, Duration::from_secs(30));
            Ok(CommandExecution {
                stdout: "ok\n".into(),
                stderr: String::new(),
                exit_code: 0,
                timed_out: false,
                duration: Duration::from_millis(7),
            })
        }
    }

    struct FileCommandExecutor {
        expected_files: BTreeMap<String, Vec<u8>>,
        expected_redactions: Vec<Vec<u8>>,
    }

    struct SecretCommandExecutor;

    impl CommandExecutor for SecretCommandExecutor {
        fn run(
            &self,
            command: &[String],
            environment: &BTreeMap<String, String>,
            files: &BTreeMap<String, Vec<u8>>,
            additional_redactions: &[Vec<u8>],
            working_directory: Option<&Path>,
            timeout: Duration,
        ) -> Result<CommandExecution, String> {
            assert_eq!(command, ["sh", "-c", "echo ok"]);
            assert_eq!(
                environment,
                &BTreeMap::from([
                    ("GITHUB_PASSWORD".into(), "synthetic-secret".into()),
                    ("PLAIN".into(), "literal-value".into()),
                ])
            );
            assert!(files.is_empty());
            assert_eq!(additional_redactions, [b"synthetic-secret".to_vec()]);
            assert_eq!(working_directory, None);
            assert_eq!(timeout, Duration::from_secs(30));
            Ok(CommandExecution {
                stdout: "synthetic-secret\n".into(),
                stderr: "synthetic-secret\n".into(),
                exit_code: 0,
                timed_out: false,
                duration: Duration::from_millis(7),
            })
        }
    }

    impl CommandExecutor for FileCommandExecutor {
        fn run(
            &self,
            command: &[String],
            environment: &BTreeMap<String, String>,
            files: &BTreeMap<String, Vec<u8>>,
            additional_redactions: &[Vec<u8>],
            working_directory: Option<&Path>,
            timeout: Duration,
        ) -> Result<CommandExecution, String> {
            assert_eq!(command, ["sh", "-c", "echo ok"]);
            assert!(environment.is_empty());
            assert_eq!(files, &self.expected_files);
            assert_eq!(additional_redactions, self.expected_redactions);
            assert_eq!(working_directory, None);
            assert_eq!(timeout, Duration::from_secs(30));
            Ok(CommandExecution {
                stdout: "ok\n".into(),
                stderr: String::new(),
                exit_code: 0,
                timed_out: false,
                duration: Duration::from_millis(1),
            })
        }
    }

    #[test]
    fn execute_with_secret_resolves_op_refs_overlays_env_and_masks_outputs() {
        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        Store::open(directory.path(), &identity)
            .expect("open temporary vault")
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([("password".into(), json!("synthetic-secret"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write source-shaped secret entry");
        let config = ReadOnlyRuntimeConfig {
            available_tools: vec!["execute_with_secret".into()],
            can_run_commands: true,
            allowed_executables: vec!["sh".into()],
            allowed_paths: vec!["github".into()],
            ..ReadOnlyRuntimeConfig::default()
        };
        let runtime = StoreReadOnlyRuntime::open(directory.path(), identity, config, None, None)
            .expect("runtime")
            .with_command_executor(Arc::new(SecretCommandExecutor));
        let arguments = json!({
            "command": ["sh", "-c", "echo ok"],
            "secret_refs": ["op://vault/github/password"],
            "env_vars": {"PLAIN": "literal-value"},
            "timeout": 30
        });

        runtime
            .authorize("execute_with_secret", &arguments)
            .expect("authorized");
        let result = runtime
            .call("execute_with_secret", &arguments)
            .expect("dispatch");
        assert!(!result.is_error, "{}", result.text);
        let output: serde_json::Value = serde_json::from_str(&result.text).expect("JSON result");
        assert_eq!(output["exit_code"], 0);
        assert_eq!(output["duration_ms"], 7);
        assert!(output["stdout"].as_str().unwrap().contains("***"));
        assert!(output["stderr"].as_str().unwrap().contains("***"));
        assert!(!result.text.contains("synthetic-secret"));
    }

    #[test]
    fn execute_with_secret_fails_closed_for_duplicate_names_and_prompt_approval() {
        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        Store::open(directory.path(), &identity)
            .expect("open temporary vault")
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([("password".into(), json!("synthetic-secret"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write source-shaped secret entry");
        let base_config = ReadOnlyRuntimeConfig {
            available_tools: vec!["execute_with_secret".into()],
            can_run_commands: true,
            allowed_executables: vec!["sh".into()],
            allowed_paths: vec!["github".into()],
            ..ReadOnlyRuntimeConfig::default()
        };
        let runtime =
            StoreReadOnlyRuntime::open(directory.path(), identity, base_config.clone(), None, None)
                .expect("runtime")
                .with_command_executor(Arc::new(SecretCommandExecutor));
        let duplicate = json!({
            "command": ["sh", "-c", "echo ok"],
            "secret_refs": ["op://vault/github/password", "op://vault/github/password"]
        });
        assert!(
            runtime
                .call("execute_with_secret", &duplicate)
                .unwrap()
                .text
                .contains("duplicate environment variable name")
        );

        let prompt_directory = tempdir().expect("temporary prompt vault");
        fs::create_dir(prompt_directory.path().join("entries")).expect("entries directory");
        fs::write(
            prompt_directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(
            prompt_directory.path().join("identity.age"),
            b"fixture marker",
        )
        .expect("identity marker");
        let prompt_identity = symvault_crypto::generate_identity();
        Store::open(prompt_directory.path(), &prompt_identity)
            .expect("open prompt vault")
            .write_new_entry(
                "github",
                &Entry {
                    path: "github".into(),
                    data: BTreeMap::from([("password".into(), json!("synthetic-secret"))]),
                    ..Entry::default()
                },
                &prompt_identity,
            )
            .expect("write source-shaped secret entry");
        let prompt_config = ReadOnlyRuntimeConfig {
            approval_mode: "prompt".into(),
            ..base_config
        };
        let prompt_runtime = StoreReadOnlyRuntime::open(
            prompt_directory.path(),
            prompt_identity,
            prompt_config,
            None,
            None,
        )
        .expect("prompt runtime")
        .with_command_executor(Arc::new(SecretCommandExecutor));
        let prompt = prompt_runtime
            .call(
                "execute_with_secret",
                &json!({"command":["sh","-c","echo ok"],"secret_refs":[]}),
            )
            .unwrap_err();
        assert!(prompt.contains("requires approval"));
    }

    struct RecordingApproval {
        tty: bool,
        answer: ApprovalResult,
        requests: Mutex<Vec<ApprovalRequest>>,
        tty_checks: std::sync::atomic::AtomicUsize,
    }

    impl RecordingApproval {
        fn new(tty: bool, approved: bool, remembered: bool) -> Arc<Self> {
            Arc::new(Self {
                tty,
                answer: ApprovalResult {
                    approved,
                    remembered,
                    error: None,
                },
                requests: Mutex::new(Vec::new()),
                tty_checks: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn requests(&self) -> Vec<ApprovalRequest> {
            self.requests.lock().expect("approval request lock").clone()
        }
    }

    impl ApprovalSeam for RecordingApproval {
        fn is_tty_present(&self) -> bool {
            self.tty_checks
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.tty
        }

        fn request(&self, request: &ApprovalRequest) -> ApprovalResult {
            self.requests
                .lock()
                .expect("approval request lock")
                .push(request.clone());
            self.answer.clone()
        }
    }

    fn approval_test_runtime(
        root: &Path,
        mut config: ReadOnlyRuntimeConfig,
        approval: Arc<dyn ApprovalSeam>,
    ) -> StoreReadOnlyRuntime {
        config.available_tools = vec!["execute_with_secret".into()];
        fs::create_dir_all(root.join("entries")).expect("entries directory");
        fs::write(root.join("config.yaml"), b"vault:\n  format_version: 2\n")
            .expect("vault config");
        fs::write(root.join("identity.age"), b"fixture marker").expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        Store::open(root, &identity).expect("open temporary vault");
        StoreReadOnlyRuntime::open(root, identity, config, None, None)
            .expect("runtime")
            .with_approval_seam(approval)
    }

    #[test]
    fn execute_with_secret_prompt_redacts_values_and_remembers_agent_scope() {
        let directory = tempdir().expect("temporary vault directory");
        let fake = RecordingApproval::new(true, true, true);
        let runtime = approval_test_runtime(
            directory.path(),
            ReadOnlyRuntimeConfig {
                agent_name: "alice".into(),
                approval_mode: "prompt".into(),
                approval_timeout: Duration::from_secs(73),
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&fake) as Arc<dyn ApprovalSeam>,
        );
        let environment = BTreeMap::from([
            ("API_KEY".to_owned(), "secret-from-ref".to_owned()),
            ("PLAIN".to_owned(), "literal-value".to_owned()),
        ]);
        let command = vec![
            "curl".to_owned(),
            "--header=secret-from-ref".to_owned(),
            "literal-value".to_owned(),
        ];

        runtime
            .check_execute_with_secret_approval(&command, &environment)
            .expect("approval granted");
        let request = fake.requests().pop().expect("one approval request");
        assert_eq!(request.operation, "execute_with_secret");
        assert_eq!(request.agent_name, "alice");
        assert_eq!(request.timeout, Duration::from_secs(73));
        assert_eq!(request.risk_level, RiskLevel::High);
        assert_eq!(request.secrets_accessed, 0);
        assert!(request.can_remember);
        assert!(request.details.contains("[REDACTED]"));
        assert!(request.details.contains("env vars: [API_KEY PLAIN]"));
        assert!(!request.details.contains("secret-from-ref"));
        assert!(!request.details.contains("literal-value"));

        runtime
            .check_execute_with_secret_approval(&["sh".into()], &environment)
            .expect("remembered approval applies to this agent's action scope");
        assert_eq!(fake.requests().len(), 1, "remembered approval skips prompt");
        assert_eq!(
            runtime
                .approval_key_counter
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "remembered cache hit does not increment the approval counter"
        );
    }

    #[test]
    fn execute_with_secret_approval_denial_and_missing_tty_fail_closed() {
        let directory = tempdir().expect("temporary vault directory");
        let no_tty = RecordingApproval::new(false, true, false);
        let runtime = approval_test_runtime(
            directory.path(),
            ReadOnlyRuntimeConfig {
                approval_mode: "prompt".into(),
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&no_tty) as Arc<dyn ApprovalSeam>,
        );
        let result = runtime.check_execute_with_secret_approval(&["sh".into()], &BTreeMap::new());
        assert_eq!(
            result.unwrap_err(),
            "execute_with_secret requires approval but no TTY or GUI dialog available"
        );
        assert!(no_tty.requests().is_empty());
        assert_eq!(
            no_tty.tty_checks.load(std::sync::atomic::Ordering::Acquire),
            1
        );

        let prompt_directory = tempdir().expect("temporary prompt vault");
        let denied = RecordingApproval::new(true, false, false);
        let runtime = approval_test_runtime(
            prompt_directory.path(),
            ReadOnlyRuntimeConfig {
                approval_mode: "prompt".into(),
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&denied) as Arc<dyn ApprovalSeam>,
        );
        assert_eq!(
            runtime
                .check_execute_with_secret_approval(&["sh".into()], &BTreeMap::new())
                .unwrap_err(),
            "execute_with_secret denied: user did not approve"
        );
        assert_eq!(denied.requests().len(), 1);

        let deny_directory = tempdir().expect("temporary deny vault");
        let unused = RecordingApproval::new(true, true, false);
        let runtime = approval_test_runtime(
            deny_directory.path(),
            ReadOnlyRuntimeConfig {
                approval_mode: "deny".into(),
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&unused) as Arc<dyn ApprovalSeam>,
        );
        assert_eq!(
            runtime
                .check_execute_with_secret_approval(&["sh".into()], &BTreeMap::new())
                .unwrap_err(),
            "execute_with_secret denied: approval mode is 'deny'"
        );
        assert!(unused.requests().is_empty());
    }

    #[test]
    fn execute_with_secret_unknown_mode_fails_closed_and_zero_timeout_defaults() {
        let directory = tempdir().expect("temporary vault directory");
        let unused = RecordingApproval::new(true, true, false);
        let runtime = approval_test_runtime(
            directory.path(),
            ReadOnlyRuntimeConfig {
                approval_mode: "unrecognized".into(),
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&unused) as Arc<dyn ApprovalSeam>,
        );
        assert!(
            runtime
                .check_execute_with_secret_approval(&["sh".into()], &BTreeMap::new())
                .unwrap_err()
                .contains("unknown approval mode")
        );
        assert!(
            unused.requests().is_empty(),
            "unknown mode cannot reach executor"
        );

        let zero_directory = tempdir().expect("temporary zero-timeout vault");
        let prompt = RecordingApproval::new(true, true, false);
        let runtime = approval_test_runtime(
            zero_directory.path(),
            ReadOnlyRuntimeConfig {
                approval_mode: "prompt".into(),
                approval_timeout: Duration::ZERO,
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&prompt) as Arc<dyn ApprovalSeam>,
        );
        runtime
            .check_execute_with_secret_approval(&["sh".into()], &BTreeMap::new())
            .expect("approved with fallback timeout");
        assert_eq!(prompt.requests()[0].timeout, Duration::from_secs(30));
    }

    fn api_approval_runtime(
        root: &Path,
        config: ReadOnlyRuntimeConfig,
        approval: Arc<dyn ApprovalSeam>,
        include_entry: bool,
        base_url: String,
    ) -> StoreReadOnlyRuntime {
        let mut config = config;
        config.available_tools = vec!["execute_api_request".into()];
        fs::create_dir_all(root.join("entries")).expect("entries directory");
        fs::write(root.join("config.yaml"), b"vault:\n  format_version: 2\n")
            .expect("vault config");
        fs::write(root.join("identity.age"), b"fixture marker").expect("identity marker");
        fs::create_dir_all(root.join("templates")).expect("template directory");
        fs::write(
            root.join("templates/fixture.yaml"),
            format!(
                "base_url: {base_url}\nauth_type: bearer\nentry_ref: api-fixture\nallowed_endpoints: [/v1/*]\nallowed_methods: [GET]\nallow_private: true\n"
            ),
        )
        .expect("write synthetic API template");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root, &identity).expect("open temporary API vault");
        if include_entry {
            store
                .write_new_entry(
                    "api-fixture",
                    &Entry {
                        path: "api-fixture".into(),
                        data: BTreeMap::from([
                            ("credential".into(), json!("fixture-api-token")),
                            (
                                "nested".into(),
                                json!({"long_secret":"fixture-api-token-extra"}),
                            ),
                        ]),
                        ..Entry::default()
                    },
                    &identity,
                )
                .expect("synthetic API credential entry");
        }
        StoreReadOnlyRuntime::open(root, identity, config, None, None)
            .expect("API runtime")
            .with_approval_seam(approval)
    }

    #[test]
    fn execute_api_request_approval_is_fail_closed_critical_and_queue_first() {
        let no_tty_dir = tempdir().expect("no-TTY API vault");
        let no_tty = RecordingApproval::new(false, true, false);
        let runtime = api_approval_runtime(
            no_tty_dir.path(),
            ReadOnlyRuntimeConfig {
                agent_name: "alice".into(),
                approval_mode: "prompt".into(),
                can_run_commands: true,
                allowed_paths: vec!["*".into()],
                require_approval: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&no_tty) as Arc<dyn ApprovalSeam>,
            false,
            "http://127.0.0.1:9".into(),
        );
        assert_eq!(
            runtime
                .call(
                    "execute_api_request",
                    &json!({"template":"fixture","endpoint":"/v1/status"}),
                )
                .unwrap_err(),
            "execute_api_request requires approval but no TTY or GUI dialog available"
        );
        assert!(no_tty.requests().is_empty());

        let denied_dir = tempdir().expect("denied API vault");
        let denied = RecordingApproval::new(true, false, false);
        let runtime = api_approval_runtime(
            denied_dir.path(),
            ReadOnlyRuntimeConfig {
                agent_name: "alice".into(),
                approval_mode: "prompt".into(),
                approval_timeout: Duration::from_secs(73),
                can_run_commands: true,
                allowed_paths: vec!["*".into()],
                require_approval: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&denied) as Arc<dyn ApprovalSeam>,
            false,
            "http://127.0.0.1:9".into(),
        );
        assert_eq!(
            runtime
                .call(
                    "execute_api_request",
                    &json!({"template":"fixture","endpoint":"/v1/status"}),
                )
                .unwrap_err(),
            "execute_api_request denied: user did not approve"
        );
        let denied_request = denied.requests().pop().expect("one denied prompt");
        assert_eq!(denied_request.operation, "execute_api_request");
        assert_eq!(denied_request.risk_level, RiskLevel::Critical);
        assert!(!denied_request.can_remember);
        assert_eq!(denied_request.secrets_accessed, 0);
        assert_eq!(denied_request.timeout, Duration::from_secs(73));
        assert_eq!(
            runtime
                .approval_key_counter
                .load(std::sync::atomic::Ordering::Acquire),
            0,
            "denial happens before credential resolution"
        );

        let granted_dir = tempdir().expect("approved API vault");
        let granted = RecordingApproval::new(true, true, false);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("local API listener");
        let address = listener.local_addr().expect("local API address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept approved API request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("bounded API read");
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
            use std::io::BufRead as _;
            let mut line = String::new();
            reader.read_line(&mut line).expect("read API request line");
            let mut headers = String::new();
            loop {
                line.clear();
                reader
                    .read_line(&mut line)
                    .expect("read API request headers");
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                headers.push_str(&line);
            }
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer fixture-api-token"),
                "{headers}"
            );
            let body = r#"{"token":"fixture-api-token","long":"fixture-api-token-extra"}"#;
            use std::io::Write as _;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write approved API response");
        });
        let runtime = api_approval_runtime(
            granted_dir.path(),
            ReadOnlyRuntimeConfig {
                agent_name: "alice".into(),
                approval_mode: "prompt".into(),
                approval_timeout: Duration::from_secs(73),
                can_run_commands: true,
                allowed_paths: vec!["*".into()],
                require_approval: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&granted) as Arc<dyn ApprovalSeam>,
            true,
            format!("http://{address}"),
        );
        let response = runtime
            .call(
                "execute_api_request",
                &json!({"template":"fixture","endpoint":"/v1/status"}),
            )
            .expect("approved API execution");
        assert!(
            response.text.contains("\\\"token\\\":\\\"***\\\""),
            "{}",
            response.text
        );
        assert!(!response.text.contains("fixture-api-token-extra"));
        server.join().expect("join approved API server");
        let granted_request = granted.requests().pop().expect("one granted prompt");
        assert_eq!(granted_request.risk_level, RiskLevel::Critical);
        assert!(!granted_request.can_remember);
        assert_eq!(granted_request.secrets_accessed, 0);
        assert_eq!(granted_request.timeout, Duration::from_secs(73));
        assert_eq!(
            runtime
                .approval_key_counter
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "the granted prompt increments the API approval counter"
        );

        let queue_dir = tempdir().expect("queued API vault");
        let queue_fake = RecordingApproval::new(false, true, false);
        let queue = Arc::new(ApprovalQueue::default());
        let runtime = api_approval_runtime(
            queue_dir.path(),
            ReadOnlyRuntimeConfig {
                agent_name: "alice".into(),
                approval_mode: "prompt".into(),
                can_run_commands: true,
                allowed_paths: vec!["*".into()],
                require_approval: true,
                ..ReadOnlyRuntimeConfig::default()
            },
            Arc::clone(&queue_fake) as Arc<dyn ApprovalSeam>,
            false,
            "http://127.0.0.1:9".into(),
        )
        .with_approval_queue(Arc::clone(&queue));
        let runtime = Arc::new(runtime);
        let call_runtime = Arc::clone(&runtime);
        let call = std::thread::spawn(move || {
            call_runtime.call(
                "execute_api_request",
                &json!({"template":"fixture","endpoint":"/v1/status"}),
            )
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let pending = loop {
            if let Some(entry) = queue.pending().expect("read pending approvals").first() {
                break entry.clone();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "API approval was not queued"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            pending.request.reason,
            "agent API request requires approval"
        );
        queue
            .deny(&pending.id, "fixture")
            .expect("deny queued API request");
        assert!(
            call.join()
                .expect("join queued API call")
                .unwrap_err()
                .contains("denied by approval device")
        );
        assert!(
            queue_fake.requests().is_empty(),
            "attached queue takes precedence over the TTY seam"
        );
        assert_eq!(
            queue_fake
                .tty_checks
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    #[test]
    fn execute_with_secret_environment_names_match_go_unicode_oracle() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../testdata/port/mcp/execute-with-secret.json"
        ))
        .expect("Go oracle fixture");
        let names = &fixture["name_cases"];
        for (input, key) in [
            (("ß", "password"), "sharp_s"),
            (("service²", "password"), "superscript_two"),
            (("serviceⅫ", "password"), "letter_number"),
            (("i\u{0307}", "password"), "combining_uppercase"),
            (("\u{1f80}", "password"), "greek_simple_upper"),
            (("\u{1f88}", "password"), "greek_upper"),
            (("\u{11f04}", "password"), "kawi_letter"),
            (("service\u{11f50}", ""), "kawi_digit"),
            (("\u{1e4d0}", "password"), "nag_mundari_letter"),
            (("\u{31350}", "password"), "han_ext_h_letter"),
            (("9service", ""), "leading_digit"),
            (("", ""), "empty"),
        ] {
            assert_eq!(generate_env_var_name(input.0, input.1), names[key], "{key}");
        }
        let expected_digest = fixture["unicode_name_digest"]
            .as_str()
            .expect("Go exhaustive Unicode digest");
        assert_eq!(expected_digest.len(), 16);
        let mut digest = 0xcbf29ce484222325_u64;
        let mut add = |byte: u8| {
            digest ^= u64::from(byte);
            digest = digest.wrapping_mul(0x100000001b3);
        };
        for code in 0..=0x10ffff_u32 {
            if (0xd800..=0xdfff).contains(&code) {
                continue;
            }
            let character = char::from_u32(code).expect("Unicode scalar");
            for byte in code.to_be_bytes() {
                add(byte);
            }
            let name = generate_env_var_name(&character.to_string(), "");
            for byte in name.bytes().chain(std::iter::once(0)) {
                add(byte);
            }
        }
        assert_eq!(format!("{digest:016x}"), expected_digest);
        let expected_audit = fixture["audit_path"].as_str().expect("Go audit path");
        let actual_audit = execute_with_secret_audit_path(
            &[
                "go".into(),
                "run".into(),
                "<fixture-child-go-source>".into(),
            ],
            &["op://vault/github/password".into()],
            &["testpass123".into()],
            0,
        );
        assert_eq!(actual_audit, expected_audit);
        assert!(!actual_audit.contains("testpass123"));
    }

    #[test]
    fn run_command_is_dispatched_through_the_store_runtime_contract() {
        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        Store::open(directory.path(), &identity)
            .expect("open temporary vault")
            .write_new_entry(
                "service",
                &Entry {
                    path: "service".into(),
                    data: BTreeMap::from([("token".into(), json!("synthetic-secret"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write source-shaped secret entry");
        let config = ReadOnlyRuntimeConfig {
            available_tools: vec!["run_command".into()],
            can_run_commands: true,
            allowed_executables: vec!["sh".into()],
            allowed_paths: vec!["*".into()],
            ..ReadOnlyRuntimeConfig::default()
        };
        let runtime = StoreReadOnlyRuntime::open(directory.path(), identity, config, None, None)
            .expect("runtime")
            .with_command_executor(Arc::new(FakeCommandExecutor));
        let arguments = json!({"command":["sh", "-c", "echo ok"], "env":{"TOKEN":"service.token"}});

        runtime
            .authorize("run_command", &arguments)
            .expect("authorized");
        let result = runtime.call("run_command", &arguments).expect("dispatch");
        let output: serde_json::Value = serde_json::from_str(&result.text).expect("JSON result");
        assert_eq!(output["exit_code"], 0);
        assert!(output["stdout"].as_str().unwrap().contains("ok"));
        assert_eq!(output["duration_ms"], 7);
    }

    #[test]
    fn run_command_resolves_and_decodes_file_refs_before_real_executor_boundary() {
        use base64::Engine as _;

        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        let binary = vec![0x50, 0x4b, 0x03, 0x04, 0x00, 0xff, 0x10];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&binary);
        Store::open(directory.path(), &identity)
            .expect("open store")
            .write_new_entry(
                "service",
                &Entry {
                    path: "service".into(),
                    data: BTreeMap::from([
                        ("pin".into(), json!("synthetic-file-pin")),
                        ("certificate".into(), json!(encoded)),
                    ]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write source entry");
        let expected_files = BTreeMap::from([
            ("CERT".into(), binary.clone()),
            ("PIN".into(), b"synthetic-file-pin".to_vec()),
        ]);
        let expected_redactions = vec![
            encoded.as_bytes().to_vec(),
            binary,
            b"synthetic-file-pin".to_vec(),
        ];
        let runtime = StoreReadOnlyRuntime::open(
            directory.path(),
            identity,
            ReadOnlyRuntimeConfig {
                available_tools: vec!["run_command".into()],
                can_run_commands: true,
                allowed_executables: vec!["sh".into()],
                allowed_paths: vec!["*".into()],
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("runtime")
        .with_command_executor(Arc::new(FileCommandExecutor {
            expected_files,
            expected_redactions,
        }));
        let arguments = json!({
            "command": ["sh", "-c", "echo ok"],
            "files": {
                "PIN": "service.pin",
                "CERT": {"ref": "service.certificate", "encoding": "base64"}
            }
        });

        runtime
            .authorize("run_command", &arguments)
            .expect("authorized");
        let result = runtime.call("run_command", &arguments).expect("dispatch");
        assert!(!result.is_error);
        assert!(result.text.contains("\"exit_code\":0"));
    }

    #[test]
    fn run_command_scope_checks_dotted_bare_entry_fallback() {
        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(directory.path(), &identity).expect("open store");
        store
            .write_new_entry(
                "allowed/foo",
                &Entry {
                    path: "allowed/foo".into(),
                    data: BTreeMap::from([("other".into(), json!("inside"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write candidate entry");
        store
            .write_new_entry(
                "allowed/foo.bar",
                &Entry {
                    path: "allowed/foo.bar".into(),
                    data: BTreeMap::from([("token".into(), json!("outside"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write dotted bare entry");
        let runtime = StoreReadOnlyRuntime::open(
            directory.path(),
            identity,
            ReadOnlyRuntimeConfig {
                available_tools: vec!["run_command".into()],
                can_run_commands: true,
                allowed_executables: vec!["sh".into()],
                allowed_paths: vec!["allowed/foo".into()],
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("runtime")
        .with_command_executor(Arc::new(FakeCommandExecutor));
        let arguments = json!({
            "command":["sh", "-c", "echo ok"],
            "env":{"TOKEN":"allowed/foo.bar"}
        });

        runtime
            .authorize("run_command", &arguments)
            .expect("base authorization");
        let error = runtime
            .call("run_command", &arguments)
            .expect_err("resolved bare entry is outside the configured scope");
        assert_eq!(
            error,
            "access denied: secret ref path \"allowed/foo.bar\" outside allowed scope"
        );
    }

    #[test]
    fn run_command_files_scope_checks_dotted_bare_entry_fallback() {
        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(directory.path(), &identity).expect("open store");
        store
            .write_new_entry(
                "allowed/foo",
                &Entry {
                    path: "allowed/foo".into(),
                    data: BTreeMap::from([("other".into(), json!("inside"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write candidate entry");
        store
            .write_new_entry(
                "allowed/foo.bar",
                &Entry {
                    path: "allowed/foo.bar".into(),
                    data: BTreeMap::from([("token".into(), json!("outside"))]),
                    ..Entry::default()
                },
                &identity,
            )
            .expect("write dotted bare entry");
        let runtime = StoreReadOnlyRuntime::open(
            directory.path(),
            identity,
            ReadOnlyRuntimeConfig {
                available_tools: vec!["run_command".into()],
                can_run_commands: true,
                allowed_executables: vec!["sh".into()],
                allowed_paths: vec!["allowed/foo".into()],
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("runtime")
        .with_command_executor(Arc::new(FakeCommandExecutor));
        let arguments = json!({
            "command": ["sh", "-c", "echo ok"],
            "files": {"TOKEN": "allowed/foo.bar"}
        });

        runtime
            .authorize("run_command", &arguments)
            .expect("base authorization");
        let error = runtime
            .call("run_command", &arguments)
            .expect_err("resolved bare entry is outside configured scope");
        assert_eq!(
            error,
            "access denied: secret ref path \"allowed/foo.bar\" outside allowed scope"
        );
    }

    #[test]
    fn run_command_rejects_invalid_files_and_non_string_working_dir() {
        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let runtime = StoreReadOnlyRuntime::open(
            directory.path(),
            symvault_crypto::generate_identity(),
            ReadOnlyRuntimeConfig {
                available_tools: vec!["run_command".into()],
                can_run_commands: true,
                allowed_executables: vec!["sh".into()],
                allowed_paths: vec!["*".into()],
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        )
        .expect("runtime")
        .with_command_executor(Arc::new(FakeCommandExecutor));

        for (arguments, expected) in [
            (
                json!({"command":["sh", "-c", "echo ok"], "files":"not an object"}),
                "argument \"files\" must be an object",
            ),
            (
                json!({"command":["sh", "-c", "echo ok"], "working_dir":true}),
                "argument \"working_dir\" must be a string",
            ),
        ] {
            runtime
                .authorize("run_command", &arguments)
                .expect("base authorization");
            let result = runtime
                .call("run_command", &arguments)
                .expect("invalid argument is a tool result error");
            assert!(result.is_error);
            assert_eq!(result.text, expected);
        }
    }

    #[test]
    fn command_timeout_and_denied_environment_match_go_policy_bounds() {
        assert_eq!(parse_command_timeout(None).unwrap(), 30);
        assert_eq!(parse_command_timeout(Some(&json!(1))).unwrap(), 1);
        assert_eq!(parse_command_timeout(Some(&json!("300"))).unwrap(), 300);
        assert_eq!(
            parse_command_timeout(Some(&json!(1.5))).unwrap_err(),
            "argument \"timeout\" must be a whole number of seconds"
        );
        assert_eq!(
            parse_command_timeout(Some(&json!(301))).unwrap_err(),
            "argument \"timeout\" must be between 1 and 300 seconds"
        );
        let names = [
            "PATH".to_owned(),
            "PYTHONPATH".to_owned(),
            "TOKEN".to_owned(),
        ];
        assert_eq!(denied_env_names(names.iter()), ["PATH", "PYTHONPATH"]);
    }

    #[test]
    fn run_file_specs_match_go_string_and_base64_forms() {
        assert_eq!(
            parse_run_file_spec(&json!("service.pin")).unwrap(),
            ("service.pin".into(), "")
        );
        assert_eq!(
            parse_run_file_spec(&json!({"ref":"service.cert","encoding":"base64"})).unwrap(),
            ("service.cert".into(), "base64")
        );
        assert_eq!(
            parse_run_file_spec(&json!({"encoding":"base64"})).unwrap_err(),
            "missing required \"ref\" string"
        );
        assert!(
            parse_run_file_spec(&json!({"ref":"service.cert","encoding":1}))
                .unwrap_err()
                .contains("encoding\" must be a string")
        );
        assert!(
            parse_run_file_spec(&json!({"ref":"service.cert","encoding":"rot13"}))
                .unwrap_err()
                .contains("unsupported encoding")
        );
    }

    #[test]
    fn run_command_evaluates_run_policy_for_secret_ref_path_before_resolution() {
        use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};

        let directory = tempdir().expect("temporary vault directory");
        fs::create_dir(directory.path().join("entries")).expect("entries directory");
        fs::write(
            directory.path().join("config.yaml"),
            b"vault:\n  format_version: 2\n",
        )
        .expect("vault config");
        fs::write(directory.path().join("identity.age"), b"fixture marker")
            .expect("identity marker");
        let runtime = StoreReadOnlyRuntime::open(
            directory.path(),
            symvault_crypto::generate_identity(),
            ReadOnlyRuntimeConfig {
                agent_name: "agent".into(),
                available_tools: vec!["run_command".into()],
                can_run_commands: true,
                allowed_paths: vec!["*".into()],
                ..ReadOnlyRuntimeConfig::default()
            },
            Some(Engine::new([Policy {
                version: "1".into(),
                description: "command denial fixture".into(),
                rules: vec![Rule {
                    name: "deny command use".into(),
                    priority: 1,
                    conditions: Conditions {
                        agent_id: "agent".into(),
                        path: "service".into(),
                        action: "run".into(),
                        ..Conditions::default()
                    },
                    action: Action::Deny,
                }],
            }])),
            None,
        )
        .expect("runtime")
        .with_command_executor(Arc::new(FakeCommandExecutor));
        let arguments = json!({
            "command":["sh", "-c", "echo ok"],
            "env":{"TOKEN":"service.token"}
        });

        runtime
            .authorize("run_command", &arguments)
            .expect("base authorization");
        let error = runtime
            .call("run_command", &arguments)
            .expect_err("run policy denies before resolving the missing entry");
        assert_eq!(error, "policy denied by rule \"deny command use\"");
    }
    include!("api_review_tests.rs");
}
