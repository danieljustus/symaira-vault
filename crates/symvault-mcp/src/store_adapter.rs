use crate::call::{
    ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore, ReadOnlyUnavailableTool,
    ToolCallResult, ToolCallRuntime,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use symvault_core::policy::{Action, Engine, EvalContext};
use symvault_crypto::Identity;
use symvault_store::{
    sharing::{ShareFilter, ShareStore, SHARE_STORE_FILE},
    Entry, Store, StoreError, WriteRecord,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub type SharedAuditLogger = Arc<Mutex<symvault_store::audit::Logger>>;

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
        match self.store.get(path, &self.identity) {
            Ok(entry) => Ok(Some(Self::project(path, entry))),
            Err(StoreError::EntryNotFound(_)) => Ok(None),
            Err(error) => Err(store_error(error)),
        }
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
    policy: Option<Engine>,
    audit: Option<SharedAuditLogger>,
    rate_limiter: Mutex<Option<MinuteRateLimiter>>,
    agent_name: String,
    transport: String,
    unavailable_tools: Vec<String>,
    now_unix: Option<i64>,
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
            share_root: root,
            policy,
            audit,
            rate_limiter: Mutex::new(None),
            agent_name,
            transport,
            unavailable_tools,
            now_unix,
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
            share_root,
            policy,
            audit,
            rate_limiter: Mutex::new(None),
            agent_name,
            transport,
            unavailable_tools,
            now_unix,
        })
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

    fn list_shares(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let share_store = self
            .share_store
            .lock()
            .map_err(|_| "share store lock poisoned".to_owned())?;
        render_list_shares(&share_store, &self.agent_name, arguments)
    }

    fn revoke_share(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let grant_id = match arguments.get("grant_id") {
            None => {
                self.append_audit("share_revoke", "<invalid>", false);
                return Ok(ToolCallResult::error(
                    "missing string argument \"grant_id\"",
                ));
            }
            Some(Value::String(value)) => value,
            Some(_) => {
                self.append_audit("share_revoke", "<invalid>", false);
                return Ok(ToolCallResult::error(
                    "argument \"grant_id\" is not a string",
                ));
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
            Err(error) => Ok(ToolCallResult::error(format!(
                "failed to revoke share grant: {error}"
            ))),
        }
    }

    fn audit_target<'a>(name: &'a str, arguments: &'a Value) -> &'a str {
        match name {
            "fetch" => arguments
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("<invalid>"),
            "search" => arguments
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("<invalid>"),
            _ => arguments
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(name),
        }
    }

    fn authorize_policy(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        let path = match name {
            "fetch" => arguments.get("id").and_then(Value::as_str),
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
                self.append_audit("tool_denied", path, false);
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
        let result = if name == "symaira_audit_self" {
            self.audit_self(arguments)
        } else if name == "list_shares" {
            self.list_shares(arguments)
        } else if name == "revoke_share" {
            self.revoke_share(arguments)
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
            "set_entry_field" => {
                let path = arguments
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("<invalid>");
                let ok = result.as_ref().is_ok_and(|value| !value.is_error);
                self.append_audit("set", path, ok);
            }
            "delete_entry" => {
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
            _ => {}
        }
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
        "set_entry_field",
        "delete_entry",
        "find_entries",
        "get_entry",
        "get_entry_value",
        "get_entry_metadata",
        "list_shares",
        "revoke_share",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
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
    use super::{render_list_shares, MinuteRateLimiter, MCP_RATE_LIMIT_WINDOW};
    use serde_json::json;
    use std::fs;
    use std::time::{Duration, Instant};
    use symvault_store::sharing::ShareStore;
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
        assert!(all_json
            .as_array()
            .expect("array")
            .iter()
            .all(|grant| grant["from_agent"] == "alice"));

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
}
