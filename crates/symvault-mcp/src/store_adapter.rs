use crate::call::{
    ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore, ReadOnlyUnavailableTool,
    ToolCallResult, ToolCallRuntime,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader},
    path::Path,
    sync::{Arc, Mutex},
};
use symvault_core::policy::{Action, Engine, EvalContext};
use symvault_crypto::Identity;
use symvault_store::{Entry, Store, StoreError, WriteRecord};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub type SharedAuditLogger = Arc<Mutex<symvault_store::audit::Logger>>;

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
    policy: Option<Engine>,
    audit: Option<SharedAuditLogger>,
    agent_name: String,
    transport: String,
    unavailable_tools: Vec<String>,
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
        config.vault_dir = root.to_string_lossy().into_owned();
        config.vault_unlocked = true;
        let agent_name = config.agent_name.clone();
        let transport = config.transport.clone();
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
            policy,
            audit,
            agent_name,
            transport,
            unavailable_tools,
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
        config.vault_dir = adapter.root().to_string_lossy().into_owned();
        config.vault_unlocked = true;
        let agent_name = config.agent_name.clone();
        let transport = config.transport.clone();
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
            policy,
            audit,
            agent_name,
            transport,
            unavailable_tools,
        })
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

    fn authorize_policy(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        let path = arguments
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        // Go's executeTool evaluates policy only after extracting a non-empty
        // entry path. `health`, `symaira_whoami`, and `find_entries` therefore
        // bypass the path policy; only get_entry/get_entry_metadata reach this point
        // with a path in this bounded runtime.
        if path.is_empty() {
            return Ok(());
        }
        let action_type = match name {
            "find_entries" => "find",
            "get_entry" | "get_entry_metadata" => "get",
            "set_entry_field" => "set",
            "delete_entry" => "delete",
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
            let path = arguments
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(name);
            if !self.unavailable_tools.iter().any(|tool| tool == name) {
                self.append_audit("tool_denied", path, false);
            }
            return Err(error);
        }
        self.authorize_policy(name, arguments)?;
        Ok(())
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String> {
        let result = if name == "symaira_audit_self" {
            self.audit_self(arguments)
        } else {
            self.inner.call(name, arguments)
        };
        match name {
            "symaira_audit_self" => {}
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
            _ => {}
        }
        result
    }
}

fn store_error(error: StoreError) -> String {
    error.to_string()
}

/// The thirteen handlers in this bounded runtime. The catalog remains owned by
/// the protocol layer; this list is the injected availability registry used
/// by authorization and whoami.
pub fn read_only_tool_names() -> Vec<String> {
    [
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
