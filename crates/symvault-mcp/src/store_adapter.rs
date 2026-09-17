use crate::call::{
    ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore, ReadOnlyUnavailableTool,
    ToolCallResult, ToolCallRuntime,
};
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, Mutex};
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

    fn set_field(&self, path: &str, field: &str, value: Value, now: &str) -> Result<(), String> {
        let (mut entry, existing) = match self.store.get(path, &self.identity) {
            Ok(entry) => (entry, true),
            Err(StoreError::EntryNotFound(_)) => (Entry::default(), false),
            Err(error) => return Err(store_error(error)),
        };
        validate_field_lengths(field, &value)?;
        if let (Some(existing), Value::Object(incoming)) = (entry.data.get_mut(field), &value) {
            if let Value::Object(existing) = existing {
                merge_json_objects(existing, incoming);
            } else {
                entry.data.insert(field.to_owned(), value);
            }
        } else {
            entry.data.insert(field.to_owned(), value);
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
            .map_err(store_error)
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
        let result = self.inner.call(name, arguments);
        match name {
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

/// The ten handlers in this bounded runtime. The catalog remains owned by
/// the protocol layer; this list is the injected availability registry used
/// by authorization and whoami.
pub fn read_only_tool_names() -> Vec<String> {
    [
        "health",
        "symaira_whoami",
        "list_entries",
        "generate_password",
        "generate_totp",
        "set_entry_field",
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
