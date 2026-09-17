use crate::call::{
    ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore, ReadOnlyUnavailableTool,
    ToolCallResult, ToolCallRuntime,
};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use symvault_core::policy::{Action, Engine, EvalContext};
use symvault_crypto::Identity;
use symvault_store::{Entry, Store, StoreError};

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
}

/// A concrete `tools/call` runtime over the encrypted Rust store.
pub struct StoreReadOnlyRuntime {
    inner: ReadOnlyRuntime<StoreReadOnlyAdapter>,
    policy: Option<Engine>,
    agent_name: String,
}

impl StoreReadOnlyRuntime {
    pub fn open(
        root: impl AsRef<Path>,
        identity: Identity,
        mut config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        _quota: Option<Arc<symvault_core::persistent_quota::QuotaCounter>>,
    ) -> Result<Self, String> {
        if config.available_tools.is_empty() {
            return Err("MCP runtime tool registry is empty".into());
        }
        let adapter = StoreReadOnlyAdapter::open(root, identity)?;
        let root = adapter.root().to_path_buf();
        config.vault_dir = root.to_string_lossy().into_owned();
        config.vault_unlocked = true;
        let agent_name = config.agent_name.clone();
        Ok(Self {
            inner: ReadOnlyRuntime::new(adapter, config),
            policy,
            agent_name,
        })
    }

    pub fn from_store(
        store: Store,
        identity: Identity,
        mut config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        _quota: Option<Arc<symvault_core::persistent_quota::QuotaCounter>>,
    ) -> Result<Self, String> {
        if config.available_tools.is_empty() {
            return Err("MCP runtime tool registry is empty".into());
        }
        let adapter = StoreReadOnlyAdapter { store, identity };
        config.vault_dir = adapter.root().to_string_lossy().into_owned();
        config.vault_unlocked = true;
        let agent_name = config.agent_name.clone();
        Ok(Self {
            inner: ReadOnlyRuntime::new(adapter, config),
            policy,
            agent_name,
        })
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
        // bypass the path policy; only get_entry_metadata reaches this point
        // with a path in this bounded runtime.
        if path.is_empty() {
            return Ok(());
        }
        let action_type = match name {
            "find_entries" => "find",
            "get_entry_metadata" => "get",
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
        self.inner.authorize(name, arguments)?;
        self.authorize_policy(name, arguments)?;
        Ok(())
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String> {
        self.inner.call(name, arguments)
    }
}

fn store_error(error: StoreError) -> String {
    error.to_string()
}

/// The four handlers in this bounded runtime. The catalog remains owned by
/// the protocol layer; this list is the injected availability registry used
/// by authorization and whoami.
pub fn read_only_tool_names() -> Vec<String> {
    [
        "health",
        "symaira_whoami",
        "find_entries",
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
