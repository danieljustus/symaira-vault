use crate::call::{
    ReadOnlyEntry, ReadOnlyRuntime, ReadOnlyRuntimeConfig, ReadOnlyStore, ReadOnlyUnavailableTool,
    ToolCallResult, ToolCallRuntime,
};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use symvault_core::persistent_quota::QuotaCounter;
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
    quota: Option<Arc<QuotaCounter>>,
    agent_name: String,
    reads_per_hour: i64,
    reads_per_day: i64,
}

impl StoreReadOnlyRuntime {
    pub fn open(
        root: impl AsRef<Path>,
        identity: Identity,
        mut config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        quota: Option<Arc<QuotaCounter>>,
    ) -> Result<Self, String> {
        if config.available_tools.is_empty() {
            return Err("MCP runtime tool registry is empty".into());
        }
        if quota.is_none() && (config.max_reads_per_hour > 0 || config.max_reads_per_day > 0) {
            return Err("configured MCP read quotas require a quota counter".into());
        }
        let adapter = StoreReadOnlyAdapter::open(root, identity)?;
        let root = adapter.root().to_path_buf();
        config.vault_dir = root.to_string_lossy().into_owned();
        config.vault_unlocked = true;
        if let Some(counter) = &quota {
            config.reads_used = counter
                .check("mcp_reads", i64::MAX)
                .map_err(|error| error.to_string())?
                .1;
        }
        let agent_name = config.agent_name.clone();
        let reads_per_hour = config.max_reads_per_hour;
        let reads_per_day = config.max_reads_per_day;
        Ok(Self {
            inner: ReadOnlyRuntime::new(adapter, config),
            policy,
            quota,
            agent_name,
            reads_per_hour,
            reads_per_day,
        })
    }

    pub fn from_store(
        store: Store,
        identity: Identity,
        mut config: ReadOnlyRuntimeConfig,
        policy: Option<Engine>,
        quota: Option<Arc<QuotaCounter>>,
    ) -> Result<Self, String> {
        if config.available_tools.is_empty() {
            return Err("MCP runtime tool registry is empty".into());
        }
        if quota.is_none() && (config.max_reads_per_hour > 0 || config.max_reads_per_day > 0) {
            return Err("configured MCP read quotas require a quota counter".into());
        }
        let adapter = StoreReadOnlyAdapter { store, identity };
        config.vault_dir = adapter.root().to_string_lossy().into_owned();
        config.vault_unlocked = true;
        if let Some(counter) = &quota {
            config.reads_used = counter
                .check("mcp_reads", i64::MAX)
                .map_err(|error| error.to_string())?
                .1;
        }
        let agent_name = config.agent_name.clone();
        let reads_per_hour = config.max_reads_per_hour;
        let reads_per_day = config.max_reads_per_day;
        Ok(Self {
            inner: ReadOnlyRuntime::new(adapter, config),
            policy,
            quota,
            agent_name,
            reads_per_hour,
            reads_per_day,
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

    fn consume_quota(&self) -> Result<(), ToolCallResult> {
        let Some(counter) = &self.quota else {
            return Ok(());
        };
        for (name, limit) in [
            ("mcp_reads", self.reads_per_hour),
            ("mcp_reads_day", self.reads_per_day),
        ] {
            if limit <= 0 {
                continue;
            }
            let (allowed, _) = counter
                .check(name, limit)
                .map_err(|error| ToolCallResult::error(format!("quota check failed: {error}")))?;
            if !allowed {
                return Err(ToolCallResult::error(format!(
                    "read quota exceeded for {name}"
                )));
            }
        }
        counter
            .increment("mcp_reads")
            .map_err(|error| ToolCallResult::error(format!("quota update failed: {error}")))?;
        if self.reads_per_day > 0 {
            counter
                .increment("mcp_reads_day")
                .map_err(|error| ToolCallResult::error(format!("quota update failed: {error}")))?;
        }
        Ok(())
    }
}

impl ToolCallRuntime for StoreReadOnlyRuntime {
    fn authorize(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult> {
        self.inner.authorize(name, arguments)?;
        self.authorize_policy(name, arguments)?;
        self.consume_quota()?;
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
