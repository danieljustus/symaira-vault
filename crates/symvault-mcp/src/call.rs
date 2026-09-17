use serde::de::{self, Deserialize, MapAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// A result returned by an MCP tool handler.
#[derive(Clone, Debug, Default)]
pub struct ToolCallResult {
    pub text: String,
    pub is_error: bool,
    pub structured_content: Option<Value>,
}

impl ToolCallResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
            ..Self::default()
        }
    }

    pub fn structured(text: impl Into<String>, value: Value) -> Self {
        Self {
            text: text.into(),
            structured_content: Some(value),
            ..Self::default()
        }
    }
}

/// Injected runtime boundary for `tools/call`.
///
/// The protocol layer owns ordering and wire semantics. The runtime owns the
/// actual vault/store and policy implementation, which keeps this crate free
/// of ambient vault, keychain, GUI, and clipboard access. Authorization is
/// deliberately a separate step and happens before `call` can touch storage.
pub trait ToolCallRuntime: Send + Sync {
    /// Return a tool-result error for a denied call, matching Go's
    /// `validateToolAccess` path. This is not a JSON-RPC transport error.
    fn authorize(&self, name: &str, arguments: &Value) -> Result<(), ToolCallResult>;

    /// Execute an authorized tool. Handler failures become JSON-RPC internal
    /// errors, matching Go's `executeTool` dispatch boundary.
    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String>;
}

/// A decrypted entry projection needed by the read-only MCP tools.
///
/// The projection contains metadata and field *types* but is deliberately
/// consumed by the runtime without returning field values. A store adapter can
/// populate it from `symvault-store::Entry` while retaining the vault's
/// zeroizing and identity ownership at the store boundary.
#[derive(Clone, Debug, Default)]
pub struct ReadOnlyEntry {
    pub path: String,
    pub fields: BTreeMap<String, Value>,
    pub secret_type: String,
    pub usage_hint: String,
    pub auto_rotate: bool,
    pub expires_at: Option<String>,
    pub created: String,
    pub updated: String,
    pub version: i64,
    pub tags: Vec<String>,
}

/// Read-only storage boundary. Implementations own vault identity and I/O;
/// this protocol crate only sees the bounded decrypted projection above.
pub trait ReadOnlyStore: Send + Sync {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String>;
    fn get(&self, path: &str) -> Result<Option<ReadOnlyEntry>, String>;
}

#[derive(Clone, Debug, Default)]
pub struct ReadOnlyUnavailableTool {
    pub name: String,
    pub code: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct ReadOnlyRuntimeConfig {
    pub server_name: String,
    pub server_version: String,
    pub transport: String,
    pub agent_name: String,
    pub tier: String,
    pub allowed_paths: Vec<String>,
    pub approval_mode: String,
    pub can_write: bool,
    pub can_run_commands: bool,
    pub can_use_clipboard: bool,
    pub can_use_autotype: bool,
    pub redact_fields: Option<Vec<String>>,
    pub max_reads_per_hour: i64,
    pub max_reads_per_day: i64,
    pub max_secrets_in_session: i64,
    pub reads_used: i64,
    pub secrets_used: i64,
    pub available_tools: Vec<String>,
    pub unavailable_tools: Vec<ReadOnlyUnavailableTool>,
    pub vault_dir: String,
    pub vault_unlocked: bool,
}

impl Default for ReadOnlyRuntimeConfig {
    fn default() -> Self {
        Self {
            server_name: "Symaira Vault MCP".into(),
            server_version: "1.0.0".into(),
            transport: "stdio".into(),
            agent_name: "default".into(),
            tier: String::new(),
            allowed_paths: vec!["*".into()],
            approval_mode: String::new(),
            can_write: false,
            can_run_commands: false,
            can_use_clipboard: false,
            can_use_autotype: false,
            redact_fields: None,
            max_reads_per_hour: 0,
            max_reads_per_day: 0,
            max_secrets_in_session: 0,
            reads_used: 0,
            secrets_used: 0,
            available_tools: Vec::new(),
            unavailable_tools: Vec::new(),
            vault_dir: String::new(),
            vault_unlocked: false,
        }
    }
}

/// Productive read-only runtime for the four portable tools in this slice.
///
/// The runtime performs argument validation, scope checks, search, metadata
/// projection, and whoami construction over an injected store. It never opens
/// a vault or discovers a platform provider itself; the owning application
/// supplies a store adapter and policy/profile configuration.
pub struct ReadOnlyRuntime<S> {
    store: S,
    config: ReadOnlyRuntimeConfig,
}

impl<S> ReadOnlyRuntime<S> {
    pub fn new(store: S, config: ReadOnlyRuntimeConfig) -> Self {
        Self { store, config }
    }
}

impl<S: ReadOnlyStore> ToolCallRuntime for ReadOnlyRuntime<S> {
    fn authorize(&self, name: &str, _arguments: &Value) -> Result<(), ToolCallResult> {
        if self.config.available_tools.iter().any(|tool| tool == name) {
            return Ok(());
        }
        let unavailable = self
            .config
            .unavailable_tools
            .iter()
            .find(|tool| tool.name == name);
        let message = unavailable
            .map(|tool| tool.reason.clone())
            .unwrap_or_else(|| format!("tool {name:?} is not allowed"));
        Err(ToolCallResult::error(message))
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<ToolCallResult, String> {
        match name {
            "health" => self.health(),
            "symaira_whoami" => self.whoami(),
            "find_entries" => self.find_entries(arguments),
            "get_entry_metadata" => self.get_entry_metadata(arguments),
            _ => Err(format!("read-only runtime has no handler for {name}")),
        }
    }
}

impl<S: ReadOnlyStore> ReadOnlyRuntime<S> {
    fn health(&self) -> Result<ToolCallResult, String> {
        let mut result = Map::new();
        result.insert(
            "server".into(),
            Value::String(self.config.server_name.clone()),
        );
        result.insert("status".into(), Value::String("healthy".into()));
        result.insert(
            "transport".into(),
            Value::String(self.config.transport.clone()),
        );
        result.insert(
            "version".into(),
            Value::String(self.config.server_version.clone()),
        );
        json_text(Value::Object(result))
    }

    fn whoami(&self) -> Result<ToolCallResult, String> {
        let entries_count = self
            .store
            .list()
            .map_err(|error| format!("list entries: {error}"))?
            .len();
        let profile = serde_json::json!({
            "name": self.config.agent_name,
            "tier": self.config.tier,
            "allowed_paths": self.config.allowed_paths,
            "approval_mode": self.config.approval_mode,
            "can_write": self.config.can_write,
            "can_run_commands": self.config.can_run_commands,
            "can_use_clipboard": self.config.can_use_clipboard,
            "can_use_autotype": self.config.can_use_autotype,
            "redact_fields": self.config.redact_fields,
        });
        let unavailable = self
            .config
            .unavailable_tools
            .iter()
            .map(|tool| {
                serde_json::json!({
                    "name": tool.name,
                    "code": tool.code,
                    "reason": tool.reason,
                })
            })
            .collect::<Vec<_>>();
        let info = serde_json::json!({
            "agent": self.config.agent_name,
            "symaira_version": self.config.server_version,
            "profile": profile,
            "tools": {"available": self.config.available_tools, "unavailable": unavailable},
            "quotas": {
                "reads_per_hour": {"used": self.config.reads_used, "limit": self.config.max_reads_per_hour},
                "reads_per_day": {"used": self.config.reads_used, "limit": self.config.max_reads_per_day},
                "secrets_per_session": {"used": self.config.secrets_used, "limit": self.config.max_secrets_in_session},
            },
            "vault": {"unlocked": self.config.vault_unlocked, "entries_count": entries_count, "dir": self.config.vault_dir},
            "cli_alternative_hint": "Use 'symvault status' for a comprehensive overview.",
            "errors_doc": "See https://github.com/danieljustus/symaira-vault/blob/main/docs/errors.md for error code documentation.",
            "tier_upgrade_hint": "Upgrade your agent tier in ~/.symvault/config.yaml to unlock additional tools.",
        });
        json_text(info)
    }

    fn find_entries(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let query = match required_string(arguments, "query") {
            Ok(query) => query,
            Err(result) => return Ok(result),
        };
        let needle = query.to_lowercase();
        let mut matches = Vec::new();
        for entry in self
            .store
            .list()
            .map_err(|error| format!("find entries: {error}"))?
        {
            if !self.scope_allows(&entry.path) {
                continue;
            }
            let mut fields = Vec::new();
            if entry.path.to_lowercase().contains(&needle) {
                fields.push("path".to_string());
            }
            for (field, value) in &entry.fields {
                collect_field_matches(
                    &mut fields,
                    field,
                    value,
                    &needle,
                    self.config.redact_fields.as_deref().unwrap_or(&[]),
                );
            }
            fields.sort();
            if !fields.is_empty() {
                matches.push(ReadOnlyMatch {
                    path: crate::render::sanitize_for_mcp(&entry.path),
                    fields,
                });
            }
        }
        matches.sort_by(|left, right| left.path.cmp(&right.path));
        symvault_gojson::to_string(&matches)
            .map(ToolCallResult::text)
            .map_err(|error| error.to_string())
    }

    fn get_entry_metadata(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let path = match required_string(arguments, "path") {
            Ok(path) => path,
            Err(result) => return Ok(result),
        };
        if !self.scope_allows(path) {
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }
        let Some(entry) = self
            .store
            .get(path)
            .map_err(|error| format!("get entry: {error}"))?
        else {
            return Ok(ToolCallResult::error(format!("entry not found: {path}")));
        };
        let usage_hint = crate::render::embed_as_data(
            "usage_hint",
            &crate::render::sanitize_for_mcp(&entry.usage_hint),
        )
        .map_err(|error| format!("embed usage hint: {error}"))?;
        let fields = entry
            .fields
            .iter()
            .map(|(name, value)| {
                let mut field = Map::new();
                field.insert(
                    "handle".into(),
                    Value::String(format!("op://{path}/{name}")),
                );
                field.insert("kind".into(), Value::String(infer_field_kind(value)));
                field.insert("name".into(), Value::String(name.clone()));
                field.insert("usage".into(), usage_for(path, name));
                Value::Object(field)
            })
            .collect::<Vec<_>>();
        let mut meta = Map::new();
        meta.insert("created".into(), Value::String(entry.created));
        meta.insert("updated".into(), Value::String(entry.updated));
        meta.insert("version".into(), Value::from(entry.version));
        let mut result = Map::new();
        result.insert("auto_rotate".into(), Value::Bool(entry.auto_rotate));
        result.insert("fields".into(), Value::Array(fields));
        result.insert("has_value".into(), Value::Bool(!entry.fields.is_empty()));
        result.insert("meta".into(), Value::Object(meta));
        result.insert("path".into(), Value::String(path.into()));
        result.insert(
            "tags".into(),
            Value::Array(
                entry
                    .tags
                    .iter()
                    .map(|tag| {
                        crate::render::embed_as_data("tag", &crate::render::sanitize_for_mcp(tag))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| format!("embed tag: {error}"))?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        result.insert("type".into(), Value::String(entry.secret_type));
        result.insert("usage_hint".into(), Value::String(usage_hint));
        if let Some(expires_at) = entry.expires_at {
            result.insert("expires_at".into(), Value::String(expires_at));
        }
        json_text(Value::Object(result))
    }

    fn scope_allows(&self, path: &str) -> bool {
        if self.config.allowed_paths.is_empty() {
            return false;
        }
        let path = normalize_scope_path(path);
        self.config.allowed_paths.iter().any(|allowed| {
            allowed == "*"
                || path == normalize_scope_path(allowed)
                || path.starts_with(&format!("{}/", normalize_scope_path(allowed)))
        })
    }
}

#[derive(serde::Serialize)]
struct ReadOnlyMatch {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Fields")]
    fields: Vec<String>,
}

fn json_text(value: Value) -> Result<ToolCallResult, String> {
    symvault_gojson::to_string(&value)
        .map(ToolCallResult::text)
        .map_err(|error| error.to_string())
}

fn required_string<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, ToolCallResult> {
    match arguments.get(name) {
        None => Err(ToolCallResult::error(format!(
            "missing string argument \"{name}\""
        ))),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(ToolCallResult::error(format!(
            "argument \"{name}\" is not a string"
        ))),
    }
}

fn infer_field_kind(value: &Value) -> String {
    match value {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Object(map)
            if map.get("type") == Some(&Value::String("totp".into()))
                && map
                    .get("secret")
                    .and_then(Value::as_str)
                    .is_some_and(|secret| !secret.is_empty()) =>
        {
            "totp"
        }
        Value::Object(_) => "object",
        Value::Null => "null",
        Value::Array(_) => "[]serde_json::Value",
    }
    .into()
}

fn usage_for(path: &str, field: &str) -> Value {
    let reference = format!("{path}.{field}");
    serde_json::json!({
        "note": format!("The raw value is never returned to agents. Pass \"{reference}\" as a run_command env reference (SymVault resolves and injects it; the command sees the value, you don't), or use copy_to_clipboard/autotype for interactive use, or request_credential to ask the user directly. Consuming it this way does not require unsealing first."),
        "run_command": {"env": {"<VAR_NAME>": reference}},
    })
}

fn collect_field_matches(
    fields: &mut Vec<String>,
    prefix: &str,
    value: &Value,
    needle: &str,
    redact_fields: &[String],
) {
    if is_redacted_field(prefix, redact_fields) {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let field = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_field_matches(fields, &field, nested, needle, redact_fields);
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                collect_field_matches(
                    fields,
                    &format!("{prefix}[{index}]"),
                    nested,
                    needle,
                    redact_fields,
                );
            }
        }
        scalar => {
            let rendered = scalar
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| scalar.to_string());
            if !prefix.is_empty() && rendered.to_lowercase().contains(needle) {
                fields.push(prefix.to_owned());
            }
        }
    }
}

fn is_redacted_field(field: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        pattern == field
            || pattern == "*"
            || pattern
                .strip_suffix(".*")
                .is_some_and(|prefix| field.starts_with(&format!("{prefix}.")))
    })
}

fn normalize_scope_path(path: &str) -> String {
    let mut components = Vec::new();
    let normalized = path.trim().replace('\\', "/");
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value),
        }
    }
    components.join("/")
}

struct CallParams {
    name: String,
    arguments: Value,
}

impl Default for CallParams {
    fn default() -> Self {
        Self {
            name: String::new(),
            arguments: Value::Object(Map::new()),
        }
    }
}

struct CallParamsVisitor;

impl<'de> Visitor<'de> for CallParamsVisitor {
    type Value = CallParams;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tools/call parameter object or null")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(CallParams {
            name: String::new(),
            arguments: Value::Object(Map::new()),
        })
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut result = CallParams {
            name: String::new(),
            arguments: Value::Object(Map::new()),
        };
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            // encoding/json's field matching is case-insensitive and folds
            // the two non-ASCII runes that share ASCII simple-fold classes.
            let key = key.replace('ſ', "s").replace('K', "k");
            if key.eq_ignore_ascii_case("name") {
                match value {
                    Value::String(name) => result.name = name,
                    Value::Null => {}
                    other => {
                        return Err(de::Error::custom(format!(
                            "json: cannot unmarshal {} into Go struct field .name of type string",
                            crate::go_kind(&other)
                        )));
                    }
                }
            } else if key.eq_ignore_ascii_case("arguments") {
                result.arguments = match value {
                    Value::Null => Value::Object(Map::new()),
                    other => other,
                };
            }
        }
        Ok(result)
    }
}

impl<'de> Deserialize<'de> for CallParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CallParamsVisitor)
    }
}

pub(crate) fn parse_params(raw: Option<&str>) -> Result<(String, Value), String> {
    let params = raw
        .map_or_else(|| Ok(CallParams::default()), serde_json::from_str)
        .map_err(|err| err.to_string())?;
    Ok((params.name, params.arguments))
}

pub(crate) fn payload(result: ToolCallResult) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "content".to_string(),
        serde_json::json!([{
            "type": "text",
            "text": crate::render::sanitize_for_mcp(&result.text),
        }]),
    );
    payload.insert("isError".to_string(), Value::Bool(result.is_error));
    if let Some(structured) = result.structured_content {
        payload.insert("structuredContent".to_string(), structured);
    }
    Value::Object(payload)
}
