use serde::Serialize;
use serde::de::{self, Deserialize, MapAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use symvault_core::secret_ref::SecretHandle;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

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

fn format_go_general_float(value: f64) -> String {
    let scientific = format!("{value:e}");
    let Some((mantissa, exponent)) = scientific.split_once('e') else {
        return value.to_string();
    };
    let exponent = exponent.parse::<i32>().unwrap_or(0);
    if !(-4..6).contains(&exponent) {
        let mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
        return format!(
            "{mantissa}e{}{abs:02}",
            if exponent >= 0 { "+" } else { "-" },
            abs = exponent.unsigned_abs()
        );
    }

    let negative = mantissa.starts_with('-');
    let digits = mantissa
        .trim_start_matches('-')
        .chars()
        .filter(|ch| *ch != '.')
        .collect::<String>();
    let point = exponent + 1;
    let mut fixed = if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else if point as usize >= digits.len() {
        format!("{digits}{}", "0".repeat(point as usize - digits.len()))
    } else {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    };
    if fixed.contains('.') {
        while fixed.ends_with('0') {
            fixed.pop();
        }
        if fixed.ends_with('.') {
            fixed.pop();
        }
    }
    if negative {
        fixed.insert(0, '-');
    }
    fixed
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
    pub classification: i32,
}

/// Read-only storage boundary. Implementations own vault identity and I/O;
/// this protocol crate only sees the bounded decrypted projection above.
pub trait ReadOnlyStore: Send + Sync {
    fn list(&self) -> Result<Vec<ReadOnlyEntry>, String>;
    fn get(&self, path: &str) -> Result<Option<ReadOnlyEntry>, String>;

    /// Delete one entry when the injected store supports writes. Read-only
    /// test stores retain the default fail-closed implementation.
    fn delete_entry(&self, _path: &str) -> Result<(), String> {
        Err("store does not support deletes".into())
    }

    /// Persist one field mutation when the injected store supports writes.
    /// Read-only test stores retain the default fail-closed implementation.
    fn set_field(
        &self,
        _path: &str,
        _field: &str,
        _value: Value,
        _now: &str,
    ) -> Result<(), String> {
        Err("store does not support writes".into())
    }
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
    pub require_approval: bool,
    pub can_read_values: bool,
    pub auto_unseal: bool,
    pub expose_payment_values: bool,
    /// Go-compatible semantic prompt-injection handling for value responses.
    /// Supported values are `off`, `log-only`, `wrap`, and `deny`.
    pub prompt_injection_mode: String,
    /// Optional deterministic clock for protocol fixtures; production uses
    /// the current Unix timestamp when this is absent.
    pub now_unix: Option<i64>,
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
    /// Authentication/session status supplied by the owning session layer.
    /// The MCP runtime never probes a platform keychain or biometric API.
    pub auth_method: String,
    pub touch_id_available: bool,
    pub cache_backend: String,
    pub cache_persistent: bool,
    pub cache_message: String,
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
            require_approval: false,
            can_read_values: false,
            auto_unseal: false,
            expose_payment_values: false,
            prompt_injection_mode: "off".into(),
            now_unix: None,
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
            auth_method: "passphrase".into(),
            touch_id_available: false,
            cache_backend: "memory".into(),
            cache_persistent: false,
            cache_message: "OS keyring unavailable. Sessions are stored in process memory only."
                .into(),
        }
    }
}

/// Productive runtime for the bounded portable tools in this slice.
///
/// The runtime performs argument validation, scope checks, search, metadata
/// projection, and whoami construction over an injected store. It never opens
/// a vault or discovers a platform provider itself; the owning application
/// supplies a store adapter and policy/profile configuration.
pub struct ReadOnlyRuntime<S> {
    store: S,
    config: ReadOnlyRuntimeConfig,
    secrets_accessed: AtomicI64,
}

impl<S> ReadOnlyRuntime<S> {
    pub fn new(store: S, config: ReadOnlyRuntimeConfig) -> Self {
        let secrets_accessed = AtomicI64::new(config.secrets_used.max(0));
        Self {
            store,
            config,
            secrets_accessed,
        }
    }
}

impl<S: ReadOnlyStore> ToolCallRuntime for ReadOnlyRuntime<S> {
    fn authorize(&self, name: &str, _arguments: &Value) -> Result<(), ToolCallResult> {
        if self.config.tier == "read-only" && name == "set_entry_field" {
            return Err(ToolCallResult::error(
                "Tool \"set_entry_field\" requires tier \"standard\"",
            ));
        }
        let deletes = name == "delete_entry" || name == "symaira_delete";
        if self.config.tier == "read-only" && deletes {
            return Err(ToolCallResult::error(format!(
                "Tool \"{name}\" requires tier \"standard\""
            )));
        }
        if self.config.tier == "standard" && deletes {
            return Err(ToolCallResult::error(format!(
                "Tool \"{name}\" requires tier \"admin\""
            )));
        }
        if self.config.available_tools.iter().any(|tool| tool == name) {
            let approval_mode =
                if self.config.approval_mode.is_empty() && self.config.require_approval {
                    "prompt"
                } else {
                    self.config.approval_mode.as_str()
                };
            if name == "get_entry_value"
                && !self.config.can_read_values
                && !matches!(approval_mode, "none" | "auto")
            {
                let message = if approval_mode == "deny" {
                    "get_entry_value denied: approval mode is 'deny'"
                } else {
                    "get_entry_value requires approval but no interactive approval is available"
                };
                return Err(ToolCallResult::error(message));
            }
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
            "get_auth_status" => self.get_auth_status(),
            "symaira_whoami" => self.whoami(),
            "list_entries" => self.list_entries(arguments),
            "generate_password" => self.generate_password(arguments),
            "sanitize_output" => self.sanitize_output(arguments),
            "symaira_search" => self.search_tools(arguments),
            "generate_template" => self.generate_template(arguments),
            "generate_totp" => self.generate_totp(arguments),
            "set_entry_field" => self.set_entry_field(arguments),
            // `symaira_delete` is Go's deprecated alias for the same handler
            // (Go dispatches both names in server_dispatch.go). Go's tier map
            // only blocks the canonical name, so the alias slips past a
            // read-only/standard restriction there; this port keeps the alias
            // subject to the same rules and names the invoked tool in the error,
            // which is the stricter side and recorded as a deliberate deviation.
            "delete_entry" | "symaira_delete" => self.delete_entry(arguments),
            "find_entries" => self.find_entries(arguments),
            "get_entry" | "get_entry_metadata" => self.get_entry_metadata(arguments),
            "get_entry_value" => self.get_entry_value(arguments),
            "search" => self.search_openai(arguments),
            "fetch" => self.fetch_openai(arguments),
            _ => Err(format!("read-only runtime has no handler for {name}")),
        }
    }
}

impl<S: ReadOnlyStore> ReadOnlyRuntime<S> {
    pub(crate) fn secret_unseal(&self, handle: &SecretHandle) -> Result<ToolCallResult, String> {
        let Some(field) = handle.field.as_deref() else {
            return Ok(ToolCallResult::error(
                "secret_unseal requires a field handle",
            ));
        };
        let path = handle.path.as_str();
        if !self.scope_allows(path) {
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }
        let entry_path = handle
            .field
            .as_deref()
            .map_or_else(|| path.to_owned(), |field| format!("{path}/{field}"));
        let max = self.config.max_secrets_in_session;
        let mut reserved = false;
        if max > 0 {
            let mut used = self.secrets_accessed.load(Ordering::Acquire);
            loop {
                if used >= max {
                    return Ok(ToolCallResult::error(format!(
                        "max secrets per session exceeded ({used}/{max})"
                    )));
                }
                match self.secrets_accessed.compare_exchange_weak(
                    used,
                    used.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        reserved = true;
                        break;
                    }
                    Err(current) => used = current,
                }
            }
        }

        let entry = match self.store.get(path) {
            Ok(Some(entry)) => entry,
            Ok(None) | Err(_) => {
                if reserved {
                    self.secrets_accessed.fetch_sub(1, Ordering::AcqRel);
                }
                return Ok(ToolCallResult::error(format!("entry not found: {path}")));
            }
        };
        let result = match entry.fields.get(field) {
            None => ToolCallResult::error(format!("field {field:?} not found in entry {path}")),
            Some(Value::String(value)) => ToolCallResult::text(value),
            Some(Value::Bool(value)) => ToolCallResult::text(value.to_string()),
            Some(Value::Null) => ToolCallResult::text(""),
            Some(Value::Number(value)) => ToolCallResult::text(
                value
                    .as_f64()
                    .map(format_go_general_float)
                    .unwrap_or_else(|| value.to_string()),
            ),
            Some(_) => ToolCallResult::error(format!(
                "field {field:?} in entry {path} is not a scalar string — use a leaf field handle (e.g. {entry_path}/<subfield>)"
            )),
        };
        if result.is_error {
            if reserved {
                self.secrets_accessed.fetch_sub(1, Ordering::AcqRel);
            }
        } else if !reserved {
            self.secrets_accessed.fetch_add(1, Ordering::AcqRel);
        }
        Ok(result)
    }

    fn get_auth_status(&self) -> Result<ToolCallResult, String> {
        #[derive(Serialize)]
        struct CacheStatus<'a> {
            backend: &'a str,
            persistent: bool,
            message: &'a str,
        }
        #[derive(Serialize)]
        struct AuthStatus<'a> {
            cache: CacheStatus<'a>,
            method: &'a str,
            #[serde(rename = "touchIDAvailable")]
            touch_id_available: bool,
        }
        serde_json::to_string(&AuthStatus {
            cache: CacheStatus {
                backend: &self.config.cache_backend,
                persistent: self.config.cache_persistent,
                message: &self.config.cache_message,
            },
            method: &self.config.auth_method,
            touch_id_available: self.config.touch_id_available,
        })
        .map(ToolCallResult::text)
        .map_err(|error| error.to_string())
    }

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

    fn generate_password(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        // Go's RequireFloat fallback uses the default length for missing,
        // string, boolean, and null values. Fractional numbers are truncated
        // by the Go int conversion before generation.
        let length = arguments
            .get("length")
            .and_then(Value::as_f64)
            .map(|value| value as isize)
            .unwrap_or(16);
        let symbols = arguments
            .get("symbols")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let password = symvault_core::password::generate_password(length, symbols)
            .map_err(|error| error.to_string())?;
        Ok(ToolCallResult::text(password.as_str()))
    }

    fn sanitize_output(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let text = match required_string(arguments, "text") {
            Ok(text) => text,
            Err(error) => return Ok(error),
        };
        let sanitized = crate::render::sanitize_for_mcp(text);
        json_text(serde_json::json!({
            "original_length": text.len(),
            "sanitized_length": sanitized.len(),
            "sanitized": sanitized,
            "was_modified": sanitized != text,
        }))
    }

    fn search_tools(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let intent = match required_string(arguments, "intent") {
            Ok(intent) => intent,
            Err(error) => {
                return Ok(ToolCallResult::error(format!(
                    "missing required argument: {}",
                    error.text
                )));
            }
        };
        let return_mode = arguments
            .get("return")
            .and_then(Value::as_str)
            .filter(|mode| matches!(*mode, "spec" | "names"))
            .unwrap_or("spec");
        let result = crate::tools::search_tools(intent, return_mode)?;
        Ok(ToolCallResult::text(result))
    }

    fn generate_template(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let template_type = match required_string(arguments, "template_type") {
            Ok(value) => value,
            Err(_) => return Ok(ToolCallResult::error("template_type is required")),
        };
        let name = arguments
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("app");
        let output_path = arguments
            .get("output_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !output_path.is_empty() {
            return Ok(ToolCallResult::error(
                "output_path is not supported by this runtime",
            ));
        }
        let dry_run = arguments
            .get("dry_run")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !dry_run {
            return Ok(ToolCallResult::error(
                "generate_template non-dry-run secret release is not supported by this runtime",
            ));
        }
        let refs = arguments
            .get("secret_refs")
            .and_then(Value::as_object)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|(alias, reference)| {
                        reference
                            .as_str()
                            .map(|_| (alias.clone(), "***".to_owned()))
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let output = match symvault_sync::template::render_builtin(template_type, name, &refs) {
            Ok(output) => output,
            Err(error) => {
                return Ok(ToolCallResult::error(format!("render template: {error}")));
            }
        };
        let wrapped = crate::render::embed_as_data("rendered_template", &output)
            .map_err(|error| format!("embed rendered template: {error}"))?;
        // Go applies the final MCP chokepoint to the whole result. That pass
        // neutralizes the literal comment closers in this text response.
        Ok(ToolCallResult::text(crate::render::sanitize_for_mcp(
            &wrapped,
        )))
    }

    fn set_entry_field(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        if !self.config.can_write {
            return Err("write operations not permitted for this agent".into());
        }
        let path = match required_string(arguments, "path") {
            Ok(path) => path,
            Err(result) => return Ok(result),
        };
        let field = match required_string(arguments, "field") {
            Ok(field) => field,
            Err(result) => return Ok(result),
        };
        let value = match required_string(arguments, "value") {
            Ok(value) => value,
            Err(result) => return Ok(result),
        };
        if !self.scope_allows(path) {
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }
        let approval_mode = if self.config.approval_mode.is_empty() {
            if self.config.require_approval {
                "prompt"
            } else {
                "none"
            }
        } else {
            self.config.approval_mode.as_str()
        };
        match approval_mode {
            "deny" => {
                return Ok(ToolCallResult::error(
                    "set_entry_field denied: approval mode is 'deny'",
                ));
            }
            "prompt" => {
                return Ok(ToolCallResult::error(
                    "set_entry_field requires approval but no TTY or GUI dialog available",
                ));
            }
            _ => {}
        }

        let force = arguments
            .get("force")
            .and_then(|value| match value {
                Value::Bool(value) => Some(*value),
                Value::String(value) => value.parse::<bool>().ok(),
                _ => None,
            })
            .unwrap_or(false);
        if field == "password" && !force {
            let assessment = symvault_core::password::assess_password_strength(value);
            if assessment.weak {
                let mut detail = Map::new();
                detail.insert("weak".into(), Value::Bool(true));
                let entropy = if assessment.entropy == 0.0 {
                    Value::from(0)
                } else {
                    Value::from(assessment.entropy)
                };
                detail.insert("entropy".into(), entropy);
                detail.insert(
                    "message".into(),
                    Value::String(format!(
                        "{} — re-call with force:true to store this password (the entry will be tagged as weak)",
                        assessment.message
                    )),
                );
                if !assessment.missing.is_empty() {
                    detail.insert(
                        "missing".into(),
                        Value::Array(assessment.missing.into_iter().map(Value::String).collect()),
                    );
                }
                let text = symvault_gojson::to_string(&Value::Object(detail))
                    .map_err(|error| error.to_string())?;
                return Ok(ToolCallResult::error(text));
            }
        }

        let stored = if field == "totp" {
            let parsed = match serde_json::from_str::<Value>(value) {
                Ok(parsed) => parsed,
                Err(error) => {
                    return Ok(ToolCallResult::error(format!("invalid TOTP JSON: {error}")));
                }
            };
            if !matches!(parsed, Value::Object(_) | Value::Null) {
                return Ok(ToolCallResult::error(format!(
                    "invalid TOTP JSON: json: cannot unmarshal {} into Go value of type map[string]interface {{}}",
                    crate::go_kind(&parsed)
                )));
            }
            if let Value::Object(ref map) = parsed {
                let algorithm = map.get("algorithm").and_then(Value::as_str).unwrap_or("");
                let digits = map
                    .get("digits")
                    .and_then(Value::as_f64)
                    .map(|value| value as i64)
                    .unwrap_or(0);
                let period = map
                    .get("period")
                    .and_then(Value::as_f64)
                    .map(|value| value as i64)
                    .unwrap_or(0);
                if let Err(error) =
                    symvault_core::totp::validate_totp_params(algorithm, digits, period)
                {
                    return Ok(ToolCallResult::error(format!("invalid TOTP: {error}")));
                }
            }
            parsed
        } else {
            Value::String(value.to_owned())
        };
        let now = match self.config.now_unix {
            Some(value) => OffsetDateTime::from_unix_timestamp(value)
                .map_err(|error| format!("format write clock: {error}"))?,
            None => OffsetDateTime::now_utc(),
        }
        .format(&Rfc3339)
        .map_err(|error| format!("format write clock: {error}"))?;
        self.store
            .set_field(path, field, stored, &now)
            .map_err(|error| format!("vault operation failed: {error}"))?;
        Ok(ToolCallResult::text(format!("Set {path}.{field} = ***")))
    }

    fn delete_entry(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        if !self.config.can_write {
            return Err("delete operations not permitted for this agent".into());
        }
        let path = match required_string(arguments, "path") {
            Ok(path) => path,
            Err(result) => return Ok(result),
        };
        if !self.scope_allows(path) {
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }
        let approval_mode = if self.config.approval_mode.is_empty() {
            if self.config.require_approval {
                "prompt"
            } else {
                "none"
            }
        } else {
            self.config.approval_mode.as_str()
        };
        match approval_mode {
            "deny" => {
                return Ok(ToolCallResult::error(
                    "delete_entry denied: approval mode is 'deny'",
                ));
            }
            "prompt" => {
                return Ok(ToolCallResult::error(
                    "delete_entry requires approval but no TTY or GUI dialog available",
                ));
            }
            _ => {}
        }
        match self.store.delete_entry(path) {
            Ok(()) => Ok(ToolCallResult::text(format!(
                "Successfully deleted entry: {path}"
            ))),
            Err(error) if error.starts_with("entry not found: ") => {
                Ok(ToolCallResult::error(error))
            }
            Err(error) => Err(format!("vault operation failed: {error}")),
        }
    }

    fn generate_totp(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let path = match required_string(arguments, "path") {
            Ok(path) => path,
            Err(result) => return Ok(result),
        };
        if !self.scope_allows(path) {
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }
        let destination = arguments
            .get("destination")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if self.config.can_use_clipboard {
                    "clipboard".into()
                } else if self.config.can_use_autotype {
                    "autotype".into()
                } else {
                    "return".into()
                }
            });
        let return_code = arguments
            .get("return_code")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let Some(entry) = self
            .store
            .get(path)
            .map_err(|error| format!("get entry: {error}"))?
        else {
            return Ok(ToolCallResult::error(format!("entry not found: {path}")));
        };
        let Some(totp) = entry.fields.get("totp").and_then(Value::as_object) else {
            return Err(format!("entry {path:?} does not have TOTP configuration"));
        };
        let Some(secret) = totp.get("secret").and_then(Value::as_str) else {
            return Err(format!("entry {path:?} does not have TOTP configuration"));
        };
        if secret.is_empty() {
            return Err(format!("entry {path:?} does not have TOTP configuration"));
        }
        let algorithm = totp
            .get("algorithm")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("SHA1");
        let digits = totp
            .get("digits")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(6);
        let period = totp
            .get("period")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(30);
        let now = match self.config.now_unix {
            Some(value) => value,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("failed to generate TOTP code: {error}"))?
                .as_secs() as i64,
        };
        let code = symvault_core::totp::generate_totp_at(secret, algorithm, digits, period, now)
            .map_err(|error| format!("failed to generate TOTP code: {error}"))?;

        match destination.as_str() {
            "clipboard" => {
                if !self.config.can_use_clipboard {
                    return Err("clipboard operations not permitted for this agent".into());
                }
                Ok(ToolCallResult::error("clipboard not available"))
            }
            "autotype" => {
                if !self.config.can_use_autotype {
                    return Err("autotype operations not permitted for this agent".into());
                }
                Ok(ToolCallResult::error(
                    "autotype not available on this platform",
                ))
            }
            "return" => {
                if !return_code {
                    return Ok(ToolCallResult::error(
                        "return_code must be true when destination is \"return\"",
                    ));
                }
                let approval_mode = if self.config.approval_mode.is_empty() {
                    if self.config.require_approval {
                        "prompt"
                    } else {
                        "none"
                    }
                } else {
                    self.config.approval_mode.as_str()
                };
                if !self.config.can_read_values {
                    if approval_mode == "deny" {
                        return Ok(ToolCallResult::error(
                            "generate_totp_return denied: approval mode is 'deny'",
                        ));
                    }
                    if approval_mode == "prompt" {
                        return Ok(ToolCallResult::error(
                            "generate_totp_return requires approval but no TTY or GUI dialog available",
                        ));
                    }
                }
                let expires_at = OffsetDateTime::from_unix_timestamp(code.expires_at)
                    .map_err(|error| format!("format TOTP expiry: {error}"))?
                    .format(&Rfc3339)
                    .map_err(|error| format!("format TOTP expiry: {error}"))?;
                json_text(serde_json::json!({
                    "code": code.code,
                    "expires_at": expires_at,
                    "period": code.period,
                }))
            }
            other => Ok(ToolCallResult::error(format!(
                "invalid destination \"{other}\": must be clipboard, autotype, or return"
            ))),
        }
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

    fn list_entries(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        // Go's handler treats a missing or invalid prefix as the empty prefix
        // after RequireString fails. GetBool likewise defaults invalid values
        // to false, so keep this boundary permissive and deterministic.
        let prefix = arguments
            .get("prefix")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !self.scope_allows(prefix) {
            return Err(format!(
                "access denied: path {prefix:?} outside allowed scope"
            ));
        }
        let include_details = arguments
            .get("include_details")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut entries = self
            .store
            .list()
            .map_err(|error| format!("list entries: {error}"))?;
        entries.retain(|entry| prefix.is_empty() || entry.path.starts_with(prefix));
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        if !include_details {
            return json_text(Value::Array(
                entries
                    .into_iter()
                    .map(|entry| Value::String(entry.path))
                    .collect(),
            ));
        }

        let summaries = entries
            .into_iter()
            .map(|entry| {
                let mut summary = Map::new();
                summary.insert(
                    "path".into(),
                    Value::String(crate::render::sanitize_for_mcp(&entry.path)),
                );
                if !entry.secret_type.is_empty() {
                    summary.insert("type".into(), Value::String(entry.secret_type));
                }
                if !entry.usage_hint.is_empty() {
                    summary.insert(
                        "usage_hint".into(),
                        Value::String(crate::render::sanitize_for_mcp(&entry.usage_hint)),
                    );
                }
                if entry.auto_rotate {
                    summary.insert("auto_rotate".into(), Value::Bool(true));
                }
                if !entry.fields.is_empty() {
                    summary.insert("has_value".into(), Value::Bool(true));
                    summary.insert(
                        "field_count".into(),
                        Value::from(i64::try_from(entry.fields.len()).unwrap_or(i64::MAX)),
                    );
                }
                Value::Object(summary)
            })
            .collect();
        json_text(Value::Array(summaries))
    }

    fn find_entries(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let query = match required_string(arguments, "query") {
            Ok(query) => query,
            Err(result) => return Ok(result),
        };
        let matches = self.find_matching_entries(query)?;
        let matches = matches
            .into_iter()
            .map(|entry| ReadOnlyMatch {
                path: crate::render::sanitize_for_mcp(&entry.path),
                fields: entry.fields,
            })
            .collect::<Vec<_>>();
        symvault_gojson::to_string(&matches)
            .map(ToolCallResult::text)
            .map_err(|error| error.to_string())
    }

    fn find_matching_entries(&self, query: &str) -> Result<Vec<ReadOnlyMatch>, String> {
        let needle = symvault_core::go_to_lower(query);
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
            if symvault_core::go_to_lower(&entry.path).contains(&needle) {
                fields.push("path".to_string());
            } else {
                for (field, value) in &entry.fields {
                    collect_field_matches(
                        &mut fields,
                        field,
                        value,
                        &needle,
                        self.config.redact_fields.as_deref().unwrap_or(&[]),
                    );
                }
            }
            fields.sort();
            if !fields.is_empty() {
                matches.push(ReadOnlyMatch {
                    path: entry.path,
                    fields,
                });
            }
        }
        matches.sort_by(|left, right| {
            let path_match =
                |entry: &ReadOnlyMatch| entry.fields.iter().any(|field| field == "path");
            path_match(right)
                .cmp(&path_match(left))
                .then_with(|| left.path.cmp(&right.path))
        });
        Ok(matches)
    }

    fn search_openai(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let query = match required_string(arguments, "query") {
            Ok(query) => query,
            Err(result) => return Ok(result),
        };
        let matches = self.find_matching_entries(query)?;
        let results = matches
            .into_iter()
            .map(|entry| {
                let id = crate::render::sanitize_for_mcp(&entry.path);
                let title = crate::render::sanitize_for_mcp(entry_title(&entry.path));
                let mut result = Map::new();
                result.insert("id".into(), Value::String(id.clone()));
                result.insert("title".into(), Value::String(title));
                result.insert(
                    "url".into(),
                    Value::String(format!("symvault://entry/{id}")),
                );
                if !entry.fields.is_empty() {
                    result.insert(
                        "content".into(),
                        Value::String(format!("Matching fields: {}", entry.fields.join(", "))),
                    );
                }
                Value::Object(result)
            })
            .collect::<Vec<_>>();
        let text = symvault_gojson::to_string(&Value::Array(results.clone()))
            .map_err(|error| error.to_string())?;
        let structured = Value::Object(Map::from_iter([("results".into(), Value::Array(results))]));
        Ok(ToolCallResult::structured(text, structured))
    }

    fn fetch_openai(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let id = match required_string(arguments, "id") {
            Ok(id) => id,
            Err(result) => return Ok(result),
        };
        if !self.scope_allows(id) {
            return Ok(ToolCallResult::error(format!(
                "access denied: path {id:?} outside allowed scope"
            )));
        }
        let cleaned = normalize_scope_path(id);
        if cleaned == "quarantine" || cleaned.starts_with("quarantine/") {
            return Ok(ToolCallResult::error(
                "entry is in quarantine — run 'symvault import review promote' to make it accessible",
            ));
        }
        let Some(mut entry) = self
            .store
            .get(id)
            .map_err(|error| format!("fetch entry: {error}"))?
        else {
            // Go maps a raw store error without a populated service path.
            return Ok(ToolCallResult::error("Entry \"\" not found"));
        };

        let sanitized_id = crate::render::sanitize_for_mcp(id);
        let mut metadata = Map::new();
        metadata.insert("created".into(), Value::String(entry.created.clone()));
        metadata.insert("updated".into(), Value::String(entry.updated.clone()));
        metadata.insert("version".into(), Value::from(entry.version));
        metadata.insert("type".into(), Value::String(entry.secret_type.clone()));
        let mut response = Map::new();
        response.insert("id".into(), Value::String(sanitized_id.clone()));
        response.insert(
            "title".into(),
            Value::String(crate::render::sanitize_for_mcp(entry_title(id))),
        );
        response.insert(
            "url".into(),
            Value::String(format!("symvault://entry/{sanitized_id}")),
        );
        response.insert("metadata".into(), Value::Object(metadata));

        // The Go fetch handler uses ExposeValueTools as a second gate over
        // CanReadValues. The runtime receives the filtered registry, so the
        // presence of get_entry_value is the injected, side-effect-free
        // representation of that profile decision.
        let expose_values = self
            .config
            .available_tools
            .iter()
            .any(|name| name == "get_entry_value");
        if expose_values && self.config.can_read_values && !entry.fields.is_empty() {
            let mut redact = self.config.redact_fields.clone().unwrap_or_default();
            if entry.secret_type == "payment" && !self.config.expose_payment_values {
                redact.extend(
                    ["card_number", "cvc", "iban"]
                        .into_iter()
                        .map(str::to_owned),
                );
            }
            let redacted_entry = !redact.is_empty();
            for (field, value) in &mut entry.fields {
                *value = redact_value(field, value.clone(), &redact);
            }
            if redacted_entry {
                // Match Go redactEntry: metadata was captured above, while
                // the value branch sees an entry stripped of classification.
                entry.classification = 0;
            }
            if entry.classification >= 3 && !self.config.auto_unseal {
                return self.sealed_entry_response(id, &entry);
            }
            let field_count = i64::try_from(entry.fields.len()).unwrap_or(i64::MAX);
            if self.config.max_secrets_in_session > 0 {
                let used = self.secrets_accessed.load(Ordering::Acquire);
                let next = used.saturating_add(field_count);
                if next > self.config.max_secrets_in_session {
                    return Ok(ToolCallResult::error(format!(
                        "max secrets per session exceeded ({next}/{})",
                        self.config.max_secrets_in_session
                    )));
                }
            }
            self.secrets_accessed
                .fetch_add(field_count, Ordering::AcqRel);
            let mut values = Map::new();
            for (field, value) in entry.fields {
                let wrapped = wrap_data_field(&field, value)?;
                let checked = match wrapped {
                    Value::String(text) => Value::String(apply_semantic_injection_check(
                        text,
                        &self.config.prompt_injection_mode,
                        &self.config.agent_name,
                    )?),
                    other => other,
                };
                values.insert(field, checked);
            }
            response.insert("values".into(), Value::Object(values));
        }
        let value = Value::Object(response);
        let text = symvault_gojson::to_string(&value).map_err(|error| error.to_string())?;
        Ok(ToolCallResult::structured(text, value))
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

    fn get_entry_value(&self, arguments: &Value) -> Result<ToolCallResult, String> {
        let path = match required_string(arguments, "path") {
            Ok(path) => path,
            Err(result) => return Ok(result),
        };
        if !self.scope_allows(path) {
            return Err(format!(
                "access denied: path {path:?} outside allowed scope"
            ));
        }
        let cleaned = normalize_scope_path(path);
        if cleaned == "quarantine" || cleaned.starts_with("quarantine/") {
            return Ok(ToolCallResult::error(
                "entry is in quarantine — run 'symvault import review promote' to make it accessible",
            ));
        }
        let Some(mut entry) = self
            .store
            .get(path)
            .map_err(|error| format!("get entry: {error}"))?
        else {
            return Ok(ToolCallResult::error(format!("entry not found: {path}")));
        };

        let mut redact = self.config.redact_fields.clone().unwrap_or_default();
        if entry.secret_type == "payment" && !self.config.expose_payment_values {
            redact.extend(
                ["card_number", "cvc", "iban"]
                    .into_iter()
                    .map(str::to_owned),
            );
        }
        let redacted_entry = !redact.is_empty();
        for (field, value) in &mut entry.fields {
            *value = redact_value(field, value.clone(), &redact);
        }
        // Go's redactEntry constructs a fresh Entry with only Data and
        // Metadata. Preserve that omission behavior after field redaction.
        if redacted_entry {
            entry.path.clear();
            entry.secret_type.clear();
            entry.usage_hint.clear();
            entry.auto_rotate = false;
            entry.expires_at = None;
            entry.classification = 0;
        }

        if entry.classification >= 3 && !self.config.auto_unseal {
            return self.sealed_entry_response(path, &entry);
        }

        let max_secrets = self.config.max_secrets_in_session;
        let field_count = i64::try_from(entry.fields.len()).unwrap_or(i64::MAX);
        if max_secrets > 0 {
            let used = self.secrets_accessed.load(Ordering::Acquire);
            let next = used.saturating_add(field_count);
            if next > max_secrets {
                return Ok(ToolCallResult::error(format!(
                    "max secrets per session exceeded ({next}/{max_secrets})"
                )));
            }
        }
        self.secrets_accessed
            .fetch_add(field_count, Ordering::AcqRel);
        let mut data = Map::new();
        for (field, value) in entry.fields {
            let wrapped = wrap_data_field(&field, value)?;
            let checked = match wrapped {
                Value::String(text) => {
                    match apply_semantic_injection_check(
                        text,
                        &self.config.prompt_injection_mode,
                        &self.config.agent_name,
                    ) {
                        Ok(text) => Value::String(text),
                        Err(error) => return Ok(ToolCallResult::error(error)),
                    }
                }
                other => other,
            };
            data.insert(field.clone(), checked);
        }

        let mut meta = Map::new();
        meta.insert("created".into(), Value::String(entry.created));
        meta.insert("updated".into(), Value::String(entry.updated));
        meta.insert("version".into(), Value::from(entry.version));
        if !entry.tags.is_empty() {
            meta.insert(
                "tags".into(),
                Value::Array(
                    entry
                        .tags
                        .iter()
                        .map(|tag| Value::String(crate::render::sanitize_for_mcp(tag)))
                        .collect(),
                ),
            );
        }
        let mut secret_meta = Map::new();
        if !entry.secret_type.is_empty() {
            secret_meta.insert("type".into(), Value::String(entry.secret_type));
        }
        if !entry.usage_hint.is_empty() {
            secret_meta.insert(
                "usage_hint".into(),
                Value::String(crate::render::sanitize_for_mcp(&entry.usage_hint)),
            );
        }
        if entry.auto_rotate {
            secret_meta.insert("auto_rotate".into(), Value::Bool(true));
        }
        if let Some(expires_at) = entry.expires_at {
            secret_meta.insert("expires_at".into(), Value::String(expires_at));
        }
        let mut response = Map::new();
        response.insert("data".into(), Value::Object(data));
        response.insert("meta".into(), Value::Object(meta));
        response.insert("secret_meta".into(), Value::Object(secret_meta));
        if entry.classification != 0 {
            response.insert("classification".into(), Value::from(entry.classification));
        }
        json_text(Value::Object(response))
    }

    fn sealed_entry_response(
        &self,
        path: &str,
        entry: &ReadOnlyEntry,
    ) -> Result<ToolCallResult, String> {
        let field = entry.fields.keys().next().map(String::as_str).unwrap_or("");
        let classification = match entry.classification {
            0 => "public",
            1 => "internal",
            2 => "confidential",
            3 => "secret",
            4 => "restricted",
            _ => "unknown",
        };
        let response = serde_json::json!({
            "handle": format!("op://{path}/{field}"),
            "classification": classification,
            "note": "Use secret_unseal tool to reveal the value",
            "usage": usage_for(path, field),
        });
        json_text(response)
    }

    pub(crate) fn scope_allows(&self, path: &str) -> bool {
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

fn entry_title(path: &str) -> &str {
    match path.rsplit('/').next() {
        Some("") | None => path,
        Some(name) => name,
    }
}

fn json_text(value: Value) -> Result<ToolCallResult, String> {
    symvault_gojson::to_string(&value)
        .map(ToolCallResult::text)
        .map_err(|error| error.to_string())
}

pub(crate) fn required_string<'a>(
    arguments: &'a Value,
    name: &str,
) -> Result<&'a str, ToolCallResult> {
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

fn redact_value(field: &str, value: Value, patterns: &[String]) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(name, nested)| {
                    let nested_field = format!("{field}.{name}");
                    (name, redact_value(&nested_field, nested, patterns))
                })
                .collect(),
        ),
        other => {
            if is_redacted_field(field, patterns) {
                Value::String("[REDACTED]".into())
            } else {
                other
            }
        }
    }
}

fn wrap_data_field(label: &str, value: Value) -> Result<Value, String> {
    match value {
        Value::String(value) => crate::render::embed_as_data(label, &value)
            .map(Value::String)
            .map_err(|error| format!("embed data field: {error}")),
        Value::Object(map) => map
            .into_iter()
            .map(|(name, nested)| Ok((name.clone(), wrap_data_field(&name, nested)?)))
            .collect::<Result<Map<_, _>, String>>()
            .map(Value::Object),
        other => Ok(other),
    }
}

const SEMANTIC_INJECTION_PATTERNS: &[&str] = &[
    "<|im_start|>",
    "<|endoftext|>",
    "system:",
    "ignore previous instructions",
    "ignore all instructions",
    "ignore the above",
    "disregard earlier",
    "forget your previous",
    "override your instructions",
    "you are now",
];

fn apply_semantic_injection_check(
    text: String,
    mode: &str,
    agent_name: &str,
) -> Result<String, String> {
    if mode.is_empty() || mode == "off" {
        return Ok(text);
    }
    let lower = symvault_core::go_to_lower(&text);
    let Some(pattern) = SEMANTIC_INJECTION_PATTERNS
        .iter()
        .find(|pattern| lower.contains(**pattern))
    else {
        return Ok(text);
    };
    match mode {
        // Match Go's slog warning on stderr. Keep the vault content out of
        // the diagnostic so logging cannot disclose the value being checked.
        "log-only" => {
            eprintln!("{}", semantic_injection_warning(pattern, agent_name));
            Ok(text)
        }
        "wrap" => Ok(format!(
            "[SECURITY WARNING: potential prompt injection detected (pattern: \"{pattern}\")]\n{text}"
        )),
        "deny" => Err(format!(
            "access denied: vault content contains potential prompt injection pattern \"{pattern}\""
        )),
        // Match Go's forward-compatible behavior for unknown modes.
        _ => Ok(text),
    }
}

fn semantic_injection_warning(pattern: &str, agent_name: &str) -> String {
    format!(
        "level=WARN msg=\"semantic prompt injection detected\" pattern={pattern:?} agent={agent_name:?}"
    )
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
            if !prefix.is_empty() && symvault_core::go_to_lower(&rendered).contains(needle) {
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

pub(crate) fn normalize_scope_path(path: &str) -> String {
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

#[cfg(test)]
mod semantic_injection_tests {
    use super::semantic_injection_warning;

    #[test]
    fn log_only_warning_has_no_vault_content() {
        let warning = semantic_injection_warning("ignore previous instructions", "fixture");
        assert!(warning.contains("semantic prompt injection detected"));
        assert!(warning.contains("pattern=\"ignore previous instructions\""));
        assert!(warning.contains("agent=\"fixture\""));
        assert!(!warning.contains("synthetic-secret-value"));
    }
}
