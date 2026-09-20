use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

const CATALOG_JSON: &str = include_str!("tool_catalog.json");

/// Runtime inputs that affect the Go registry's list-time filtering. Runtime
/// capabilities are injected by the caller so listing never probes a keychain,
/// vault, GUI, or command runner.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ToolListConfig {
    pub tier: Option<String>,
    pub expose_value_tools: Option<bool>,
    pub execute_api_available: bool,
    pub secure_input_available: bool,
    pub generate_totp_available: bool,
}

impl Default for ToolListConfig {
    fn default() -> Self {
        Self {
            tier: None,
            expose_value_tools: None,
            execute_api_available: false,
            secure_input_available: false,
            // Go shows this tool without profile context.
            generate_totp_available: true,
        }
    }
}

impl ToolListConfig {
    pub fn for_tier(
        tier: impl Into<String>,
        execute_api_available: bool,
        secure_input_available: bool,
        generate_totp_available: bool,
    ) -> Self {
        let tier = tier.into();
        let expose_value_tools = (tier == "admin").then_some(true).or(Some(false));
        Self {
            tier: Some(tier),
            expose_value_tools,
            execute_api_available,
            secure_input_available,
            generate_totp_available,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ToolDefinition {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deprecated: Option<bool>,
    #[serde(rename = "aliasFor", default, skip_serializing_if = "Option::is_none")]
    alias_for: Option<String>,
    #[serde(
        rename = "readOnlyHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    read_only_hint: Option<bool>,
    #[serde(
        rename = "destructiveHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capabilities: Option<Value>,
}

#[derive(Serialize)]
struct SearchResultSpec {
    name: String,
    description: String,
    #[serde(rename = "input_schema")]
    input_schema: Value,
    risk_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cli_alternative: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier_required: Option<String>,
}

static CATALOG: OnceLock<Result<Vec<ToolDefinition>, String>> = OnceLock::new();

fn catalog() -> Result<&'static [ToolDefinition], String> {
    CATALOG
        .get_or_init(|| {
            serde_json::from_str::<Vec<ToolDefinition>>(CATALOG_JSON).map_err(|err| err.to_string())
        })
        .as_deref()
        .map_err(Clone::clone)
}

pub(crate) fn contains_tool(name: &str) -> Result<bool, String> {
    Ok(catalog()?.iter().any(|definition| definition.name == name))
}

/// Return catalog discovery results using the same static registry view as Go.
/// Search intentionally includes tools that are unavailable in the current
/// runtime: callers need their risk and CLI alternative to choose a fallback.
pub(crate) fn search_tools(intent: &str, return_mode: &str) -> Result<String, String> {
    let needle = symvault_core::go_to_lower(intent);
    let matched = catalog()?
        .iter()
        .filter(|definition| definition.deprecated != Some(true))
        .filter(|definition| {
            symvault_core::go_to_lower(&definition.name).contains(&needle)
                || symvault_core::go_to_lower(&definition.description).contains(&needle)
        })
        .collect::<Vec<_>>();
    if return_mode == "names" {
        let names = matched
            .into_iter()
            .map(|definition| definition.name.clone())
            .collect::<Vec<_>>();
        return symvault_gojson::to_string(&names).map_err(|error| error.to_string());
    }
    let specs = matched
        .into_iter()
        .map(|definition| SearchResultSpec {
            name: definition.name.clone(),
            description: definition.description.clone(),
            input_schema: definition.input_schema.clone(),
            risk_level: risk_level(&definition.name).0.to_owned(),
            cli_alternative: cli_alternative(&definition.name).map(str::to_owned),
            tier_required: Some(risk_level(&definition.name).1.to_owned()),
        })
        .collect::<Vec<_>>();
    symvault_gojson::to_string(&specs).map_err(|error| error.to_string())
}

fn risk_level(name: &str) -> (&'static str, &'static str) {
    let level = match name {
        "set_auth_method"
        | "autotype"
        | "copy_to_clipboard"
        | "execute_with_secret"
        | "get_entry_value"
        | "run_command"
        | "approve_share"
        | "revoke_share"
        | "generate_totp"
        | "secret_unseal" => "high",
        "prepare_payment"
        | "delete_entry"
        | "symaira_delete"
        | "execute_api_request"
        | "request_credential"
        | "secure_input"
        | "set_entry_field" => "critical",
        "get_entry" | "get_entry_metadata" | "request_share" | "generate_template" => "medium",
        _ => "low",
    };
    let tier = match level {
        "medium" => "standard",
        "high" | "critical" => "admin",
        _ => "any",
    };
    (level, tier)
}

fn cli_alternative(name: &str) -> Option<&'static str> {
    match name {
        "list_entries" => Some("symvault list [prefix]"),
        "get_entry" | "get_entry_value" | "get_entry_metadata" => Some("symvault get <path>"),
        "find_entries" => Some("symvault find <query>"),
        "set_entry_field" => Some("symvault set <path>.<field> --value <value>"),
        "delete_entry" => Some("symvault delete <path>"),
        "generate_password" => Some("symvault generate --length N --symbols"),
        "generate_totp" => Some("symvault get <path> --totp"),
        "copy_to_clipboard" => Some("symvault get <path>.password --clip"),
        "autotype" => Some("symvault get <path>.password --autotype"),
        "health" => Some("symvault mcp --stdio (health is automatic)"),
        "run_command" => Some("symvault run --env KEY=path.field -- <command>"),
        _ => None,
    }
}

fn blocked_by_tier(tier: Option<&str>, name: &str) -> bool {
    match tier {
        Some("read-only") => matches!(
            name,
            "set_entry_field"
                | "delete_entry"
                | "run_command"
                | "execute_with_secret"
                | "execute_api_request"
                | "secure_input"
                | "request_credential"
                | "copy_to_clipboard"
                | "autotype"
                | "prepare_payment"
        ),
        Some("standard") => matches!(
            name,
            "delete_entry" | "run_command" | "execute_with_secret" | "execute_api_request"
        ),
        _ => false,
    }
}

fn available(def: &ToolDefinition, config: &ToolListConfig) -> bool {
    if matches!(def.name.as_str(), "execute_api_request") && !config.execute_api_available {
        return false;
    }
    if matches!(def.name.as_str(), "secure_input" | "request_credential")
        && !config.secure_input_available
    {
        return false;
    }
    if def.name == "generate_totp" && !config.generate_totp_available {
        return false;
    }
    if blocked_by_tier(config.tier.as_deref(), &def.name) {
        return false;
    }
    if !expose_value_tools(config) && def.name == "get_entry_value" {
        return false;
    }
    true
}

fn expose_value_tools(config: &ToolListConfig) -> bool {
    config
        .expose_value_tools
        .unwrap_or(matches!(config.tier.as_deref(), None | Some("admin")))
}

const LEAN_TOOL_SET: &[&str] = &[
    "symaira_whoami",
    "symaira_search",
    "health",
    "find_entries",
    "get_entry",
    "get_entry_metadata",
    "request_credential",
    "set_entry_field",
    "generate_password",
    "symaira_audit_self",
];

fn without_include_value(mut schema: Value) -> Value {
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        properties.remove("include_value");
    }
    schema
}

pub(crate) fn list_tools(config: &ToolListConfig, include_all: bool) -> Result<Value, String> {
    let catalog = catalog()?;
    let tools = catalog
        .iter()
        .filter(|def| available(def, config))
        .filter(|def| include_all || LEAN_TOOL_SET.contains(&def.name.as_str()))
        .map(|def| {
            let mut value = serde_json::to_value(def).expect("tool catalog is serializable");
            if config.expose_value_tools == Some(false)
                && def.name == "get_entry"
                && let Some(schema) = value.get_mut("inputSchema")
            {
                *schema = without_include_value(schema.take());
            }
            value
        })
        .collect::<Vec<_>>();
    Ok(Value::Array(tools))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_the_go_registry_size() {
        assert_eq!(catalog().unwrap().len(), 35);
    }

    #[test]
    fn standard_filter_preserves_the_go_alias_quirk() {
        let config = ToolListConfig::for_tier("standard", true, true, true);
        let tools = list_tools(&config, true).unwrap();
        let names = tools
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(!names.contains(&"delete_entry"));
        assert!(names.contains(&"symaira_delete"));
    }

    #[test]
    fn tier_defaults_hide_value_tools_without_an_explicit_flag() {
        let config = ToolListConfig {
            tier: Some("standard".to_string()),
            ..ToolListConfig::default()
        };
        let tools = list_tools(&config, true).unwrap();
        assert!(
            !tools
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == "get_entry_value")
        );
    }

    #[test]
    fn custom_tier_defaults_hide_value_tools_without_an_explicit_flag() {
        let config = ToolListConfig {
            tier: Some("custom".to_string()),
            ..ToolListConfig::default()
        };
        let tools = list_tools(&config, true).unwrap();
        assert!(
            !tools
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == "get_entry_value")
        );
    }
}
