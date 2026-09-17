use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
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

static CATALOG: OnceLock<Result<Vec<ToolDefinition>, String>> = OnceLock::new();

fn catalog() -> Result<&'static [ToolDefinition], String> {
    CATALOG
        .get_or_init(|| {
            serde_json::from_str::<Vec<ToolDefinition>>(CATALOG_JSON).map_err(|err| err.to_string())
        })
        .as_deref()
        .map_err(Clone::clone)
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
    let lean = LEAN_TOOL_SET.iter().copied().collect::<HashSet<_>>();
    let tools = catalog
        .iter()
        .filter(|def| available(def, config))
        .filter(|def| include_all || lean.contains(def.name.as_str()))
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
