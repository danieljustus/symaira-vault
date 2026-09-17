use std::{collections::BTreeMap, fs, io::Write, path::Path, time::Duration};

use symvault_core::config::{AgentProfile, Config};

/// Displays one merged agent profile, matching `agent profile show`.
///
/// Go's config loader preserves pointer nil-ness for the profile fields that
/// are omitted from YAML and emits those nil pointers as JSON nulls. The core
/// Rust config intentionally normalizes most fields to plain values for policy
/// consumers, so the source field set is retained here for presentation.
pub(crate) fn show(
    vault: &Path,
    name: &str,
    output_format: Option<&str>,
    output: &mut impl Write,
) -> Result<(), String> {
    let config_path = vault.join("config.yaml");
    let config = Config::load(&config_path).map_err(|error| format!("load config: {error}"))?;
    let profile = config
        .agents
        .get(name)
        .ok_or_else(|| format!("agent {name:?} not found in config"))?;
    let fields = source_fields(&config_path, name)?;
    let data = ProfileData::from_loaded(name, profile, &fields);

    if output_format == Some("json") {
        let view = JsonProfile(&data);
        let rendered = serde_json::to_string_pretty(&view)
            .map_err(|error| format!("write profile output: {error}"))?;
        let rendered = escape_go_json(&rendered);
        output
            .write_all(rendered.as_bytes())
            .map_err(|error| format!("write profile output: {error}"))?;
        writeln!(output).map_err(|error| format!("write profile output: {error}"))?;
    } else {
        let view = YamlProfile(&data);
        let rendered = serde_yaml_ng::to_string(&view)
            .map_err(|error| format!("write profile output: {error}"))?;
        let rendered = go_yaml_indentation(&rendered);
        output
            .write_all(rendered.as_bytes())
            .map_err(|error| format!("write profile output: {error}"))?;
    }
    Ok(())
}

/// `yaml.v3` emits sequence indicators two columns to the left of
/// `serde_yaml_ng` for the profile-shaped sequences we expose. Adjust only
/// actual sequence marker lines; block scalar content is left byte-for-byte
/// intact so a scalar beginning with `- ` cannot be mistaken for a sequence.
fn go_yaml_indentation(rendered: &str) -> String {
    let mut adjusted = String::with_capacity(rendered.len());
    let mut block_scalar_indent = None;

    for line in rendered.split_inclusive('\n') {
        let (content, newline) = line
            .strip_suffix('\n')
            .map_or((line, ""), |content| (content, "\n"));
        let leading_spaces = content.bytes().take_while(|byte| *byte == b' ').count();

        if let Some(indent) = block_scalar_indent {
            if !content.trim().is_empty() && leading_spaces <= indent {
                block_scalar_indent = None;
            }
        }

        let in_block_scalar = block_scalar_indent.is_some();
        if !in_block_scalar && content.starts_with("  - ") {
            adjusted.push_str(&content[2..]);
        } else {
            adjusted.push_str(content);
        }
        adjusted.push_str(newline);

        if block_scalar_indent.is_none() {
            let value = content
                .split_once(':')
                .map_or("", |(_, value)| value.trim());
            if is_block_scalar_header(value) {
                block_scalar_indent = Some(leading_spaces);
            }
        }
    }

    adjusted
}

fn is_block_scalar_header(value: &str) -> bool {
    let Some(first) = value.as_bytes().first().copied() else {
        return false;
    };
    if first != b'|' && first != b'>' {
        return false;
    }
    value[1..]
        .chars()
        .all(|character| matches!(character, '+' | '-' | '0'..='9'))
}

// These characters occur only inside strings in serialized JSON.
fn escape_go_json(rendered: &str) -> String {
    rendered
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

type SourceFields = BTreeMap<String, serde_yaml_ng::Value>;

fn source_fields(path: &Path, name: &str) -> Result<SourceFields, String> {
    let bytes = fs::read(path).map_err(|error| format!("load config: {error}"))?;
    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(&bytes).map_err(|error| format!("load config: {error}"))?;
    let Some(agents) = document
        .as_mapping()
        .and_then(|mapping| mapping.get(serde_yaml_ng::Value::String("agents".to_owned())))
        .and_then(serde_yaml_ng::Value::as_mapping)
    else {
        return Ok(BTreeMap::new());
    };
    let Some(profile) = agents
        .get(serde_yaml_ng::Value::String(name.to_owned()))
        .and_then(serde_yaml_ng::Value::as_mapping)
    else {
        return Ok(BTreeMap::new());
    };
    profile
        .iter()
        .map(|(key, value)| {
            key.as_str()
                .map(|key| (key.to_owned(), value.clone()))
                .ok_or_else(|| "agent profile field name must be a string".to_owned())
        })
        .collect()
}

#[derive(Clone, Debug)]
struct ProfileData {
    name: String,
    tier: Option<String>,
    approval_mode: Option<String>,
    allowed_paths: Option<Vec<String>>,
    redact_fields: Option<Vec<String>>,
    per_tool_redact_fields: Option<BTreeMap<String, Vec<String>>>,
    can_write: Option<bool>,
    can_run_commands: Option<bool>,
    can_manage_config: Option<bool>,
    can_use_clipboard: Option<bool>,
    can_use_autotype: Option<bool>,
    can_read_values: Option<bool>,
    expose_value_tools: Option<bool>,
    auto_unseal: Option<bool>,
    require_approval: Option<bool>,
    approval_timeout: Option<Duration>,
    allowed_tools: Option<Vec<String>>,
    max_reads_per_hour: Option<i64>,
    max_reads_per_day: Option<i64>,
    max_secrets_in_session: Option<i64>,
    dynamic_providers: Option<BTreeMap<String, Vec<String>>>,
    allowed_env_vars: Option<Vec<String>>,
    allowed_executables: Option<Vec<String>>,
    prompt_injection_mode: Option<String>,
    skill_path: Option<String>,
    skill_version: Option<String>,
    expose_payment_values: Option<bool>,
    payment_policy: Option<String>,
}

impl ProfileData {
    fn from_loaded(name: &str, profile: &AgentProfile, fields: &SourceFields) -> Self {
        let tier = profile.tier.clone();
        let tier_sets_capabilities = tier
            .as_deref()
            .is_some_and(|tier| matches!(tier, "read-only" | "standard" | "admin"));
        let builtin = matches!(
            name,
            "default" | "claude-code" | "codex" | "hermes" | "openclaw" | "opencode"
        );
        let builtin_skill_path = matches!(
            name,
            "claude-code" | "codex" | "hermes" | "openclaw" | "opencode"
        );
        let builtin_field = |field: &str| {
            builtin
                && matches!(
                    field,
                    "approvalMode"
                        | "canWrite"
                        | "canRunCommands"
                        | "exposeValueTools"
                        | "autoUnseal"
                )
        };
        let emits = |field: &str| {
            fields.contains_key(field) || tier_sets_capabilities || builtin_field(field)
        };
        let raw = |field: &str| fields.get(field);

        Self {
            name: name.to_owned(),
            tier,
            approval_mode: emits("approvalMode")
                .then(|| profile.approval_mode.clone())
                .flatten(),
            allowed_paths: if fields.contains_key("allowedPaths")
                && profile.allowed_paths.is_empty()
            {
                None
            } else {
                Some(profile.allowed_paths.clone())
            },
            redact_fields: raw_nonempty_slice(fields, "redactFields", &profile.redact_fields),
            per_tool_redact_fields: raw("perToolRedactFields").and_then(parse_value),
            can_write: emits("canWrite").then_some(profile.can_write),
            can_run_commands: emits("canRunCommands").then_some(profile.can_run_commands),
            can_manage_config: emits("canManageConfig").then_some(profile.can_manage_config),
            can_use_clipboard: emits("canUseClipboard").then_some(profile.can_use_clipboard),
            can_use_autotype: emits("canUseAutotype").then_some(profile.can_use_autotype),
            can_read_values: emits("canReadValues").then_some(profile.can_read_values),
            expose_value_tools: if !fields.contains_key("tier")
                && !fields.contains_key("exposeValueTools")
            {
                Some(true)
            } else {
                emits("exposeValueTools").then_some(profile.expose_value_tools)
            },
            auto_unseal: emits("autoUnseal").then_some(profile.auto_unseal),
            require_approval: emits("requireApproval").then_some(profile.require_approval),
            approval_timeout: raw("approvalTimeout").map(|_| profile.approval_timeout),
            allowed_tools: raw_nonempty_slice(fields, "allowed_tools", &profile.allowed_tools),
            max_reads_per_hour: raw("max_reads_per_hour").map(|_| profile.max_reads_per_hour),
            max_reads_per_day: raw("max_reads_per_day").map(|_| profile.max_reads_per_day),
            max_secrets_in_session: raw("max_secrets_in_session")
                .map(|_| profile.max_secrets_in_session),
            dynamic_providers: raw("dynamicProviders").and_then(parse_value),
            allowed_env_vars: raw_nonempty_slice(
                fields,
                "allowedEnvVars",
                &profile.allowed_env_vars,
            ),
            allowed_executables: if tier_sets_capabilities {
                (!profile.allowed_executables.is_empty())
                    .then_some(profile.allowed_executables.clone())
            } else if raw("allowedExecutables").is_some() && !profile.allowed_executables.is_empty()
            {
                Some(profile.allowed_executables.clone())
            } else {
                None
            },
            prompt_injection_mode: raw("promptInjectionMode")
                .map(|_| profile.prompt_injection_mode.clone()),
            skill_path: if builtin_skill_path || raw("skillPath").is_some() {
                Some(profile.skill_path.clone())
            } else {
                None
            },
            skill_version: raw("skillVersion").map(|_| profile.skill_version.clone()),
            expose_payment_values: raw("exposePaymentValues")
                .map(|_| profile.expose_payment_values),
            payment_policy: raw("paymentPolicy")
                .and_then(serde_yaml_ng::Value::as_str)
                .map(str::to_owned),
        }
    }
}

fn parse_value<T>(value: &serde_yaml_ng::Value) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_yaml_ng::from_value(value.clone()).ok()
}

fn raw_nonempty_slice(fields: &SourceFields, field: &str, value: &[String]) -> Option<Vec<String>> {
    fields
        .contains_key(field)
        .then(|| (!value.is_empty()).then(|| value.to_owned()))
        .flatten()
}

fn format_duration(value: Duration) -> String {
    let secs = value.as_secs();
    let nanos = value.subsec_nanos();
    if nanos == 0 {
        if secs.is_multiple_of(3600) {
            return format!("{}h0m0s", secs / 3600);
        }
        if secs.is_multiple_of(60) {
            return format!("{}m0s", secs / 60);
        }
        return format!("{secs}s");
    }
    format!("{}.{nanos:09}s", secs)
}

struct YamlProfile<'a>(&'a ProfileData);

impl serde::Serialize for YamlProfile<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let data = self.0;
        let mut state = serializer.serialize_struct("AgentProfile", 29)?;
        macro_rules! optional {
            ($key:literal, $field:expr) => {
                if let Some(value) = &$field {
                    state.serialize_field($key, value)?;
                }
            };
        }
        macro_rules! optional_nonempty {
            ($key:literal, $field:expr) => {
                if let Some(value) = &$field {
                    if !value.is_empty() {
                        state.serialize_field($key, value)?;
                    }
                }
            };
        }

        optional!("tier", data.tier);
        optional!("approvalMode", data.approval_mode);
        if let Some(value) = &data.allowed_paths {
            if !value.is_empty() {
                state.serialize_field("allowedPaths", value)?;
            }
        }
        optional_nonempty!("redactFields", data.redact_fields);
        optional_nonempty!("perToolRedactFields", data.per_tool_redact_fields);
        optional!("canWrite", data.can_write);
        optional!("canRunCommands", data.can_run_commands);
        optional!("canManageConfig", data.can_manage_config);
        optional!("canUseClipboard", data.can_use_clipboard);
        optional!("canUseAutotype", data.can_use_autotype);
        optional!("canReadValues", data.can_read_values);
        optional!("exposeValueTools", data.expose_value_tools);
        optional!("autoUnseal", data.auto_unseal);
        optional!("requireApproval", data.require_approval);
        if let Some(value) = data.approval_timeout {
            state.serialize_field("approvalTimeout", &format_duration(value))?;
        }
        optional_nonempty!("allowed_tools", data.allowed_tools);
        optional!("max_reads_per_hour", data.max_reads_per_hour);
        optional!("max_reads_per_day", data.max_reads_per_day);
        optional!("max_secrets_in_session", data.max_secrets_in_session);
        optional_nonempty!("dynamicProviders", data.dynamic_providers);
        optional_nonempty!("allowedEnvVars", data.allowed_env_vars);
        optional_nonempty!("allowedExecutables", data.allowed_executables);
        optional!("promptInjectionMode", data.prompt_injection_mode);
        optional!("skillPath", data.skill_path);
        optional!("skillVersion", data.skill_version);
        optional!("exposePaymentValues", data.expose_payment_values);
        optional!("paymentPolicy", data.payment_policy);
        state.end()
    }
}

struct JsonProfile<'a>(&'a ProfileData);

impl serde::Serialize for JsonProfile<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let data = self.0;
        let mut state = serializer.serialize_struct("AgentProfile", 29)?;
        macro_rules! field {
            ($key:literal, $value:expr) => {
                state.serialize_field($key, &$value)?;
            };
        }

        field!("Name", data.name);
        field!("Tier", data.tier);
        field!("ApprovalMode", data.approval_mode);
        field!("AllowedPaths", data.allowed_paths);
        field!("RedactFields", data.redact_fields);
        field!("PerToolRedactFields", data.per_tool_redact_fields);
        field!("CanWrite", data.can_write);
        field!("CanRunCommands", data.can_run_commands);
        field!("CanManageConfig", data.can_manage_config);
        field!("CanUseClipboard", data.can_use_clipboard);
        field!("CanUseAutotype", data.can_use_autotype);
        field!("CanReadValues", data.can_read_values);
        field!("ExposeValueTools", data.expose_value_tools);
        field!("AutoUnseal", data.auto_unseal);
        field!("RequireApproval", data.require_approval);
        let approval_timeout = data.approval_timeout.map(|value| value.as_nanos() as i64);
        field!("ApprovalTimeout", approval_timeout);
        field!("AllowedTools", data.allowed_tools);
        field!("MaxReadsPerHour", data.max_reads_per_hour);
        field!("MaxReadsPerDay", data.max_reads_per_day);
        field!("MaxSecretsInSession", data.max_secrets_in_session);
        field!("DynamicProviders", data.dynamic_providers);
        field!("AllowedEnvVars", data.allowed_env_vars);
        field!("AllowedExecutables", data.allowed_executables);
        field!("PromptInjectionMode", data.prompt_injection_mode);
        field!("PreCallHooks", Option::<Vec<String>>::None);
        field!("PostCallHooks", Option::<Vec<String>>::None);
        field!("SkillPath", data.skill_path);
        field!("SkillVersion", data.skill_version);
        field!("ExposePaymentValues", data.expose_payment_values);
        field!("PaymentPolicy", data.payment_policy);
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_view_keeps_go_field_order_and_duration_units() {
        let data = ProfileData {
            name: "demo".into(),
            tier: Some("standard".into()),
            approval_mode: Some("prompt".into()),
            allowed_paths: Some(vec!["team/*".into()]),
            redact_fields: None,
            per_tool_redact_fields: None,
            can_write: Some(false),
            can_run_commands: Some(false),
            can_manage_config: Some(false),
            can_use_clipboard: Some(true),
            can_use_autotype: Some(true),
            can_read_values: Some(true),
            expose_value_tools: Some(false),
            auto_unseal: Some(false),
            require_approval: Some(true),
            approval_timeout: Some(Duration::from_secs(120)),
            allowed_tools: None,
            max_reads_per_hour: None,
            max_reads_per_day: None,
            max_secrets_in_session: None,
            dynamic_providers: None,
            allowed_env_vars: None,
            allowed_executables: None,
            prompt_injection_mode: None,
            skill_path: None,
            skill_version: None,
            expose_payment_values: None,
            payment_policy: None,
        };
        let mut output = Vec::new();
        serde_json::to_writer_pretty(&mut output, &JsonProfile(&data)).unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("\"Name\": \"demo\""));
        assert!(rendered.contains("\"ApprovalTimeout\": 120000000000"));
        assert!(rendered.find("\"Name\"").unwrap() < rendered.find("\"Tier\"").unwrap());
    }

    #[test]
    fn profile_output_matches_go_sequence_indent_without_rewriting_block_scalars() {
        let data = ProfileData {
            name: "demo".into(),
            tier: None,
            approval_mode: None,
            allowed_paths: Some(vec!["team/*".into()]),
            redact_fields: None,
            per_tool_redact_fields: None,
            can_write: None,
            can_run_commands: None,
            can_manage_config: None,
            can_use_clipboard: None,
            can_use_autotype: None,
            can_read_values: None,
            expose_value_tools: None,
            auto_unseal: None,
            require_approval: None,
            approval_timeout: None,
            allowed_tools: None,
            max_reads_per_hour: None,
            max_reads_per_day: None,
            max_secrets_in_session: None,
            dynamic_providers: None,
            allowed_env_vars: None,
            allowed_executables: None,
            prompt_injection_mode: None,
            skill_path: Some("first line\n- literal content\n".into()),
            skill_version: None,
            expose_payment_values: None,
            payment_policy: None,
        };
        let rendered = serde_yaml_ng::to_string(&YamlProfile(&data)).unwrap();
        let adjusted = go_yaml_indentation(&rendered);
        assert!(adjusted.contains("allowedPaths:\n  - team/*\n"));
        assert!(adjusted.contains("  - literal content\n"));
    }

    #[test]
    fn json_output_escapes_go_html_and_line_separator_characters_only_in_strings() {
        let rendered = r#"{
  "value": "<&> ",
  "literal": "\\u003c"
}"#;
        let escaped = escape_go_json(rendered);
        assert!(escaped.contains(r#""value": "\u003c\u0026\u003e\u2028""#));
        assert!(escaped.contains(r#""literal": "\\u003c""#));
        assert!(escaped.contains("{\n"));
    }
}
