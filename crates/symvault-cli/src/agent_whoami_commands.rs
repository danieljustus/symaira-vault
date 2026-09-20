//! Read-only current-agent context, matching Go's `agent whoami` command.

use std::{fs, io::Write, path::Path};

use serde::Serialize;
use symvault_core::config::Config;

const AGENT_ENV_ERROR: &str =
    "SYMVAULT_AGENT not set. Run without agent context or set SYMVAULT_AGENT=<name>";

#[derive(Debug, Serialize)]
struct WhoamiQuotas {
    #[serde(skip_serializing_if = "is_zero")]
    max_reads_per_hour: i64,
    #[serde(skip_serializing_if = "is_zero")]
    max_reads_per_day: i64,
    #[serde(skip_serializing_if = "is_zero")]
    max_secrets_in_session: i64,
}

#[derive(Debug, Serialize)]
struct WhoamiInfo {
    name: String,
    vault_dir: String,
    tier: String,
    allowed_paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_tools: Vec<String>,
    can_write: bool,
    can_read_values: bool,
    can_use_clipboard: bool,
    can_use_autotype: bool,
    can_run_commands: bool,
    can_manage_config: bool,
    approval_mode: String,
    require_approval: bool,
    token_count: usize,
    #[serde(skip_serializing_if = "String::is_empty")]
    token_file: String,
    quotas: WhoamiQuotas,
    #[serde(skip_serializing_if = "String::is_empty")]
    skill_path: String,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// Renders the current `SYMVAULT_AGENT` profile without unlocking or touching
/// credentials. Unknown output values intentionally fall back to text, as Go
/// does for this command.
pub(crate) fn whoami(
    root: &Path,
    agent_name: &str,
    format: &str,
    output: &mut impl Write,
) -> Result<(), String> {
    if agent_name.is_empty() {
        return Err(AGENT_ENV_ERROR.to_owned());
    }
    let config =
        Config::load(root.join("config.yaml")).map_err(|error| format!("load config: {error}"))?;
    let profile = config
        .agents
        .get(agent_name)
        .ok_or_else(|| format!("agent {agent_name:?} not found in config"))?;

    let token_file_path = root.join("mcp-tokens").join(format!("{agent_name}.token"));
    let token_file = if fs::metadata(&token_file_path).is_ok() {
        token_file_path.to_string_lossy().into_owned()
    } else {
        String::new()
    };
    let info = WhoamiInfo {
        name: agent_name.to_owned(),
        vault_dir: root.to_string_lossy().into_owned(),
        tier: profile.tier.clone().unwrap_or_default(),
        allowed_paths: profile.allowed_paths.clone(),
        allowed_tools: profile.allowed_tools.clone(),
        can_write: profile.can_write,
        can_read_values: profile.can_read_values,
        can_use_clipboard: profile.can_use_clipboard,
        can_use_autotype: profile.can_use_autotype,
        can_run_commands: profile.can_run_commands,
        can_manage_config: profile.can_manage_config,
        approval_mode: profile.approval_mode.clone().unwrap_or_default(),
        require_approval: profile.require_approval,
        token_count: super::agent_list_commands::active_token_count(root, agent_name),
        token_file,
        quotas: WhoamiQuotas {
            max_reads_per_hour: profile.max_reads_per_hour,
            max_reads_per_day: profile.max_reads_per_day,
            max_secrets_in_session: profile.max_secrets_in_session,
        },
        skill_path: profile.skill_path.clone(),
    };

    if format == "json" {
        write_json(&info, output)
    } else {
        write_text(&info, output)
    }
}

fn write_json(info: &WhoamiInfo, output: &mut impl Write) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(info).map_err(|error| error.to_string())?;
    let rendered = escape_go_json_strings(&rendered);
    writeln!(output, "{rendered}").map_err(|error| error.to_string())
}

// These characters only occur inside strings in serde_json's generated JSON.
fn escape_go_json_strings(input: &str) -> String {
    input
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn write_text(info: &WhoamiInfo, output: &mut impl Write) -> Result<(), String> {
    writeln!(output, "Agent:      {}", info.name).map_err(|error| error.to_string())?;
    writeln!(output, "Vault Dir:  {}", info.vault_dir).map_err(|error| error.to_string())?;
    if !info.tier.is_empty() {
        writeln!(output, "Tier:       {}", info.tier).map_err(|error| error.to_string())?;
    }
    let paths = info.allowed_paths.join(", ");
    writeln!(output, "Paths:      {paths}").map_err(|error| error.to_string())?;
    if !info.allowed_tools.is_empty() {
        writeln!(output, "Tools:      {}", info.allowed_tools.join(", "))
            .map_err(|error| error.to_string())?;
    }
    writeln!(output, "Write:      {}", info.can_write).map_err(|error| error.to_string())?;
    writeln!(output, "Read Vals:  {}", info.can_read_values).map_err(|error| error.to_string())?;
    writeln!(output, "Clipboard:  {}", info.can_use_clipboard)
        .map_err(|error| error.to_string())?;
    writeln!(output, "Autotype:   {}", info.can_use_autotype).map_err(|error| error.to_string())?;
    writeln!(output, "Commands:   {}", info.can_run_commands).map_err(|error| error.to_string())?;
    writeln!(output, "Config:     {}", info.can_manage_config)
        .map_err(|error| error.to_string())?;
    writeln!(output, "Approval:   {}", info.approval_mode).map_err(|error| error.to_string())?;
    if info.quotas.max_reads_per_hour > 0 {
        writeln!(output, "Quota/hr:   {}", info.quotas.max_reads_per_hour)
            .map_err(|error| error.to_string())?;
    }
    if info.quotas.max_reads_per_day > 0 {
        writeln!(output, "Quota/day:  {}", info.quotas.max_reads_per_day)
            .map_err(|error| error.to_string())?;
    }
    if info.quotas.max_secrets_in_session > 0 {
        writeln!(output, "Quota/sess: {}", info.quotas.max_secrets_in_session)
            .map_err(|error| error.to_string())?;
    }
    writeln!(output, "Tokens:     {} active", info.token_count)
        .map_err(|error| error.to_string())?;
    if !info.token_file.is_empty() {
        writeln!(output, "Token File: {}", info.token_file).map_err(|error| error.to_string())?;
    }
    if !info.skill_path.is_empty() {
        writeln!(output, "Skill:      {}", info.skill_path).map_err(|error| error.to_string())?;
    }
    Ok(())
}
