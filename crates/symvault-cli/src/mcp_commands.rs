//! MCP stdio assembly for the CLI-owned vault and session boundary.
//!
//! `main.rs` owns argument parsing and process exit codes. This module owns
//! only the explicit construction of the MCP runtime from an already resolved
//! vault, agent name, and unlocked identity. It performs no keychain lookup.

use std::{
    fs,
    io::{self, BufReader},
    path::{Path, PathBuf},
};

use symvault_core::{
    config::{AgentProfile, Config},
    policy::{Engine, Policy},
};
use symvault_crypto::Identity;
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, ToolListConfig, read_only_tool_names, run_stdio,
    unavailable_tool,
};

/// Starts the bounded native MCP stdio server for an already unlocked vault.
///
/// The caller supplies the identity obtained through the CLI/session boundary.
/// This function never reads a keychain, prompts for credentials, or discovers
/// a vault from the environment.
pub fn run(vault: impl AsRef<Path>, agent: &str, identity: Identity) -> Result<(), String> {
    let root = vault.as_ref();
    let config = Config::load(root.join("config.yaml"))
        .map_err(|error| format!("load vault config: {error}"))?;
    let agent_name = if agent.is_empty() {
        config.default_agent.as_str()
    } else {
        agent
    };
    let profile = config
        .agents
        .get(agent_name)
        .ok_or_else(|| format!("agent {agent_name:?} not found"))?;
    let policy = load_policy_engine(root)?;
    let runtime_config = runtime_config(root, profile, agent_name);
    let mut handler = ProtocolHandler::with_store_read_only_runtime(
        "symaira",
        "1.0.0",
        root,
        identity,
        runtime_config,
        policy,
        None,
    )
    .map_err(|error| format!("create MCP runtime: {error}"))?;
    handler.set_tool_list_config(tool_list_config(profile));

    let stdin = io::stdin();
    let stdout = io::stdout();
    run_stdio(BufReader::new(stdin.lock()), stdout.lock(), &mut handler)
        .map_err(|error| format!("MCP stdio: {error}"))
}

fn runtime_config(root: &Path, profile: &AgentProfile, agent_name: &str) -> ReadOnlyRuntimeConfig {
    let mut available_tools = read_only_tool_names();
    if !profile.allowed_tools.is_empty() {
        available_tools.retain(|name| profile.allowed_tools.iter().any(|allowed| allowed == name));
    }
    let expose_value_tools = profile.expose_value_tools;
    let mut unavailable_tools = Vec::new();
    unavailable_tools.push(unavailable_tool(
        "execute_api_request",
        "not_available",
        "mcp.Tool is not available in the current environment",
    ));
    unavailable_tools.push(unavailable_tool(
        "generate_totp",
        "not_available",
        "mcp.Tool is not available in the current environment",
    ));
    if !expose_value_tools {
        unavailable_tools.push(unavailable_tool(
            "get_entry_value",
            "blocked_by_agent",
            format!(
                "Tool \"get_entry_value\" requires tier {:?}",
                profile.tier.as_deref().unwrap_or("standard")
            ),
        ));
    }
    ReadOnlyRuntimeConfig {
        server_name: "Symaira Vault MCP".into(),
        server_version: "1.0.0".into(),
        transport: "stdio".into(),
        agent_name: agent_name.into(),
        tier: profile.tier.clone().unwrap_or_default(),
        allowed_paths: profile.allowed_paths.clone(),
        approval_mode: profile.approval_mode.clone().unwrap_or_default(),
        can_write: profile.can_write,
        can_run_commands: profile.can_run_commands,
        can_use_clipboard: profile.can_use_clipboard,
        can_use_autotype: profile.can_use_autotype,
        redact_fields: (!profile.redact_fields.is_empty()).then(|| profile.redact_fields.clone()),
        max_reads_per_hour: profile.max_reads_per_hour,
        max_reads_per_day: profile.max_reads_per_day,
        max_secrets_in_session: profile.max_secrets_in_session,
        available_tools,
        unavailable_tools,
        vault_dir: root.to_string_lossy().into_owned(),
        vault_unlocked: true,
        ..ReadOnlyRuntimeConfig::default()
    }
}

fn tool_list_config(profile: &AgentProfile) -> ToolListConfig {
    ToolListConfig {
        tier: profile.tier.clone(),
        expose_value_tools: Some(profile.expose_value_tools),
        execute_api_available: false,
        secure_input_available: false,
        generate_totp_available: false,
    }
}

fn load_policy_engine(root: &Path) -> Result<Option<Engine>, String> {
    let directory = root.join("policies");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read policy directory: {error}")),
    };
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<PathBuf>, _>>()
        .map_err(|error| format!("read policy directory entry: {error}"))?;
    paths.sort();
    let mut policies = Vec::new();
    for path in paths {
        let extension = path.extension().and_then(|value| value.to_str());
        if !matches!(extension, Some("yaml" | "yml")) {
            continue;
        }
        let bytes = fs::read(&path).map_err(|error| format!("read policy file: {error}"))?;
        let policy: Policy = serde_yaml_ng::from_slice(&bytes)
            .map_err(|error| format!("parse policy file: {error}"))?;
        policy
            .validate()
            .map_err(|error| format!("validate policy file: {error}"))?;
        policies.push(policy);
    }
    if policies.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Engine::new(&policies)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_keeps_profile_scope_and_explicit_tool_registry() {
        let profile = AgentProfile {
            tier: Some("standard".into()),
            allowed_paths: vec!["work/*".into()],
            allowed_tools: vec!["health".into()],
            ..AgentProfile::default()
        };
        let config = runtime_config(Path::new("/fixture"), &profile, "agent");
        assert_eq!(config.allowed_paths, ["work/*"]);
        assert_eq!(config.available_tools, ["health"]);
        assert_eq!(config.tier, "standard");
        assert_eq!(config.vault_dir, "/fixture");
    }

    #[test]
    fn malformed_policy_is_not_silently_treated_as_unconfigured() {
        let root = std::env::temp_dir().join(format!("symvault-mcp-policy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("policies")).expect("policy directory");
        fs::write(root.join("policies/bad.yaml"), b"rules: [").expect("policy file");
        let error = load_policy_engine(&root).expect_err("malformed policy must fail");
        let _ = fs::remove_dir_all(&root);
        assert!(error.contains("parse policy file"));
    }
}
