//! MCP transport assembly for the CLI-owned vault and session boundary.
//!
//! `main.rs` owns argument parsing and process exit codes. This module owns
//! only the explicit construction of the MCP runtime from an already resolved
//! vault and unlocked identity. HTTP selects its configured agent per request;
//! stdio uses the CLI-selected agent. It performs no keychain lookup.

#[cfg(unix)]
use std::io::{BufRead, Write};
#[cfg(unix)]
use std::sync::OnceLock;
#[cfg(unix)]
use std::time::Duration;
use std::{
    fs,
    io::{self, BufReader, IsTerminal},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use symvault_core::{
    config::{AgentProfile, Config},
    policy::{Engine, Policy},
    session::Keyring,
};
use symvault_crypto::{Identity, SecretBytes};
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, SharedAuditLogger, StoreReadOnlyRuntime,
    ToolListConfig, read_only_tool_names, run_stdio, unavailable_tool,
};

/// Starts the bounded native MCP server for an already unlocked vault.
///
/// The caller supplies the identity and keyring obtained through the
/// CLI/session boundary. This function never reads a platform keychain,
/// prompts for credentials, or discovers a vault from the environment.
#[allow(clippy::too_many_arguments)] // These inputs are owned by the CLI boundary.
pub fn run(
    vault: impl AsRef<Path>,
    agent: Option<&str>,
    identity: Identity,
    keyring: &dyn Keyring,
    stdio: bool,
    bind: &str,
    port: u16,
    status: impl FnOnce() -> (bool, String, bool, String),
) -> Result<(), String> {
    let root = vault.as_ref();
    let config = Config::load(root.join("config.yaml"))
        .map_err(|error| format!("load vault config: {error}"))?;
    let (touch_id_available, backend, persistent, message) = status();
    if !stdio {
        let address = if bind == "localhost" {
            "127.0.0.1"
                .parse::<std::net::IpAddr>()
                .expect("literal loopback IP")
        } else {
            bind.parse::<std::net::IpAddr>()
                .map_err(|_| "MCP HTTP bind address must be a loopback IP".to_owned())?
        };
        if !address.is_loopback() {
            return Err("MCP HTTP listener must bind to loopback".to_owned());
        }
        let listener = TcpListener::bind((address, port))
            .map_err(|error| format!("bind MCP HTTP loopback {address}:{port}: {error}"))?;
        let expected_recipient = symvault_crypto::recipient_string(&identity);
        let encrypted_identity = fs::read(root.join("identity.age")).ok();
        let identity_text = symvault_crypto::identity_string(&identity);
        let auth_method = config.effective_auth_method().as_str().to_owned();
        let oauth_agent_name = config.default_agent.clone();
        let runtime_status = (touch_id_available, backend, persistent, message);
        let handler_for_agent = move |agent: &str| {
            let identity = identity_from_secret(&identity_text)?;
            let profile = config
                .agents
                .get(agent)
                .ok_or_else(|| format!("agent {agent:?} not found"))?;
            build_handler(
                root,
                agent,
                profile,
                identity,
                keyring,
                "http",
                &auth_method,
                &runtime_status,
            )
        };
        let registry_path = root.join("mcp-tokens.json");
        let consent_agent_name = oauth_agent_name.clone();
        let result = symvault_mcp::http::serve_loopback_with_oauth(
            listener,
            registry_path,
            handler_for_agent,
            oauth_agent_name,
            move |client_id, redirect_uri| {
                oauth_consent(client_id, redirect_uri, &consent_agent_name)
            },
            move |passphrase| {
                encrypted_identity.as_deref().is_some_and(|encrypted| {
                    symvault_crypto::decrypt_identity(
                        encrypted,
                        &SecretBytes::new(passphrase.as_bytes()),
                    )
                    .is_ok_and(|candidate| {
                        symvault_crypto::recipient_string(&candidate) == expected_recipient
                    })
                })
            },
        );
        result.map_err(|error| format!("MCP HTTP: {error}"))
    } else {
        let agent_name = agent
            .filter(|name| !name.is_empty())
            .unwrap_or(config.default_agent.as_str());
        let profile = config
            .agents
            .get(agent_name)
            .ok_or_else(|| format!("agent {agent_name:?} not found"))?;
        let mut handler = build_handler(
            root,
            agent_name,
            profile,
            identity,
            keyring,
            "stdio",
            config.effective_auth_method().as_str(),
            &(touch_id_available, backend, persistent, message),
        )?;
        let stdin = io::stdin();
        let stdout = io::stdout();
        run_stdio(BufReader::new(stdin.lock()), stdout.lock(), &mut handler)
            .map_err(|error| format!("MCP stdio: {error}"))
    }
}

fn oauth_consent(
    client_id: &str,
    redirect_uri: &str,
    agent_name: &str,
) -> symvault_mcp::http::OAuthConsentDecision {
    if browser_consent_selected(io::stdin().is_terminal()) {
        return symvault_mcp::http::OAuthConsentDecision::Browser;
    }
    #[cfg(unix)]
    {
        static TTY_CONSENT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let Ok(_input_guard) = TTY_CONSENT_LOCK.get_or_init(|| Mutex::new(())).try_lock() else {
            return symvault_mcp::http::OAuthConsentDecision::Denied;
        };
        let _ = write!(
            io::stderr(),
            "OAuth client {client_id:?} requests full tool access for agent {agent_name:?} at {redirect_uri}. Approve? [y/N] "
        );
        let _ = io::stderr().flush();
        let timeout = Duration::from_secs(60);
        read_tty_approval(timeout)
    }
    #[cfg(not(unix))]
    {
        let _ = (client_id, redirect_uri, agent_name);
        symvault_mcp::http::OAuthConsentDecision::Browser
    }
}

fn browser_consent_selected(stdin_is_terminal: bool) -> bool {
    !cfg!(unix) || !stdin_is_terminal
}

#[cfg(unix)]
fn read_tty_approval(timeout: Duration) -> symvault_mcp::http::OAuthConsentDecision {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    match wait_for_fd_readable(&reader, timeout) {
        Some(true) => {
            let mut answer = String::new();
            if reader.read_line(&mut answer).is_ok()
                && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
            {
                symvault_mcp::http::OAuthConsentDecision::Approved
            } else {
                symvault_mcp::http::OAuthConsentDecision::Denied
            }
        }
        Some(false) => {
            let _ = rustix::termios::tcflush(&reader, rustix::termios::QueueSelector::IFlush);
            symvault_mcp::http::OAuthConsentDecision::Denied
        }
        None => symvault_mcp::http::OAuthConsentDecision::Browser,
    }
}

#[cfg(unix)]
fn wait_for_fd_readable(fd: &impl std::os::fd::AsFd, timeout: Duration) -> Option<bool> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: timeout.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: timeout.subsec_nanos().into(),
    };
    poll(&mut fds, Some(&timeout)).ok().map(|ready| ready > 0)
}

fn identity_from_secret(secret: &SecretBytes) -> Result<Identity, String> {
    let value = std::str::from_utf8(secret.as_bytes())
        .map_err(|_| "unlocked vault identity is not valid UTF-8".to_owned())?;
    symvault_crypto::parse_identity(value)
        .map_err(|error| format!("restore unlocked vault identity: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn build_handler(
    root: &Path,
    agent_name: &str,
    profile: &AgentProfile,
    identity: Identity,
    keyring: &dyn Keyring,
    transport: &str,
    auth_method: &str,
    runtime_status: &(bool, String, bool, String),
) -> Result<ProtocolHandler, String> {
    let audit = symvault_store::audit::open_with_keyring_and_identity(
        agent_name,
        root,
        keyring,
        Some(&identity),
        symvault_store::audit::RotationConfig::default(),
    )
    .map_err(|error| format!("open audit logger: {error}"))?;
    let audit: SharedAuditLogger = Arc::new(Mutex::new(audit));
    let policy = load_policy_engine(root)?;
    let mut settings = runtime_config(root, profile, agent_name);
    let signing_key =
        symvault_store::grant_key::load_or_create_grant_signing_key(root, keyring, Some(&identity))
            .map_err(|error| format!("load grant signing key: {error}"))?;
    settings.transport = transport.to_owned();
    settings.auth_method = auth_method.to_owned();
    settings.touch_id_available = runtime_status.0;
    settings.cache_backend.clone_from(&runtime_status.1);
    settings.cache_persistent = runtime_status.2;
    settings.cache_message.clone_from(&runtime_status.3);
    let runtime =
        StoreReadOnlyRuntime::open_with_audit(root, identity, settings, policy, Some(audit))
            .map_err(|error| format!("create MCP runtime: {error}"))?
            .with_grant_signing_key(signing_key);
    let mut handler =
        ProtocolHandler::with_tool_call_runtime("symaira", "1.0.0", Arc::new(runtime));
    handler.set_tool_list_config(tool_list_config(profile));
    Ok(handler)
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
    if !(profile.can_read_values || profile.can_use_clipboard || profile.can_use_autotype) {
        unavailable_tools.push(unavailable_tool(
            "generate_totp",
            "not_available",
            "mcp.Tool is not available in the current environment",
        ));
    }
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
        can_read_values: profile.can_read_values,
        require_approval: profile.require_approval,
        prompt_injection_mode: profile.prompt_injection_mode.clone(),
        auto_unseal: profile.auto_unseal,
        expose_payment_values: profile.expose_payment_values,
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
        generate_totp_available: profile.can_read_values
            || profile.can_use_clipboard
            || profile.can_use_autotype,
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
            can_read_values: true,
            auto_unseal: true,
            expose_payment_values: true,
            ..AgentProfile::default()
        };
        let config = runtime_config(Path::new("/fixture"), &profile, "agent");
        assert_eq!(config.allowed_paths, ["work/*"]);
        assert_eq!(config.available_tools, ["health"]);
        assert_eq!(config.tier, "standard");
        assert!(config.can_read_values);
        assert!(config.auto_unseal);
        assert!(config.expose_payment_values);
        assert_eq!(config.vault_dir, "/fixture");
    }

    #[test]
    fn totp_registry_tracks_profile_capabilities() {
        for (read, clipboard, autotype) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let profile = AgentProfile {
                can_read_values: read,
                can_use_clipboard: clipboard,
                can_use_autotype: autotype,
                ..AgentProfile::default()
            };
            assert_eq!(
                tool_list_config(&profile).generate_totp_available,
                read || clipboard || autotype
            );
        }
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

    #[cfg(unix)]
    #[test]
    fn consent_timeout_leaves_stdin_available_for_the_next_prompt() {
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            wait_for_fd_readable(&reader, Duration::from_millis(1)),
            Some(false)
        );
        writer.write_all(b"y\n").unwrap();
        assert_eq!(
            wait_for_fd_readable(&reader, Duration::from_secs(1)),
            Some(true)
        );
    }

    #[test]
    fn consent_selector_uses_browser_without_tty_and_on_non_unix() {
        assert!(browser_consent_selected(false));
        #[cfg(unix)]
        assert!(!browser_consent_selected(true));
        #[cfg(not(unix))]
        assert!(browser_consent_selected(true));
    }
}
