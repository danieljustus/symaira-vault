//! MCP transport assembly for the CLI-owned vault and session boundary.
//!
//! `main.rs` owns argument parsing and process exit codes. This module owns
//! only the explicit construction of the MCP runtime from an already resolved
//! vault and unlocked identity. HTTP selects its configured agent per request;
//! stdio uses the CLI-selected agent. It performs no keychain lookup.

#[path = "mcp_tls_cert.rs"]
mod mcp_tls_cert;

#[cfg(unix)]
use std::io::{BufRead, Write};
#[cfg(unix)]
use std::sync::OnceLock;
use std::{
    fs,
    io::{self, BufReader, IsTerminal},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::run_commands::McpCommandExecutor;
#[cfg(not(target_os = "macos"))]
use symvault_core::platform::UnavailablePlatform;
use symvault_core::{
    config::{AgentProfile, Config, McpConfig},
    platform::Clipboard,
    policy::{Engine, Policy},
    session::Keyring,
};
use symvault_crypto::{Identity, SecretBytes};
use symvault_mcp::{
    ProtocolHandler, ReadOnlyRuntimeConfig, SharedAuditLogger, StoreReadOnlyRuntime,
    ToolListConfig, read_only_tool_names, run_stdio, unavailable_tool,
};
use symvault_platform::approval::is_tty_present;

/// Go's locked stdio bootstrap owns no vault runtime. Keep protocol input
/// intact and deny every tool call through the existing locked handler.
pub fn run_locked_stdio() -> Result<(), String> {
    // Go lists host-capable secure input metadata even with a nil vault. This
    // handler still owns no tool runtime: listing cannot enable a prompt/read.
    let available = locked_secure_input_metadata_available();
    let mut handler = ProtocolHandler::with_tool_list_config(
        "symaira",
        "1.0.0",
        ToolListConfig {
            secure_input_available: available,
            request_credential_available: available,
            ..ToolListConfig::default()
        },
    );
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_stdio(BufReader::new(stdin.lock()), stdout.lock(), &mut handler)
        .map_err(|error| format!("MCP stdio: {error}"))
}

fn locked_secure_input_metadata_available() -> bool {
    let mode = std::env::var("SYMVAULT_SECUREUI").unwrap_or_default();
    if mode == "none" {
        return false;
    }
    if mode != "gui" && is_tty_present() {
        return true;
    }
    if mode == "tty" {
        return false;
    }
    let names: &[&str] = if cfg!(windows) {
        &["powershell.exe"]
    } else if cfg!(target_os = "macos") {
        &["osascript"]
    } else {
        &["zenity", "kdialog"]
    };
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| {
            names.iter().any(|name| {
                let candidate = directory.join(name);
                let Ok(metadata) = candidate.metadata() else {
                    return false;
                };
                if !metadata.is_file() {
                    return false;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    true
                }
            })
        })
    })
}

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
    tls_cert: &str,
    tls_key: &str,
    tls_ca: &str,
    status: impl FnOnce() -> (bool, String, bool, String),
) -> Result<(), String> {
    let root = vault.as_ref();
    let config = Config::load(root.join("config.yaml"))
        .map_err(|error| format!("load vault config: {error}"))?;
    let clipboard_auto_clear_duration = Duration::from_secs(
        config
            .clipboard
            .as_ref()
            .map(|clipboard| clipboard.auto_clear_duration)
            .unwrap_or(30)
            .max(0) as u64,
    );
    let clipboard = clipboard_backend();
    let (touch_id_available, backend, persistent, message) = status();
    if !stdio {
        let (tls_cert, tls_key, tls_ca, mtls_enabled) =
            effective_tls(config.mcp.as_ref(), tls_cert, tls_key, tls_ca);
        let generated = if !config
            .mcp
            .as_ref()
            .is_some_and(|mcp| mcp.allow_insecure_bind)
            && (tls_cert.is_empty() || tls_key.is_empty())
        {
            Some(mcp_tls_cert::ensure_tls_cert(root)?)
        } else {
            None
        };
        let (tls_cert, tls_key) = match generated.as_ref() {
            Some((cert, key)) => (
                cert.to_str()
                    .ok_or("MCP TLS certificate path is not UTF-8")?,
                key.to_str().ok_or("MCP TLS key path is not UTF-8")?,
            ),
            None => (tls_cert, tls_key),
        };
        validate_tls(config.mcp.as_ref(), tls_cert, tls_key, tls_ca, mtls_enabled)?;
        let tls = if tls_cert.is_empty() {
            None
        } else {
            Some(
                symvault_mcp::http::load_tls_server_config(
                    tls_cert,
                    tls_key,
                    mtls_enabled.then(|| Path::new(tls_ca)),
                )
                .map_err(|error| format!("MCP HTTP TLS: {error}"))?,
            )
        };
        let address = if bind == "localhost" {
            "127.0.0.1"
                .parse::<std::net::IpAddr>()
                .expect("literal loopback IP")
        } else {
            bind.parse::<std::net::IpAddr>()
                .map_err(|_| "MCP HTTP bind address must be an IP".to_owned())?
        };
        if address.is_unspecified() {
            return Err("MCP HTTP wildcard binds are unavailable; choose a concrete IP".to_owned());
        }
        if !address.is_loopback() && tls.is_none() {
            return Err("MCP HTTP listener requires TLS when binding off loopback".to_owned());
        }
        let listener = TcpListener::bind((address, port))
            .map_err(|error| format!("bind MCP HTTP loopback {address}:{port}: {error}"))?;
        eprintln!(
            "MCP server listening on {bind}:{}",
            listener
                .local_addr()
                .map_err(|error| format!("inspect MCP HTTP listener: {error}"))?
                .port()
        );
        let server_working_dir = std::env::current_dir()
            .map_err(|error| format!("inspect server working directory: {error}"))?;
        let (approval_client_cert, approval_client_key) =
            configured_approval_tls_identity(root, mtls_enabled)?;
        let mut runtime_metadata = RuntimeMetadataGuard::new(root);
        runtime_metadata.publish(RuntimeMetadata {
            bind: address.to_string(),
            port: listener
                .local_addr()
                .map_err(|error| format!("inspect MCP HTTP listener: {error}"))?
                .port(),
            certificate: tls_cert.to_owned(),
            client_ca: tls_ca.to_owned(),
            client_auth_required: mtls_enabled,
            approval_client_certificate: approval_client_cert,
            approval_client_key,
            server_working_dir,
        })?;
        let approval_queue = Arc::new(symvault_mcp::approval::ApprovalQueue::default());
        let enroll_secret = ensure_enroll_secret(root)?;
        let expected_recipient = symvault_crypto::recipient_string(&identity);
        let encrypted_identity = fs::read(root.join("identity.age")).ok();
        let identity_text = symvault_crypto::identity_string(&identity);
        let auth_method = config.effective_auth_method().as_str().to_owned();
        let oauth_agent_name = oauth_agent(&config).to_owned();
        let runtime_status = (touch_id_available, backend, persistent, message);
        let approval_queue_for_agent = approval_queue.clone();
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
                Some(approval_queue_for_agent.clone()),
                clipboard_auto_clear_duration,
                clipboard.clone(),
            )
        };
        let registry_path = root.join("mcp-tokens.json");
        let consent_agent_name = oauth_agent_name.clone();
        let consent = move |client_id: &str, redirect_uri: &str| {
            oauth_consent(client_id, redirect_uri, &consent_agent_name)
        };
        let verify_passphrase = move |passphrase: &str| {
            encrypted_identity.as_deref().is_some_and(|encrypted| {
                symvault_crypto::decrypt_identity(
                    encrypted,
                    &SecretBytes::new(passphrase.as_bytes()),
                )
                .is_ok_and(|candidate| {
                    symvault_crypto::recipient_string(&candidate) == expected_recipient
                })
            })
        };
        let result = match tls {
            Some(tls) => symvault_mcp::http::serve_with_tls_oauth_and_approval(
                listener,
                registry_path,
                handler_for_agent,
                oauth_agent_name,
                consent,
                verify_passphrase,
                tls,
                symvault_mcp::http::LocalApprovalApi::new(approval_queue, enroll_secret),
            ),
            None => symvault_mcp::http::serve_loopback_with_oauth_and_approval(
                listener,
                registry_path,
                handler_for_agent,
                oauth_agent_name,
                consent,
                verify_passphrase,
                symvault_mcp::http::LocalApprovalApi::new(approval_queue, enroll_secret),
            ),
        };
        result.map_err(|error| format!("MCP HTTP: {error}"))
    } else {
        #[cfg(unix)]
        symvault_platform::approval::install_stdio_clipboard_signal_router(clipboard.clone())
            .map_err(|error| format!("install MCP stdio signal router: {error}"))?;
        let agent_name = agent
            .filter(|name| !name.is_empty())
            .unwrap_or(config.default_agent.as_str());
        let profile = config.agents.get(agent_name).ok_or_else(|| {
            format!("failed to create MCP server: agent {agent_name:?} not found")
        })?;
        let mut handler = build_handler(
            root,
            agent_name,
            profile,
            identity,
            keyring,
            "stdio",
            config.effective_auth_method().as_str(),
            &(touch_id_available, backend, persistent, message),
            None,
            clipboard_auto_clear_duration,
            clipboard,
        )
        .map_err(|error| format!("failed to create MCP server: {error}"))?;
        let stdin = io::stdin();
        let stdout = io::stdout();
        run_stdio(BufReader::new(stdin.lock()), stdout.lock(), &mut handler)
            .map_err(|error| format!("MCP stdio: {error}"))
    }
}

struct RuntimeMetadataGuard {
    port_path: PathBuf,
    port_record: Option<Vec<u8>>,
    tls_path: PathBuf,
    tls_record: Option<Vec<u8>>,
}

struct RuntimeMetadata {
    bind: String,
    port: u16,
    certificate: String,
    client_ca: String,
    client_auth_required: bool,
    approval_client_certificate: String,
    approval_client_key: String,
    server_working_dir: PathBuf,
}

impl RuntimeMetadataGuard {
    fn new(root: &Path) -> Self {
        Self {
            port_path: root.join(".runtime-port"),
            port_record: None,
            tls_path: root.join(".runtime-tls-cert"),
            tls_record: None,
        }
    }

    fn publish(&mut self, metadata: RuntimeMetadata) -> Result<(), String> {
        let port_record = serde_json::to_vec(
            &serde_json::json!({ "port": metadata.port, "bind": metadata.bind }),
        )
        .map_err(|error| format!("encode MCP runtime port: {error}"))?;
        symvault_sync::safeio::write_atomic(&self.port_path, &port_record)
            .map_err(|error| format!("write MCP runtime port: {error}"))?;
        self.port_record = Some(port_record);
        if metadata.certificate.is_empty() {
            // A prior TLS server may have exited without running Drop. Match
            // the Go startup contract: a cleartext listener has no TLS record.
            let _ = fs::remove_file(&self.tls_path);
        } else {
            let certificate =
                effective_absolute_path(&metadata.server_working_dir, &metadata.certificate);
            let client_ca_file =
                effective_absolute_path(&metadata.server_working_dir, &metadata.client_ca);
            let client_certificate = effective_absolute_path(
                &metadata.server_working_dir,
                &metadata.approval_client_certificate,
            );
            let client_key = effective_absolute_path(
                &metadata.server_working_dir,
                &metadata.approval_client_key,
            );
            let tls_record = serde_json::to_vec(&serde_json::json!({
                "certificate": certificate,
                "client_ca_file": client_ca_file,
                "client_auth_required": metadata.client_auth_required,
                "client_certificate": client_certificate,
                "client_key": client_key,
            }))
            .map_err(|error| format!("encode MCP runtime TLS metadata: {error}"))?;
            symvault_sync::safeio::write_atomic(&self.tls_path, &tls_record)
                .map_err(|error| format!("write MCP runtime TLS metadata: {error}"))?;
            self.tls_record = Some(tls_record);
        }
        Ok(())
    }
}

fn effective_absolute_path(server_working_dir: &Path, value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let value = Path::new(value);
    let path = if value.is_absolute() {
        value.to_path_buf()
    } else {
        server_working_dir.join(value)
    };
    fs::canonicalize(&path)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[derive(serde::Deserialize, Default)]
struct ApprovalTlsConfig {
    mcp: Option<ApprovalTlsClientConfig>,
}

#[derive(serde::Deserialize, Default)]
struct ApprovalTlsClientConfig {
    #[serde(default)]
    approval_tls_cert_file: String,
    #[serde(default)]
    approval_tls_key_file: String,
}

fn configured_approval_tls_identity(
    root: &Path,
    mtls_enabled: bool,
) -> Result<(String, String), String> {
    if !mtls_enabled {
        return Ok((String::new(), String::new()));
    }
    let config_path = root.join("config.yaml");
    let data = symvault_sync::safeio::read_bounded(&config_path, 1024 * 1024)
        .map_err(|error| format!("read approval client TLS config: {error}"))?
        .ok_or_else(|| "read approval client TLS config: config.yaml not found".to_owned())?;
    let config: ApprovalTlsConfig = serde_yaml_ng::from_slice(&data)
        .map_err(|error| format!("parse approval client TLS config: {error}"))?;
    let mcp = config.mcp.unwrap_or_default();
    Ok((
        mcp.approval_tls_cert_file.trim().to_owned(),
        mcp.approval_tls_key_file.trim().to_owned(),
    ))
}

impl Drop for RuntimeMetadataGuard {
    fn drop(&mut self) {
        remove_if_unchanged(&self.port_path, self.port_record.as_deref());
        remove_if_unchanged(&self.tls_path, self.tls_record.as_deref());
    }
}

fn remove_if_unchanged(path: &Path, expected: Option<&[u8]>) {
    let Some(expected) = expected else {
        return;
    };
    if symvault_sync::safeio::read_bounded(path, 4096)
        .ok()
        .flatten()
        .as_deref()
        == Some(expected)
    {
        let _ = fs::remove_file(path);
    }
}

fn ensure_enroll_secret(root: &Path) -> Result<Vec<u8>, String> {
    let path = root.join("mcp-server.enroll-secret");
    if let Some(secret) = symvault_sync::safeio::read_bounded(&path, 4096)
        .map_err(|error| format!("read approval ownership secret: {error}"))?
    {
        if secret.len() != 32 {
            return Err("approval ownership secret: invalid secret length".to_owned());
        }
        return Ok(secret);
    }
    let mut secret = vec![0; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| format!("generate approval ownership secret: {error}"))?;
    symvault_sync::safeio::write_atomic(&path, &secret)
        .map_err(|error| format!("write approval ownership secret: {error}"))?;
    Ok(secret)
}

fn effective_tls<'a>(
    config: Option<&'a McpConfig>,
    cert_flag: &'a str,
    key_flag: &'a str,
    ca_flag: &'a str,
) -> (&'a str, &'a str, &'a str, bool) {
    let cert = if cert_flag.is_empty() {
        config.map_or("", |mcp| mcp.tls_cert_file.trim())
    } else {
        cert_flag
    };
    let key = if key_flag.is_empty() {
        config.map_or("", |mcp| mcp.tls_key_file.trim())
    } else {
        key_flag
    };
    let ca = if ca_flag.is_empty() {
        config.map_or("", |mcp| mcp.tls_client_ca_file.trim())
    } else {
        ca_flag
    };
    let mtls = !ca_flag.is_empty() || config.is_some_and(|mcp| mcp.mtls_enabled);
    (cert, key, ca, mtls)
}

fn validate_tls(
    config: Option<&McpConfig>,
    cert: &str,
    key: &str,
    ca: &str,
    mtls: bool,
) -> Result<(), String> {
    let allow_insecure = config.is_some_and(|mcp| mcp.allow_insecure_bind);
    let tls_enabled = !cert.trim().is_empty() && !key.trim().is_empty();
    // Keep the source order from Go's validateTLSSettings so a mixed-invalid
    // configuration reports the same fail-closed reason on both runtimes.
    if mtls && allow_insecure {
        return Err(
            "refusing MCP.allow_insecure_bind=true with MCP.mtls_enabled=true: mTLS requires TLS"
                .to_owned(),
        );
    }
    if mtls && !tls_enabled {
        return Err(
            "refusing MCP.mtls_enabled=true without a server TLS certificate and key".to_owned(),
        );
    }
    if mtls && ca.trim().is_empty() {
        return Err(
            "refusing MCP.mtls_enabled=true without MCP.tls_client_ca_file; client verification must remain enabled"
                .to_owned(),
        );
    }
    if cert.is_empty() != key.is_empty() {
        return Err("MCP HTTP requires both TLS certificate and key".to_owned());
    }
    if !tls_enabled && !allow_insecure {
        return Err(
            "MCP HTTP requires TLS certificate and key unless MCP.allow_insecure_bind=true"
                .to_owned(),
        );
    }
    Ok(())
}

fn oauth_agent(config: &Config) -> &str {
    if config.agents.contains_key("oauth") {
        "oauth"
    } else {
        &config.default_agent
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
    approval_queue: Option<Arc<symvault_mcp::approval::ApprovalQueue>>,
    clipboard_auto_clear_duration: Duration,
    clipboard: Arc<dyn Clipboard>,
) -> Result<ProtocolHandler, String> {
    let audit = symvault_store::audit::open_with_keyring(
        agent_name,
        root,
        keyring,
        symvault_store::audit::RotationConfig::default(),
    )
    .map_err(|error| format!("open audit logger: {error}"))?;
    let audit: SharedAuditLogger = Arc::new(Mutex::new(audit));
    let policy = load_policy_engine(root)?;
    let mut settings = runtime_config(root, profile, agent_name, transport);
    let signing_key =
        symvault_store::grant_key::load_or_create_grant_signing_key(root, keyring, Some(&identity))
            .map_err(|error| format!("load grant signing key: {error}"))?;
    settings.transport = transport.to_owned();
    settings.auth_method = auth_method.to_owned();
    settings.touch_id_available = runtime_status.0;
    settings.cache_backend.clone_from(&runtime_status.1);
    settings.cache_persistent = runtime_status.2;
    settings.cache_message.clone_from(&runtime_status.3);
    let command_executor = Arc::new(McpCommandExecutor::new());
    let runtime =
        StoreReadOnlyRuntime::open_with_audit(root, identity, settings, policy, Some(audit))
            .map_err(|error| format!("create MCP runtime: {error}"))?
            .with_grant_signing_key(signing_key)
            .with_command_executor(command_executor)
            .with_clipboard_auto_clear_duration(clipboard_auto_clear_duration);
    let mut runtime = runtime.with_clipboard(clipboard);
    if let Some(queue) = approval_queue {
        runtime = runtime.with_approval_queue(queue);
    }
    let mut handler =
        ProtocolHandler::with_tool_call_runtime("symaira", "1.0.0", Arc::new(runtime));
    handler.set_tool_list_config(tool_list_config(
        profile,
        transport == "stdio" && is_tty_present(),
    ));
    Ok(handler)
}

#[cfg(test)]
#[doc(hidden)]
#[allow(dead_code, clippy::too_many_arguments)]
pub fn build_handler_for_contract_test(
    root: &Path,
    agent_name: &str,
    profile: &AgentProfile,
    identity: Identity,
    keyring: &dyn Keyring,
    transport: &str,
    auth_method: &str,
    runtime_status: &(bool, String, bool, String),
) -> Result<ProtocolHandler, String> {
    build_handler(
        root,
        agent_name,
        profile,
        identity,
        keyring,
        transport,
        auth_method,
        runtime_status,
        None,
        Duration::from_secs(30),
        clipboard_backend(),
    )
}

fn clipboard_backend() -> Arc<dyn Clipboard> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(symvault_platform::MacOsPlatform)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(UnavailablePlatform)
    }
}

fn runtime_config(
    root: &Path,
    profile: &AgentProfile,
    agent_name: &str,
    transport: &str,
) -> ReadOnlyRuntimeConfig {
    let mut available_tools = read_only_tool_names();
    // Keep direct calls subject to the same actionable capability check as
    // Go; tools/list separately hides the tool when the profile lacks access.
    available_tools.push("execute_api_request".into());
    if profile.can_run_commands {
        // This CLI always installs McpCommandExecutor in build_handler. Keep
        // the secret-aware command tool opt-in to the profile capability and
        // let the normal allowed_tools filter below further restrict it.
        available_tools.push("execute_with_secret".into());
    }
    let secure_input_available = transport == "stdio" && is_tty_present();
    let mut unavailable_tools = Vec::new();
    if secure_input_available {
        available_tools.push("secure_input".into());
        available_tools.push("request_credential".into());
    } else {
        for name in ["secure_input", "request_credential"] {
            unavailable_tools.push(unavailable_tool(
                name,
                "not_available",
                format!(
                    "tool \"{name}\" is not available in the current environment (requires TTY or GUI dialog). Alternatives: set_entry_field"
                ),
            ));
        }
    }
    if !profile.allowed_tools.is_empty() {
        available_tools.retain(|name| profile.allowed_tools.iter().any(|allowed| allowed == name));
        unavailable_tools.retain(|tool| {
            profile
                .allowed_tools
                .iter()
                .any(|allowed| allowed == &tool.name)
        });
    }
    let expose_value_tools = profile.expose_value_tools;
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
        approval_timeout: profile.approval_timeout,
        can_write: profile.can_write,
        can_read_values: profile.can_read_values,
        require_approval: profile.require_approval,
        prompt_injection_mode: profile.prompt_injection_mode.clone(),
        auto_unseal: profile.auto_unseal,
        expose_payment_values: profile.expose_payment_values,
        can_run_commands: profile.can_run_commands,
        allowed_executables: profile.allowed_executables.clone(),
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

fn tool_list_config(profile: &AgentProfile, secure_input_available: bool) -> ToolListConfig {
    let allowed = |tool: &str| {
        profile.allowed_tools.is_empty()
            || profile.allowed_tools.iter().any(|allowed| allowed == tool)
    };
    let execute_api_available = profile.can_run_commands
        && (profile.allowed_tools.is_empty()
            || profile
                .allowed_tools
                .iter()
                .any(|allowed| allowed == "execute_api_request"));
    ToolListConfig {
        tier: profile.tier.clone(),
        expose_value_tools: Some(profile.expose_value_tools),
        execute_api_available,
        secure_input_available: secure_input_available && allowed("secure_input"),
        request_credential_available: secure_input_available && allowed("request_credential"),
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
    fn configured_tls_and_cli_overrides_keep_mtls_requirement() {
        let configured = McpConfig {
            tls_cert_file: "configured-cert.pem".into(),
            tls_key_file: "configured-key.pem".into(),
            tls_client_ca_file: "configured-ca.pem".into(),
            mtls_enabled: true,
            ..McpConfig::default()
        };
        assert_eq!(
            effective_tls(Some(&configured), "", "", ""),
            (
                "configured-cert.pem",
                "configured-key.pem",
                "configured-ca.pem",
                true
            )
        );
        assert_eq!(
            effective_tls(Some(&configured), "cli-cert.pem", "", "cli-ca.pem"),
            ("cli-cert.pem", "configured-key.pem", "cli-ca.pem", true)
        );
        assert_eq!(
            effective_tls(None, "cli-cert.pem", "cli-key.pem", "cli-ca.pem"),
            ("cli-cert.pem", "cli-key.pem", "cli-ca.pem", true)
        );
    }

    #[test]
    fn plaintext_requires_explicit_insecure_opt_in() {
        assert!(validate_tls(None, "", "", "", false).is_err());
        let mut config = McpConfig::default();
        assert!(validate_tls(Some(&config), "", "", "", false).is_err());
        config.allow_insecure_bind = true;
        assert!(validate_tls(Some(&config), "", "", "", false).is_ok());
        assert!(validate_tls(Some(&config), "", "", "ca.pem", true).is_err());
    }

    #[test]
    fn mtls_validation_matches_go_order_and_fails_closed() {
        let error = validate_tls(None, "", "", "", true).unwrap_err();
        assert!(error.contains("without a server TLS certificate and key"));

        let insecure = McpConfig {
            allow_insecure_bind: true,
            ..McpConfig::default()
        };
        let error = validate_tls(Some(&insecure), "", "", "", true).unwrap_err();
        assert!(error.contains("mTLS requires TLS"));

        let error = validate_tls(None, "cert.pem", "key.pem", " \t", true).unwrap_err();
        assert!(error.contains("client verification must remain enabled"));
        assert!(validate_tls(None, "cert.pem", "key.pem", "ca.pem", true).is_ok());
    }

    #[test]
    fn oauth_keeps_a_configured_dedicated_agent() {
        let mut config = Config::default();
        assert_eq!(oauth_agent(&config), config.default_agent);
        config
            .agents
            .insert("oauth".into(), AgentProfile::default());
        assert_eq!(oauth_agent(&config), "oauth");
    }

    #[test]
    fn runtime_config_keeps_profile_scope_and_explicit_tool_registry() {
        let profile = AgentProfile {
            tier: Some("standard".into()),
            allowed_paths: vec!["work/*".into()],
            allowed_tools: vec!["health".into()],
            allowed_executables: vec!["git".into()],
            approval_timeout: std::time::Duration::from_secs(91),
            can_read_values: true,
            auto_unseal: true,
            expose_payment_values: true,
            ..AgentProfile::default()
        };
        let config = runtime_config(Path::new("/fixture"), &profile, "agent", "http");
        assert_eq!(config.allowed_paths, ["work/*"]);
        assert_eq!(config.available_tools, ["health"]);
        assert_eq!(config.allowed_executables, ["git"]);
        assert_eq!(config.approval_timeout, std::time::Duration::from_secs(91));
        assert_eq!(config.tier, "standard");
        assert!(config.can_read_values);
        assert!(config.auto_unseal);
        assert!(config.expose_payment_values);
        assert_eq!(config.vault_dir, "/fixture");
    }

    #[test]
    fn runtime_config_preserves_clipboard_dispatch_capability_and_allowlist() {
        let capability_denied_but_named = AgentProfile {
            allowed_tools: vec!["copy_to_clipboard".into()],
            can_use_clipboard: false,
            ..AgentProfile::default()
        };
        let denied = runtime_config(
            Path::new("/fixture"),
            &capability_denied_but_named,
            "agent",
            "stdio",
        );
        assert_eq!(denied.available_tools, ["copy_to_clipboard"]);
        assert!(!denied.can_use_clipboard);

        let explicitly_excluded = AgentProfile {
            allowed_tools: vec!["health".into()],
            can_use_clipboard: true,
            ..AgentProfile::default()
        };
        let excluded = runtime_config(
            Path::new("/fixture"),
            &explicitly_excluded,
            "agent",
            "stdio",
        );
        assert_eq!(excluded.available_tools, ["health"]);
        assert!(excluded.can_use_clipboard);
    }

    #[test]
    fn runtime_config_exposes_secret_command_only_with_capability_and_allowlist() {
        let capable_but_excluded = AgentProfile {
            can_run_commands: true,
            allowed_tools: vec!["health".into()],
            ..AgentProfile::default()
        };
        assert_eq!(
            runtime_config(
                Path::new("/fixture"),
                &capable_but_excluded,
                "agent",
                "http"
            )
            .available_tools,
            ["health"],
            "explicit allowlist must exclude execute_with_secret"
        );

        let capable_and_allowed = AgentProfile {
            can_run_commands: true,
            allowed_tools: vec!["execute_with_secret".into()],
            ..AgentProfile::default()
        };
        assert_eq!(
            runtime_config(Path::new("/fixture"), &capable_and_allowed, "agent", "http")
                .available_tools,
            ["execute_with_secret"]
        );

        let no_command_capability = AgentProfile {
            allowed_tools: vec!["execute_with_secret".into()],
            ..AgentProfile::default()
        };
        assert!(
            runtime_config(
                Path::new("/fixture"),
                &no_command_capability,
                "agent",
                "http"
            )
            .available_tools
            .is_empty()
        );
    }

    #[test]
    fn api_request_tool_requires_command_capability_and_profile_allowlist() {
        let capable_and_allowed = AgentProfile {
            can_run_commands: true,
            allowed_tools: vec!["execute_api_request".into()],
            ..AgentProfile::default()
        };
        assert_eq!(
            runtime_config(Path::new("/fixture"), &capable_and_allowed, "agent", "http")
                .available_tools,
            ["execute_api_request"]
        );
        assert!(tool_list_config(&capable_and_allowed, false).execute_api_available);

        let explicitly_excluded = AgentProfile {
            can_run_commands: true,
            allowed_tools: vec!["health".into()],
            ..AgentProfile::default()
        };
        assert!(
            !runtime_config(Path::new("/fixture"), &explicitly_excluded, "agent", "http")
                .available_tools
                .contains(&"execute_api_request".into())
        );
        assert!(!tool_list_config(&explicitly_excluded, false).execute_api_available);

        let no_run_capability = AgentProfile {
            allowed_tools: vec!["execute_api_request".into()],
            ..AgentProfile::default()
        };
        assert!(
            runtime_config(Path::new("/fixture"), &no_run_capability, "agent", "http")
                .available_tools
                .contains(&"execute_api_request".into()),
            "runtime keeps the dispatch route installed so direct calls reach the capability denial"
        );
        assert!(!tool_list_config(&no_run_capability, false).execute_api_available);
    }

    #[test]
    fn runtime_metadata_is_private_and_only_its_own_records_are_removed() {
        let root = tempfile::tempdir().unwrap();
        let port = root.path().join(".runtime-port");
        let tls = root.path().join(".runtime-tls-cert");
        let server_cwd = root.path().join("server-cwd");
        fs::create_dir(&server_cwd).unwrap();
        fs::write(
            root.path().join("config.yaml"),
            "mcp:\n  approval_tls_cert_file: certs/approval-client.pem\n  approval_tls_key_file: certs/approval-client.key\n",
        )
        .unwrap();
        let (approval_cert, approval_key) =
            configured_approval_tls_identity(root.path(), true).unwrap();
        {
            let mut metadata = RuntimeMetadataGuard::new(root.path());
            metadata
                .publish(RuntimeMetadata {
                    bind: "127.0.0.1".into(),
                    port: 9443,
                    certificate: "certs/server.pem".into(),
                    client_ca: "certs/ca.pem".into(),
                    client_auth_required: true,
                    approval_client_certificate: approval_cert.clone(),
                    approval_client_key: approval_key.clone(),
                    server_working_dir: server_cwd.clone(),
                })
                .unwrap();
            let record: serde_json::Value =
                serde_json::from_slice(&fs::read(&port).unwrap()).unwrap();
            assert_eq!(record["port"], 9443);
            assert_eq!(record["bind"], "127.0.0.1");
            assert!(tls.is_file());
            let tls_record: serde_json::Value =
                serde_json::from_slice(&fs::read(&tls).unwrap()).unwrap();
            for (field, relative) in [
                ("certificate", "certs/server.pem"),
                ("client_ca_file", "certs/ca.pem"),
                ("client_certificate", "certs/approval-client.pem"),
                ("client_key", "certs/approval-client.key"),
            ] {
                assert_eq!(
                    tls_record[field],
                    server_cwd.join(relative).to_string_lossy().as_ref()
                );
                assert!(Path::new(tls_record[field].as_str().unwrap()).is_absolute());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&port).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(
                    fs::metadata(&tls).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert!(!port.exists());
        assert!(!tls.exists());

        fs::write(&tls, b"stale tls metadata").unwrap();
        let mut metadata = RuntimeMetadataGuard::new(root.path());
        metadata
            .publish(RuntimeMetadata {
                bind: "127.0.0.1".into(),
                port: 9445,
                certificate: String::new(),
                client_ca: String::new(),
                client_auth_required: false,
                approval_client_certificate: String::new(),
                approval_client_key: String::new(),
                server_working_dir: server_cwd.clone(),
            })
            .unwrap();
        assert!(!tls.exists());
        drop(metadata);
        assert!(!port.exists());

        let mut metadata = RuntimeMetadataGuard::new(root.path());
        metadata
            .publish(RuntimeMetadata {
                bind: "127.0.0.1".into(),
                port: 9444,
                certificate: "/tmp/server.pem".into(),
                client_ca: String::new(),
                client_auth_required: false,
                approval_client_certificate: String::new(),
                approval_client_key: String::new(),
                server_working_dir: server_cwd,
            })
            .unwrap();
        fs::write(&port, b"owned by another server").unwrap();
        drop(metadata);
        assert_eq!(fs::read(&port).unwrap(), b"owned by another server");
        assert!(!tls.exists());
    }

    #[test]
    fn existing_enroll_secret_must_match_cli_proof_size() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("mcp-server.enroll-secret");
        fs::write(&path, [0xA5; 31]).unwrap();
        assert_eq!(
            ensure_enroll_secret(root.path()).unwrap_err(),
            "approval ownership secret: invalid secret length"
        );
        fs::write(&path, [0xA5; 32]).unwrap();
        assert_eq!(ensure_enroll_secret(root.path()).unwrap().len(), 32);
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
                tool_list_config(&profile, false).generate_totp_available,
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
