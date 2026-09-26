//! Local approval queue commands from Go `cmd/approval.go`.
//!
//! `approval list` uses the loopback-only local route authenticated with a
//! timestamped HMAC over the vault's enroll secret. It is separate from the
//! enrolled-device bearer API. The local queue is never reconstructed here;
//! the running MCP server remains authoritative.

use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use getifaddrs::{Address, InterfaceFlags};
use hmac::{Hmac, Mac};
use qrcode::{Color as QrColor, EcLevel, QrCode};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{ParsedCertificate, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use ureq::tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig, parse_pem};
use zeroize::Zeroizing;

const RUNTIME_PORT: &str = ".runtime-port";
const RUNTIME_TLS: &str = ".runtime-tls-cert";
const ENROLL_SECRET: &str = "mcp-server.enroll-secret";
const LOCAL_APPROVALS: &str = "/api/v1/local/approvals";
const LOCAL_APPROVAL_ACTION: &str = "/api/v1/local/approvals/";
const DEVICE_ENROLL_CODE: &str = "/api/v1/devices/enroll-code";
const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct RuntimePort {
    port: u16,
    #[serde(default)]
    bind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RuntimeTls {
    certificate: String,
    #[serde(default)]
    client_auth_required: bool,
    #[serde(default)]
    client_ca_file: String,
    #[serde(default)]
    client_certificate: String,
    #[serde(default)]
    client_key: String,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigTlsFallback {
    mcp: Option<ConfigMcpTlsFallback>,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigMcpTlsFallback {
    #[serde(default)]
    tls_cert_file: String,
    #[serde(default)]
    tls_client_ca_file: String,
    #[serde(default)]
    approval_tls_cert_file: String,
    #[serde(default)]
    approval_tls_key_file: String,
    #[serde(default)]
    mtls_enabled: bool,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct ApprovalList {
    requests: Vec<ApprovalEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApprovalDecision {
    outcome: ApprovalOutcome,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApprovalOutcome {
    id: String,
    status: String,
    #[serde(default = "zero_timestamp")]
    decided_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    decided_by: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct ApprovalEntry {
    agent_name: String,
    path: String,
    write: bool,
    reason: String,
    created_at: String,
    expires_at: String,
    id: String,
    status: String,
    #[serde(default = "zero_timestamp")]
    decided_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    decided_by: String,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct EnrollCode {
    code: String,
    expires_at: String,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct PairingPayload<'a> {
    host: &'a str,
    port: u16,
    code: &'a str,
    fingerprint: &'a str,
}

/// Ask the running Go server to mint a code over its localhost-only endpoint.
/// `host` is the address the phone will use; the mint request always targets
/// loopback even when the server is listening on a LAN interface.
pub(crate) fn pair(
    vault: &Path,
    host: Option<&str>,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    let (port, bind) = runtime_server(vault)?;
    let host = select_pair_host(host, &bind, detect_lan_ipv4)?;
    let runtime_tls = load_runtime_tls(vault)?;
    let certificate =
        symvault_sync::safeio::read_bounded(Path::new(&runtime_tls.certificate), 1024 * 1024)
            .map_err(|_| "read server TLS certificate".to_owned())?
            .ok_or_else(|| "read server TLS certificate".to_owned())?;
    let certificates = parse_certificate_chain(&certificate, "parse server TLS certificate")?;
    let secret = symvault_sync::safeio::read_bounded(&vault.join(ENROLL_SECRET), 64)
        .map_err(|error| format!("load vault-ownership proof secret: {error}"))?
        .ok_or_else(|| "load vault-ownership proof secret: file not found".to_owned())?;
    if secret.len() != 32 {
        return Err("load vault-ownership proof secret: invalid secret length".to_owned());
    }
    let secret = Zeroizing::new(secret);
    let timestamp = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|error| format!("format approval timestamp: {error}"))?
        .format(&Rfc3339)
        .map_err(|error| format!("format approval timestamp: {error}"))?;
    let proof = enroll_proof(&secret, timestamp.as_bytes());
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&certificates))
        .build();
    let agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .proxy(None)
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .new_agent();
    let url = format!("https://127.0.0.1:{port}{DEVICE_ENROLL_CODE}");
    let mut response = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Enroll-Timestamp", &timestamp)
        .header("X-Enroll-Proof", &proof)
        .send_empty()
        .map_err(|error| {
            format!("call {DEVICE_ENROLL_CODE} (is 'symvault serve' running with TLS?): {error}")
        })?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_string()
        .map_err(|error| format!("decode approval response: {error}"))?;
    let minted: EnrollCode = decode_api_response(status, &body)?;
    if minted.code.is_empty() || minted.fingerprint.is_empty() {
        return Err("decode approval response: missing code or fingerprint".to_owned());
    }
    let payload = PairingPayload {
        host: &host,
        port,
        code: &minted.code,
        fingerprint: &minted.fingerprint,
    };
    print!(
        "{}",
        render_pair_output(&payload, &minted.expires_at, json, quiet, terminal_width())?
    );
    Ok(())
}

fn select_pair_host(
    explicit_host: Option<&str>,
    bind: &str,
    detect: impl FnOnce() -> Result<Vec<Ipv4Addr>, String>,
) -> Result<String, String> {
    validate_pair_bind(bind)?;
    if let Some(host) = explicit_host {
        validate_pair_target(host, bind)?;
        return Ok(host.trim().to_owned());
    }

    let candidates = detect().unwrap_or_default();
    match candidates.as_slice() {
        [] => Err("could not auto-detect a LAN address; pass --host <ip> explicitly".to_owned()),
        [host] => Ok(host.to_string()),
        _ => {
            let mut message =
                String::from("multiple network addresses found; pass --host to pick one:\n");
            for host in candidates {
                message.push_str(&format!("  {host}\n"));
            }
            Err(message)
        }
    }
}

fn detect_lan_ipv4() -> Result<Vec<Ipv4Addr>, String> {
    let interfaces = getifaddrs::InterfaceFilter::new()
        .v4()
        .get()
        .map_err(|error| error.to_string())?;
    let mut addresses = Vec::new();
    for interface in interfaces {
        if let Address::V4(address) = interface.address {
            let ip = address.address;
            if is_lan_ipv4(interface.flags, ip) {
                addresses.push(ip);
            }
        }
    }
    Ok(addresses)
}

fn is_lan_ipv4(flags: InterfaceFlags, ip: Ipv4Addr) -> bool {
    flags.contains(InterfaceFlags::UP)
        && !flags.contains(InterfaceFlags::LOOPBACK)
        && !ip.is_loopback()
        && !ip.is_link_local()
}

fn render_pair_output(
    payload: &PairingPayload<'_>,
    expires_at: &str,
    json: bool,
    quiet: bool,
    width: usize,
) -> Result<String, String> {
    if quiet {
        return Ok(String::new());
    }
    if json {
        return serde_json::to_string(payload)
            .map(|value| format!("{value}\n"))
            .map_err(|error| error.to_string());
    }

    let data = serde_json::to_string(payload).map_err(|error| error.to_string())?;
    let qr = render_qr_for_width(&data, width);
    let mut output = String::from("\n=== Approval Device Pairing ===\n\n");
    match qr {
        Ok(art) => {
            output.push_str(&art);
            output.push('\n');
        }
        Err(error) => output.push_str(&format!("(QR code not shown: {error})\n\n")),
    }
    output.push_str("Scan this with the Symaira Vault iOS app, or enter it manually:\n\n");
    output.push_str(&format!(
        "  Host:        {}\n  Port:        {}\n  Code:        {}\n  Fingerprint: {}\n\nExpires: {}\n",
        payload.host, payload.port, payload.code, payload.fingerprint, expires_at
    ));
    Ok(output)
}

fn render_qr_for_width(data: &str, width: usize) -> Result<String, String> {
    const MIN_QR_WIDTH: usize = 41;
    if width > 0 && width < MIN_QR_WIDTH {
        return Err(format!(
            "terminal too narrow for QR code; need at least {MIN_QR_WIDTH} columns"
        ));
    }
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .map_err(|error| format!("qr encode: {error}"))?;
    let size = code.width();
    let total_size = size + 8;
    let mut output = String::new();
    for y in (0..total_size).step_by(2) {
        for x in 0..total_size {
            let top = qr_is_dark(&code, x, y, size);
            let bottom = qr_is_dark(&code, x, y + 1, size);
            output.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        output.push('\n');
    }
    Ok(output)
}

fn qr_is_dark(code: &QrCode, x: usize, y: usize, size: usize) -> bool {
    x >= 4 && y >= 4 && x < size + 4 && y < size + 4 && code[(x - 4, y - 4)] == QrColor::Dark
}

fn terminal_width() -> usize {
    terminal_size::terminal_size_of(std::io::stderr())
        .map(|(terminal_size::Width(width), _)| usize::from(width))
        .unwrap_or(80)
}

fn validate_pair_target(host: &str, bind: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.chars().any(char::is_control)
    {
        return Err("--host must be a LAN address reachable by the phone".to_owned());
    }
    if host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|address| {
            address.is_loopback() || address.is_unspecified() || address.is_multicast()
        })
    {
        return Err("--host must be a LAN address reachable by the phone".to_owned());
    }
    validate_pair_bind(bind)
}

fn validate_pair_bind(bind: &str) -> Result<(), String> {
    let bind = bind.trim();
    let loopback = bind == "localhost"
        || bind
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if loopback {
        return Err(format!(
            "'symvault serve' is bound to {bind} (loopback-only) — a phone on the LAN cannot reach it. Restart the server with --bind 0.0.0.0 (all interfaces) or --bind <lan-ip>, then run 'approval-pair' again"
        ));
    }
    Ok(())
}

/// Fetch and render the live queue, preserving Go's loopback, TLS and
/// vault-ownership-proof boundary. mTLS uses the dedicated local approval
/// identity after validating its chain, client-auth usage, and distinct key.
pub(crate) fn list(
    vault: &Path,
    output_format: &str,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    let result: ApprovalList = approval_api_request(vault, "GET", LOCAL_APPROVALS)?;
    render(result, output_format, json, quiet)
}

pub(crate) fn decide(
    vault: &Path,
    request_id: &str,
    approve: bool,
    deny: bool,
    output_format: &str,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    if approve == deny {
        return Err("exactly one of --approve or --deny is required".to_owned());
    }
    let action = if approve { "approve" } else { "deny" };
    let path = format!("{LOCAL_APPROVAL_ACTION}{request_id}/{action}");
    let result: ApprovalDecision = approval_api_request(vault, "POST", &path)?;
    render_decision(result, output_format, json, quiet)
}

fn approval_api_request<T: DeserializeOwned>(
    vault: &Path,
    method: &str,
    path: &str,
) -> Result<T, String> {
    let (port, bind) = runtime_server(vault)?;
    let ip = bind.parse::<IpAddr>().ok();
    let loopback = bind == "localhost" || ip.is_some_and(|value| value.is_loopback());
    if !loopback {
        return Err(format!(
            "approval CLI requires a server bound to loopback; running server is bound to {bind:?}"
        ));
    }

    let runtime_tls = load_runtime_tls(vault)?;
    let certificate =
        symvault_sync::safeio::read_bounded(Path::new(&runtime_tls.certificate), 1024 * 1024)
            .map_err(|_| "read server TLS certificate".to_owned())?
            .ok_or_else(|| "read server TLS certificate".to_owned())?;
    let server_certificates =
        parse_certificate_chain(&certificate, "parse server TLS certificate")?;
    let client_identity = if runtime_tls.client_auth_required {
        Some(load_approval_client_identity(
            &server_certificates[0],
            &runtime_tls,
        )?)
    } else {
        None
    };

    let secret = symvault_sync::safeio::read_bounded(&vault.join(ENROLL_SECRET), 64)
        .map_err(|error| format!("load vault-ownership proof secret: {error}"))?
        .ok_or_else(|| "load vault-ownership proof secret: file not found".to_owned())?;
    if secret.len() != 32 {
        return Err("load vault-ownership proof secret: invalid secret length".to_owned());
    }
    let secret = Zeroizing::new(secret);
    let timestamp = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|error| format!("format approval timestamp: {error}"))?
        .format(&Rfc3339)
        .map_err(|error| format!("format approval timestamp: {error}"))?;
    let proof = enroll_proof(&secret, timestamp.as_bytes());

    let host = match ip {
        Some(IpAddr::V6(_)) => format!("[{bind}]"),
        _ => bind,
    };
    let url = format!("https://{host}:{port}{path}");
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&server_certificates))
        .client_cert(client_identity)
        .build();
    let agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .proxy(None)
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .new_agent();
    let response = match method {
        "GET" => agent
            .get(&url)
            .header("X-Enroll-Timestamp", &timestamp)
            .header("X-Enroll-Proof", &proof)
            .call(),
        "POST" => agent
            .post(&url)
            .header("X-Enroll-Timestamp", &timestamp)
            .header("X-Enroll-Proof", &proof)
            .send_empty(),
        _ => return Err(format!("unsupported local approval method {method:?}")),
    };
    let mut response =
        response.map_err(|error| format!("connect to local approval server: {error}"))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_string()
        .map_err(|error| format!("decode approval response: {error}"))?;
    decode_api_response(status, &body)
}

fn decode_api_response<T: DeserializeOwned>(status: u16, body: &str) -> Result<T, String> {
    if !(200..300).contains(&status) {
        if let Ok(api_error) = serde_json::from_str::<ApiError>(body)
            && !api_error.error.trim().is_empty()
        {
            return Err(format!("approval server: {}", api_error.error));
        }
        return Err(format!("approval server returned HTTP {status}"));
    }
    serde_json::from_str(body).map_err(|error| format!("decode approval response: {error}"))
}

fn runtime_server(vault: &Path) -> Result<(u16, String), String> {
    let path = vault.join(RUNTIME_PORT);
    let data = symvault_sync::safeio::read_bounded(&path, 4096)
        .map_err(|error| format!("read running server metadata: {error}"))?
        .ok_or_else(|| {
            "could not find the running server — is 'symvault serve' running?".to_owned()
        })?;
    if let Ok(record) = serde_json::from_slice::<RuntimePort>(&data)
        && record.port > 0
    {
        return Ok((
            record.port,
            if record.bind.is_empty() {
                "127.0.0.1".to_owned()
            } else {
                record.bind
            },
        ));
    }
    let port = std::str::from_utf8(&data)
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            "could not find the running server — is 'symvault serve' running?".to_owned()
        })?;
    Ok((port, "127.0.0.1".to_owned()))
}

fn load_runtime_tls(vault: &Path) -> Result<RuntimeTls, String> {
    let path = vault.join(RUNTIME_TLS);
    if let Ok(Some(data)) = symvault_sync::safeio::read_bounded(&path, 64 * 1024)
        && let Ok(record) = serde_json::from_slice::<RuntimeTls>(&data)
        && !record.certificate.trim().is_empty()
    {
        return Ok(record);
    }

    // Go cmd/approval.go falls back to config.yaml when the runtime snapshot
    // is absent or malformed. Keep that fallback, but leave the identity
    // verifier below responsible for rejecting incomplete mTLS credentials.
    let config_path = vault.join("config.yaml");
    let config_data = symvault_sync::safeio::read_bounded(&config_path, 1024 * 1024)
        .map_err(|_| "could not find valid running server TLS metadata or config.yaml".to_owned())?
        .ok_or_else(|| {
            "could not find valid running server TLS metadata or config.yaml".to_owned()
        })?;
    let config: ConfigTlsFallback = serde_yaml_ng::from_slice(&config_data).map_err(|_| {
        "could not find valid running server TLS metadata or config.yaml".to_owned()
    })?;
    let mcp = config.mcp.unwrap_or_default();
    let certificate = match mcp.tls_cert_file.trim() {
        "" => vault.join("mcp-server.crt").to_string_lossy().into_owned(),
        value => value.to_owned(),
    };
    Ok(RuntimeTls {
        certificate,
        client_auth_required: mcp.mtls_enabled,
        client_ca_file: mcp.tls_client_ca_file.trim().to_owned(),
        client_certificate: mcp.approval_tls_cert_file.trim().to_owned(),
        client_key: mcp.approval_tls_key_file.trim().to_owned(),
    })
}

fn parse_certificate_chain(pem: &[u8], error: &str) -> Result<Vec<Certificate<'static>>, String> {
    let mut certificates = Vec::new();
    for item in parse_pem(pem) {
        match item.map_err(|_| error.to_owned())? {
            PemItem::Certificate(certificate) => certificates.push(certificate),
            PemItem::PrivateKey(_) => {}
            _ => {}
        }
    }
    if certificates.is_empty() {
        return Err(error.to_owned());
    }
    Ok(certificates)
}

fn load_approval_client_identity(
    server_certificate: &Certificate<'static>,
    runtime_tls: &RuntimeTls,
) -> Result<ClientCert, String> {
    if runtime_tls.client_certificate.trim().is_empty()
        || runtime_tls.client_key.trim().is_empty()
        || runtime_tls.client_ca_file.trim().is_empty()
    {
        return Err("approval CLI cannot connect while the running MCP server requires mTLS because the dedicated local approval client certificate, key, and CA must both be configured".to_owned());
    }
    let client_pem = symvault_sync::safeio::read_bounded(
        Path::new(&runtime_tls.client_certificate),
        1024 * 1024,
    )
    .map_err(|_| "read local approval client identity".to_owned())?
    .ok_or_else(|| "read local approval client identity".to_owned())?;
    let client_certificates =
        parse_certificate_chain(&client_pem, "parse local approval client identity")?;
    let server_der = CertificateDer::from(server_certificate.der().to_vec());
    let client_der = client_certificates
        .iter()
        .map(|certificate| CertificateDer::from(certificate.der().to_vec()))
        .collect::<Vec<_>>();
    let server_parsed = ParsedCertificate::try_from(&server_der)
        .map_err(|_| "inspect server TLS certificate".to_owned())?;
    let client_parsed = ParsedCertificate::try_from(&client_der[0])
        .map_err(|_| "parse local approval client identity".to_owned())?;
    if server_parsed.subject_public_key_info() == client_parsed.subject_public_key_info() {
        return Err("approval CLI refuses to reuse the MCP server certificate identity as the approval client identity".to_owned());
    }

    let ca_pem =
        symvault_sync::safeio::read_bounded(Path::new(&runtime_tls.client_ca_file), 1024 * 1024)
            .map_err(|_| "read approval client CA".to_owned())?
            .ok_or_else(|| "read approval client CA".to_owned())?;
    let ca_certificates = parse_certificate_chain(&ca_pem, "parse approval client CA")?;
    let mut roots = RootCertStore::empty();
    for certificate in ca_certificates {
        roots
            .add(CertificateDer::from(certificate.der().to_vec()))
            .map_err(|_| "parse approval client CA".to_owned())?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| "parse approval client CA".to_owned())?;
    // Go's x509.Verify is called without CRLs, so no revocation list is configured here.
    verifier
        .verify_client_cert(&client_der[0], &client_der[1..], UnixTime::now())
        .map_err(|_| "verify local approval client identity".to_owned())?;

    let key_pem = Zeroizing::new(
        symvault_sync::safeio::read_bounded(Path::new(&runtime_tls.client_key), 1024 * 1024)
            .map_err(|_| "load local approval client identity failed".to_owned())?
            .ok_or_else(|| "load local approval client identity failed".to_owned())?,
    );
    let key = PrivateKey::from_pem(&key_pem)
        .map_err(|_| "load local approval client identity failed".to_owned())?;
    let rustls_key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|_| "load local approval client identity failed".to_owned())?;
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(client_der, rustls_key, &provider)
        .and_then(|identity| identity.keys_match())
        .map_err(|_| "load local approval client identity failed".to_owned())?;
    Ok(ClientCert::new_with_certs(&client_certificates, key))
}

fn enroll_proof(secret: &[u8], timestamp: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a secret of any length");
    mac.update(timestamp);
    let bytes = mac.finalize().into_bytes();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn zero_timestamp() -> String {
    "0001-01-01T00:00:00Z".to_owned()
}

fn render(
    result: ApprovalList,
    output_format: &str,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    if json || output_format == "json" {
        println!(
            "{}",
            serde_json::to_string(&result).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if output_format == "yaml" {
        print!(
            "{}",
            serde_yaml_ng::to_string(&result).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if result.requests.is_empty() {
        println!("No pending approval requests.");
        return Ok(());
    }
    println!(
        "{:<18} {:<20} {:<32} {:<6} {:<10} EXPIRES",
        "REQUEST ID", "AGENT", "PATH", "WRITE", "STATUS"
    );
    for request in result.requests {
        let expires = OffsetDateTime::parse(&request.expires_at, &Rfc3339)
            .ok()
            .and_then(|date| date.replace_nanosecond(0).ok())
            .and_then(|date| date.format(&Rfc3339).ok())
            .unwrap_or(request.expires_at);
        println!(
            "{:<18} {:<20} {:<32} {:<6} {:<10} {}",
            request.id, request.agent_name, request.path, request.write, request.status, expires
        );
    }
    Ok(())
}

fn render_decision(
    result: ApprovalDecision,
    output_format: &str,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    if json || output_format == "json" {
        println!(
            "{}",
            serde_json::to_string(&result).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if output_format == "yaml" {
        print!(
            "{}",
            serde_yaml_ng::to_string(&result).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    println!(
        "Approval request {:?} {}.",
        result.outcome.id, result.outcome.status
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{
        ApprovalDecision, EnrollCode, PairingPayload, RUNTIME_TLS, RuntimeTls, decode_api_response,
        enroll_proof, is_lan_ipv4, load_approval_client_identity, load_runtime_tls,
        parse_certificate_chain, render_pair_output, render_qr_for_width, select_pair_host,
        validate_pair_target,
    };
    use getifaddrs::InterfaceFlags;
    use std::net::Ipv4Addr;
    use ureq::tls::Certificate;

    const GO_ENROLL_SOURCE: &str = include_str!("../../../internal/approval/enroll.go");
    const GO_DEVICE_APPROVAL_SOURCE: &str = include_str!("../../../cmd/device_approval.go");
    const GO_LOCAL_SOURCE: &str = include_str!("../../../internal/approval/local.go");
    const GO_QUEUE_SOURCE: &str = include_str!("../../../internal/approval/queue.go");
    const GO_APPROVAL_SOURCE: &str = include_str!("../../../cmd/approval.go");
    const GO_RUNTIME_TLS_SOURCE: &str = include_str!("../../../internal/cli/port_utils.go");
    const GO_MTLS_E2E_SOURCE: &str = include_str!("../../../cmd/approval_mtls_e2e_test.go");

    #[test]
    fn enroll_proof_uses_go_hmac_sha256_bytes() {
        assert!(GO_ENROLL_SOURCE.contains("hmac.New(sha256.New, secret)"));
        assert!(
            GO_ENROLL_SOURCE.contains("PathDeviceEnrollCode = \"/api/v1/devices/enroll-code\"")
        );
        assert!(GO_ENROLL_SOURCE.contains("HeaderEnrollTimestamp = \"X-Enroll-Timestamp\""));
        assert!(GO_ENROLL_SOURCE.contains("HeaderEnrollProof = \"X-Enroll-Proof\""));
        assert!(GO_DEVICE_APPROVAL_SOURCE.contains("https://127.0.0.1:%d%s"));
        assert!(
            GO_DEVICE_APPROVAL_SOURCE
                .contains("req.Header.Set(\"Content-Type\", \"application/json\")")
        );
        assert!(GO_ENROLL_SOURCE.contains("\"fingerprint\": h.fingerprint"));
        assert_eq!(
            enroll_proof(&(0u8..32).collect::<Vec<_>>(), b"2026-09-24T00:00:00Z"),
            "2a5b82136548c4dabec59c8055dc424ac6bdd0f34ecab28eb732881f642ae651"
        );
    }

    #[test]
    fn device_pair_decodes_go_success_and_rejects_go_failures() {
        let minted: EnrollCode = decode_api_response(
            200,
            r#"{"code":"ABCD1234","expires_at":"2026-09-24T00:05:00Z","fingerprint":"sha256:test"}"#,
        )
        .expect("Go mint response");
        assert_eq!(minted.code, "ABCD1234");
        assert_eq!(minted.fingerprint, "sha256:test");
        assert_eq!(
            decode_api_response::<EnrollCode>(
                401,
                r#"{"error":"missing or invalid proof of vault-directory ownership"}"#,
            )
            .unwrap_err(),
            "approval server: missing or invalid proof of vault-directory ownership"
        );
        assert!(decode_api_response::<EnrollCode>(200, r#"{"code":"ABCD1234"}"#).is_err());
    }

    #[test]
    fn device_pair_requires_phone_host_and_reachable_server_bind() {
        assert!(
            validate_pair_target("  ", "0.0.0.0")
                .unwrap_err()
                .contains("--host")
        );
        assert!(validate_pair_target("127.0.0.1", "0.0.0.0").is_err());
        assert!(validate_pair_target("192.168.1.42\nInjected:", "0.0.0.0").is_err());
        for bind in ["127.0.0.1", "::1", "localhost"] {
            let error = validate_pair_target("192.168.1.42", bind).unwrap_err();
            assert!(error.contains("loopback-only"), "{bind}: {error}");
        }
        assert!(validate_pair_target("192.168.1.42", "0.0.0.0").is_ok());
    }

    #[test]
    fn device_pair_uses_explicit_host_without_detecting_interfaces() {
        let host = select_pair_host(Some(" 192.168.1.42 "), "0.0.0.0", || {
            panic!("explicit host must bypass interface detection")
        })
        .expect("explicit host");
        assert_eq!(host, "192.168.1.42");
    }

    #[test]
    fn device_pair_auto_detects_only_one_unambiguous_host() {
        let host = select_pair_host(None, "0.0.0.0", || Ok(vec![Ipv4Addr::new(192, 168, 1, 42)]))
            .expect("one candidate");
        assert_eq!(host, "192.168.1.42");
    }

    #[test]
    fn device_pair_reports_missing_or_ambiguous_host_candidates() {
        let missing = select_pair_host(None, "0.0.0.0", || Ok(Vec::new())).unwrap_err();
        assert_eq!(
            missing,
            "could not auto-detect a LAN address; pass --host <ip> explicitly"
        );
        let failed =
            select_pair_host(None, "0.0.0.0", || Err("interface query failed".into())).unwrap_err();
        assert_eq!(failed, missing);

        let multiple = select_pair_host(None, "0.0.0.0", || {
            Ok(vec![
                Ipv4Addr::new(192, 168, 1, 42),
                Ipv4Addr::new(10, 0, 0, 12),
            ])
        })
        .unwrap_err();
        assert_eq!(
            multiple,
            "multiple network addresses found; pass --host to pick one:\n  192.168.1.42\n  10.0.0.12\n"
        );
    }

    #[test]
    fn device_pair_rejects_loopback_bind_before_host_detection() {
        let error = select_pair_host(None, "127.0.0.1", || {
            panic!("loopback bind must be rejected before host detection")
        })
        .unwrap_err();
        assert!(error.contains("loopback-only"), "{error}");
    }

    #[test]
    fn device_pair_lan_detection_filters_down_local_and_link_local_addresses() {
        let up = InterfaceFlags::UP;
        let up_loopback = up | InterfaceFlags::LOOPBACK;
        assert!(is_lan_ipv4(up, Ipv4Addr::new(192, 168, 1, 42)));
        assert!(!is_lan_ipv4(
            InterfaceFlags::empty(),
            Ipv4Addr::new(192, 168, 1, 42)
        ));
        assert!(!is_lan_ipv4(up_loopback, Ipv4Addr::new(192, 168, 1, 42)));
        assert!(!is_lan_ipv4(up, Ipv4Addr::LOCALHOST));
        assert!(!is_lan_ipv4(up, Ipv4Addr::new(169, 254, 10, 2)));
    }

    #[test]
    fn device_pair_qr_and_manual_fallback_rendering() {
        let payload = PairingPayload {
            host: "192.168.1.42",
            port: 8443,
            code: "ABCD1234",
            fingerprint: "sha256:test",
        };
        let qr = render_qr_for_width(r#"{"host":"192.168.1.42"}"#, 41).expect("QR");
        assert!(
            qr.chars().any(|glyph| matches!(glyph, '█' | '▀' | '▄')),
            "{qr}"
        );
        assert!(qr.ends_with('\n'));
        assert!(
            render_qr_for_width("data", 40)
                .unwrap_err()
                .contains("need at least 41 columns")
        );

        let fallback = render_pair_output(&payload, "2026-09-26T12:00:00Z", false, false, 40)
            .expect("manual fallback");
        assert!(fallback.starts_with("\n=== Approval Device Pairing ===\n\n"));
        assert!(fallback.contains("(QR code not shown: terminal too narrow"));
        assert!(fallback.contains("Scan this with the Symaira Vault iOS app"));
        assert!(fallback.contains("  Code:        ABCD1234\n"));
        assert!(fallback.ends_with("Expires: 2026-09-26T12:00:00Z\n"));

        let qr_output = render_pair_output(&payload, "2026-09-26T12:00:00Z", false, false, 80)
            .expect("QR output");
        assert!(qr_output.starts_with("\n=== Approval Device Pairing ===\n\n"));
        assert!(!qr_output.contains("QR code not shown"));
        assert!(
            qr_output
                .chars()
                .any(|glyph| matches!(glyph, '█' | '▀' | '▄'))
        );

        let json = render_pair_output(&payload, "ignored", true, false, 0).expect("JSON");
        assert_eq!(
            json,
            "{\"host\":\"192.168.1.42\",\"port\":8443,\"code\":\"ABCD1234\",\"fingerprint\":\"sha256:test\"}\n"
        );
        assert_eq!(
            render_pair_output(&payload, "ignored", false, true, 40).unwrap(),
            ""
        );
    }

    #[test]
    fn decide_response_matches_go_success_and_conflict_contract() {
        assert!(
            GO_LOCAL_SOURCE
                .contains("writeApprovalJSON(w, http.StatusOK, map[string]any{\"outcome\": out})")
        );
        assert!(GO_LOCAL_SOURCE.contains("status := http.StatusConflict"));
        assert!(GO_QUEUE_SOURCE.contains("approval request %s already %s"));

        let success: ApprovalDecision = decode_api_response(
            200,
            r#"{"outcome":{"id":"apr-test","status":"approved","decided_at":"2026-09-24T10:00:00Z","decided_by":"local-cli"}}"#,
        )
        .expect("decode Go success response");
        assert_eq!(success.outcome.id, "apr-test");
        assert_eq!(success.outcome.status, "approved");
        assert_eq!(success.outcome.decided_by, "local-cli");

        let conflict = decode_api_response::<ApprovalDecision>(
            409,
            r#"{"error":"approval request apr-test already approved"}"#,
        )
        .expect_err("repeat decision must surface HTTP conflict");
        assert_eq!(
            conflict,
            "approval server: approval request apr-test already approved"
        );
    }

    #[test]
    fn runtime_mtls_paths_match_go_effective_tls_metadata() {
        let metadata: RuntimeTls = serde_json::from_str(
            r#"{"certificate":"server.pem","client_ca_file":"clients-ca.pem","client_certificate":"approval.pem","client_key":"approval.key","client_auth_required":true}"#,
        )
        .expect("parse Go runtime TLS snapshot");
        assert!(metadata.client_auth_required);
        assert_eq!(metadata.client_ca_file, "clients-ca.pem");
        assert_eq!(metadata.client_certificate, "approval.pem");
        assert_eq!(metadata.client_key, "approval.key");
        for field in [
            "client_ca_file",
            "client_certificate",
            "client_key",
            "client_auth_required",
        ] {
            assert!(GO_RUNTIME_TLS_SOURCE.contains(field));
        }
        assert!(GO_APPROVAL_SOURCE.contains("validateApprovalClientIdentity"));
        assert!(GO_APPROVAL_SOURCE.contains("x509.ExtKeyUsageClientAuth"));
        assert!(GO_APPROVAL_SOURCE.contains("tls.LoadX509KeyPair(clientCertFile, clientKeyFile)"));
        assert!(GO_APPROVAL_SOURCE.contains("clientLeaf.Verify(x509.VerifyOptions"));
        assert!(GO_MTLS_E2E_SOURCE.contains("old CA/client was accepted after rotation"));
    }

    #[test]
    fn missing_or_malformed_runtime_tls_uses_go_config_paths() {
        assert!(GO_APPROVAL_SOURCE.contains("cli.LoadRuntimeTLSConfig(vaultDir)"));
        assert!(
            GO_APPROVAL_SOURCE.contains("configpkg.Load(filepath.Join(vaultDir, \"config.yaml\"))")
        );
        for key in [
            "TLSCertFile",
            "TLSClientCAFile",
            "ApprovalTLSCertFile",
            "ApprovalTLSKeyFile",
            "MTLSEnabled",
        ] {
            assert!(GO_APPROVAL_SOURCE.contains(&format!("cfg.MCP.{key}")));
        }

        let vault = tempfile::tempdir().expect("temporary vault");
        fs::write(
            vault.path().join("config.yaml"),
            "mcp:\n  tls_cert_file: ' /server/cert.pem '\n  tls_client_ca_file: ' /clients/ca.pem '\n  approval_tls_cert_file: ' /clients/approval.pem '\n  approval_tls_key_file: ' /clients/approval.key '\n  mtls_enabled: true\n",
        )
        .expect("write Go-compatible fallback config");

        let missing_snapshot =
            load_runtime_tls(vault.path()).expect("config fallback for missing snapshot");
        assert_eq!(missing_snapshot.certificate, "/server/cert.pem");
        assert_eq!(missing_snapshot.client_ca_file, "/clients/ca.pem");
        assert_eq!(missing_snapshot.client_certificate, "/clients/approval.pem");
        assert_eq!(missing_snapshot.client_key, "/clients/approval.key");
        assert!(missing_snapshot.client_auth_required);

        fs::write(vault.path().join(RUNTIME_TLS), "{malformed").expect("write malformed snapshot");
        let malformed_snapshot =
            load_runtime_tls(vault.path()).expect("config fallback for malformed snapshot");
        assert_eq!(malformed_snapshot.certificate, missing_snapshot.certificate);
        assert_eq!(
            malformed_snapshot.client_ca_file,
            missing_snapshot.client_ca_file
        );
        assert_eq!(
            malformed_snapshot.client_certificate,
            missing_snapshot.client_certificate
        );
        assert_eq!(malformed_snapshot.client_key, missing_snapshot.client_key);
        assert!(malformed_snapshot.client_auth_required);
    }

    #[test]
    fn config_fallback_keeps_mtls_identity_validation_fail_closed() {
        let vault = tempfile::tempdir().expect("temporary vault");
        fs::write(
            vault.path().join("config.yaml"),
            "mcp:\n  tls_cert_file: /server/cert.pem\n  mtls_enabled: true\n",
        )
        .expect("write incomplete mTLS config");
        let runtime_tls = load_runtime_tls(vault.path()).expect("parse TLS fallback");
        let error = load_approval_client_identity(&Certificate::from_der(&[]), &runtime_tls)
            .expect_err("incomplete configured identity must fail closed");
        assert!(error.contains("dedicated local approval client certificate"));
    }

    #[test]
    fn mtls_refuses_missing_identity_paths_before_reading_files() {
        let runtime_tls = RuntimeTls {
            certificate: String::new(),
            client_auth_required: true,
            client_ca_file: String::new(),
            client_certificate: String::new(),
            client_key: String::new(),
        };
        let server_certificate = Certificate::from_der(&[]);
        let error = load_approval_client_identity(&server_certificate, &runtime_tls)
            .expect_err("missing identity paths must fail closed");
        assert!(error.contains("dedicated local approval client certificate"));
    }

    #[test]
    fn malformed_certificate_bundle_fails_closed() {
        assert_eq!(
            parse_certificate_chain(b"not a certificate", "parse client identity")
                .expect_err("malformed PEM must fail closed"),
            "parse client identity"
        );
    }

    #[test]
    fn client_identity_requires_client_auth_trust_distinct_key_and_matching_private_key() {
        let vault = tempfile::tempdir().expect("temporary identity files");
        let server_certificate =
            Certificate::from_pem(include_bytes!("../tests/fixtures/approval-mtls/server.pem"))
                .expect("parse server fixture");
        let client_certificate = write_fixture(
            vault.path(),
            "approval-client.pem",
            include_bytes!("../tests/fixtures/approval-mtls/approval-client.pem"),
        );
        let client_key = write_fixture(
            vault.path(),
            "approval-client.key",
            include_bytes!("../tests/fixtures/approval-mtls/approval-client.key"),
        );
        let client_ca = write_fixture(
            vault.path(),
            "client-ca.pem",
            include_bytes!("../tests/fixtures/approval-mtls/client-ca.pem"),
        );
        let runtime_tls = RuntimeTls {
            certificate: "server.pem".to_owned(),
            client_auth_required: true,
            client_ca_file: client_ca.to_string_lossy().into_owned(),
            client_certificate: client_certificate.to_string_lossy().into_owned(),
            client_key: client_key.to_string_lossy().into_owned(),
        };
        assert!(load_approval_client_identity(&server_certificate, &runtime_tls).is_ok());

        let server_identity = write_fixture(
            vault.path(),
            "server.pem",
            include_bytes!("../tests/fixtures/approval-mtls/server.pem"),
        );
        let mut cloned_identity = RuntimeTls {
            client_certificate: server_identity.to_string_lossy().into_owned(),
            ..runtime_tls.clone()
        };
        let error = load_approval_client_identity(&server_certificate, &cloned_identity)
            .expect_err("server key reuse must fail before CA or key loading");
        assert!(error.contains("refuses to reuse the MCP server certificate identity"));

        cloned_identity.client_certificate = client_certificate.to_string_lossy().into_owned();
        cloned_identity.client_ca_file = write_fixture(
            vault.path(),
            "rotated-client-ca.pem",
            include_bytes!("../tests/fixtures/approval-mtls/rotated-client-ca.pem"),
        )
        .to_string_lossy()
        .into_owned();
        let error = load_approval_client_identity(&server_certificate, &cloned_identity)
            .expect_err("old CA identity must fail after CA rotation");
        assert_eq!(error, "verify local approval client identity");

        cloned_identity.client_ca_file = client_ca.to_string_lossy().into_owned();
        cloned_identity.client_key = write_fixture(
            vault.path(),
            "wrong-client.key",
            include_bytes!("../tests/fixtures/approval-mtls/server.key"),
        )
        .to_string_lossy()
        .into_owned();
        let error = load_approval_client_identity(&server_certificate, &cloned_identity)
            .expect_err("mismatched private key must fail closed");
        assert_eq!(error, "load local approval client identity failed");
    }

    fn write_fixture(directory: &std::path::Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, contents).expect("write test identity fixture");
        path
    }
}
