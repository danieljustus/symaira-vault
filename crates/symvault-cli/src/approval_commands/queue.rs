//! Local approval queue commands from Go `cmd/approval.go`.
//!
//! The live server remains authoritative. This CLI talks only to its
//! loopback-only local API, proves ownership of the selected vault with the
//! enrollment-secret HMAC, pins the configured server certificate, and uses a
//! distinct approval-client identity when the server requires mutual TLS.

use std::{
    io::{Cursor, Read},
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use hmac::{Hmac, Mac};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{ParsedCertificate, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

const RUNTIME_PORT: &str = ".runtime-port";
const RUNTIME_TLS: &str = ".runtime-tls-cert";
const ENROLL_SECRET: &str = "mcp-server.enroll-secret";
const LOCAL_APPROVALS: &str = "/api/v1/local/approvals";
const LOCAL_APPROVAL_ACTION: &str = "/api/v1/local/approvals/";
const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct RuntimePort {
    port: u16,
    #[serde(default)]
    bind: String,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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

pub(crate) fn list(
    vault: &Path,
    output_format: &str,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    let result: ApprovalList = approval_api_request(vault, "GET", LOCAL_APPROVALS)?;
    render_list(result, output_format, json, quiet)
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
    // Select the TLS provider explicitly before the HTTP client needs it.
    let _ = rustls::crypto::ring::default_provider().install_default();

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
    let pinned_certificates = server_certificates
        .iter()
        .map(|certificate| reqwest::Certificate::from_der(certificate.as_ref()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "parse server TLS certificate".to_owned())?;
    let mut client_builder = reqwest::blocking::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(pinned_certificates)
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10));
    if let Some(identity) = client_identity {
        client_builder = client_builder.identity(identity);
    }
    let client = client_builder
        .build()
        .map_err(|error| format!("create local approval HTTP client: {error}"))?;
    let response = match method {
        "GET" => client
            .get(&url)
            .header("X-Enroll-Timestamp", &timestamp)
            .header("X-Enroll-Proof", &proof)
            .send(),
        "POST" => client
            .post(&url)
            .header("X-Enroll-Timestamp", &timestamp)
            .header("X-Enroll-Proof", &proof)
            .send(),
        _ => return Err(format!("unsupported local approval method {method:?}")),
    };
    let response =
        response.map_err(|error| format!("connect to local approval server: {error}"))?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("decode approval response: {error}"))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("decode approval response: response exceeds size limit".to_owned());
    }
    let body =
        String::from_utf8(body).map_err(|error| format!("decode approval response: {error}"))?;
    decode_api_response(status, &body)
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

    // Go falls back to config.yaml when the runtime snapshot is absent or
    // malformed. The identity verifier rejects incomplete mTLS credentials.
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

fn parse_certificate_chain(
    pem: &[u8],
    error: &str,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut certificates = Vec::new();
    let mut input = Cursor::new(pem);
    while let Some((kind, data)) =
        rustls::pki_types::pem::from_buf(&mut input).map_err(|_| error.to_owned())?
    {
        if kind == rustls::pki_types::pem::SectionKind::Certificate {
            certificates.push(CertificateDer::from(data));
        }
    }
    if certificates.is_empty() {
        return Err(error.to_owned());
    }
    Ok(certificates)
}

fn load_approval_client_identity(
    server_certificate: &CertificateDer<'static>,
    runtime_tls: &RuntimeTls,
) -> Result<reqwest::Identity, String> {
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
    let server_der = server_certificate.clone();
    let client_der = client_certificates.to_vec();
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
            .add(certificate.clone())
            .map_err(|_| "parse approval client CA".to_owned())?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| "parse approval client CA".to_owned())?;
    // Go's x509.Verify is called without CRLs, so no revocation list is configured.
    verifier
        .verify_client_cert(&client_der[0], &client_der[1..], UnixTime::now())
        .map_err(|_| "verify local approval client identity".to_owned())?;

    let key_pem = Zeroizing::new(
        symvault_sync::safeio::read_bounded(Path::new(&runtime_tls.client_key), 1024 * 1024)
            .map_err(|_| "load local approval client identity failed".to_owned())?
            .ok_or_else(|| "load local approval client identity failed".to_owned())?,
    );
    let rustls_key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|_| "load local approval client identity failed".to_owned())?;
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(client_der, rustls_key, &provider)
        .and_then(|identity| identity.keys_match())
        .map_err(|_| "load local approval client identity failed".to_owned())?;
    let mut identity_pem = Zeroizing::new(Vec::with_capacity(client_pem.len() + key_pem.len()));
    identity_pem.extend_from_slice(&client_pem);
    identity_pem.extend_from_slice(&key_pem);
    reqwest::Identity::from_pem(&identity_pem)
        .map_err(|_| "load local approval client identity failed".to_owned())
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

fn zero_timestamp() -> String {
    "0001-01-01T00:00:00Z".to_owned()
}

fn render_list(
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
