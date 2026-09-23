//! Local approval queue commands from Go `cmd/approval.go`.
//!
//! `approval list` uses the loopback-only local route authenticated with a
//! timestamped HMAC over the vault's enroll secret. It is separate from the
//! enrolled-device bearer API. The local queue is never reconstructed here;
//! the running MCP server remains authoritative.

use std::{net::IpAddr, path::Path, time::Duration};

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use zeroize::Zeroizing;

const RUNTIME_PORT: &str = ".runtime-port";
const RUNTIME_TLS: &str = ".runtime-tls-cert";
const ENROLL_SECRET: &str = "mcp-server.enroll-secret";
const LOCAL_APPROVALS: &str = "/api/v1/local/approvals";
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
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct ApprovalList {
    requests: Vec<ApprovalEntry>,
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

/// Fetch and render the live queue, preserving Go's loopback, TLS and
/// vault-ownership-proof boundary. mTLS servers are rejected until the CLI
/// can validate and present the dedicated approval client identity.
pub(crate) fn list(
    vault: &Path,
    output_format: &str,
    json: bool,
    quiet: bool,
) -> Result<(), String> {
    let (port, bind) = runtime_server(vault)?;
    let ip = bind.parse::<IpAddr>().ok();
    let loopback = bind == "localhost" || ip.is_some_and(|value| value.is_loopback());
    if !loopback {
        return Err(format!(
            "approval CLI requires a server bound to loopback; running server is bound to {bind:?}"
        ));
    }

    let runtime_tls = load_runtime_tls(vault)?;
    if runtime_tls.client_auth_required {
        return Err("approval CLI cannot connect while the running MCP server requires mTLS; support for the dedicated local approval client identity is not available in this Rust command".to_owned());
    }

    let certificate =
        symvault_sync::safeio::read_bounded(Path::new(&runtime_tls.certificate), 1024 * 1024)
            .map_err(|_| "read server TLS certificate".to_owned())?
            .ok_or_else(|| "read server TLS certificate".to_owned())?;
    let certificate = Certificate::from_pem(&certificate)
        .map_err(|_| "parse server TLS certificate".to_owned())?;

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
    let url = format!("https://{host}:{port}{LOCAL_APPROVALS}");
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&[certificate]))
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
    let mut response = agent
        .get(&url)
        .header("X-Enroll-Timestamp", &timestamp)
        .header("X-Enroll-Proof", &proof)
        .call()
        .map_err(|error| format!("connect to local approval server: {error}"))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_string()
        .map_err(|error| format!("decode approval response: {error}"))?;
    if !(200..300).contains(&status) {
        if let Ok(api_error) = serde_json::from_str::<ApiError>(&body)
            && !api_error.error.trim().is_empty()
        {
            return Err(format!("approval server: {}", api_error.error));
        }
        return Err(format!("approval server returned HTTP {status}"));
    }
    let result: ApprovalList = serde_json::from_str(&body)
        .map_err(|error| format!("decode approval response: {error}"))?;
    render(result, output_format, json, quiet)
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
    let data = symvault_sync::safeio::read_bounded(&path, 64 * 1024)
        .map_err(|error| format!("read running server TLS metadata: {error}"))?
        .ok_or_else(|| "could not find the running server TLS certificate metadata".to_owned())?;
    let record: RuntimeTls = serde_json::from_slice(&data)
        .map_err(|_| "could not find the running server TLS certificate metadata".to_owned())?;
    if record.certificate.trim().is_empty() {
        return Err("could not find the running server TLS certificate metadata".to_owned());
    }
    Ok(record)
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

#[cfg(test)]
mod tests {
    use super::enroll_proof;

    const GO_ENROLL_SOURCE: &str = include_str!("../../../internal/approval/enroll.go");

    #[test]
    fn enroll_proof_uses_go_hmac_sha256_bytes() {
        assert!(GO_ENROLL_SOURCE.contains("hmac.New(sha256.New, secret)"));
        assert_eq!(
            enroll_proof(&(0u8..32).collect::<Vec<_>>(), b"2026-09-24T00:00:00Z"),
            "2a5b82136548c4dabec59c8055dc424ac6bdd0f34ecab28eb732881f642ae651"
        );
    }
}
